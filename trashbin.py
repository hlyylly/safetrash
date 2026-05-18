"""
安全垃圾桶 - 拖文件进来即彻底删除 + 跨盘副本查找（带 SQLite 持久化索引）
依赖: pip install tkinterdnd2
"""
import os
import sys
import stat
import time
import json
import string
import sqlite3
import hashlib
import threading
import secrets
import tkinter as tk
from tkinter import messagebox
from pathlib import Path

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
except ImportError:
    import tkinter.messagebox as mb
    mb.showerror("缺少依赖", "请先在命令行执行:\n\npip install tkinterdnd2")
    sys.exit(1)


BUF_SIZE = 1024 * 1024
HEAD_SAMPLE = 4096
BATCH_SIZE = 5000  # 批量写入 DB
MAX_INDEX_THREADS = 4  # 多盘并发数

PROTECTED_PATHS = {
    p.lower().rstrip("\\/") for p in [
        "C:\\", "C:\\Windows", "C:\\Program Files",
        "C:\\Program Files (x86)", "C:\\ProgramData", "C:\\Users",
        "/", "/bin", "/boot", "/dev", "/etc", "/home",
        "/lib", "/proc", "/root", "/run", "/sbin", "/srv",
        "/sys", "/tmp", "/usr", "/var",
    ]
}

SCAN_SKIP_DIRS = {
    "appdata", "$recycle.bin", "system volume information",
    "windows", "winsxs", "program files", "program files (x86)", "programdata",
    "perflogs", "msocache", "recovery", "boot",
    "node_modules", ".git", ".svn", ".hg", "__pycache__", ".mypy_cache",
    ".pytest_cache", ".tox", ".venv", "venv", "env", ".idea", ".vscode",
    "dist", "build", "target", "out",
    ".cache", ".local", ".npm", ".m2", ".gradle", ".rustup", ".cargo",
    "proc", "sys", "dev", "run", "snap",
}

# 副本扫描忽略的扩展名（系统/缓存类，避免假阳性）
SCAN_SKIP_EXTS = {
    ".tmp", ".temp", ".log", ".lnk", ".url",
    ".dll", ".sys", ".exe", ".so", ".dylib",
}

CONFIG_DIR = Path(os.environ.get("APPDATA") or Path.home() / ".config") / "safetrash"
CONFIG_FILE = CONFIG_DIR / "config.json"
INDEX_DB = CONFIG_DIR / "index.db"


# ---------- 工具 ----------

def is_protected(p: Path) -> bool:
    try:
        s = str(p.resolve()).rstrip("\\/").lower()
        return s in PROTECTED_PATHS
    except OSError:
        return False


def list_drives():
    if sys.platform == "win32":
        return [f"{c}:\\" for c in string.ascii_uppercase
                if os.path.exists(f"{c}:\\")]
    drives = [str(Path.home())]
    for root in ["/mnt", "/media", f"/run/media/{os.environ.get('USER','')}"]:
        if os.path.isdir(root):
            for d in os.listdir(root):
                full = os.path.join(root, d)
                if os.path.isdir(full):
                    drives.append(full)
    return drives


def default_drive():
    home = Path.home()
    if sys.platform == "win32":
        return f"{str(home)[0].upper()}:\\"
    return str(home)


def load_config():
    try:
        return json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {"scan_drives": [default_drive()], "custom_paths": []}


def save_config(cfg: dict):
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        CONFIG_FILE.write_text(json.dumps(cfg, ensure_ascii=False, indent=2),
                               encoding="utf-8")
    except OSError:
        pass


def fmt_size(n):
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} PB"


# ---------- 安全删除 ----------

def overwrite_file(path: Path, passes: int):
    size = path.stat().st_size
    if size == 0 or passes <= 0:
        return
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    with open(path, "r+b") as f:
        for _ in range(passes):
            f.seek(0)
            remaining = size
            while remaining > 0:
                chunk = min(BUF_SIZE, remaining)
                f.write(secrets.token_bytes(chunk))
                remaining -= chunk
            f.flush()
            os.fsync(f.fileno())


def delete_path(path: Path, passes: int, log_fn, db=None):
    if not path.exists():
        log_fn(f"✗ 不存在: {path}")
        return

    if path.is_file() or path.is_symlink():
        try:
            if path.is_file():
                try:
                    overwrite_file(path, passes)
                except OSError as e:
                    log_fn(f"  覆盖失败({e.strerror})，退化为直接删除")
            try:
                rand = path.parent / secrets.token_hex(8)
                path.rename(rand)
                rand.unlink()
            except OSError:
                path.unlink(missing_ok=True)
            if db:
                db.remove_path(str(path))
            log_fn(f"✓ {path}")
        except Exception as e:
            log_fn(f"✗ {path}: {e}")
        return

    if path.is_dir():
        if is_protected(path):
            log_fn(f"✗ 拒绝操作受保护目录: {path}")
            return
        all_items = sorted(path.rglob("*"),
                           key=lambda p: len(p.parts), reverse=True)
        for child in all_items:
            if child.is_file() or child.is_symlink():
                delete_path(child, passes, log_fn, db)
        for child in all_items:
            if child.is_dir():
                try:
                    child.rmdir()
                except OSError:
                    pass
        try:
            path.rmdir()
            log_fn(f"✓ 目录 {path}")
        except OSError as e:
            log_fn(f"✗ 目录残留: {path} ({e.strerror})")


# ---------- 哈希 ----------

def file_head_hash(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        h.update(f.read(HEAD_SAMPLE))
    return h.hexdigest()


def file_full_hash(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            buf = f.read(BUF_SIZE)
            if not buf:
                break
            h.update(buf)
    return h.hexdigest()


# ---------- SQLite 索引 ----------

class IndexDB:
    def __init__(self):
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(INDEX_DB), check_same_thread=False)
        # 性能优先：索引可重建，断电只丢未提交批次
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=OFF")
        self.conn.execute("PRAGMA temp_store=MEMORY")
        self.conn.execute("PRAGMA cache_size=-65536")  # 64MB
        self.conn.execute("PRAGMA locking_mode=NORMAL")
        self.lock = threading.Lock()
        self._init_schema()

    def _init_schema(self):
        with self.lock:
            c = self.conn.cursor()
            c.execute("""CREATE TABLE IF NOT EXISTS files (
                path TEXT PRIMARY KEY,
                size INTEGER NOT NULL,
                mtime REAL NOT NULL,
                head_hash TEXT,
                full_hash TEXT
            )""")
            c.execute("CREATE INDEX IF NOT EXISTS idx_size ON files(size)")
            self.conn.commit()

    def upsert_many(self, rows):
        if not rows:
            return
        with self.lock:
            self.conn.executemany(
                """INSERT INTO files(path,size,mtime,head_hash,full_hash)
                   VALUES(?,?,?,NULL,NULL)
                   ON CONFLICT(path) DO UPDATE SET
                     size=excluded.size,
                     mtime=excluded.mtime,
                     head_hash=CASE WHEN files.mtime=excluded.mtime
                                    THEN files.head_hash ELSE NULL END,
                     full_hash=CASE WHEN files.mtime=excluded.mtime
                                    THEN files.full_hash ELSE NULL END""",
                rows,
            )
            self.conn.commit()

    def find_by_size(self, size):
        with self.lock:
            return self.conn.execute(
                "SELECT path, mtime, head_hash, full_hash FROM files WHERE size=?",
                (size,),
            ).fetchall()

    def update_hash(self, path, head=None, full=None):
        with self.lock:
            if head is not None and full is not None:
                self.conn.execute(
                    "UPDATE files SET head_hash=?, full_hash=? WHERE path=?",
                    (head, full, path))
            elif head is not None:
                self.conn.execute(
                    "UPDATE files SET head_hash=? WHERE path=?", (head, path))
            self.conn.commit()

    def remove_path(self, path: str):
        with self.lock:
            self.conn.execute("DELETE FROM files WHERE path=?", (path,))
            self.conn.commit()

    def remove_under(self, prefix: str):
        with self.lock:
            self.conn.execute("DELETE FROM files WHERE path LIKE ?",
                              (prefix + "%",))
            self.conn.commit()

    def count(self):
        with self.lock:
            return self.conn.execute("SELECT COUNT(*) FROM files").fetchone()[0]

    def total_size(self):
        with self.lock:
            r = self.conn.execute("SELECT COALESCE(SUM(size),0) FROM files").fetchone()
            return r[0] if r else 0

    def clear(self):
        with self.lock:
            self.conn.execute("DELETE FROM files")
            self.conn.commit()
            self.conn.execute("VACUUM")


# ---------- 索引构建 ----------

def _scandir_walk(root, cancel):
    """递归遍历，yield (path, size, mtime)。比 os.walk 快约 30%，
    DirEntry 自带 stat 缓存避免重复 syscall。"""
    stack = [root]
    while stack:
        if cancel.is_set():
            return
        cur = stack.pop()
        try:
            it = os.scandir(cur)
        except OSError:
            continue
        with it:
            for entry in it:
                if cancel.is_set():
                    return
                name = entry.name
                try:
                    if entry.is_dir(follow_symlinks=False):
                        nl = name.lower()
                        if (nl not in SCAN_SKIP_DIRS
                                and not name.startswith("$")
                                and not name.startswith(".")):
                            stack.append(entry.path)
                        continue
                    if not entry.is_file(follow_symlinks=False):
                        continue
                    ext = os.path.splitext(name)[1].lower()
                    if ext in SCAN_SKIP_EXTS:
                        continue
                    st = entry.stat(follow_symlinks=False)
                    if st.st_size == 0:
                        continue
                    yield entry.path, st.st_size, st.st_mtime
                except (OSError, PermissionError):
                    continue


class Indexer:
    """后台扫描指定根，更新索引数据库（多盘并发 + scandir）"""

    def __init__(self, db: IndexDB):
        self.db = db
        self.thread = None
        self.cancel = threading.Event()
        self.running = False
        self.scanned = 0
        self._scanned_lock = threading.Lock()

    def start(self, roots, on_progress, on_done):
        if self.running:
            return False
        self.cancel.clear()
        self.scanned = 0
        self.running = True
        self.thread = threading.Thread(
            target=self._run,
            args=(roots, on_progress, on_done),
            daemon=True,
        )
        self.thread.start()
        return True

    def stop(self):
        self.cancel.set()

    def _inc(self, n):
        with self._scanned_lock:
            self.scanned += n

    def _scan_one_root(self, root, on_progress):
        if self.cancel.is_set():
            return
        root_p = Path(root)
        if not root_p.exists():
            return
        norm = str(root_p)
        if not norm.endswith(os.sep):
            norm += os.sep
        self.db.remove_under(norm)

        batch = []
        last_report = time.monotonic()
        for path, size, mtime in _scandir_walk(str(root_p), self.cancel):
            batch.append((path, size, mtime))
            if len(batch) >= BATCH_SIZE:
                self.db.upsert_many(batch)
                self._inc(len(batch))
                batch = []
                now = time.monotonic()
                if now - last_report > 0.3:
                    on_progress(self.scanned)
                    last_report = now
            if self.cancel.is_set():
                break
        if batch:
            self.db.upsert_many(batch)
            self._inc(len(batch))
        on_progress(self.scanned)

    def _run(self, roots, on_progress, on_done):
        from concurrent.futures import ThreadPoolExecutor
        try:
            workers = min(MAX_INDEX_THREADS, max(1, len(roots)))
            with ThreadPoolExecutor(max_workers=workers) as ex:
                futures = [ex.submit(self._scan_one_root, r, on_progress)
                           for r in roots]
                for f in futures:
                    try:
                        f.result()
                    except Exception as e:
                        print(f"扫描根失败: {e}", file=sys.stderr)
        finally:
            self.running = False
            on_done(self.cancel.is_set(), self.scanned)


# ---------- 基于索引的副本查找 ----------

def find_duplicates(target: Path, db: IndexDB, cancel_flag=None):
    try:
        target_size = target.stat().st_size
    except OSError:
        return []
    if target_size == 0:
        return []
    try:
        target_resolved = str(target.resolve()).lower()
    except OSError:
        target_resolved = str(target).lower()

    rows = db.find_by_size(target_size)
    if not rows:
        return []

    # head 阶段
    try:
        target_head = file_head_hash(target)
    except OSError:
        return []
    candidates = []
    for path, mtime, head_h, full_h in rows:
        if cancel_flag and cancel_flag.is_set():
            return []
        if path.lower() == target_resolved:
            continue
        if not os.path.isfile(path):
            db.remove_path(path)
            continue
        try:
            cur_mtime = os.path.getmtime(path)
        except OSError:
            db.remove_path(path)
            continue
        # mtime 变了 → 之前的 hash 作废
        if abs(cur_mtime - mtime) > 1:
            head_h = None
            full_h = None
        if head_h is None:
            try:
                head_h = file_head_hash(Path(path))
                db.update_hash(path, head=head_h)
            except OSError:
                continue
        if head_h != target_head:
            continue
        candidates.append((path, full_h))

    if not candidates:
        return []

    # full 阶段
    try:
        target_full = file_full_hash(target)
    except OSError:
        return []
    matched = []
    for path, full_h in candidates:
        if cancel_flag and cancel_flag.is_set():
            return []
        if full_h is None:
            try:
                full_h = file_full_hash(Path(path))
                db.update_hash(path, head=target_head, full=full_h)
            except OSError:
                continue
        if full_h == target_full:
            matched.append(Path(path))
    return matched


# ---------- 扫描设置对话框 ----------

class ScanConfigDialog(tk.Toplevel):
    def __init__(self, parent, config, db, indexer):
        super().__init__(parent)
        self.title("扫描设置")
        self.geometry("480x540")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()
        self.result = None
        self.db = db
        self.indexer = indexer

        tk.Label(self, text="勾选要纳入副本索引的盘 / 路径：",
                 font=("Microsoft YaHei UI", 10)).pack(
                 anchor="w", padx=12, pady=(12, 6))

        list_frame = tk.Frame(self, relief=tk.SUNKEN, bd=1)
        list_frame.pack(fill=tk.X, padx=12, pady=4)

        self.drives = list_drives()
        selected = set(config.get("scan_drives", []))
        self.vars = {}
        for d in self.drives:
            v = tk.BooleanVar(value=(d in selected))
            self.vars[d] = v
            tk.Checkbutton(list_frame, text=d, variable=v,
                           anchor="w").pack(fill=tk.X, padx=8, pady=2)

        custom_frame = tk.Frame(self)
        custom_frame.pack(fill=tk.X, padx=12, pady=6)
        tk.Label(custom_frame, text="额外路径（每行一个）:").pack(anchor="w")
        self.custom_text = tk.Text(custom_frame, height=4)
        self.custom_text.pack(fill=tk.X)
        for p in config.get("custom_paths", []):
            self.custom_text.insert(tk.END, p + "\n")

        # 索引状态
        idx_frame = tk.LabelFrame(self, text=" 索引状态 ", padx=8, pady=6)
        idx_frame.pack(fill=tk.X, padx=12, pady=8)
        cnt = self.db.count()
        size = self.db.total_size()
        self.idx_status = tk.StringVar(
            value=f"已索引 {cnt:,} 个文件 · 总 {fmt_size(size)}")
        tk.Label(idx_frame, textvariable=self.idx_status,
                 fg="#444").pack(anchor="w")

        idx_btn = tk.Frame(idx_frame)
        idx_btn.pack(fill=tk.X, pady=(6, 0))
        tk.Button(idx_btn, text="保存并立即建立索引",
                  command=lambda: self._save(rebuild=True)).pack(side=tk.LEFT)
        tk.Button(idx_btn, text="清空索引",
                  command=self._clear).pack(side=tk.LEFT, padx=6)
        tk.Button(idx_btn, text="取消索引",
                  command=self.indexer.stop).pack(side=tk.LEFT)

        btn = tk.Frame(self)
        btn.pack(fill=tk.X, padx=12, pady=10)
        tk.Button(btn, text="取消", width=10,
                  command=self.destroy).pack(side=tk.RIGHT, padx=4)
        tk.Button(btn, text="只保存", width=10,
                  command=lambda: self._save(rebuild=False)).pack(side=tk.RIGHT)

    def _save(self, rebuild):
        drives = [d for d, v in self.vars.items() if v.get()]
        custom = [line.strip() for line in
                  self.custom_text.get("1.0", tk.END).splitlines()
                  if line.strip()]
        self.result = {"scan_drives": drives, "custom_paths": custom,
                       "rebuild": rebuild}
        self.destroy()

    def _clear(self):
        if messagebox.askyesno("确认", "清空整个索引数据库？",
                               parent=self):
            self.db.clear()
            self.idx_status.set("索引已清空")


# ---------- 副本确认对话框 ----------

class DuplicateDialog(tk.Toplevel):
    def __init__(self, parent, source: Path, duplicates):
        super().__init__(parent)
        self.title("发现副本")
        self.geometry("680x500")
        self.transient(parent)
        self.grab_set()
        self.result = []

        tk.Label(self, text=f"原文件: {source}",
                 font=("Microsoft YaHei UI", 10, "bold"),
                 wraplength=660, anchor="w", justify="left").pack(
                 fill=tk.X, padx=12, pady=(12, 4))
        tk.Label(
            self,
            text=f"在其他位置发现 {len(duplicates)} 个内容完全相同的副本，勾选要一并删除的：",
            fg="#444").pack(anchor="w", padx=12)

        top_btn = tk.Frame(self)
        top_btn.pack(fill=tk.X, padx=12, pady=(6, 0))
        tk.Button(top_btn, text="全选",
                  command=lambda: [v.set(True) for v, _ in self.vars]
                  ).pack(side=tk.LEFT, padx=2)
        tk.Button(top_btn, text="全不选",
                  command=lambda: [v.set(False) for v, _ in self.vars]
                  ).pack(side=tk.LEFT, padx=2)

        wrap = tk.Frame(self)
        wrap.pack(fill=tk.BOTH, expand=True, padx=12, pady=8)
        canvas = tk.Canvas(wrap, highlightthickness=0)
        vs = tk.Scrollbar(wrap, command=canvas.yview)
        canvas.configure(yscrollcommand=vs.set)
        inner = tk.Frame(canvas)
        inner.bind("<Configure>",
                   lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=inner, anchor="nw")
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vs.pack(side=tk.RIGHT, fill=tk.Y)

        self.vars = []
        for d in duplicates:
            v = tk.BooleanVar(value=True)
            self.vars.append((v, d))
            tk.Checkbutton(inner, text=str(d), variable=v,
                           anchor="w", wraplength=600,
                           justify="left").pack(fill=tk.X, padx=4, pady=1)

        btn = tk.Frame(self)
        btn.pack(fill=tk.X, padx=12, pady=10)
        tk.Button(btn, text="只删原文件", width=14,
                  command=self.destroy).pack(side=tk.RIGHT, padx=4)
        tk.Button(btn, text="一起删除所选", width=14,
                  command=self._ok).pack(side=tk.RIGHT)

    def _ok(self):
        self.result = [d for v, d in self.vars if v.get()]
        self.destroy()


# ---------- 主程序 ----------

class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title("安全垃圾桶")
        root.geometry("500x700")
        root.minsize(440, 580)

        self.config = load_config()
        self.passes = tk.IntVar(value=1)
        self.confirm = tk.BooleanVar(value=True)
        self.find_dup = tk.BooleanVar(value=False)
        self.busy = False

        self.db = IndexDB()
        self.indexer = Indexer(self.db)

        # 设置栏
        bar = tk.Frame(root, bg="#f0f0f0")
        bar.pack(fill=tk.X)
        tk.Label(bar, text=" 覆盖:", bg="#f0f0f0").pack(side=tk.LEFT, pady=6)
        tk.Spinbox(bar, from_=0, to=10, width=3,
                   textvariable=self.passes).pack(side=tk.LEFT, padx=2)
        tk.Checkbutton(bar, text="确认", variable=self.confirm,
                       bg="#f0f0f0").pack(side=tk.LEFT, padx=6)
        tk.Checkbutton(bar, text="查副本", variable=self.find_dup,
                       bg="#f0f0f0").pack(side=tk.LEFT, padx=6)
        tk.Button(bar, text="⚙ 扫描设置",
                  command=self.open_scan_config).pack(
                  side=tk.RIGHT, padx=6, pady=3)

        # 垃圾桶
        self.bin_frame = tk.Frame(root, bg="#fafafa",
                                  relief=tk.GROOVE, bd=2)
        self.bin_frame.pack(fill=tk.BOTH, expand=False,
                            padx=12, pady=12, ipady=20)
        self.bin_label = tk.Label(self.bin_frame, text="🗑️",
                                  font=("Segoe UI Emoji", 110),
                                  bg="#fafafa", cursor="hand2")
        self.bin_label.pack(pady=10)
        self.tip_label = tk.Label(
            self.bin_frame, text="拖文件或文件夹到这里",
            font=("Microsoft YaHei UI", 11), fg="#666", bg="#fafafa")
        self.tip_label.pack()

        for w in (self.bin_frame, self.bin_label, self.tip_label):
            w.drop_target_register(DND_FILES)
            w.dnd_bind("<<Drop>>", self.on_drop)
            w.dnd_bind("<<DragEnter>>", lambda e: self._set_state("hover"))
            w.dnd_bind("<<DragLeave>>", lambda e: self._set_state("idle"))

        # 状态栏（索引状态 + 工作状态两行）
        status_bar = tk.Frame(root)
        status_bar.pack(fill=tk.X, padx=14)
        self.idx_status = tk.StringVar()
        self.work_status = tk.StringVar(value="就绪")
        tk.Label(status_bar, textvariable=self.idx_status,
                 fg="#555", anchor="w").pack(fill=tk.X)
        tk.Label(status_bar, textvariable=self.work_status,
                 fg="#222", anchor="w").pack(fill=tk.X)

        # 日志
        log_frame = tk.LabelFrame(root, text=" 日志 ", padx=4, pady=4)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=12, pady=(4, 8))
        self.log_text = tk.Text(log_frame, height=10, wrap=tk.NONE,
                                font=("Consolas", 9),
                                bg="#1e1e1e", fg="#d4d4d4",
                                insertbackground="#fff")
        vs = tk.Scrollbar(log_frame, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=vs.set, state=tk.DISABLED)
        vs.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.pack(fill=tk.BOTH, expand=True)

        bb = tk.Frame(root)
        bb.pack(fill=tk.X, padx=12, pady=(0, 10))
        tk.Button(bb, text="清空日志", command=self.clear_log).pack(side=tk.LEFT)
        tk.Button(bb, text="重建索引",
                  command=self.rebuild_index).pack(side=tk.LEFT, padx=8)

        self._refresh_idx_status()

    # ----- 索引相关 -----
    def _refresh_idx_status(self):
        if self.indexer.running:
            self.idx_status.set(
                f"索引中… 已扫描 {self.indexer.scanned:,} 个文件")
        else:
            cnt = self.db.count()
            size = self.db.total_size()
            self.idx_status.set(
                f"索引: {cnt:,} 个文件 · {fmt_size(size)}")

    def rebuild_index(self):
        roots = list(self.config.get("scan_drives", []))
        roots += list(self.config.get("custom_paths", []))
        if not roots:
            messagebox.showinfo("提示", "先在「扫描设置」里选好要索引的盘 / 路径")
            return
        if self.indexer.running:
            messagebox.showinfo("提示", "索引正在进行中")
            return
        self.log(f">>> 开始建立索引: {', '.join(roots)}")

        def on_progress(n):
            self.root.after(0, self._refresh_idx_status)

        def on_done(canceled, n):
            self.root.after(0, self._refresh_idx_status)
            tag = "已取消" if canceled else "完成"
            self.root.after(0, self.log,
                            f">>> 索引{tag}，共 {n:,} 个文件")

        self.indexer.start(roots, on_progress, on_done)

    def open_scan_config(self):
        dlg = ScanConfigDialog(self.root, self.config, self.db, self.indexer)
        self.root.wait_window(dlg)
        if dlg.result:
            self.config["scan_drives"] = dlg.result["scan_drives"]
            self.config["custom_paths"] = dlg.result["custom_paths"]
            save_config(self.config)
            self._refresh_idx_status()
            self.log(f"已更新扫描范围: {self.config['scan_drives']} "
                     f"+ {len(self.config['custom_paths'])} 自定义")
            if dlg.result.get("rebuild"):
                self.rebuild_index()

    # ----- UI 辅助 -----
    def _set_state(self, state: str):
        if self.busy:
            return
        if state == "hover":
            self.bin_label.config(text="📂", fg="#2b8aef")
            self.tip_label.config(text="松开即删除", fg="#2b8aef")
        else:
            self.bin_label.config(text="🗑️", fg="black")
            self.tip_label.config(text="拖文件或文件夹到这里", fg="#666")

    def log(self, msg: str):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, msg + "\n")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)

    def clear_log(self):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete("1.0", tk.END)
        self.log_text.config(state=tk.DISABLED)

    # ----- 拖入 / 删除 -----
    def on_drop(self, event):
        paths_raw = self.root.tk.splitlist(event.data)
        paths = [Path(p) for p in paths_raw if p]
        if not paths:
            return
        if self.confirm.get():
            preview = "\n".join(str(p) for p in paths[:5])
            if len(paths) > 5:
                preview += f"\n... 共 {len(paths)} 项"
            if not messagebox.askyesno(
                "确认彻底删除",
                f"确定要彻底删除以下 {len(paths)} 项？\n此操作无法撤销。\n\n{preview}",
                icon="warning",
            ):
                self._set_state("idle")
                return

        self.busy = True
        self._busy_ui(True)
        threading.Thread(target=self._worker,
                         args=(paths,), daemon=True).start()

    def _busy_ui(self, busy: bool):
        if busy:
            self.bin_label.config(text="♻️", fg="#e8a93f")
            self.tip_label.config(text="处理中...", fg="#e8a93f")
        else:
            self._set_state("idle")

    def _worker(self, paths):
        passes = max(0, self.passes.get())
        do_find = self.find_dup.get()
        self.root.after(0, self.work_status.set,
                        f"处理 {len(paths)} 项…")
        self.root.after(0, self.log,
                        f">>> 处理 {len(paths)} 项（覆盖 {passes} 次"
                        f"{'，查副本' if do_find else ''}）")
        for p in paths:
            if do_find and p.is_file():
                self._scan_and_delete_dups(p)
            delete_path(p, passes, lambda m: self.root.after(0, self.log, m),
                        db=self.db)
        self.root.after(0, self._done)

    def _scan_and_delete_dups(self, source: Path):
        cnt = self.db.count()
        if cnt == 0:
            self.root.after(0, self.log,
                            "  (索引为空，跳过副本查找。请先「重建索引」)")
            return

        self.root.after(0, self.work_status.set,
                        f"查找副本: {source.name}")
        dups = find_duplicates(source, self.db)
        self.root.after(0, self.log,
                        f"  副本查找结果: {len(dups)} 个 [{source.name}]")
        if not dups:
            return

        evt = threading.Event()
        choice = {"result": []}

        def show_dialog():
            dlg = DuplicateDialog(self.root, source, dups)
            self.root.wait_window(dlg)
            choice["result"] = dlg.result
            evt.set()

        self.root.after(0, show_dialog)
        evt.wait()

        passes = max(0, self.passes.get())
        for d in choice["result"]:
            self.root.after(0, self.log, f"  [副本] {d}")
            delete_path(d, passes,
                        lambda m: self.root.after(0, self.log, m),
                        db=self.db)

    def _done(self):
        self.busy = False
        self._busy_ui(False)
        self._refresh_idx_status()
        self.work_status.set("就绪")
        self.log("--- 本批完成 ---\n")


def main():
    root = TkinterDnD.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
