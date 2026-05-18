# SafeTrash · 安全垃圾桶

> 拖文件进来，彻底删除 + 自动清理散落各盘的副本。

一个跨平台的小工具，解决"删了一份文件，但电脑里还散着好几个复制版本"的痛点。

## 特性

- 🗑️ **拖入即删**：把文件 / 文件夹拖到垃圾桶图标，一键彻底删除
- 🔁 **覆盖写入**：可配置 0~10 轮随机字节覆盖（默认 1 轮，速度与安全平衡）
- 🔍 **副本查找**：基于 SHA-256 内容哈希，跨盘找出所有内容相同的副本
- 💾 **SQLite 持久化索引**：扫一次长期受益；hash 算过就缓存；多盘并发扫描
- 🛡️ **受保护目录黑名单**：拒绝操作 `C:\`、`/etc`、`/home` 等系统关键目录
- 🪶 **零依赖运行**：打包成单文件 exe（Win 15MB）/ Linux 二进制（约 20MB）
- 🪟 **Windows / Linux 双端**：同一份 Python 源码，分别打包

## 截图

```
┌─────────────────────────────────────┐
│ 覆盖: [1▼]  ☑ 确认  ☑ 查副本  ⚙ 设置 │
├─────────────────────────────────────┤
│                                     │
│              🗑️                     │
│                                     │
│        拖文件或文件夹到这里          │
│                                     │
├─────────────────────────────────────┤
│ 索引: 87,234 个文件 · 12.3 GB        │
│ 就绪                                 │
├─ 日志 ──────────────────────────────┤
│ ✓ D:\old\report.xlsx                │
│   发现 3 个副本: report.xlsx        │
│ ✓ E:\备份\report.xlsx               │
│ ✓ F:\下载\report (2).xlsx           │
│ --- 本批完成 ---                    │
└─────────────────────────────────────┘
```

## 下载

去 [Releases](../../releases) 下载对应平台的可执行文件，双击即用。

## 使用

1. **第一次启动**：点击右上角 `⚙ 扫描设置`，勾选要纳入副本搜索的盘符 / 路径，"保存并立即建立索引"
2. **正常使用**：勾选顶部 `查副本`，把要删的文件拖到垃圾桶
3. **副本对话框**：列出全盘内容相同的副本，勾选要一并删除的项

## 从源码运行

```bash
git clone https://github.com/hlyylly/safetrash.git
cd safetrash
pip install tkinterdnd2
python trashbin.py
```

## 自己打包

### Windows
```powershell
pip install pyinstaller tkinterdnd2
python -m PyInstaller --onefile --windowed --name=SafeTrash `
    --collect-all tkinterdnd2 --clean trashbin.py
# 产物: dist\SafeTrash.exe
```

### Linux (Ubuntu / 麒麟 / 深度等)
```bash
sudo apt install -y python3-tk python3-venv
bash build_linux.sh
# 产物: dist/SafeTrash
```

## 设计说明

### 副本查找如何做到秒级响应

三级过滤策略，每一级都比上一级贵 10~100 倍，所以越早过滤掉越好：

1. **大小过滤**（SQLite 索引，O(log n)）：从全表中拉出所有同 size 的候选
2. **前 4KB 哈希过滤**：只读前 4 KB 算 SHA-256，秒杀绝大多数假阳性
3. **完整哈希比对**：极少数走到这一步才读完整内容

算过的 head_hash 和 full_hash 写回数据库，下次涉及同一文件免算。
扫描使用 `os.scandir` + 多盘并发 + SQLite `synchronous=OFF` 批量插入。

### 关于 SSD 上的"彻底删除"

需要清楚一个事实：

> **SSD 上 `rm` + TRIM 比 `shred` 多轮覆盖更彻底。**

因为 SSD 的 FTL（Flash Translation Layer）做磨损均衡，"覆盖写入"的物理块并不一定是原文件所在的块；而 TRIM 直接告诉 SSD 主控"这些块作废"，主控的垃圾回收会真正清零 NAND。

工具默认覆盖 1 轮主要是给机械硬盘和 NTFS-on-FUSE 等场景兜底；如果你跑在 SSD 上、且系统已启用 TRIM，把覆盖次数调成 0 也完全 OK。

删除后建议手动触发：
- Linux: `sudo fstrim -av`
- Windows: `Optimize-Volume -DriveLetter C -ReTrim -Verbose`（PowerShell 管理员）

## 数据存储位置

- 配置：`%APPDATA%\safetrash\config.json` / `~/.config/safetrash/config.json`
- 索引数据库：同上目录下 `index.db`

清空索引在"扫描设置 → 清空索引"。

## License

MIT
