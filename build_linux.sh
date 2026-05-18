#!/usr/bin/env bash
# 在 Linux（Ubuntu / 麒麟 / 其他）上把 trashbin.py 打包成单文件可执行
# 用法: bash build_linux.sh
# 产物: ./dist/SafeTrash   （直接 chmod +x 后双击运行）

set -euo pipefail
cd "$(dirname "$0")"

PY=${PYTHON:-python3}

echo ">>> 检查 Python 与 tkinter..."
$PY --version
$PY -c "import tkinter; print('tkinter OK')" || {
    echo "缺少 tkinter，请先安装："
    echo "  Ubuntu/Debian/麒麟:  sudo apt install -y python3-tk"
    echo "  Fedora/RHEL:        sudo dnf install -y python3-tkinter"
    exit 1
}

echo ">>> 创建虚拟环境（避免污染系统 Python）..."
if [[ ! -d .venv ]]; then
    $PY -m venv .venv
fi
# shellcheck source=/dev/null
source .venv/bin/activate

echo ">>> 安装依赖..."
pip install --upgrade pip >/dev/null
pip install tkinterdnd2 pyinstaller

echo ">>> 开始打包..."
pyinstaller --onefile --windowed \
    --name="SafeTrash" \
    --collect-all tkinterdnd2 \
    --clean --noconfirm \
    trashbin.py

if [[ -f dist/SafeTrash ]]; then
    chmod +x dist/SafeTrash
    echo
    echo ">>> 完成！产物: $(pwd)/dist/SafeTrash"
    ls -lh dist/SafeTrash
    echo
    echo "可以直接运行: ./dist/SafeTrash"
    echo "或加入桌面快捷方式，见同目录的 SafeTrash.desktop"
else
    echo "打包失败，请检查上方日志"
    exit 1
fi
