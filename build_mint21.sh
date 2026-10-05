#!/usr/bin/env bash
# Mint 21.3 一键构建脚本 - 使用代理安装依赖并打包
set -euo pipefail

PROXY="http://192.168.18.18:8118"
export http_proxy="$PROXY"
export https_proxy="$PROXY"
export HTTP_PROXY="$PROXY"
export HTTPS_PROXY="$PROXY"

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIST_DIR="$PROJECT_DIR/dist"

echo "========================================"
echo "  EasyAir v2 - Mint 21.3 一键构建"
echo "========================================"
echo "代理: $PROXY"
echo "项目: $PROJECT_DIR"
echo ""

# 1. 系统依赖
echo "[1/7] 更新并安装系统依赖..."
sudo -E apt-get update -y 2>&1 | tail -3
sudo -E apt-get install -y \
    python3 python3-venv python3-pip \
    aircrack-ng hashcat hcxtools \
    libgl1-mesa-glx libxcb-xinerama0 libxcb-cursor0 \
    2>&1 | tail -5

# 2. 虚拟环境
echo "[2/7] 创建虚拟环境..."
python3 -m venv "$PROJECT_DIR/.venv"
source "$PROJECT_DIR/.venv/bin/activate"

# 3. pip 代理
echo "[3/7] 配置 pip 代理..."
pip config set global.proxy "$PROXY"
pip install --upgrade pip setuptools wheel 2>&1 | tail -2

# 4. Python 依赖
echo "[4/7] 安装 Python 依赖 (PyQt5, psutil, pyinstaller)..."
pip install PyQt5 psutil pyinstaller 2>&1 | tail -5

# 5. 验证导入
echo "[5/7] 验证模块导入..."
.venv/bin/python3 -c "
from PyQt5.QtWidgets import QApplication
import psutil, core.aircore, ui.main_ui
print('  所有模块导入 OK')
"

# 6. 打包
echo "[6/7] 打包单文件 (PyInstaller)..."
cd "$PROJECT_DIR"
.venv/bin/pyinstaller --onefile --clean --noconfirm \
    --name easyair \
    --add-data "core:core" \
    --add-data "ui:ui" \
    --add-data "config:config" \
    --hidden-import=PyQt5 \
    --hidden-import=PyQt5.QtCore \
    --hidden-import=PyQt5.QtWidgets \
    --hidden-import=PyQt5.QtGui \
    --hidden-import=PyQt5.QtPrintSupport \
    --hidden-import=PyQt5.sip \
    --hidden-import=psutil \
    main.py 2>&1 | tail -10

# 7. 验证产物
echo "[7/7] 验证产物..."
if [[ -f "$DIST_DIR/easyair" ]]; then
    chmod +x "$DIST_DIR/easyair"
    SIZE=$(du -h "$DIST_DIR/easyair" | cut -f1)
    echo ""
    echo "========================================"
    echo "  ✅ 构建成功!"
    echo "========================================"
    echo "产物: $DIST_DIR/easyair ($SIZE)"
    echo ""
    echo "部署到 Mint 21.3 目标机:"
    echo "  scp $DIST_DIR/easyair user@mint21:/home/user/"
    echo "  ssh user@mint21 'chmod +x easyair && ./easyair'"
    echo ""
    echo "或直接拷贝 U 盘过去运行。"
else
    echo "❌ 构建失败: 未找到 dist/easyair"
    exit 1
fi
