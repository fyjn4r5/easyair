# EasyAir v2 - Mint 21.3 专用傻瓜式 WiFi 抓包破解工具

## 功能特性
- ✅ **自动监听模式**: 抓包时自动开启，停止时自动关闭
- ✅ **多字典支持**: 拖拽排序、右键添加/移除/清空、目录批量导入、顺序持久化
- ✅ **双引擎破解**: Hashcat (GPU/CPU 可选) / Aircrack-ng
- ✅ **GPU/CPU 切换**: 自动检测、仅GPU、仅CPU 三种模式
- ✅ **一键全自动**: 扫描 → 选中 → 抓包 → Deauth 一气呵成
- ✅ **配置持久化**: 字典列表、引擎选择、设备选择、额外参数自动保存
- ✅ **单文件打包**: PyInstaller 打包，Mint 21.3 直接运行

## 快速开始 (Mint 21.3)

### 方法一：使用构建脚本 (推荐，自动走代理)
```bash
cd easyair_v2
chmod +x build_mint21.sh
./build_mint21.sh
# 产物在 dist/easyair，拷贝到目标机即可运行
```

### 方法二：手动构建
```bash
# 1. 安装系统依赖
sudo apt update && sudo apt install -y python3 python3-venv aircrack-ng hashcat hcxtools

# 2. 创建虚拟环境并安装依赖 (可配置代理)
export http_proxy=http://192.168.18.18:8118
export https_proxy=http://192.168.18.18:8118
python3 -m venv .venv
source .venv/bin/activate
pip config set global.proxy http://192.168.18.18:8118
pip install PyQt5 psutil pyinstaller

# 3. 打包
.venv/bin/pyinstaller --onefile --clean --noconfirm \
    --name easyair \
    --add-data "core:core" --add-data "ui:ui" --add-data "config:config" \
    --hidden-import=PyQt5 --hidden-import=PyQt5.QtCore --hidden-import=PyQt5.QtWidgets \
    --hidden-import=PyQt5.QtGui --hidden-import=PyQt5.QtPrintSupport --hidden-import=PyQt5.sip \
    --hidden-import=psutil \
    main.py
```

## 运行要求
- **Mint 21.3 / Ubuntu 22.04+** (GLIBC 2.35+)
- **支持监听模式的无线网卡** (推荐: RTL8812AU, MT7601U, AR9271 等)
- **sudo/root 权限** (airmon-ng 等需要提权，GUI 会自动调用 pkexec)
- **Hashcat 6.2+** (已预装或构建时自动安装)

## 使用流程
1. 启动 `./easyair`
2. 选择物理网卡 → 点击"开启监听模式" (或勾选自动模式)
3. 点击"开始扫描" → 列表出现周围 AP
4. 选中目标 AP → 点击"开始抓取握手包"
5. (可选) 点击"一键 Deauth" 加速握手捕获
6. 右侧添加字典文件 (拖拽排序，支持多个)
7. 选择破解引擎: **Hashcat** (推荐) / Aircrack-ng
8. 选择设备: GPU+CPU / 仅GPU / 仅CPU
9. 点击"开始破解" → 等待结果

## 配置文件
`config/settings.json` 自动保存：
- 字典列表顺序
- 破解引擎选择
- GPU/CPU 设置
- Hashcat 额外参数
- 自动监听模式开关

## 目录结构
```
easyair_v2/
├── build_mint21.sh       # 一键构建脚本 (走代理)
├── main.py               # 入口
├── core/
│   ├── __init__.py
│   └── aircore.py        # 核心逻辑 (aircrack/hashcat/监听模式/配置)
├── ui/
│   ├── __init__.py
│   └── main_ui.py        # PyQt5 界面 (拖拽字典、自动监听、双引擎)
├── config/
│   └── settings.json     # 自动生成
├── captures/             # 抓包文件输出
├── wordlists/            # 默认字典目录
└── dist/
    └── easyair           # 打包产物 (单文件)
```

## 常见问题
- **无网卡显示**: 虚拟机需 USB 直通；真机检查 `iw dev` 有输出
- **权限错误**: 确保用户在 sudoers 或使用 pkexec (GUI 会弹窗)
- **Hashcat 报错**: 加 `--force` 到额外参数；CPU 模式需装 `ocl-icd-opencl-dev`
- **GLIBC 版本不匹配**: 必须在 Mint 21.3 / Ubuntu 22.04 环境构建 (脚本已处理)
