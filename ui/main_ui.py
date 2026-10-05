from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QComboBox, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QTextEdit, QGroupBox,
    QSplitter, QFileDialog, QMessageBox, QCheckBox, QListWidget,
    QListWidgetItem, QAbstractItemView, QMenu, QAction, QInputDialog,
    QLineEdit, QSpinBox, QDialog, QDialogButtonBox, QFormLayout,
    QTabWidget, QProgressBar, QTreeWidget, QTreeWidgetItem, QFrame
)
from PyQt5.QtCore import Qt, pyqtSignal, QTimer
from PyQt5.QtGui import QFont, QColor
from pathlib import Path


class WordListDialog(QDialog):
    """字典管理对话框"""
    def __init__(self, parent=None, current_lists=None):
        super().__init__(parent)
        self.setWindowTitle("字典管理")
        self.resize(600, 400)
        self.wordlists = list(current_lists) if current_lists else []
        self._setup_ui()
        self._load_lists()

    def _setup_ui(self):
        layout = QVBoxLayout(self)

        # 列表
        self.list_widget = QListWidget()
        self.list_widget.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.list_widget.setDragDropMode(QAbstractItemView.InternalMove)
        self.list_widget.setDefaultDropAction(Qt.MoveAction)
        self.list_widget.setContextMenuPolicy(Qt.CustomContextMenu)
        self.list_widget.customContextMenuRequested.connect(self._show_menu)
        layout.addWidget(self.list_widget)

        # 按钮栏
        btn_layout = QHBoxLayout()
        self.btn_add_files = QPushButton("添加文件")
        self.btn_add_dir = QPushButton("添加目录")
        self.btn_remove = QPushButton("移除选中")
        self.btn_clear = QPushButton("清空")
        btn_layout.addWidget(self.btn_add_files)
        btn_layout.addWidget(self.btn_add_dir)
        btn_layout.addWidget(self.btn_remove)
        btn_layout.addWidget(self.btn_clear)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)

        # 对话框按钮
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        # 信号
        self.btn_add_files.clicked.connect(self._add_files)
        self.btn_add_dir.clicked.connect(self._add_dir)
        self.btn_remove.clicked.connect(self._remove_selected)
        self.btn_clear.clicked.connect(self._clear_all)

    def _load_lists(self):
        self.list_widget.clear()
        for wl in self.wordlists:
            self.list_widget.addItem(wl)

    def _show_menu(self, pos):
        menu = QMenu(self)
        act_up = QAction("上移", self)
        act_down = QAction("下移", self)
        act_remove = QAction("移除", self)
        menu.addAction(act_up)
        menu.addAction(act_down)
        menu.addSeparator()
        menu.addAction(act_remove)
        act_up.triggered.connect(self._move_up)
        act_down.triggered.connect(self._move_down)
        act_remove.triggered.connect(self._remove_selected)
        menu.exec_(self.list_widget.mapToGlobal(pos))

    def _move_up(self):
        for item in self.list_widget.selectedItems():
            row = self.list_widget.row(item)
            if row > 0:
                self.list_widget.takeItem(row)
                self.list_widget.insertItem(row - 1, item)
                self.list_widget.setCurrentItem(item)

    def _move_down(self):
        items = self.list_widget.selectedItems()
        for item in reversed(items):
            row = self.list_widget.row(item)
            if row < self.list_widget.count() - 1:
                self.list_widget.takeItem(row)
                self.list_widget.insertItem(row + 1, item)
                self.list_widget.setCurrentItem(item)

    def _add_files(self):
        files, _ = QFileDialog.getOpenFileNames(self, "选择字典文件", str(Path.home()), "文本文件 (*.txt *.lst *.dic);;所有文件 (*.*)")
        for f in files:
            if f not in self.wordlists:
                self.wordlists.append(f)
                self.list_widget.addItem(f)

    def _add_dir(self):
        dir_path = QFileDialog.getExistingDirectory(self, "选择字典目录", str(Path.home()))
        if dir_path:
            for ext in ("*.txt", "*.lst", "*.dic", "*.dict"):
                for f in Path(dir_path).rglob(ext):
                    fp = str(f)
                    if fp not in self.wordlists:
                        self.wordlists.append(fp)
                        self.list_widget.addItem(fp)

    def _remove_selected(self):
        for item in self.list_widget.selectedItems():
            self.wordlists.remove(item.text())
            self.list_widget.takeItem(self.list_widget.row(item))

    def _clear_all(self):
        self.wordlists.clear()
        self.list_widget.clear()

    def get_wordlists(self):
        return self.wordlists


class CrackResultWidget(QTreeWidget):
    """破解结果显示 - 类似 EWSA 风格"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setHeaderLabels(["BSSID", "ESSID", "密码", "握手包", "状态", "耗时"])
        self.setColumnWidth(0, 180)
        self.setColumnWidth(1, 150)
        self.setColumnWidth(2, 180)
        self.setColumnWidth(3, 200)
        self.setColumnWidth(4, 80)
        self.setColumnWidth(5, 80)
        self.setAlternatingRowColors(True)
        self.setRootIsDecorated(False)

    def add_target(self, bssid, essid, cap_file):
        """添加破解目标"""
        item = QTreeWidgetItem([bssid, essid, "破解中...", cap_file, "进行中", "00:00"])
        item.setData(0, Qt.UserRole, {"bssid": bssid, "essid": essid, "cap": cap_file})
        self.addTopLevelItem(item)
        return item

    def update_progress(self, item, password, elapsed):
        """更新破解进度"""
        if password:
            item.setText(2, password)
            item.setText(4, "成功")
            item.setForeground(4, QColor("#2e7d32"))
            item.setForeground(2, QColor("#1565c0"))
        else:
            item.setText(5, elapsed)
        self.scrollToItem(item)

    def set_failed(self, item, reason="失败"):
        item.setText(4, reason)
        item.setForeground(4, QColor("#c62828"))


class MainUI(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("EasyAir - WiFi 抓包破解 (EWSA 风格)")
        self.resize(1400, 850)
        self._setup_ui()

    def _setup_ui(self):
        root = QVBoxLayout(self)
        root.setSpacing(6)
        root.setContentsMargins(8, 8, 8, 8)

        # ===== 顶部工具栏 =====
        toolbar = QFrame()
        toolbar.setFrameShape(QFrame.StyledPanel)
        toolbar.setMaximumHeight(50)
        tb_layout = QHBoxLayout(toolbar)
        tb_layout.setContentsMargins(10, 5, 10, 5)

        # 网卡选择
        tb_layout.addWidget(QLabel("网卡:"))
        self.iface_combo = QComboBox()
        self.iface_combo.setMinimumWidth(180)
        tb_layout.addWidget(self.iface_combo)

        self.btn_refresh_iface = QPushButton("刷新")
        tb_layout.addWidget(self.btn_refresh_iface)

        tb_layout.addSpacing(20)

        # 自动模式指示
        self.lbl_auto = QLabel("🔄 全自动模式: 扫描→抓包→破解")
        self.lbl_auto.setStyleSheet("color: #2e7d32; font-weight: bold;")
        tb_layout.addWidget(self.lbl_auto)

        tb_layout.addStretch()

        # 字典管理按钮
        self.btn_dict_mgr = QPushButton("📁 字典管理")
        self.btn_dict_mgr.setMinimumWidth(100)
        tb_layout.addWidget(self.btn_dict_mgr)

        # 破解设置按钮
        self.btn_crack_cfg = QPushButton("⚙ 破解设置")
        self.btn_crack_cfg.setMinimumWidth(100)
        tb_layout.addWidget(self.btn_crack_cfg)

        root.addWidget(toolbar)

        # ===== 主分割区 =====
        main_splitter = QSplitter(Qt.Horizontal)

        # ---- 左侧: AP 列表 + 扫描/抓包控制 ----
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setSpacing(6)
        left_layout.setContentsMargins(0, 0, 0, 0)

        # AP 表格
        ap_group = QGroupBox("周边 AP (双击选择目标)")
        ap_layout = QVBoxLayout(ap_group)

        self.ap_table = QTableWidget()
        self.ap_table.setColumnCount(7)
        self.ap_table.setHorizontalHeaderLabels(["信号", "SSID", "BSSID", "信道", "加密", "厂商", "客户端"])
        self.ap_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.ap_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.ap_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.ap_table.setAlternatingRowColors(True)
        self.ap_table.setShowGrid(False)
        self.ap_table.verticalHeader().setVisible(False)
        self.ap_table.setSelectionMode(QAbstractItemView.SingleSelection)
        ap_layout.addWidget(self.ap_table)

        # 扫描/抓包控制
        ctrl_layout = QHBoxLayout()
        self.btn_scan = QPushButton("🔍 开始扫描")
        self.btn_scan.setMinimumHeight(36)
        self.btn_scan.setStyleSheet("font-weight: bold; background: #1976d2; color: white;")
        self.btn_stop_scan = QPushButton("⏹ 停止扫描")
        self.btn_stop_scan.setMinimumHeight(36)
        self.btn_capture = QPushButton("📡 抓取握手包")
        self.btn_capture.setMinimumHeight(36)
        self.btn_capture.setStyleSheet("font-weight: bold; background: #f57c00; color: white;")
        self.btn_deauth = QPushButton("💥 Deauth")
        self.btn_deauth.setMinimumHeight(36)
        ctrl_layout.addWidget(self.btn_scan)
        ctrl_layout.addWidget(self.btn_stop_scan)
        ctrl_layout.addWidget(self.btn_capture)
        ctrl_layout.addWidget(self.btn_deauth)
        ap_layout.addLayout(ctrl_layout)

        # 状态栏
        self.status_label = QLabel("就绪 - 点击'开始扫描'搜索周边 AP")
        self.status_label.setStyleSheet("color: #666; padding: 4px;")
        ap_layout.addWidget(self.status_label)

        left_layout.addWidget(ap_group)

        # 当前目标信息
        target_group = QGroupBox("当前目标")
        target_layout = QFormLayout(target_group)
        self.lbl_target_essid = QLabel("未选择")
        self.lbl_target_bssid = QLabel("未选择")
        self.lbl_target_ch = QLabel("未选择")
        self.lbl_target_enc = QLabel("未选择")
        self.lbl_handshake = QLabel("未捕获")
        self.lbl_handshake.setStyleSheet("color: #c62828; font-weight: bold;")
        target_layout.addRow("SSID:", self.lbl_target_essid)
        target_layout.addRow("BSSID:", self.lbl_target_bssid)
        target_layout.addRow("信道:", self.lbl_target_ch)
        target_layout.addRow("加密:", self.lbl_target_enc)
        target_layout.addRow("握手包:", self.lbl_handshake)
        left_layout.addWidget(target_group)

        main_splitter.addWidget(left_widget)

        # ---- 右侧: 破解面板 (EWSA 风格) ----
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setSpacing(6)
        right_layout.setContentsMargins(0, 0, 0, 0)

        # 破解引擎选择
        engine_group = QGroupBox("破解引擎")
        engine_layout = QHBoxLayout(engine_group)
        engine_layout.addWidget(QLabel("引擎:"))
        self.crack_engine = QComboBox()
        self.crack_engine.addItems(["Hashcat (GPU/CPU)", "Aircrack-ng (CPU)"])
        engine_layout.addWidget(self.crack_engine)
        engine_layout.addWidget(QLabel("设备:"))
        self.device_combo = QComboBox()
        self.device_combo.addItems(["GPU + CPU (自动)", "仅 GPU", "仅 CPU"])
        engine_layout.addWidget(self.device_combo)
        engine_layout.addStretch()
        right_layout.addWidget(engine_group)

        # 破解进度
        progress_group = QGroupBox("破解进度")
        progress_layout = QVBoxLayout(progress_group)
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)  # 不定进度
        self.progress_bar.setVisible(False)
        progress_layout.addWidget(self.progress_bar)
        self.lbl_progress = QLabel("等待开始...")
        self.lbl_progress.setStyleSheet("color: #666;")
        progress_layout.addWidget(self.lbl_progress)
        right_layout.addWidget(progress_group)

        # 破解结果列表 (核心 - EWSA 风格)
        result_group = QGroupBox("破解结果")
        result_layout = QVBoxLayout(result_group)
        self.crack_result = CrackResultWidget()
        result_layout.addWidget(self.crack_result)

        # 结果操作按钮
        result_btn_layout = QHBoxLayout()
        self.btn_start_crack = QPushButton("▶ 开始破解")
        self.btn_start_crack.setMinimumHeight(40)
        self.btn_start_crack.setStyleSheet("font-weight: bold; background: #2e7d32; color: white; font-size: 14px;")
        self.btn_stop_crack = QPushButton("⏹ 停止破解")
        self.btn_stop_crack.setMinimumHeight(40)
        self.btn_stop_crack.setStyleSheet("font-weight: bold; background: #c62828; color: white; font-size: 14px;")
        self.btn_export = QPushButton("📤 导出结果")
        result_btn_layout.addWidget(self.btn_start_crack)
        result_btn_layout.addWidget(self.btn_stop_crack)
        result_btn_layout.addWidget(self.btn_export)
        result_layout.addLayout(result_btn_layout)

        right_layout.addWidget(result_group)

        main_splitter.addWidget(right_widget)
        main_splitter.setStretchFactor(0, 1)
        main_splitter.setStretchFactor(1, 1)

        root.addWidget(main_splitter, 1)

        # ===== 底部日志 =====
        log_group = QGroupBox("运行日志")
        log_layout = QVBoxLayout(log_group)
        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)
        self.log_box.setMaximumHeight(150)
        self.log_box.setFont(QFont("Monospace", 9))
        log_layout.addWidget(self.log_box)
        root.addWidget(log_group)
