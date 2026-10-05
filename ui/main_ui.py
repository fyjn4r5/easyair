from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QComboBox, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QTextEdit, QGroupBox,
    QSplitter, QFileDialog, QMessageBox, QCheckBox, QListWidget,
    QListWidgetItem, QAbstractItemView, QMenu, QAction, QInputDialog,
    QLineEdit, QSpinBox, QDialog, QDialogButtonBox, QFormLayout,
    QTabWidget, QProgressBar, QTreeWidget, QTreeWidgetItem, QFrame,
    QSystemTrayIcon, QStyle, QApplication, QPlainTextEdit
)
from PyQt5.QtCore import Qt, pyqtSignal, QTimer, QSize
from PyQt5.QtGui import QFont, QColor, QIcon, QPixmap, QPainter
from pathlib import Path


def create_status_icon(color: str, size: int = 16) -> QIcon:
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing)
    painter.setBrush(QColor(color))
    painter.setPen(Qt.NoPen)
    painter.drawEllipse(2, 2, size - 4, size - 4)
    painter.end()
    return QIcon(pixmap)


class WordListDialog(QDialog):
    def __init__(self, parent=None, current_lists=None):
        super().__init__(parent)
        self.setWindowTitle("字典管理")
        self.resize(600, 400)
        self.wordlists = list(current_lists) if current_lists else []
        self._setup_ui()
        self._load_lists()

    def _setup_ui(self):
        layout = QVBoxLayout(self)

        self.list_widget = QListWidget()
        self.list_widget.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.list_widget.setDragDropMode(QAbstractItemView.InternalMove)
        self.list_widget.setDefaultDropAction(Qt.MoveAction)
        self.list_widget.setContextMenuPolicy(Qt.CustomContextMenu)
        self.list_widget.customContextMenuRequested.connect(self._show_menu)
        layout.addWidget(self.list_widget)

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

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

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
    COL_BSSID, COL_ESSID, COL_PWD, COL_CAP, COL_STATE, COL_TIME, COL_NOTE = range(7)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setHeaderLabels(["BSSID", "SSID", "密码", "握手包", "状态", "耗时", "备注"])
        header = self.header()
        header.setSectionResizeMode(QHeaderView.Interactive)
        header.setStretchLastSection(True)
        for idx, w in enumerate((170, 130, 160, 180, 80, 80, 150)):
            self.setColumnWidth(idx, w)
        self.setAlternatingRowColors(True)
        self.setRootIsDecorated(False)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)

    def add_target(self, bssid, essid, cap_file, note=""):
        item = QTreeWidgetItem([bssid, essid, "破解中...", cap_file, "进行中", "00:00", note])
        item.setData(0, Qt.UserRole, {"bssid": bssid, "essid": essid, "cap": cap_file})
        self.addTopLevelItem(item)
        return item

    def to_record(self, item) -> dict:
        return {
            "bssid": item.text(self.COL_BSSID),
            "essid": item.text(self.COL_ESSID),
            "password": item.text(self.COL_PWD),
            "cap": item.text(self.COL_CAP),
            "status": item.text(self.COL_STATE),
            "elapsed": item.text(self.COL_TIME),
            "note": item.text(self.COL_NOTE),
        }

    def load_record(self, rec: dict):
        item = QTreeWidgetItem([
            rec.get("bssid", ""), rec.get("essid", ""),
            rec.get("password", "") or "破解中...",
            rec.get("cap", ""), rec.get("status", ""),
            rec.get("elapsed", ""), rec.get("note", ""),
        ])
        self.addTopLevelItem(item)
        state = rec.get("status", "")
        if state == "成功":
            self._paint_success(item)
        elif state and state not in ("进行中",):
            item.setText(self.COL_STATE, state)
            item.setForeground(self.COL_STATE, QColor("#c62828"))
        return item

    def _paint_success(self, item):
        item.setForeground(self.COL_STATE, QColor("#2e7d32"))
        item.setForeground(self.COL_PWD, QColor("#1565c0"))

    def update_progress(self, item, password, elapsed):
        if password:
            item.setText(self.COL_PWD, password)
            item.setText(self.COL_STATE, "成功")
            item.setForeground(self.COL_STATE, QColor("#2e7d32"))
            item.setForeground(self.COL_PWD, QColor("#1565c0"))
            self.scrollToItem(item)
        item.setText(self.COL_TIME, elapsed)

    def set_failed(self, item, reason="失败"):
        item.setText(self.COL_STATE, reason)
        item.setForeground(self.COL_STATE, QColor("#c62828"))

    def set_note(self, item, note):
        item.setText(self.COL_NOTE, note)

    def current_record(self):
        items = self.selectedItems()
        return items[0] if items else None


class CrackSettingsDialog(QDialog):
    ENGINES = ["Hashcat (GPU/CPU)", "Aircrack-ng (CPU)"]
    DEVICES = ["GPU + CPU (自动)", "仅 GPU", "仅 CPU"]

    def __init__(self, parent=None, config=None):
        super().__init__(parent)
        self.setWindowTitle("破解设置")
        self.setMinimumWidth(430)
        config = config or {}

        layout = QVBoxLayout(self)
        form = QFormLayout()

        self.engine_combo = QComboBox()
        self.engine_combo.addItems(self.ENGINES)
        self.device_combo = QComboBox()
        self.device_combo.addItems(self.DEVICES)
        self.engine_combo.currentTextChanged.connect(self._sync_device)
        form.addRow("破解引擎:", self.engine_combo)
        form.addRow("计算设备:", self.device_combo)

        self.extra_args = QLineEdit(config.get("hashcat_extra_args", ""))
        self.extra_args.setPlaceholderText("--force --opencl-device-types 1,2")
        form.addRow("Hashcat 额外参数:", self.extra_args)

        self.auto_mon = QCheckBox("自动监听模式 (扫描时自动开启)")
        self.auto_mon.setChecked(config.get("auto_monitor", True))
        form.addRow(self.auto_mon)

        self.scan_secs = QSpinBox()
        self.scan_secs.setRange(0, 3600)
        self.scan_secs.setSingleStep(15)
        self.scan_secs.setSuffix(" 秒")
        self.scan_secs.setSpecialValueText("手动停止")
        self.scan_secs.setValue(int(config.get("scan_auto_stop", 0) or 0))
        form.addRow("扫描自动停止:", self.scan_secs)

        layout.addLayout(form)

        hint = QLabel("提示: Aircrack-ng 仅支持 CPU，切换引擎时设备会自动锁定。\n"
                      "停止扫描不会关闭监听模式，可直接继续抓取握手包。")
        hint.setStyleSheet("color: #888;")
        hint.setWordWrap(True)
        layout.addWidget(hint)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self.engine_combo.setCurrentText(config.get("crack_engine", self.ENGINES[0]))
        self.device_combo.setCurrentText(config.get("crack_device", self.DEVICES[0]))
        self._sync_device(self.engine_combo.currentText())

    def _sync_device(self, engine: str):
        is_aircrack = engine.startswith("Aircrack")
        self.device_combo.setEnabled(not is_aircrack)
        if is_aircrack:
            self.device_combo.setCurrentText(self.DEVICES[2])

    def values(self) -> dict:
        return {
            "crack_engine": self.engine_combo.currentText(),
            "crack_device": self.device_combo.currentText(),
            "hashcat_extra_args": self.extra_args.text().strip(),
            "auto_monitor": self.auto_mon.isChecked(),
            "scan_auto_stop": self.scan_secs.value(),
        }


class MainUI(QWidget):
    monitor_status_changed = pyqtSignal(str)
    scan_status_changed = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("EasyAir - WiFi 抓包破解 (EWSA 风格)")
        self.resize(1400, 850)
        
        self.icon_on = create_status_icon("#2e7d32")
        self.icon_off = create_status_icon("#9e9e9e")
        self.icon_starting = create_status_icon("#f57c00")
        self.icon_error = create_status_icon("#c62828")
        self.icon_scanning = create_status_icon("#1976d2")
        
        self._setup_ui()
        self._setup_tray()

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

        tb_layout.addWidget(QLabel("网卡:"))
        self.iface_combo = QComboBox()
        self.iface_combo.setMinimumWidth(180)
        tb_layout.addWidget(self.iface_combo)

        self.btn_refresh_iface = QPushButton("刷新")
        tb_layout.addWidget(self.btn_refresh_iface)

        tb_layout.addSpacing(10)

        # 监听模式状态指示器 (带图标的按钮) - 关键：补回这个按钮
        self.btn_mon_toggle = QPushButton()
        self.btn_mon_toggle.setCheckable(True)
        self.btn_mon_toggle.setFixedSize(40, 40)
        self.btn_mon_toggle.setIcon(self.icon_off)
        self.btn_mon_toggle.setIconSize(QSize(24, 24))
        self.btn_mon_toggle.setToolTip("监听模式: 关闭\n点击开启/关闭")
        self.btn_mon_toggle.setStyleSheet("""
            QPushButton {
                border: 2px solid #ddd;
                border-radius: 20px;
                background: #fafafa;
            }
            QPushButton:checked {
                border: 2px solid #2e7d32;
                background: #e8f5e9;
            }
            QPushButton:hover {
                background: #f5f5f5;
            }
        """)
        tb_layout.addWidget(self.btn_mon_toggle)

        self.lbl_mon_status = QLabel("监听模式: 关闭")
        self.lbl_mon_status.setStyleSheet("color: #9e9e9e; font-weight: bold; min-width: 120px;")
        tb_layout.addWidget(self.lbl_mon_status)

        tb_layout.addSpacing(20)

        self.lbl_scan_status = QLabel()
        self.lbl_scan_status.setFixedSize(20, 20)
        self.lbl_scan_status.setPixmap(create_status_icon("#9e9e9e", 20).pixmap(20, 20))
        self.lbl_scan_status.setToolTip("扫描状态: 空闲")
        tb_layout.addWidget(self.lbl_scan_status)

        self.lbl_scan_text = QLabel("扫描: 空闲")
        self.lbl_scan_text.setStyleSheet("color: #666; min-width: 100px;")
        tb_layout.addWidget(self.lbl_scan_text)

        tb_layout.addStretch()

        self.btn_dict_mgr = QPushButton("📁 字典管理")
        self.btn_dict_mgr.setMinimumWidth(100)
        tb_layout.addWidget(self.btn_dict_mgr)

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

        ap_group = QGroupBox("周边 AP (双击选择目标)")
        ap_layout = QVBoxLayout(ap_group)

        self.ap_table = QTableWidget()
        self.ap_table.setColumnCount(7)
        self.ap_table.setHorizontalHeaderLabels(["信号", "SSID", "BSSID", "信道", "加密", "认证", "信号强度"])
        ap_header = self.ap_table.horizontalHeader()
        ap_header.setSectionResizeMode(QHeaderView.Interactive)
        ap_header.setStretchLastSection(False)
        for idx, w in enumerate((50, 160, 170, 55, 110, 80, 90)):
            self.ap_table.setColumnWidth(idx, w)
        self.ap_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.ap_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.ap_table.setAlternatingRowColors(True)
        self.ap_table.setShowGrid(False)
        self.ap_table.verticalHeader().setVisible(False)
        self.ap_table.setSelectionMode(QAbstractItemView.SingleSelection)
        ap_layout.addWidget(self.ap_table)

        ctrl_layout = QHBoxLayout()
        self.btn_scan = QPushButton("🔍 开始扫描")
        self.btn_scan.setMinimumHeight(36)
        self.btn_scan.setStyleSheet("font-weight: bold; background: #1976d2; color: white;")
        self.btn_stop_scan = QPushButton("⏹ 停止扫描")
        self.btn_stop_scan.setMinimumHeight(36)
        self.btn_stop_scan.setEnabled(False)
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

        self.status_label = QLabel("就绪 - 点击'开始扫描'搜索周边 AP")
        self.status_label.setStyleSheet("color: #666; padding: 4px;")
        ap_layout.addWidget(self.status_label)

        left_layout.addWidget(ap_group)

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

        cap_group = QGroupBox("握手包库 (按日期归类, 双击载入)")
        cap_layout = QVBoxLayout(cap_group)
        self.cap_tree = QTreeWidget()
        self.cap_tree.setHeaderLabels(["日期 / 握手包", "大小"])
        cap_header = self.cap_tree.header()
        cap_header.setSectionResizeMode(QHeaderView.Interactive)
        cap_header.setStretchLastSection(False)
        self.cap_tree.setColumnWidth(0, 240)
        self.cap_tree.setColumnWidth(1, 80)
        self.cap_tree.setFixedHeight(120)
        self.cap_tree.setAlternatingRowColors(True)
        cap_layout.addWidget(self.cap_tree)
        left_layout.addWidget(cap_group)

        main_splitter.addWidget(left_widget)

        # ---- 右侧: 破解面板 (EWSA 风格) ----
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setSpacing(6)
        right_layout.setContentsMargins(0, 0, 0, 0)

        engine_group = QGroupBox("当前引擎")
        engine_layout = QHBoxLayout(engine_group)
        self.lbl_engine = QLabel("Hashcat (GPU/CPU)  |  GPU + CPU (自动)")
        self.lbl_engine.setStyleSheet("color: #1565c0; font-weight: bold;")
        engine_layout.addWidget(self.lbl_engine)
        engine_layout.addStretch()
        self.btn_change_engine = QPushButton("更改")
        engine_layout.addWidget(self.btn_change_engine)
        right_layout.addWidget(engine_group)

        progress_group = QGroupBox("破解进度")
        progress_layout = QVBoxLayout(progress_group)
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setVisible(False)
        progress_layout.addWidget(self.progress_bar)
        self.scan_elapsed = QLabel("")
        self.scan_elapsed.setStyleSheet("color: #888;")
        progress_layout.addWidget(self.scan_elapsed)
        self.lbl_progress = QLabel("等待开始...")
        self.lbl_progress.setStyleSheet("color: #666;")
        progress_layout.addWidget(self.lbl_progress)
        right_layout.addWidget(progress_group)

        result_group = QGroupBox("破解结果 (按日期归类)")
        result_layout = QVBoxLayout(result_group)
        self.result_tabs = QTabWidget()
        self.result_tabs.setDocumentMode(True)
        result_layout.addWidget(self.result_tabs)

        result_btn_layout = QHBoxLayout()
        self.btn_start_crack = QPushButton("▶ 开始破解")
        self.btn_start_crack.setMinimumHeight(40)
        self.btn_start_crack.setStyleSheet("font-weight: bold; background: #2e7d32; color: white; font-size: 14px;")
        self.btn_stop_crack = QPushButton("⏹ 停止破解")
        self.btn_stop_crack.setMinimumHeight(40)
        self.btn_stop_crack.setStyleSheet("font-weight: bold; background: #c62828; color: white; font-size: 14px;")
        self.btn_stop_crack.setEnabled(False)
        self.btn_note = QPushButton("📝 备注")
        self.btn_note.setToolTip("为选中记录添加备注，如破解地点")
        self.btn_del_record = QPushButton("🗑 删除")
        self.btn_export = QPushButton("📤 导出结果")
        result_btn_layout.addWidget(self.btn_start_crack)
        result_btn_layout.addWidget(self.btn_stop_crack)
        result_btn_layout.addWidget(self.btn_note)
        result_btn_layout.addWidget(self.btn_del_record)
        result_btn_layout.addWidget(self.btn_export)
        result_layout.addLayout(result_btn_layout)

        right_layout.addWidget(result_group, 1)

        main_splitter.addWidget(right_widget)
        main_splitter.setStretchFactor(0, 3)
        main_splitter.setStretchFactor(1, 4)

        root.addWidget(main_splitter, 1)

        # ===== 底部日志: 抓包 / 破解 双Tab =====
        log_group = QGroupBox("运行日志")
        log_layout = QVBoxLayout(log_group)
        self.log_tabs = QTabWidget()
        self.log_tabs.setDocumentMode(True)
        self.log_tabs.setMaximumHeight(190)

        self.log_scan_box = self._make_log_box()
        self.log_crack_box = self._make_log_box()
        self.log_tabs.addTab(self.log_scan_box, "📡 抓包日志")
        self.log_tabs.addTab(self.log_crack_box, "🔓 破解日志")
        log_layout.addWidget(self.log_tabs)
        root.addWidget(log_group)

    def _make_log_box(self):
        box = QPlainTextEdit()
        box.setReadOnly(True)
        box.setMaximumBlockCount(800)
        box.setFont(QFont("Monospace", 9))
        box.setLineWrapMode(QPlainTextEdit.NoWrap)
        return box

    def _setup_tray(self):
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return
        
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(self.icon_off)
        self.tray_icon.setToolTip("EasyAir - 监听模式: 关闭")
        
        tray_menu = QMenu()
        self.tray_action_mon = QAction("监听模式: 关闭", self)
        self.tray_action_mon.setEnabled(False)
        tray_menu.addAction(self.tray_action_mon)
        tray_menu.addSeparator()
        act_show = QAction("显示主界面", self)
        act_show.triggered.connect(self.showNormal)
        tray_menu.addAction(act_show)
        act_quit = QAction("退出", self)
        act_quit.triggered.connect(QApplication.instance().quit)
        tray_menu.addAction(act_quit)
        
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.activated.connect(self._on_tray_activated)
        self.tray_icon.show()

    def _on_tray_activated(self, reason):
        if reason == QSystemTrayIcon.DoubleClick:
            self.showNormal()
            self.raise_()
            self.activateWindow()

    def set_monitor_status(self, status: str):
        if status == "off":
            self.btn_mon_toggle.setChecked(False)
            self.btn_mon_toggle.setIcon(self.icon_off)
            self.btn_mon_toggle.setToolTip("监听模式: 关闭\n点击开启")
            self.lbl_mon_status.setText("监听模式: 关闭")
            self.lbl_mon_status.setStyleSheet("color: #9e9e9e; font-weight: bold; min-width: 120px;")
            if hasattr(self, 'tray_icon'):
                self.tray_icon.setIcon(self.icon_off)
                self.tray_icon.setToolTip("EasyAir - 监听模式: 关闭")
                self.tray_action_mon.setText("监听模式: 关闭")
        elif status == "starting":
            self.btn_mon_toggle.setIcon(self.icon_starting)
            self.btn_mon_toggle.setToolTip("监听模式: 启动中...")
            self.lbl_mon_status.setText("监听模式: 启动中...")
            self.lbl_mon_status.setStyleSheet("color: #f57c00; font-weight: bold; min-width: 120px;")
            if hasattr(self, 'tray_icon'):
                self.tray_icon.setIcon(self.icon_starting)
                self.tray_icon.setToolTip("EasyAir - 监听模式: 启动中...")
        elif status == "on":
            self.btn_mon_toggle.setChecked(True)
            self.btn_mon_toggle.setIcon(self.icon_on)
            self.btn_mon_toggle.setToolTip("监听模式: 已开启\n点击关闭")
            self.lbl_mon_status.setText("监听模式: 已开启")
            self.lbl_mon_status.setStyleSheet("color: #2e7d32; font-weight: bold; min-width: 120px;")
            if hasattr(self, 'tray_icon'):
                self.tray_icon.setIcon(self.icon_on)
                self.tray_icon.setToolTip("EasyAir - 监听模式: 已开启")
                self.tray_action_mon.setText("监听模式: 已开启")
        elif status == "error":
            self.btn_mon_toggle.setChecked(False)
            self.btn_mon_toggle.setIcon(self.icon_error)
            self.btn_mon_toggle.setToolTip("监听模式: 错误")
            self.lbl_mon_status.setText("监听模式: 错误")
            self.lbl_mon_status.setStyleSheet("color: #c62828; font-weight: bold; min-width: 120px;")
            if hasattr(self, 'tray_icon'):
                self.tray_icon.setIcon(self.icon_error)
                self.tray_icon.setToolTip("EasyAir - 监听模式: 错误")

    def set_scan_status(self, status: str):
        if status == "idle":
            self.btn_scan.setEnabled(True)
            self.btn_stop_scan.setEnabled(False)
            self.lbl_scan_status.setPixmap(create_status_icon("#9e9e9e", 20).pixmap(20, 20))
            self.lbl_scan_text.setText("扫描: 空闲")
            self.lbl_scan_text.setStyleSheet("color: #666; min-width: 100px;")
        elif status == "scanning":
            self.btn_scan.setEnabled(False)
            self.btn_stop_scan.setEnabled(True)
            self.lbl_scan_status.setPixmap(create_status_icon("#1976d2", 20).pixmap(20, 20))
            self.lbl_scan_text.setText("扫描: 进行中...")
            self.lbl_scan_text.setStyleSheet("color: #1976d2; font-weight: bold; min-width: 100px;")
        elif status == "stopping":
            self.lbl_scan_text.setText("扫描: 停止中...")
            self.lbl_scan_text.setStyleSheet("color: #f57c00; min-width: 100px;")

    def closeEvent(self, event):
        if hasattr(self, 'tray_icon'):
            self.tray_icon.hide()
        super().closeEvent(event)
