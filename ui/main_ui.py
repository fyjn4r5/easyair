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
        if items:
            return items[0]
        item = self.currentItem()
        if item is not None and item.parent() is None:  # 只认顶层记录
            return item
        return None


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
        self.scan_secs.setValue(int(config.get("scan_auto_stop", 45) or 45))
        form.addRow("扫描自动停止:", self.scan_secs)

        self.temp_limit = QSpinBox()
        self.temp_limit.setRange(0, 110)
        self.temp_limit.setSingleStep(5)
        self.temp_limit.setSuffix(" °C")
        self.temp_limit.setSpecialValueText("不限制")
        self.temp_limit.setValue(int(config.get("hashcat_temp_limit", 85) or 0))
        self.temp_limit.setToolTip(
            "GPU 温度达到该值时 hashcat 自动中止，防止硬件过热损坏。\n"
            "常见显卡的安全上限约 83~90 °C，默认 85 °C。0 表示不限制。")
        form.addRow("GPU 温度上限:", self.temp_limit)

        layout.addLayout(form)

        hint = QLabel("提示: Aircrack-ng 仅支持 CPU，切换引擎时设备会自动锁定。\n"
                      "停止扫描不会关闭监听模式，可直接继续抓取握手包。\n"
                      "所有设置保存后立即生效，重启后仍然保留。")
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
            # 标记用户主动设置过, 之后即使设为 0(不自动停止)也不再被迁移
            "scan_auto_stop_explicit": True,
            "hashcat_temp_limit": self.temp_limit.value(),
        }


class MainUI(QWidget):
    monitor_status_changed = pyqtSignal(str)
    scan_status_changed = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        # 标题带版本号: 之前多个版本并存, 无法判断跑的是哪个构建
        ver = "1.12.2"
        try:
            import main as _m
            ver = getattr(_m, "VERSION", ver)
        except Exception:  # noqa: BLE001
            pass
        self.setWindowTitle(f"EasyAir v{ver} - WiFi 抓包破解")
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

        # 监听模式: 只保留状态指示, 开关统一由「设置」里的自动监听管理
        # (之前顶部还有一个独立开关, 与设置项重复且容易状态不一致)
        self.btn_mon_toggle = QPushButton()
        self.btn_mon_toggle.setCheckable(True)
        self.btn_mon_toggle.setFixedSize(40, 40)
        self.btn_mon_toggle.setIcon(self.icon_off)
        self.btn_mon_toggle.setIconSize(QSize(24, 24))
        self.btn_mon_toggle.setEnabled(False)
        self.btn_mon_toggle.setToolTip(
            "监听模式由「设置」中的自动监听统一管理\n扫描或抓包时自动开启")
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
        """)
        tb_layout.addWidget(self.btn_mon_toggle)

        self.lbl_mon_status = QLabel("监听模式: 关闭")
        self.lbl_mon_status.setStyleSheet("color: #9e9e9e; font-weight: bold; min-width: 120px;")
        tb_layout.addWidget(self.lbl_mon_status)

        tb_layout.addStretch()

        self.btn_dict_mgr = QPushButton("📁 字典")
        self.btn_dict_mgr.setMinimumWidth(84)
        tb_layout.addWidget(self.btn_dict_mgr)

        self.btn_crack_cfg = QPushButton("⚙ 设置")
        self.btn_crack_cfg.setMinimumWidth(84)
        tb_layout.addWidget(self.btn_crack_cfg)

        root.addWidget(toolbar)

        # ===== 状态条: 左侧目标信息 / 右侧引擎与破解进度 =====
        # 把所有全局信息收进这一条, 两侧面板只留「表格 + 按钮行」,
        # 结构完全对称 => AP 表与破解结果表高度一致
        target_bar = QFrame()
        target_bar.setObjectName("targetBar")
        target_bar.setFixedHeight(40)
        tgt_layout = QHBoxLayout(target_bar)
        tgt_layout.setContentsMargins(12, 0, 12, 0)
        tgt_layout.setSpacing(8)

        title = QLabel("当前目标")
        title.setStyleSheet("font-weight: bold; color: #37474f;")
        tgt_layout.addWidget(title)

        self.lbl_target_essid = self._add_target_field(tgt_layout, "SSID", "未选择")
        self.lbl_target_bssid = self._add_target_field(tgt_layout, "BSSID", "未选择")
        self.lbl_target_ch = self._add_target_field(tgt_layout, "信道", "--")
        self.lbl_target_enc = self._add_target_field(tgt_layout, "加密", "--")
        self.lbl_handshake = QLabel("握手包 未捕获")
        self.lbl_handshake.setStyleSheet("color: #c62828; font-weight: bold;")
        tgt_layout.addWidget(self.lbl_handshake)
        tgt_layout.addSpacing(16)

        tgt_layout.addStretch()

        self.lbl_engine = QLabel("Hashcat · GPU+CPU")
        self.lbl_engine.setStyleSheet("color: #1565c0; font-weight: bold;")
        tgt_layout.addWidget(self.lbl_engine)
        self.btn_change_engine = QPushButton("更改")
        self.btn_change_engine.setFixedSize(56, 24)
        tgt_layout.addWidget(self.btn_change_engine)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setFixedSize(150, 12)
        self.progress_bar.setTextVisible(False)
        tgt_layout.addWidget(self.progress_bar)
        self.lbl_progress = QLabel("等待开始")
        self.lbl_progress.setStyleSheet("color: #607d8b;")
        self.lbl_progress.setFixedWidth(150)
        tgt_layout.addWidget(self.lbl_progress)

        root.addWidget(target_bar)

        # ===== 中部: 左右对称, 两个表格等宽等高 =====
        main_splitter = QSplitter(Qt.Horizontal)
        main_splitter.setChildrenCollapsible(False)
        # 两个 QTableWidget 实时重排非常昂贵, 改为松手后才重排
        main_splitter.setOpaqueResize(True)
        main_splitter.setHandleWidth(6)

        # ---- 左侧: 周边 AP ----
        ap_group = QGroupBox("周边 AP  ·  双击设为目标")
        ap_group_layout = QVBoxLayout(ap_group)
        ap_group_layout.setContentsMargins(8, 6, 8, 8)
        ap_group_layout.setSpacing(6)

        self.ap_table = QTableWidget()
        self.ap_table.setColumnCount(7)
        # 客户端列按原宽 92 的 1/4 = 23px。实测 23px 放不下"客户端"表头
        # (需 42px)也放不下"N 台"(需 33px), 因此表头缩写为"端"、内容只显示
        # 数字, 完整信息(客户端数与 MAC 列表)放在 tooltip 里。
        # BSSID 130px = 字体实测刚好容纳一个 MAC(AA:BB:CC:DD:EE:FF 需 122px)。
        self.ap_table.setHorizontalHeaderLabels(
            ["信号", "SSID", "端", "BSSID", "信道", "加密", "强度"])
        # BSSID/信道/加密 明细对日常使用不是必需, 但抓包要用 BSSID,
        # 因此保留列但收窄, 完整信息通过 tooltip 展示
        ap_header = self.ap_table.horizontalHeader()
        ap_header.setSectionResizeMode(QHeaderView.Interactive)
        ap_header.setStretchLastSection(False)
        ap_header.setHighlightSections(False)
        # 关键: QHeaderView.minimumSectionSize 默认被字体撑到 57px,
        # 任何小于它的 setColumnWidth 都会被悄悄抬回 57 —— 这就是"端"列
        # 无论如何都缩不下去的原因。这里显式降到 12px 才能真正收窄。
        ap_header.setMinimumSectionSize(12)
        # 信号44 / SSID221 / 端23 / BSSID130 / 信道44 / 加密88 / 强度52 = 602
        # 总宽与调整前一致; 客户端(92->23)和 BSSID(150->130)省下的宽度给了 SSID
        for idx, w in enumerate((44, 221, 23, 130, 44, 88, 52)):
            self.ap_table.setColumnWidth(idx, w)
        self.ap_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.ap_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.ap_table.setAlternatingRowColors(True)
        self.ap_table.setShowGrid(False)
        self.ap_table.verticalHeader().setVisible(False)
        self.ap_table.setWordWrap(False)
        # 拖动变卡的主因: 纵向表头默认 Interactive, 每次布局都要逐行重算
        # sizeHint。固定行高 + 按像素滚动后, 拖动/滚动不再触发行级重排。
        _ap_vh = self.ap_table.verticalHeader()
        _ap_vh.setSectionResizeMode(QHeaderView.Fixed)
        _ap_vh.setDefaultSectionSize(26)
        self.ap_table.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)
        self.ap_table.setHorizontalScrollMode(QAbstractItemView.ScrollPerPixel)
        self.ap_table.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        # "认证"列信息价值低(与加密重复), 并入加密列显示, 省出宽度给客户端
        self.ap_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.Interactive)
        self.ap_table.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.ap_table.setSelectionMode(QAbstractItemView.SingleSelection)
        ap_group_layout.addWidget(self.ap_table, 1)

        ctrl_layout = QHBoxLayout()
        ctrl_layout.setSpacing(6)
        # 扫描与停止合并为一个切换按钮
        self.btn_scan = QPushButton("🔍 扫描")
        self.btn_scan.setStyleSheet(
            "font-weight: bold; background: #1976d2; color: white;")
        self.btn_scan.setToolTip("点击开始扫描 AP；扫描中点击可随时停止（不关闭监听）")
        self.btn_capture = QPushButton("📡 抓握手包")
        self.btn_capture.setStyleSheet("font-weight: bold; background: #f57c00; color: white;")
        self.btn_capture.setToolTip("自动对目标 AP 发送 deauth 促使客户端重连，并抓取握手包")
        for b in (self.btn_scan, self.btn_capture):
            b.setMinimumHeight(32)
            ctrl_layout.addWidget(b)
        ap_group_layout.addLayout(ctrl_layout)

        main_splitter.addWidget(ap_group)

        # ---- 右侧: 破解结果 (与左侧结构完全一致) ----
        result_group = QGroupBox("破解结果  ·  按日期归类")
        result_layout = QVBoxLayout(result_group)
        result_layout.setContentsMargins(8, 6, 8, 8)
        result_layout.setSpacing(6)
        self.result_tabs = QTabWidget()
        self.result_tabs.setDocumentMode(True)
        # 历史日期 tab 过多时会被压缩并把日期省略成 "2026-10-…",
        # 改为按需出现滚动按钮且不省略, 保证日期始终完整可见
        self.result_tabs.setUsesScrollButtons(True)
        self.result_tabs.tabBar().setElideMode(Qt.ElideNone)
        self.result_tabs.tabBar().setExpanding(False)
        result_layout.addWidget(self.result_tabs, 1)

        result_btn_layout = QHBoxLayout()
        result_btn_layout.setSpacing(6)
        # 开始破解与停止合并为一个切换按钮
        self.btn_start_crack = QPushButton("▶ 开始破解")
        self.btn_start_crack.setStyleSheet(
            "font-weight: bold; background: #2e7d32; color: white;")
        self.btn_start_crack.setToolTip("点击开始破解；破解中点击可随时停止")
        self.btn_copy_wifi = QPushButton("📋 复制WiFi")
        self.btn_copy_wifi.setToolTip(
            "把选中记录的 WiFi 名称和密码复制为可直接粘贴的格式")
        self.btn_copy_wifi.setEnabled(False)   # 无破解结果时置灰
        self.btn_note = QPushButton("📝 备注")
        self.btn_note.setToolTip("为选中记录添加备注，如破解地点")
        self.btn_del_record = QPushButton("🗑 删除")
        self.btn_export = QPushButton("📤 导出")
        self.btn_batch_add = QPushButton("📥 批量加入")
        self.btn_batch_add.setToolTip(
            "把握手包库中选中的多个握手包一次性加入右侧列表批量破解")
        for b in (self.btn_start_crack, self.btn_batch_add, self.btn_copy_wifi,
                  self.btn_note, self.btn_del_record, self.btn_export):
            b.setMinimumHeight(32)
            result_btn_layout.addWidget(b)
        result_layout.addLayout(result_btn_layout)

        main_splitter.addWidget(result_group)
        main_splitter.setStretchFactor(0, 1)
        main_splitter.setStretchFactor(1, 1)
        main_splitter.setSizes([540, 540])

        # ===== 竖向分割: 上下可拖拽 =====
        body_splitter = QSplitter(Qt.Vertical)
        body_splitter.setChildrenCollapsible(False)
        body_splitter.setOpaqueResize(True)
        body_splitter.setHandleWidth(6)
        body_splitter.addWidget(main_splitter)
        body_splitter.addWidget(self._build_bottom_tabs())
        body_splitter.setStretchFactor(0, 5)
        body_splitter.setStretchFactor(1, 2)
        body_splitter.setSizes([500, 210])

        root.addWidget(body_splitter, 1)

        # ===== 底部状态行 =====
        status_line = QFrame()
        status_line.setObjectName("targetBar")
        status_line.setFixedHeight(26)
        st_layout = QHBoxLayout(status_line)
        st_layout.setContentsMargins(12, 0, 12, 0)
        # 扫描时长与倒计时放在任务栏最左侧, 之后才是状态文字
        self.scan_elapsed = QLabel("")
        self.scan_elapsed.setStyleSheet("color: #607d8b;")
        self.scan_elapsed.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        self.scan_elapsed.setMinimumWidth(230)
        self.scan_elapsed.setToolTip("扫描时长与自动停止倒计时")
        st_layout.addWidget(self.scan_elapsed)
        self.status_label = QLabel("就绪 · 点击「扫描」搜索周边 AP")
        self.status_label.setStyleSheet("color: #455a64;")
        st_layout.addWidget(self.status_label)
        st_layout.addStretch()
        root.addWidget(status_line)

        self.setStyleSheet(self._app_stylesheet())

    def _add_target_field(self, layout, name, value):
        cap = QLabel(name)
        cap.setStyleSheet("color: #90a4ae;")
        val = QLabel(value)
        val.setStyleSheet("color: #263238; font-weight: bold;")
        val.setMinimumWidth(90)
        val.setToolTip(value)
        layout.addWidget(cap)
        layout.addWidget(val)
        return val

    def _build_bottom_tabs(self):
        """底部 Tab: 握手包库 / 抓包日志 / 破解日志 —— 全部收进一处, 主界面更干净"""
        self.bottom_tabs = QTabWidget()
        self.bottom_tabs.setDocumentMode(True)

        cap_page = QWidget()
        cap_layout = QVBoxLayout(cap_page)
        cap_layout.setContentsMargins(6, 6, 6, 6)
        self.cap_tree = QTreeWidget()
        self.cap_tree.setHeaderLabels(["日期 / 握手包", "大小"])
        cap_header = self.cap_tree.header()
        cap_header.setSectionResizeMode(QHeaderView.Interactive)
        cap_header.setStretchLastSection(False)
        self.cap_tree.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.cap_tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.cap_tree.setColumnWidth(0, 460)
        self.cap_tree.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)
        _cap_vh = self.cap_tree.header()
        _cap_vh.setSectionResizeMode(QHeaderView.Fixed)
        self.cap_tree.setColumnWidth(1, 90)
        self.cap_tree.setAlternatingRowColors(True)
        self.cap_tree.setRootIsDecorated(True)
        cap_layout.addWidget(self.cap_tree)
        self.bottom_tabs.addTab(cap_page, "📦 握手包库  (双击载入)")

        self.log_scan_box = self._make_log_box()
        self.log_crack_box = self._make_log_box()
        self.bottom_tabs.addTab(self.log_scan_box, "📡 抓包日志")
        self.bottom_tabs.addTab(self.log_crack_box, "🔓 破解日志")
        # 兼容旧引用
        self.log_tabs = self.bottom_tabs
        return self.bottom_tabs

    @staticmethod
    def _app_stylesheet():
        return """
        QGroupBox {
            font-weight: bold;
            border: 1px solid #dfe6ea;
            border-radius: 6px;
            margin-top: 10px;
            background: #ffffff;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            subcontrol-position: top left;
            left: 10px;
            padding: 0 4px;
            color: #546e7a;
        }
        QFrame#targetBar {
            background: #f4f7f9;
            border: 1px solid #e3eaee;
            border-radius: 6px;
        }
        QPushButton {
            border: 1px solid #cfd8dc;
            border-radius: 4px;
            background: #fafbfc;
            padding: 4px 10px;
        }
        QPushButton:hover { background: #eceff1; }
        QPushButton:disabled { color: #b0bec5; background: #f5f7f8; }
        QTableWidget, QTreeWidget {
            gridline-color: #eceff1;
            selection-background-color: #bbdefb;
            selection-color: #0d47a1;
        }
        QHeaderView::section {
            background: #f4f7f9;
            border: none;
            border-right: 1px solid #e3eaee;
            border-bottom: 1px solid #e3eaee;
            padding: 5px 4px;
            color: #455a64;
            font-weight: bold;
        }
        QTabWidget::pane { border: 1px solid #dfe6ea; border-radius: 4px; }
        QTabBar::tab {
            padding: 5px 14px;
            border: 1px solid #dfe6ea;
            border-bottom: none;
            border-top-left-radius: 4px;
            border-top-right-radius: 4px;
            background: #f0f3f5;
            color: #607d8b;
        }
        QTabBar::tab:selected {
            background: #ffffff;
            color: #1565c0;
            font-weight: bold;
        }
        """

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
            self.btn_scan.setText("🔍 扫描")
            self.btn_scan.setStyleSheet(
                "font-weight: bold; background: #1976d2; color: white;")

        elif status == "scanning":
            self.btn_scan.setEnabled(True)
            self.btn_scan.setText("⏹ 停止扫描")
            self.btn_scan.setStyleSheet(
                "font-weight: bold; background: #c62828; color: white;")
            self.btn_scan.setToolTip("扫描进行中，点击可随时停止（不关闭监听模式）")
        elif status == "stopping":
            self.btn_scan.setEnabled(False)
            self.btn_scan.setText("⏹ 停止中...")
            self.btn_scan.setToolTip("正在停止…")

    def closeEvent(self, event):
        if hasattr(self, 'tray_icon'):
            self.tray_icon.hide()
        super().closeEvent(event)
