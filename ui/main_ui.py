from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QComboBox, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QTextEdit, QGroupBox,
    QSplitter, QFileDialog, QMessageBox, QCheckBox, QListWidget,
    QListWidgetItem, QAbstractItemView, QMenu, QAction, QInputDialog,
    QLineEdit, QSpinBox
)
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QDragEnterEvent, QDropEvent
from pathlib import Path

class WordListWidget(QListWidget):
    """支持拖拽排序、右键菜单的字典列表"""
    order_changed = pyqtSignal(list)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setDragDropMode(QAbstractItemView.DragDropMode.InternalMove)
        self.setDefaultDropAction(Qt.DropAction.MoveAction)
        self.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self._show_menu)

    def _show_menu(self, pos):
        menu = QMenu(self)
        act_add = QAction("添加字典文件...", self)
        act_add_dir = QAction("添加目录下所有字典...", self)
        act_remove = QAction("移除选中", self)
        act_clear = QAction("清空列表", self)
        act_up = QAction("上移", self)
        act_down = QAction("下移", self)
        menu.addAction(act_add)
        menu.addAction(act_add_dir)
        menu.addSeparator()
        menu.addAction(act_remove)
        menu.addAction(act_clear)
        menu.addSeparator()
        menu.addAction(act_up)
        menu.addAction(act_down)

        act_add.triggered.connect(lambda: self.parent()._add_wordlist_files())
        act_add_dir.triggered.connect(lambda: self.parent()._add_wordlist_dir())
        act_remove.triggered.connect(self._remove_selected)
        act_clear.triggered.connect(self.clear)
        act_up.triggered.connect(self._move_up)
        act_down.triggered.connect(self._move_down)

        menu.exec_(self.mapToGlobal(pos))

    def _remove_selected(self):
        for item in self.selectedItems():
            self.takeItem(self.row(item))
        self._emit_order()

    def _move_up(self):
        for item in self.selectedItems():
            row = self.row(item)
            if row > 0:
                self.takeItem(row)
                self.insertItem(row - 1, item)
                self.setCurrentItem(item)
        self._emit_order()

    def _move_down(self):
        items = self.selectedItems()
        for item in reversed(items):
            row = self.row(item)
            if row < self.count() - 1:
                self.takeItem(row)
                self.insertItem(row + 1, item)
                self.setCurrentItem(item)
        self._emit_order()

    def _emit_order(self):
        paths = [self.item(i).text() for i in range(self.count())]
        self.order_changed.emit(paths)

    def dropEvent(self, event: QDropEvent):
        super().dropEvent(event)
        self._emit_order()

    def add_wordlist(self, path: str):
        if path and all(self.item(i).text() != path for i in range(self.count())):
            self.addItem(path)
            self._emit_order()

    def get_all(self) -> list:
        return [self.item(i).text() for i in range(self.count())]


class MainUI(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("EasyAir - 傻瓜式 WiFi 抓包破解")
        self.resize(1200, 800)
        self._setup_ui()

    def _setup_ui(self):
        root = QVBoxLayout(self)

        # ===== 顶部：网卡与监听模式 =====
        top_group = QGroupBox("无线网卡控制")
        top_layout = QHBoxLayout(top_group)

        top_layout.addWidget(QLabel("物理网卡："))
        self.iface_combo = QComboBox()
        self.iface_combo.setMinimumWidth(150)
        top_layout.addWidget(self.iface_combo)

        self.btn_refresh = QPushButton("刷新网卡")
        self.btn_mon_toggle = QPushButton("开启监听模式")
        self.btn_mon_toggle.setCheckable(True)
        self.chk_auto_mon = QCheckBox("自动监听模式(抓包时自动开启/停止时关闭)")
        self.chk_auto_mon.setChecked(True)

        top_layout.addWidget(self.btn_refresh)
        top_layout.addWidget(self.btn_mon_toggle)
        top_layout.addWidget(self.chk_auto_mon)
        top_layout.addStretch()

        root.addWidget(top_group)

        # ===== 中部：左右分割 =====
        mid_splitter = QSplitter(Qt.Orientation.Horizontal)

        # ---- 左侧：AP 扫描与抓包 ----
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)

        ap_group = QGroupBox("AP 扫描与抓包")
        ap_layout = QVBoxLayout(ap_group)

        self.ap_table = QTableWidget()
        self.ap_table.setColumnCount(7)
        self.ap_table.setHorizontalHeaderLabels(["SSID", "BSSID", "CH", "ENC", "CIPHER", "AUTH", "PWR"])
        self.ap_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.ap_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.ap_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.ap_table.setAlternatingRowColors(True)
        ap_layout.addWidget(self.ap_table)

        btn_row = QHBoxLayout()
        self.btn_scan = QPushButton("开始扫描")
        self.btn_stop_scan = QPushButton("停止扫描")
        self.btn_capture = QPushButton("开始抓取握手包")
        self.btn_deauth = QPushButton("一键 Deauth (10次)")
        self.btn_auto = QPushButton("一键全自动(扫描→选中→抓包→Deauth)")
        btn_row.addWidget(self.btn_scan)
        btn_row.addWidget(self.btn_stop_scan)
        btn_row.addWidget(self.btn_capture)
        btn_row.addWidget(self.btn_deauth)
        btn_row.addWidget(self.btn_auto)
        ap_layout.addLayout(btn_row)

        left_layout.addWidget(ap_group)

        # ---- 右侧：字典管理 + 破解设置 ----
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)

        # 字典管理
        dict_group = QGroupBox("字典管理 (拖拽排序，右键菜单)")
        dict_layout = QVBoxLayout(dict_group)

        self.wordlist_widget = WordListWidget()
        self.wordlist_widget.setMinimumHeight(200)
        dict_layout.addWidget(self.wordlist_widget)

        dict_btn_row = QHBoxLayout()
        self.btn_add_wl = QPushButton("添加文件")
        self.btn_add_wl_dir = QPushButton("添加目录")
        self.btn_clear_wl = QPushButton("清空")
        dict_btn_row.addWidget(self.btn_add_wl)
        dict_btn_row.addWidget(self.btn_add_wl_dir)
        dict_btn_row.addWidget(self.btn_clear_wl)
        dict_layout.addLayout(dict_btn_row)

        right_layout.addWidget(dict_group)

        # 破解设置
        crack_set_group = QGroupBox("破解设置")
        crack_set_layout = QVBoxLayout(crack_set_group)

        row1 = QHBoxLayout()
        row1.addWidget(QLabel("破解引擎："))
        self.crack_engine = QComboBox()
        self.crack_engine.addItems(["Hashcat (推荐)", "Aircrack-ng"])
        row1.addWidget(self.crack_engine)

        row1.addWidget(QLabel("设备："))
        self.device_combo = QComboBox()
        self.device_combo.addItems(["GPU + CPU (自动)", "仅 GPU", "仅 CPU"])
        row1.addWidget(self.device_combo)

        self.chk_show_hashcat = QCheckBox("显示 Hashcat 实时进度")
        self.chk_show_hashcat.setChecked(True)
        row1.addWidget(self.chk_show_hashcat)
        row1.addStretch()
        crack_set_layout.addLayout(row1)

        row2 = QHBoxLayout()
        row2.addWidget(QLabel("Hashcat 额外参数："))
        self.hashcat_extra = QLineEdit()
        self.hashcat_extra.setPlaceholderText("例如: --force --opencl-device-types 1,2")
        row2.addWidget(self.hashcat_extra)
        crack_set_layout.addLayout(row2)

        right_layout.addWidget(crack_set_group)

        # 破解执行
        crack_exec_group = QGroupBox("执行破解")
        crack_exec_layout = QVBoxLayout(crack_exec_group)

        cap_row = QHBoxLayout()
        cap_row.addWidget(QLabel("握手包："))
        self.cap_path = QLabel("自动检测最新 handshake-*.cap")
        self.cap_path.setStyleSheet("color: #666;")
        cap_row.addWidget(self.cap_path, 1)
        self.btn_choose_cap = QPushButton("手动选择 .cap")
        self.btn_refresh_cap = QPushButton("刷新")
        cap_row.addWidget(self.btn_choose_cap)
        cap_row.addWidget(self.btn_refresh_cap)
        crack_exec_layout.addLayout(cap_row)

        crack_btn_row = QHBoxLayout()
        self.btn_crack = QPushButton("开始破解")
        self.btn_crack.setStyleSheet("font-weight: bold; padding: 8px; background: #2e7d32; color: white;")
        self.btn_stop_crack = QPushButton("停止破解")
        self.btn_stop_crack.setStyleSheet("padding: 8px; background: #c62828; color: white;")
        crack_btn_row.addWidget(self.btn_crack)
        crack_btn_row.addWidget(self.btn_stop_crack)
        crack_exec_layout.addLayout(crack_btn_row)

        right_layout.addWidget(crack_exec_group)

        mid_splitter.addWidget(left_widget)
        mid_splitter.addWidget(right_widget)
        mid_splitter.setStretchFactor(0, 2)
        mid_splitter.setStretchFactor(1, 1)

        root.addWidget(mid_splitter, 1)

        # ===== 底部日志 =====
        log_group = QGroupBox("运行日志")
        log_layout = QVBoxLayout(log_group)
        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)
        self.log_box.setMaximumHeight(180)
        log_layout.addWidget(self.log_box)
        root.addWidget(log_group)
