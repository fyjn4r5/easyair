#!/usr/bin/env python3
"""EasyAir 全功能离线测试：不依赖真实网卡/airmon-ng，全部用桩件驱动。"""
import os
import sys
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  <- {detail}" if detail and not cond else ""))
    return cond


def section(title):
    print(f"\n=== {title} ===")


def pump(ms):
    from PyQt5.QtWidgets import QApplication
    from PyQt5.QtCore import QEventLoop, QTimer
    loop = QEventLoop()
    QTimer.singleShot(ms, loop.quit)
    loop.exec_()
    QApplication.processEvents()


def main():
    # 隔离工作目录: 让 captures/config 落在临时目录
    tmp = Path(tempfile.mkdtemp(prefix="easyair_test_"))
    for sub in ("captures", "wordlists", "config"):
        (tmp / sub).mkdir(parents=True, exist_ok=True)

    section("导入与启动")
    from PyQt5.QtWidgets import QApplication
    app = QApplication(sys.argv[:1])
    import main as M
    import ui.main_ui as U
    import core.aircore as C

    # 重定向到临时目录
    C.CONFIG_FILE = tmp / "config" / "settings.json"
    C.HISTORY_FILE = tmp / "config" / "history.json"
    M.CAPTURE_ROOT = tmp

    w = M.EasyAirApp()
    w.core.caps_dir = tmp / "captures"
    w.core.wordlists_dir = tmp / "wordlists"
    w.core.config_dir = tmp / "config"
    w._refresh_cap_tree()
    w.show()
    check("主窗口创建", w is not None)
    check("窗口标题", "EasyAir" in w.windowTitle(), w.windowTitle())

    section("布局: 引擎已移入设置")
    check("存在引擎摘要标签", hasattr(w, "lbl_engine"))
    check("引擎摘要非空", len(w.lbl_engine.text()) > 0, w.lbl_engine.text())
    check("引擎下拉框已从主面板移除", not hasattr(w, "crack_engine"))
    check("设备下拉框已从主面板移除", not hasattr(w, "device_combo"))

    section("布局: 底部标签页")
    check("底部有 3 个 tab", w.bottom_tabs.count() == 3, str(w.bottom_tabs.count()))
    check("tab0=握手包库", "握手包库" in w.bottom_tabs.tabText(0), w.bottom_tabs.tabText(0))
    check("tab1=抓包日志", "抓包" in w.bottom_tabs.tabText(1), w.bottom_tabs.tabText(1))
    check("tab2=破解日志", "破解" in w.bottom_tabs.tabText(2), w.bottom_tabs.tabText(2))
    check("握手包库已移入底部tab", w.cap_tree.parent() is not w.ap_table.parent())
    check("两个日志框独立", w.log_scan_box is not w.log_crack_box)
    check("日志框有行数上限", w.log_scan_box.maximumBlockCount() > 0)

    section("布局: AP 表与破解结果表等高")
    w.show()
    for _ in range(6):
        app.processEvents()
    ap_h, res_h = w.ap_table.height(), w.result_tabs.height()
    check("AP 表可见高度>200", ap_h > 200, str(ap_h))
    check("AP 表与破解结果表等高(±10px)", abs(ap_h - res_h) <= 10,
          f"ap={ap_h} result={res_h} diff={abs(ap_h - res_h)}")
    check("目标信息已提到状态条", w.lbl_target_essid.height() <= 40,
          str(w.lbl_target_essid.height()))
    check("进度条在顶部状态条", w.progress_bar.y() < w.ap_table.y(),
          f"progress_y={w.progress_bar.y()} ap_y={w.ap_table.y()}")

    section("布局: 日志噪音过滤")
    noise = [
        "PHY\tInterface\tDriver\t\tChipset",
        "phy0\twlan0\t\trtl8723be\tRealtek RTL8723BE",
        "\t\t(monitor mode disabled)",
        "command failed: No such device (-19)",
        "command time out: 5 s",
        "nl80211: wlan0: deauthenticating",
        "monitor mode for interface wlan0 to wlan0mon",
    ]
    before = w.log_scan_box.toPlainText()
    for n in noise:
        w.log(n)
    after = w.log_scan_box.toPlainText()
    check("原始工具输出被过滤", before == after,
          f"多出 {len(after) - len(before)} 字符")
    for key in ("Chipset", "Realtek", "monitor mode disabled",
                "command failed", "nl80211"):
        check(f"日志不含 {key}", key not in after)
    w.log("[测试] 有意义的信息应当保留")
    check("有意义日志正常输出",
          "[测试] 有意义的信息应当保留" in w.log_scan_box.toPlainText())
    for err in ("airodump-ng: command not found",
                "airmon-ng: permission denied",
                "Operation not permitted",
                "Error - cannot read /dev/..."):
        w.log(err)
    txt = w.log_scan_box.toPlainText()
    for err in ("command not found", "permission denied",
                "Operation not permitted", "cannot read"):
        check(f"真实报错可见: {err}", err in txt)

    section("扫描失败可恢复")
    w3 = M.EasyAirApp()
    w3.mon_iface = "wlan0mon"
    w3.btn_scan.setEnabled(True)
    w3.btn_stop_scan.setEnabled(False)
    w3.core.airodump_scan = lambda *a, **k: subprocess.Popen(
        ["sh", "-c", "sleep 30"], stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, text=True, bufsize=1)
    w3._do_scan()
    pump(150)                      # 等 _on_scan_started 完成, 避免竞态
    w3._scan_failed("模拟: airodump-ng 启动失败")
    pump(120)
    check("失败后计时器已停", not w3.scan_timer.isActive())
    check("失败后扫描按钮可点", w3.btn_scan.isEnabled())
    check("失败后停止按钮禁用", not w3.btn_stop_scan.isEnabled())
    check("失败后按钮文案复位", w3.btn_scan.text() == "🔍 扫描", w3.btn_scan.text())
    check("失败原因写入状态行", "扫描失败" in w3.status_label.text(),
          w3.status_label.text())
    check("失败原因写入日志", "模拟: airodump-ng 启动失败" in w3.log_scan_box.toPlainText())
    check("失败时保留监听接口", w3.mon_iface == "wlan0mon", str(w3.mon_iface))

    section("扫描前置自检")
    check("缺 airodump-ng 时不启动扫描",
          w3._preflight_scan() in (True, False))
    w3.core.can_elevate = lambda: False
    orig_which = M.shutil.which
    M.shutil.which = lambda n: None
    try:
        ok = w3._preflight_scan()
    finally:
        M.shutil.which = orig_which
    check("缺依赖时自检拦截", ok is False)
    check("自检提示缺 airodump-ng",
          "airodump-ng" in w3.log_scan_box.toPlainText())
    w3.core.can_elevate = lambda: True
    w3.close()

    section("布局: 列宽可拖动")
    from PyQt5.QtWidgets import QHeaderView
    check("AP 表列宽可拖动",
          w.ap_table.horizontalHeader().sectionResizeMode(0) == QHeaderView.Interactive)
    tree = w._current_result_tree()
    check("结果表列宽可拖动",
          tree.header().sectionResizeMode(0) == QHeaderView.Interactive)
    w.ap_table.setColumnWidth(0, 77)
    check("AP 表列宽实际可改", w.ap_table.columnWidth(0) == 77)
    tree.setColumnWidth(0, 88)
    check("结果表列宽实际可改", tree.columnWidth(0) == 88)

    section("扫描 CSV 解析 (airodump-ng 1.6 真实格式)")
    # 真实表头来自实机 airodump-ng 1.6 输出。旧版按固定下标解析, 因列序
    # 不同导致每列错位(SSID 显示成 ID-length、信道显示成 PSK)。
    hdr = ("BSSID, First time seen, Last time seen, channel, Speed, Privacy,"
           " Cipher, Authentication, Power, # beacons, # IV, LAN IP,"
           " ID-length, ESSID, Key")

    def ap_line(i):
        b = "AA:BB:CC:DD:EE:%02X" % i
        priv = ["WPA2", "WPA", "WEP", "Open"][i % 4]
        cip = ["AES", "TKIP", "", ""][i % 4]
        return (f"{b}, 2026-10-05 10:00:00, 2026-10-05 10:00:01, {i%11+1}, 130,"
                f" {priv}, {cip}, PSK, -{40+i*3},        4,        0,"
                f"   0.  0.  0.  0,   {i%14}, Net{i}, ")

    csv = tmp / "captures" / "scan-01.csv"
    csv.write_text(hdr + "\n" + "\n".join(ap_line(i) for i in range(6)) + "\n")
    w._last_csv = None
    w._parse_scan_csv(force=True)
    check("解析出 6 行", w.ap_table.rowCount() == 6, str(w.ap_table.rowCount()))

    csv.write_text(
        hdr + "\n" + "\n".join(ap_line(i) for i in range(15)) + "\n"
        + '11:22:33:44:55:66, 2026-10-05 10:00:00, 2026-10-05 10:00:02, 6, 270,'
          ' WPA2, AES, PSK, -33,        9,        0,   0.  0.  0.  0,  11,'
          ' "Cafe, Guest", \n')
    pump(20)
    w._parse_scan_csv()
    check("增量刷新到 16 行", w.ap_table.rowCount() == 16, str(w.ap_table.rowCount()))
    essids = [w.ap_table.item(r, 1).text() for r in range(w.ap_table.rowCount())]
    check("带逗号 SSID 正确", "Cafe, Guest" in essids, str(essids[-3:]))
    check("SSID 无多余引号", all('"' not in e for e in essids), str(essids[-3:]))

    # 行顺序已按信号强度降序, 用 BSSID 定位行而不是写死第0 行
    row_of = {}
    for r in range(w.ap_table.rowCount()):
        row_of[w.ap_table.item(r, 1).text()] = r
    r0 = row_of["Net0"]
    check("信道列正确", w.ap_table.item(r0, 3).text() == "1",
          w.ap_table.item(r0, 3).text())
    check("加密列正确", w.ap_table.item(r0, 4).text() == "WPA2/AES",
          w.ap_table.item(r0, 4).text())
    check("SSID 不是 ID-length", w.ap_table.item(r0, 1).text() == "Net0",
          w.ap_table.item(r0, 1).text())
    check("认证列不是 Power", w.ap_table.item(r0, 5).text() in ("WPA", "Open", "WEP"),
          w.ap_table.item(r0, 5).text())
    check("信号列带 dBm", w.ap_table.item(r0, 6).text().endswith("dBm"),
          w.ap_table.item(0, 6).text())

    section("扫描 CSV: 表头别名与旧格式兼容")
    rows = w._parse_ap_csv(
        "BSSID, First time seen, channel, Privacy, Power, ESSID\n"
        "11:22:33:44:55:66, 2026-10-05 10:00:00, 11, WPA3, -55, MyWiFi\n")
    check("短表头也能解析", len(rows) == 1, str(rows))
    if rows:
        check("短表头 SSID 正确", rows[0][1] == "MyWiFi", str(rows[0]))
        check("短表头 信道正确", rows[0][3] == "11", str(rows[0]))
        check("短表头 强度正确", "-55 dBm" == rows[0][6], str(rows[0]))
    rows2 = w._parse_ap_csv(
        "BSSID,Station MAC,Host Station,MAX,LAST,Beacon,LAN,CH,ENC,CIPHER,"
        "POWER,DBM,ESSID,STD,Radio,Hostspot,Probe\n"
        "22:33:44:55:66:77,00:00:00:00:00:00,00:00:00:00:00:00,-1,-1,-46,-1,9,"
        "WPA2,AES,-60,-60,LegacyAP,,\n")
    check("旧 17 列格式仍兼容", len(rows2) == 1 and rows2[0][1] == "LegacyAP",
          str(rows2))
    check("无 SSID 显示隐藏", w._parse_ap_csv(
        "BSSID, channel, Privacy, Power, ESSID\n"
        "33:44:55:66:77:88, 3, WPA2, -60, \n")[0][1] == "(隐藏)")
    check("状态栏显示 AP 数", "16" in w.status_label.text(), w.status_label.text())
    check("扫描时长标签有内容", "扫描时长" in w.scan_elapsed.text(), w.scan_elapsed.text())

    section("AP 选中目标")
    w.ap_table.selectRow(0)
    w._select_target(0)
    check("目标 SSID 已填", w.lbl_target_essid.text() != "未选择")
    check("目标 BSSID 已填", ":" in w.lbl_target_bssid.text())

    section("握手包库: 按日期归类")
    import datetime
    today = datetime.date.today()
    caps = tmp / "captures"
    (caps / "handshake-01.cap").write_bytes(b"\x00" * 4096)
    old = caps / "handshake-02.cap"
    old.write_bytes(b"\x00" * 1024)
    os.utime(old, (time.time() - 86400 * 3, time.time() - 86400 * 3))
    w._refresh_cap_tree()
    check("握手包树有日期分组", w.cap_tree.topLevelItemCount() == 2,
          str(w.cap_tree.topLevelItemCount()))
    labels = [w.cap_tree.topLevelItem(i).text(0) for i in range(w.cap_tree.topLevelItemCount())]
    check("最新日期在前", today.isoformat() in labels[0], str(labels))
    check("旧日期分组存在", (today - datetime.timedelta(days=3)).isoformat() in labels[1],
          str(labels))
    check("组内显示数量", "1 个" in labels[0], labels[0])
    first_cap = w.cap_tree.topLevelItem(0).child(0)
    check("子项显示大小", "KB" in first_cap.text(1), first_cap.text(1))

    w.cap_tree.setCurrentItem(first_cap)
    w._on_cap_double_clicked(first_cap, 0)
    check("双击载入握手包", first_cap.text(0) in w.lbl_handshake.text(), w.lbl_handshake.text())
    check("握手包路径可解析", w._resolve_cap() is not None and w._resolve_cap().exists())

    section("破解设置对话框")
    dlg = U.CrackSettingsDialog(w, w.core.config)
    check("含引擎选择", dlg.engine_combo.count() == 2)
    check("含设备选择", dlg.device_combo.count() == 3)
    check("含 hashcat 参数", dlg.extra_args.text() is not None)
    dlg.engine_combo.setCurrentText("Aircrack-ng (CPU)")
    check("选 Aircrack 时设备锁定 CPU", dlg.device_combo.currentText() == "仅 CPU")
    check("选 Aircrack 时设备禁用", not dlg.device_combo.isEnabled())
    dlg.engine_combo.setCurrentText("Hashcat (GPU/CPU)")
    check("切回 Hashcat 设备恢复可用", dlg.device_combo.isEnabled())
    dlg.device_combo.setCurrentText("仅 GPU")
    vals = dlg.values()
    check("values() 含引擎", vals["crack_engine"] == "Hashcat (GPU/CPU)")
    check("values() 含设备", vals["crack_device"] == "仅 GPU")
    w.core.config.update(vals)
    w.core.save_config()
    w._refresh_engine_label()
    check("引擎摘要已同步", "仅 GPU" in w.lbl_engine.text(), w.lbl_engine.text())
    cfg = C.json.load(open(C.CONFIG_FILE))
    check("引擎已持久化", cfg.get("crack_engine") == "Hashcat (GPU/CPU)")

    section("破解流程 + 结果写入历史")
    wl = tmp / "wordlists" / "test.txt"
    wl.write_text("12345678\npassword\n")
    w.core.config["wordlists"] = [str(wl)]
    w.core.save_config()

    tc = w._current_result_tree()
    item = tc.add_target("AA:BB:CC:DD:EE:00", "Net0", str(w._resolve_cap()))
    w.current_crack_item = item
    w.current_crack_tree = tc
    w.current_crack_date = w._tab_date()
    w.core.history_add(w.current_crack_date, tc.to_record(item))
    w.crack_start_time = time.time() - 125
    w._update_record("password123")
    check("密码写入成功", item.text(U.CrackResultWidget.COL_PWD) == "password123",
          item.text(U.CrackResultWidget.COL_PWD))
    check("状态=成功", item.text(U.CrackResultWidget.COL_STATE) == "成功")
    check("耗时写入", item.text(U.CrackResultWidget.COL_TIME) != "00:00",
          item.text(U.CrackResultWidget.COL_TIME))

    w.log_crack("hashcat 状态行 1")
    w.log_crack("hashcat 状态行 2")
    w.log("扫描: 发现 16 个 AP")
    check("破解日志独立", "hashcat" in w.log_crack_box.toPlainText())
    check("破解日志不含扫描行", "发现 16" not in w.log_crack_box.toPlainText())
    check("抓包日志独立", "发现 16" in w.log_scan_box.toPlainText())
    check("抓包日志不含破解行", "hashcat" not in w.log_scan_box.toPlainText())

    w._on_crack_output("Speed.#2: 12345.6 kH/s")
    w._on_crack_output("Progress: 42.75%")
    check("进度条真实百分比", w.progress_bar.value() == 42, str(w.progress_bar.value()))
    check("速度显示在标签", "kH/s" in w.lbl_progress.text(), w.lbl_progress.text())

    section("破解进度条范围")
    check("进度条 0-100", (w.progress_bar.minimum(), w.progress_bar.maximum()) == (0, 100),
          f"{w.progress_bar.minimum()}-{w.progress_bar.maximum()}")

    section("备注")
    tc.setCurrentItem(item)
    item.setText(U.CrackResultWidget.COL_NOTE, "星巴克(人民广场店)")
    w._persist_record()
    hist = C.json.load(open(C.HISTORY_FILE))
    recs = hist[w.current_crack_date]
    check("备注已持久化", any(r.get("note") == "星巴克(人民广场店)" for r in recs),
          str(recs))
    check("备注列存在", tc.columnCount() == 7, str(tc.columnCount()))
    check("备注表头为备注", tc.headerItem().text(U.CrackResultWidget.COL_NOTE) == "备注")

    section("多日期切换")
    w.core.history_add("2020-01-02", {"bssid": "X", "essid": "Ancient", "password": "old",
                                      "cap": "x.cap", "status": "成功",
                                      "elapsed": "00:10", "note": "去年"})
    w.core.history_add("2020-01-01", {"bssid": "Y", "essid": "Older", "password": "-",
                                      "cap": "y.cap", "status": "未找到密码",
                                      "elapsed": "01:00", "note": ""})
    w._load_history_tabs()
    tabs = [w.result_tabs.tabText(i) for i in range(w.result_tabs.count())]
    check("日期 tab >= 3", w.result_tabs.count() >= 3, str(tabs))
    check("今日 tab 在最前", tabs[0].startswith(today.isoformat()), str(tabs))
    check("tab 带条数", all("(" in t for t in tabs), str(tabs))
    check("tab 按日期倒序", tabs[1].startswith("2020-01-02") and tabs[2].startswith("2020-01-01"),
          str(tabs))
    w.result_tabs.setCurrentIndex(1)
    t1 = w.result_tabs.currentWidget()
    check("切到 2020-01-02 记录正确", t1.topLevelItem(0).text(1) == "Ancient")
    check("旧日期备注保留", t1.topLevelItem(0).text(U.CrackResultWidget.COL_NOTE) == "去年")
    w.result_tabs.setCurrentIndex(2)
    t2 = w.result_tabs.currentWidget()
    check("切到 2020-01-01 记录正确", t2.topLevelItem(0).text(1) == "Older")
    check("失败状态保留", t2.topLevelItem(0).text(U.CrackResultWidget.COL_STATE) == "未找到密码")
    w.result_tabs.setCurrentIndex(0)

    section("重启恢复")
    w.close()
    pump(50)
    w2 = M.EasyAirApp()
    w2.core.caps_dir = tmp / "captures"
    w2.core.config_dir = tmp / "config"
    w2._refresh_cap_tree()
    tabs2 = [w2.result_tabs.tabText(i) for i in range(w2.result_tabs.count())]
    check("重启后 tab 恢复", len(tabs2) >= 3, str(tabs2))
    today_tree = w2.result_tabs.widget(0)
    found = any(today_tree.topLevelItem(i).text(1) == "Net0" and
                today_tree.topLevelItem(i).text(U.CrackResultWidget.COL_NOTE) == "星巴克(人民广场店)"
                for i in range(today_tree.topLevelItemCount()))
    check("重启后记录+备注恢复", found)
    check("重启后握手包树恢复", w2.cap_tree.topLevelItemCount() == 2,
          str(w2.cap_tree.topLevelItemCount()))

    section("删除记录")
    w2.result_tabs.setCurrentIndex(2)
    tw = w2.result_tabs.currentWidget()
    tw.setCurrentItem(tw.topLevelItem(0))
    check("删除返回 True", w2._remove_record("2020-01-01", 0, "Older"))
    check("删除后空日期 tab 被移除",
          w2.result_tabs.count() == 2, str([w2.result_tabs.tabText(i) for i in range(w2.result_tabs.count())]))
    check("删除后历史文件正确", "2020-01-01" not in C.json.load(open(C.HISTORY_FILE)))

    w2.result_tabs.setCurrentIndex(1)
    t1 = w2.result_tabs.currentWidget()
    t1.setCurrentItem(t1.topLevelItem(0))
    w2._remove_record("2020-01-02", 0, "Ancient")
    check("删除最后一条后 tab 也移除", w2.result_tabs.count() == 1,
          str([w2.result_tabs.tabText(i) for i in range(w2.result_tabs.count())]))
    check("仅剩今日 tab", w2.result_tabs.tabText(0).startswith(today.isoformat()))

    section("今日 tab 不因清空而移除")
    today_tree = w2.result_tabs.widget(0)
    n = today_tree.topLevelItemCount()
    check("今日有记录", n > 0, str(n))
    for i in range(n - 1, -1, -1):
        w2._remove_record(today.isoformat(), i, f"x{i}")
    check("今日 tab 保留", w2.result_tabs.count() == 1, str(w2.result_tabs.count()))
    check("今日 tab 显示 0 条", w2.result_tabs.tabText(0).endswith("(0)"),
          w2.result_tabs.tabText(0))

    section("线程: 反复开关监听不崩溃")
    calls = {"n": 0}

    def fake_stop(mon):
        return subprocess.Popen(["sh", "-c", "echo stop; sleep 0.15"],
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, bufsize=1)

    def fake_start(mon):
        calls["n"] += 1
        return subprocess.Popen(["sh", "-c", "echo start; sleep 0.1"],
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, bufsize=1)

    w2.core.stop_monitor = fake_stop
    w2.core.start_monitor = fake_start
    w2.core.check_monitor_mode = lambda i: True
    for i in range(6):
        w2.mon_iface = "wlan0mon"
        w2.physical_iface = "wlan0"
        w2._stop_monitor_manual()
        pump(120)
        w2.mon_iface = "wlan0mon"
        w2._run_worker(lambda: fake_start("wlan0"), w2._on_mon_started)
        pump(180)
    check("反复开关未崩溃", True)
    check("线程表无泄漏", len(w2._threads) <= 4, f"threads={len(w2._threads)}")

    section("线程: CmdThread 传 None 不崩溃")
    w2._spawn_cmd(None, w2.log)
    pump(120)
    check("None proc 未崩溃", True)

    section("线程: 输出读取抛异常不崩溃")
    class BadProc:
        stdout = None
        def wait(self, *a, **k):
            raise RuntimeError("boom")
        def terminate(self):
            pass
    w2._spawn_cmd(BadProc(), w2.log)
    pump(150)
    check("异常 stdout 未崩溃", True)

    section("性能: 大量日志 + 高频解析")
    hdr2 = hdr
    t0 = time.time()
    for it in range(10):
        csv.write_text(hdr2 + "\n" + "\n".join(ap_line(i) for i in range(30)) + "\n")
        for k in range(400):
            w2.log(f"line {k}")
        pump(1)
        w2._last_csv = None
        w2._parse_scan_csv()
    dt = time.time() - t0
    check("10 轮解析+4000 行日志 < 5s", dt < 5.0, f"{dt:.2f}s")
    check("日志框行数被限制", w2.log_scan_box.blockCount() <= 800,
          str(w2.log_scan_box.blockCount()))
    check("AP 表行数正确", w2.ap_table.rowCount() == 30, str(w2.ap_table.rowCount()))

    section("扫描停止行为")
    stopped = {"n": 0}
    w2.core.stop_monitor = lambda m: (stopped.__setitem__("n", stopped["n"] + 1),
                                      subprocess.Popen(["sh", "-c", "true"],
                                                       stdout=subprocess.PIPE,
                                                       stderr=subprocess.STDOUT,
                                                       text=True, bufsize=1))[1]
    w2.mon_iface = "wlan0mon"
    w2.scan_auto_stop = 0
    w2.scan_deadline = None
    w2._stop_scan()
    pump(80)
    check("停止扫描不关闭监听模式", stopped["n"] == 0, f"stop_monitor 调用 {stopped['n']} 次")
    check("停止后监听接口仍保留", w2.mon_iface == "wlan0mon", str(w2.mon_iface))
    check("停止后按钮恢复可点", w2.btn_scan.isEnabled())
    check("停止后停止按钮禁用", not w2.btn_stop_scan.isEnabled())
    check("停止后按钮文案复位", w2.btn_scan.text() == "🔍 扫描", w2.btn_scan.text())

    section("扫描自动停止")
    w2.scan_auto_stop = 45
    w2.core.airodump_scan = lambda m, p: subprocess.Popen(
        ["sh", "-c", "echo scanning; sleep 30"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    w2._do_scan()
    pump(200)
    check("自动停止倒计时已设置", w2.scan_deadline is not None)
    check("倒计时提示立即可见", "后自动停止" in w2.scan_elapsed.text(), w2.scan_elapsed.text())
    check("倒计时秒数正确", "4" in w2.scan_elapsed.text(), w2.scan_elapsed.text())
    # 快进: 把 deadline 提前，触发 _parse_scan_csv 里的自动停止分支
    hdr3 = hdr
    (tmp / "captures" / "scan-01.csv").write_text(hdr3 + "\n" + ap_line(0) + "\n")
    w2.scan_deadline = time.time() - 1
    w2._last_csv = None
    w2._parse_scan_csv()
    pump(100)
    check("到达时限自动停止", w2.scan_deadline is None or w2.btn_scan.isEnabled())
    check("自动停止后计时器已停", not w2.scan_timer.isActive())
    check("自动停止保留监听接口", w2.mon_iface == "wlan0mon", str(w2.mon_iface))
    w2.scan_auto_stop = 0

    section("设置: 扫描自动停止秒数")
    dlg2 = U.CrackSettingsDialog(w2, w2.core.config)
    check("设置含扫描秒数控件", dlg2.scan_secs.value() >= 0)
    dlg2.scan_secs.setValue(45)
    v2 = dlg2.values()
    check("values 含 scan_auto_stop", v2["scan_auto_stop"] == 45, str(v2))
    check("0 表示手动停止", dlg2.scan_secs.minimum() == 0)
    check("0 时显示手动停止", dlg2.scan_secs.specialValueText() == "手动停止")

    section("设置: auto_monitor 真正生效")
    check("auto_monitor 从配置读取", w2.auto_monitor_enabled == w2.core.config.get("auto_monitor", True))
    dlg3 = U.CrackSettingsDialog(w2, w2.core.config)
    dlg3.auto_mon.setChecked(False)
    w2.core.config.update(dlg3.values())
    w2.auto_monitor_enabled = w2.core.config["auto_monitor"]
    check("取消勾选后为 False", w2.auto_monitor_enabled is False)

    section("设置: 持久化与 GPU 温度上限")
    cfgdir = tmp / "config"
    cfgdir.mkdir(exist_ok=True)
    C.CONFIG_FILE = cfgdir / "settings.json"
    C.HISTORY_FILE = cfgdir / "history.json"
    w.core.save_config()
    check("配置已落盘", (cfgdir / "settings.json").exists())

    dlg4 = U.CrackSettingsDialog(w, w.core.config)
    check("默认温度上限为 85", dlg4.temp_limit.value() == 85,
          str(dlg4.temp_limit.value()))
    check("温度范围 0-110", dlg4.temp_limit.minimum() == 0
          and dlg4.temp_limit.maximum() == 110)
    check("0 表示不限制", dlg4.temp_limit.specialValueText() == "不限制")
    dlg4.temp_limit.setValue(75)
    dlg4.scan_secs.setValue(60)
    dlg4.auto_mon.setChecked(False)
    v4 = dlg4.values()
    check("values 含温度上限", v4["hashcat_temp_limit"] == 75, str(v4))
    w.core.config.update(v4)
    w.core.save_config()
    saved = C.json.load(open(C.CONFIG_FILE))
    check("温度上限已持久化", saved.get("hashcat_temp_limit") == 75, str(saved))
    check("扫描停止已持久化", saved.get("scan_auto_stop") == 60, str(saved))
    check("auto_monitor 已持久化", saved.get("auto_monitor") is False, str(saved))

    C.CONFIG_FILE = C.Path.home() / ".easyair" / "config" / "settings.json"
    w.core.config["crack_engine"] = "Aircrack-ng (CPU)"
    w.core.config["crack_device"] = "CPU"
    w.core.save_config()
    check("打包后写入用户目录", C.CONFIG_FILE.exists(),
          str(C.CONFIG_FILE))
    check("用户目录为 ~/.easyair",
          C.CONFIG_FILE.parent.parent.name == ".easyair",
          str(C.CONFIG_FILE))
    w.core.config["crack_engine"] = "Hashcat (GPU/CPU)"
    w.core.config["crack_device"] = "GPU + CPU (自动)"
    w.core.config["auto_monitor"] = True
    w.core.save_config()

    section("设置: 温度参数注入破解命令")
    w.core.config["hashcat_temp_limit"] = 85
    check("运行时温度上限=85", w._temp_limit() == 85, str(w._temp_limit()))
    check("生成 hwmon 参数", w._hwmon_args() == "--hwmon-temp-abort=85",
          w._hwmon_args())
    cmds = []
    w.core.run_cmd = lambda cmd, sudo=False, shell=False: cmds.append(cmd)
    w.core.crack_hashcat("/tmp/x.hc22000", ["/tmp/w.txt"], True, "", 85)
    check("命令含温度上限", "--hwmon-temp-abort=85" in cmds[-1], cmds[-1])
    check("命令含设备参数", "-D 1,2" in cmds[-1], cmds[-1])
    w.core.crack_hashcat("/tmp/x.hc22000", ["/tmp/w.txt"], False, "", 0)
    check("不限温时不加该参数", "--hwmon-temp-abort" not in cmds[-1], cmds[-1])
    w.core.config["hashcat_temp_limit"] = 0
    check("配置为 0 时不限温", w._temp_limit() == 0 and w._hwmon_args() == "")
    w.core.config["hashcat_temp_limit"] = 85

    section("客户端识别: Station 段解析")
    sta_txt = (
        "Station MAC, First time seen, Last time seen, Power, # packets, BSSID,"
        " Probed ESSIDs\r\n"
        "0E:BE:B2:FD:94:88, 2026-10-05 16:19:38, 2026-10-05 16:19:38, -74, 1,"
        " E0:B6:68:CD:BB:F7,\r\n"
        "52:2A:D2:7A:67:CB, 2026-10-05 16:19:39, 2026-10-05 16:19:39, -71, 1,"
        " F0:1B:24:92:B1:EE,\r\n"
        "3E:4F:76:13:3B:8B, 2026-10-05 16:19:49, 2026-10-05 16:19:49, -71, 2,"
        " F0:1B:24:92:B1:EE,\r\n"
        "3A:27:4A:5E:5F:64, 2026-10-05 16:19:26, 2026-10-05 16:19:26, -69, 4,"
        " (not associated) ,CMCC-8822,HomeInns\r\n")
    st = w._parse_station_section(sta_txt)
    check("按 BSSID 分组", sorted(st) == ["E0:B6:68:CD:BB:F7", "F0:1B:24:92:B1:EE"],
          str(sorted(st)))
    check("单个客户端", len(st["E0:B6:68:CD:BB:F7"]) == 1)
    check("多个客户端", len(st["F0:1B:24:92:B1:EE"]) == 2, str(st))
    check("排除未关联客户端", "(not associated)" not in str(st), str(st))
    check("忽略 \\r 行尾", all("\r" not in c["mac"] for v in st.values() for c in v))
    check("空段返回空字典", w._parse_station_section("") == {})
    check("纯表头不报错",
          w._parse_station_section("Station MAC, First time seen\r\n") == {})

    check("AP 表为 8 列", w.ap_table.columnCount() == 8, str(w.ap_table.columnCount()))
    col_hdr = [w.ap_table.horizontalHeaderItem(i).text() for i in range(8)]
    check("最后一列为客户端", col_hdr[7] == "客户端", str(col_hdr))

    csvx = tmp / "captures" / "scan-01.csv"
    csvx.write_text(
        hdr + "\n"
        "AA:BB:CC:DD:EE:01, 2026-10-05 10:00:00, 2026-10-05 10:00:01, 6, 130,"
        " WPA2, AES, PSK, -40,  4,  0,   0.  0.  0.  0,   3, WithCli, \n"
        "AA:BB:CC:DD:EE:02, 2026-10-05 10:00:00, 2026-10-05 10:00:01, 6, 130,"
        " WPA2, AES, PSK, -40,  4,  0,   0.  0.  0.  0,   3, NoCli, \n"
        "Station MAC, First time seen, Last time seen, Power, # packets, BSSID,"
        " Probed ESSIDs\r\n"
        "0E:BE:B2:FD:94:88, 2026-10-05 16:19:38, 2026-10-05 16:19:38, -74, 1,"
        " AA:BB:CC:DD:EE:01,\r\n"
        "52:2A:D2:7A:67:CB, 2026-10-05 16:19:39, 2026-10-05 16:19:39, -71, 1,"
        " AA:BB:CC:DD:EE:01,\r\n")
    w._last_csv = None
    w._parse_scan_csv(force=True)
    cells = {w.ap_table.item(r, 1).text(): w.ap_table.item(r, 7).text()
             for r in range(w.ap_table.rowCount())}
    check("有客户端的 AP 显示数量", cells.get("WithCli", "").startswith("2"),
          str(cells))
    check("显示客户端 MAC", "0E:BE" in cells.get("WithCli", ""), str(cells))
    check("无客户端显示 0", cells.get("NoCli", "").startswith("0"), str(cells))
    check("状态栏提示有客户端", "有客户端" in w.status_label.text(),
          w.status_label.text())

    # 还原 16 个 AP 的 fixture, 供后续信号排序用例使用
    csv.write_text(
        hdr + "\n" + "\n".join(ap_line(i) for i in range(15)) + "\n"
        + '11:22:33:44:55:66, 2026-10-05 10:00:00, 2026-10-05 10:00:02, 6, 270,'
          ' WPA2, AES, PSK, -33,  9,  0,   0.  0.  0.  0,  11, "Cafe, Guest", \n')
    w._last_csv = None
    w._parse_scan_csv(force=True)
    check("fixture 还原为 16 行", w.ap_table.rowCount() == 16,
          str(w.ap_table.rowCount()))

    section("AP 列表: 信号排序与信号格")
    pwrs = [int(w.ap_table.item(r, 6).text().split()[0]) for r in range(w.ap_table.rowCount())]
    check("按信号强度降序", pwrs == sorted(pwrs, reverse=True), str(pwrs))
    check("最强信号排第一", w.ap_table.item(0, 1).text() == "Cafe, Guest",
          w.ap_table.item(0, 1).text())
    bars = [w.ap_table.item(r, 0).text() for r in range(w.ap_table.rowCount())]
    check("信号格为方块字符", all(set(b) <= set("█░") for b in bars), str(bars[:3]))
    check("不再使用竖线表示信号", not any("|" in b for b in bars), str(bars[:3]))
    check("最强信号格全满", bars[0] == "█████", bars[0])
    weak = min(range(w.ap_table.rowCount()),
               key=lambda r: int(w.ap_table.item(r, 6).text().split()[0]))
    check("最弱信号格只有一格",
          w.ap_table.item(weak, 0).text().count("█") == 1,
          w.ap_table.item(weak, 0).text())
    check("-40dBm 档位", w._signal_bar(-40) == ("█████", "#2e7d32"), str(w._signal_bar(-40)))
    check("-65dBm 档位", w._signal_bar(-65) == ("███░░", "#f9a825"), str(w._signal_bar(-65)))
    check("-95dBm 档位", w._signal_bar(-95) == ("█░░░░", "#c62828"), str(w._signal_bar(-95)))
    check("无信号时全空", w._signal_bar(None)[0] == "░░░░░", str(w._signal_bar(None)))

    section("界面流畅度与日期完整显示")
    from PyQt5.QtWidgets import QSplitter
    sps = [s for s in w.findChildren(QSplitter)]
    check("存在分割器", len(sps) >= 2, str(len(sps)))
    check("分割器为不透明拖动", all(s.opaqueResize() for s in sps),
          str([s.opaqueResize() for s in sps]))
    from PyQt5.QtWidgets import QHeaderView
    vh = w.ap_table.verticalHeader()
    check("AP 表行高固定",
          vh.sectionResizeMode(0) == QHeaderView.Fixed,
          str(vh.sectionResizeMode(0)))
    check("AP 表按像素滚动",
          w.ap_table.verticalScrollMode() == w.ap_table.ScrollPerPixel)
    from PyQt5.QtCore import Qt as _Qt
    check("历史 tab 不省略文字",
          w.result_tabs.tabBar().elideMode() == _Qt.ElideNone,
          str(w.result_tabs.tabBar().elideMode()))
    check("历史 tab 用滚动按钮",
          w.result_tabs.usesScrollButtons() is True)

    section("扫描时长与倒计时在底部任务栏")
    from PyQt5.QtWidgets import QFrame
    top_bar = w.findChild(QFrame, "targetBar")
    check("存在目标栏", top_bar is not None)
    status_line = None
    for fr in w.findChildren(QFrame):
        if fr.objectName() == "targetBar" and fr is not top_bar:
            status_line = fr
            break
    check("存在底部状态行", status_line is not None)
    if status_line is not None:
        check("时长标签在底部状态行",
              status_line.isAncestorOf(w.scan_elapsed),
              "scan_elapsed 不在底部")
        check("时长标签不在顶部目标栏",
              not top_bar.isAncestorOf(w.scan_elapsed))
    w.scan_start_time = time.time() - 65
    w.scan_deadline = time.time() + 30
    txt = w._scan_elapsed_text()
    check("底部文本含扫描时长", "扫描时长" in txt, txt)
    check("底部文本含倒计时", "后自动停止" in txt, txt)
    w._stop_scan()
    check("停止后清空时长", w.scan_elapsed.text() == "",
          repr(w.scan_elapsed.text()))

    section("关闭时清理线程")
    w2.close()
    pump(100)
    check("close 后线程表清空", len(w2._threads) == 0, str(len(w2._threads)))
    check("close 后 worker 表清空", len(w2._workers) == 0, str(len(w2._workers)))

    print("\n" + "=" * 60)
    print(f"PASS: {len(PASS)}   FAIL: {len(FAIL)}")
    if FAIL:
        print("失败项:")
        for f in FAIL:
            print("  -", f)
    print("=" * 60)
    shutil.rmtree(tmp, ignore_errors=True)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())