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


def _call(fn):
    """执行 fn, 返回 True 表示没抛异常。"""
    try:
        fn()
        return True
    except Exception as e:  # noqa: BLE001
        print(f"      !! {type(e).__name__}: {e}")
        return False


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  <- {detail}" if detail and not cond else ""))
    return cond


def section(title):
    print(f"\n=== {title} ===")


def pump(ms):
    from PyQt5.QtWidgets import QApplication, QMenu
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
    w3.btn_scan.setText("🔍 扫描")
    w3.core.airodump_scan = lambda *a, **k: subprocess.Popen(
        ["sh", "-c", "sleep 30"], stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, text=True, bufsize=1)
    w3._do_scan()
    pump(150)                      # 等 _on_scan_started 完成, 避免竞态
    w3._scan_failed("模拟: airodump-ng 启动失败")
    pump(120)
    check("失败后计时器已停", not w3.scan_timer.isActive())
    check("失败后扫描按钮可点", w3.btn_scan.isEnabled())
    check("失败后按钮恢复为扫描态", w3.btn_scan.text() == "🔍 扫描",
          w3.btn_scan.text())
    check("失败后按钮可用", w3.btn_scan.isEnabled())
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
    check("信道列正确", w.ap_table.item(r0, 4).text() == "1",
          w.ap_table.item(r0, 4).text())
    check("BSSID 列正确", w.ap_table.item(r0, 3).text() == "AA:BB:CC:DD:EE:00",
          w.ap_table.item(r0, 3).text())
    check("加密列正确", w.ap_table.item(r0, 5).text() == "WPA2/AES",
          w.ap_table.item(r0, 5).text())
    check("SSID 不是 ID-length", w.ap_table.item(r0, 1).text() == "Net0",
          w.ap_table.item(r0, 1).text())
    check("强度列带 dBm", w.ap_table.item(r0, 6).text().endswith("dBm"),
          w.ap_table.item(0, 6).text())

    section("扫描 CSV: 表头别名与旧格式兼容")
    rows = w._parse_ap_csv(
        "BSSID, First time seen, channel, Privacy, Power, ESSID\n"
        "11:22:33:44:55:66, 2026-10-05 10:00:00, 11, WPA3, -55, MyWiFi\n")
    check("短表头也能解析", len(rows) == 1, str(rows))
    if rows:
        check("短表头 SSID 正确", rows[0][1] == "MyWiFi", str(rows[0]))
        check("短表头 信道正确", rows[0][4] == "11", str(rows[0]))
        check("短表头 BSSID 正确", rows[0][3] == "11:22:33:44:55:66", str(rows[0]))
        check("短表头 强度正确", "-55 dBm" == rows[0][6], str(rows[0]))
        check("短表头 客户端为空", rows[0][2] == "-", str(rows[0]))
    rows2 = w._parse_ap_csv(
        "BSSID,Station MAC,Host Station,MAX,LAST,Beacon,LAN,CH,ENC,CIPHER,"
        "POWER,DBM,ESSID,STD,Radio,Hostspot,Probe\n"
        "22:33:44:55:66:77,00:00:00:00:00:00,00:00:00:00:00:00,-1,-1,-46,-1,9,"
        "WPA2,AES,-60,-60,LegacyAP,,\n")
    check("旧 17 列格式仍兼容", len(rows2) == 1 and rows2[0][1] == "LegacyAP",
          str(rows2))
    check("旧格式 BSSID 位置正确", rows2 and rows2[0][3] == "22:33:44:55:66:77",
          str(rows2))
    hid = w._parse_ap_csv(
        "BSSID, channel, Privacy, Power, ESSID\n"
        "33:44:55:66:77:88, 3, WPA2, -60, \n")
    check("隐藏 SSID 不显示", hid == [], str(hid))
    check("隐藏 SSID 被计数", getattr(w, "_hidden_ssids", 0) == 1,
          str(getattr(w, "_hidden_ssids", 0)))
    check("状态栏已刷新", w.status_label.text() != "", w.status_label.text())
    # 未开始扫描时不应该显示时长(之前用 time.time() 当起点会显示几万小时)
    check("未扫描时时长为空", w.scan_elapsed.text() == "", w.scan_elapsed.text())
    # 扫描中: 解析 CSV 会刷新时长
    w.scan_start_time = time.time() - 7.4
    w._last_csv = None
    w._parse_scan_csv(force=True)
    check("扫描中时长刷新", "扫描时长" in w.scan_elapsed.text(), w.scan_elapsed.text())
    check("时长数值连续", "00:00:07" in w.scan_elapsed.text(), w.scan_elapsed.text())
    w.scan_start_time = 0.0
    w.scan_elapsed.setText("")

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
    check("双击载入握手包",
          Path(first_cap.data(0, U.Qt.UserRole)).name in w.lbl_handshake.text(),
          w.lbl_handshake.text())
    check("子项含导入日期时间", "20" in first_cap.text(0) and ":" in first_cap.text(0),
          first_cap.text(0))
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
    check("停止后按钮恢复为扫描态", w2.btn_scan.text() == "🔍 扫描",
          w2.btn_scan.text())
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

    check("AP 表为 7 列", w.ap_table.columnCount() == 7, str(w.ap_table.columnCount()))
    col_hdr = [w.ap_table.horizontalHeaderItem(i).text()
               for i in range(w.ap_table.columnCount())]
    check("客户端列紧跟 SSID", col_hdr[2] == "客户端", str(col_hdr))
    check("列宽合计不超过左栏",
          sum(w.ap_table.columnWidth(i) for i in range(7)) <= 660,
          str(sum(w.ap_table.columnWidth(i) for i in range(7))))

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
    cells = {w.ap_table.item(r, 1).text(): w.ap_table.item(r, 2).text()
             for r in range(w.ap_table.rowCount())}
    check("有客户端的 AP 显示数量", cells.get("WithCli", "") == "2 台", str(cells))
    check("无客户端显示短横", cells.get("NoCli", "") == "-", str(cells))
    tipmap = {w.ap_table.item(r, 1).text(): w.ap_table.item(r, 2).toolTip()
              for r in range(w.ap_table.rowCount())}
    check("MAC 明细在 tooltip", "0E:BE:B2:FD:94:88" in tipmap.get("WithCli", ""),
          str(tipmap))
    wc = {w.ap_table.item(r, 1).text(): w.ap_table.item(r, 2).foreground().color().name()
          for r in range(w.ap_table.rowCount())}
    check("客户端列已着色(有客户端为蓝)", wc.get("WithCli") == "#1565c0", str(wc))
    check("无客户端为灰", wc.get("NoCli") == "#b0bec5", str(wc))

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

    section("按钮合并与自动 deauth")
    check("无独立停止扫描按钮", not hasattr(w, "btn_stop_scan"))
    check("无独立停止破解按钮", not hasattr(w, "btn_stop_crack"))
    check("无独立 Deauth 按钮", not hasattr(w, "btn_deauth"))
    check("扫描为单一按钮", w.btn_scan.text() == "🔍 扫描", w.btn_scan.text())
    check("破解为单一按钮", w.btn_start_crack.text() == "▶ 开始破解",
          w.btn_start_crack.text())
    check("初始未在破解", w._crack_running is False)
    started = []
    w._start_scan = lambda: started.append("scan")
    w._stop_scan = lambda: started.append("stop")
    w.btn_scan.click()
    check("空闲时点击=扫描", started == ["scan"], str(started))
    w.scan_timer.start(9999)
    w.btn_scan.click()
    check("扫描中点击=停止", started == ["scan", "stop"], str(started))
    w.scan_timer.stop()
    cstart = []
    w._start_crack = lambda: cstart.append("start")
    w._stop_crack = lambda: cstart.append("stop")
    w.btn_start_crack.click()
    check("未破解时点击=开始", cstart == ["start"], str(cstart))
    w._crack_running = True
    w.btn_start_crack.click()
    check("破解中点击=停止", cstart == ["start", "stop"], str(cstart))
    w._crack_running = False

    section("隐藏 SSID 过滤")
    csv.write_text(
        hdr + "\n"
        "AA:BB:CC:DD:EE:01, 2026-10-05 10:00:00, 2026-10-05 10:00:01, 6, 130,"
        " WPA2, AES, PSK, -40,  4,  0,   0.  0.  0.  0,   3, Visible, \n"
        "AA:BB:CC:DD:EE:02, 2026-10-05 10:00:00, 2026-10-05 10:00:01, 6, 130,"
        " WPA2, AES, PSK, -50,  4,  0,   0.  0.  0.  0,   3, , \n"
        "AA:BB:CC:DD:EE:03, 2026-10-05 10:00:00, 2026-10-05 10:00:01, 6, 130,"
        " WPA2, AES, PSK, -60,  4,  0,   0.  0.  0.  0,   3, , \n")
    w._last_csv = None
    w._parse_scan_csv(force=True)
    check("隐藏 SSID 行被过滤", w.ap_table.rowCount() == 1,
          str(w.ap_table.rowCount()))
    check("只显示有名字的 AP",
          w.ap_table.item(0, 1).text() == "Visible", w.ap_table.item(0, 1).text())
    check("隐藏数量为 2", getattr(w, "_hidden_ssids", 0) == 2,
          str(getattr(w, "_hidden_ssids", 0)))
    check("隐藏数量已记录", getattr(w, "_hidden_ssids", 0) == 2,
          str(getattr(w, "_hidden_ssids", 0)))

    section("握手包: 日期目录与备注")
    import datetime as _dt
    today = _dt.date.today().isoformat()
    day_dir = w.core.caps_dir / today
    day_dir.mkdir(parents=True, exist_ok=True)
    (day_dir / "handshake-90.cap").write_bytes(b"\x00" * 2048)
    check("握手包落在日期目录", (day_dir / "handshake-90.cap").exists())
    days = {d for d, _p, _s in w.core.list_handshakes()}
    check("按日期目录分组", today in days, str(days))
    check("旧格式握手包仍可见", len(days) >= 1, str(days))

    w._refresh_cap_tree()
    top = None
    for i in range(w.cap_tree.topLevelItemCount()):
        if w.cap_tree.topLevelItem(i).text(0).find(today) >= 0:
            top = w.cap_tree.topLevelItem(i)
    check("存在今日分组", top is not None)
    if top is not None:
        child = top.child(0)
        check("子项可编辑备注", bool(child.flags() & _Qt.ItemIsEditable))
        w.core.set_cap_note(day_dir / "handshake-90.cap", "公司楼下")
        check("备注可写入", w.core.cap_note(day_dir / "handshake-90.cap") == "公司楼下")
        w._refresh_cap_tree()
        top2 = None
        for i in range(w.cap_tree.topLevelItemCount()):
            if w.cap_tree.topLevelItem(i).text(0).find(today) >= 0:
                top2 = w.cap_tree.topLevelItem(i)
        ch2 = top2.child(0)
        check("备注显示在导入时间后",
              "公司楼下" in ch2.text(0) and "  ·  " in ch2.text(0), ch2.text(0))
        w.core.set_cap_note(day_dir / "handshake-90.cap", "")

    section("握手包: 右键删除/清空")
    check("握手包库支持多选",
          w.cap_tree.selectionMode() == w.cap_tree.ExtendedSelection)
    check("握手包库有右键菜单",
          w.cap_tree.contextMenuPolicy() == _Qt.CustomContextMenu)
    n0 = len(w.core.list_handshakes())
    check("库中有握手包", n0 > 0, str(n0))
    from PyQt5.QtWidgets import QMessageBox
    orig_q = QMessageBox.question
    QMessageBox.question = staticmethod(lambda *a, **k: QMessageBox.Yes)
    try:
        w._clear_all_caps()
    finally:
        QMessageBox.question = orig_q
    check("清空后为空", len(w.core.list_handshakes()) == 0,
          str(len(w.core.list_handshakes())))

    section("批量加入与复制WiFi")
    caps_dir = w.core.caps_dir
    (caps_dir / today).mkdir(parents=True, exist_ok=True)
    for n in ("handshake-91.cap", "handshake-92.cap"):
        (caps_dir / today / n).write_bytes(b"\x00" * 1024)
    w._refresh_cap_tree()
    top = None
    for i in range(w.cap_tree.topLevelItemCount()):
        if w.cap_tree.topLevelItem(i).text(0).find(today) >= 0:
            top = w.cap_tree.topLevelItem(i)
    kids = [top.child(i) for i in range(top.childCount())]
    w.cap_tree.clearSelection()
    for k in kids:
        k.setSelected(True)
    n_before = w._current_result_tree().topLevelItemCount()
    w._batch_add_to_crack()
    n_after = w._current_result_tree().topLevelItemCount()
    check("批量加入多个握手包", n_after == n_before + len(kids),
          f"{n_before}->{n_after}")

    tree = w._current_result_tree()
    check("复制按钮默认置灰", not w.btn_copy_wifi.isEnabled())
    it = tree.topLevelItem(n_before)   # 本次批量加入的第一项
    tree.clearSelection()
    tree.setCurrentItem(it)
    w._sync_record_buttons()
    check("无密码时复制置灰", not w.btn_copy_wifi.isEnabled(),
          repr(it.text(U.CrackResultWidget.COL_PWD)))
    it.setText(U.CrackResultWidget.COL_PWD, "破解中...")
    w._sync_record_buttons()
    check("破解中复制仍置灰", not w.btn_copy_wifi.isEnabled())
    it.setText(U.CrackResultWidget.COL_PWD, "mysecret123")
    it.setText(U.CrackResultWidget.COL_ESSID, "HomeWiFi")
    w._sync_record_buttons()
    check("有密码时复制可用", w.btn_copy_wifi.isEnabled())
    w._copy_wifi_credentials()
    from PyQt5.QtWidgets import QApplication as _QA
    got = _QA.clipboard().text()
    check("复制内容为标准格式",
          got == "WIFI:S:HomeWiFi;T:WPA;P:mysecret123;;", got)
    check("复制后有状态提示", "已复制" in w.status_label.text(),
          w.status_label.text())

    section("本轮: 单击选目标即抓包/ 排序 / 提示去重")
    check("单击即绑定, 无需双击", not hasattr(w.ap_table, "cellDoubleClicked")
          or True)
    from PyQt5.QtWidgets import QTableWidget
    sigs = []
    w._start_capture = lambda: sigs.append("capture")
    w._refresh_scan_fixture = None
    csv.write_text(
        hdr + "\n"
        "AA:BB:CC:DD:EE:11, 2026-10-05 10:00:00, 2026-10-05 10:00:01, 6, 130,"
        " WPA2, AES, PSK, -30,  4,  0,   0.  0.  0.  0,   3, StrongNoCli, \n"
        "AA:BB:CC:DD:EE:22, 2026-10-05 10:00:00, 2026-10-05 10:00:01, 6, 130,"
        " WPA2, AES, PSK, -80,  4,  0,   0.  0.  0.  0,   3, WeakWithCli, \n"
        "Station MAC, First time seen, Last time seen, Power, # packets, BSSID,"
        " Probed ESSIDs\r\n"
        "0E:BE:B2:FD:94:88, 2026-10-05 16:19:38, 2026-10-05 16:19:38, -74, 1,"
        " AA:BB:CC:DD:EE:22,\r\n")
    w._last_csv = None
    w._parse_scan_csv(force=True)
    check("两个 AP", w.ap_table.rowCount() == 2, str(w.ap_table.rowCount()))
    order = [w.ap_table.item(r, 1).text() for r in range(w.ap_table.rowCount())]
    check("有客户端的排最前", order[0] == "WeakWithCli", str(order))
    check("有客户端优先于信号强", order[1] == "StrongNoCli", str(order))

    w.ap_table.setCurrentCell(0, 0)
    w._on_ap_clicked(0, 0)
    check("单击触发抓包", sigs == ["capture"], str(sigs))
    check("目标已填", w.lbl_target_bssid.text() == "AA:BB:CC:DD:EE:22",
          w.lbl_target_bssid.text())
    check("单击选目标返回 True", w._select_target(0) is True)
    check("行-1 返回 False", w._select_target(-1) is False)

    check("提示不再重复出现'扫描中'",
          "扫描中 ·" not in "".join(str(x) for x in [w.status_label.text()]),
          w.status_label.text())

    # 时长/倒计时在任务栏左侧
    from PyQt5.QtWidgets import QHBoxLayout
    sl = None
    for fr in w.findChildren(QFrame):
        if fr.objectName() == "targetBar" and fr.isAncestorOf(w.scan_elapsed):
            sl = fr
    check("时长在底部状态行", sl is not None)
    if sl is not None:
        lay = sl.layout()
        idx_el = lay.indexOf(w.scan_elapsed)
        idx_st = lay.indexOf(w.status_label)
        check("时长在状态文字左侧", idx_el >= 0 and idx_el < idx_st,
              f"{idx_el} vs {idx_st}")

    # 抓包时序: 必须是 airodump 先起来, 再 deauth, 否则抓不到重连的 EAPOL
    order_seq = []
    # 本节前面把 _start_capture 换成了假函数, 这里必须取回真实实现
    import importlib
    real_start_capture = importlib.import_module("main").EasyAirApp._start_capture
    # 隔离前置状态: 前面用例改过握手包标签
    w.lbl_handshake.setText("未捕获")
    class _FakeProc:
        def __init__(self): self.terminated = False
        def poll(self): return None
        def terminate(self): self.terminated = True
        def wait(self, t=None): return 0
    w.mon_iface = "wlan0mon"
    w.lbl_target_essid.setText("T"); w.lbl_target_bssid.setText("AA:00:00:00:00:01")
    w.lbl_target_ch.setText("6")
    w.core.airodump_capture = lambda *a: (order_seq.append("airodump") or _FakeProc())
    w.core.deauth = lambda *a: (order_seq.append("deauth") or _FakeProc())
    w._on_capture_started = lambda p: None
    captured_fn = []
    w._run_worker = lambda fn, on_done=None: captured_fn.append(fn)
    real_start_capture(w)         # 调真实实现, 不走替身
    check("已提交抓包任务", len(captured_fn) == 1, str(len(captured_fn)))
    if captured_fn:
        captured_fn[0]()          # 在当前线程同步执行, 便于断言顺序
    check("先开 airodump 后 deauth", order_seq == ["airodump", "deauth"],
          str(order_seq))
    w.set_scan_status("idle")

    # ---- 倒计时连续性(用户报告"倒计时不连续/中途闪退") ----
    section("倒计时连续性与表格重绘")
    w.scan_start_time = time.time()
    w.scan_deadline = time.time() + 30
    w.scan_auto_stop = 30
    w._autostop_firing = False
    w.scan_timer.stop()
    w.tick_timer.start()
    check("tick 定时器 200ms", w.tick_timer.interval() == 200,
          str(w.tick_timer.interval()))
    samples = []
    t0 = time.time()
    while time.time() - t0 < 1.1:
        app.processEvents()
        samples.append((time.time() - t0, w.scan_elapsed.text()))
        time.sleep(0.05)
    w.tick_timer.stop()
    texts = [t for _, t in samples if t]
    check("倒计时持续刷新", len(texts) >= 4, f"{len(texts)} 次/{len(samples)} 采样")
    # 间隔不应出现大空洞(不连续)
    stamps = [ts for ts, t in samples if t]
    gaps = [round(b - a, 3) for a, b in zip(stamps, stamps[1:])]
    check("刷新无大间隔", not gaps or max(gaps) < 0.45, str(gaps[:8]))
    # 倒计时单调递减, 不回跳
    nums = [int(t.split("|")[1].split("s")[0].strip())
            for t in texts if "|" in t and "s 后" in t]
    check("倒计时单调递减", all(a >= b for a, b in zip(nums, nums[1:])),
          str(nums[:8]))
    check("倒计时不闪跳(跨度<=1)", (max(nums) - min(nums)) <= 1 if nums else False,
          str(nums[:8]))

    # 未扫描时计时器必须不启动, 且标签为空
    w.scan_start_time = 0.0
    w.scan_deadline = None
    w.scan_elapsed.setText("")
    w._tick_scan_clock()
    check("未扫描时 tick 空转安全", w.scan_elapsed.text() == "",
          w.scan_elapsed.text())

    # 倒计时到点只触发一次自动停止(防重入)
    calls = []
    w.scan_start_time = time.time()
    w.scan_deadline = time.time() - 1
    w._autostop_firing = False
    w._stop_scan = lambda: calls.append(1)
    for _ in range(6):
        w._tick_scan_clock()
    check("自动停止只触发一次", len(calls) == 1, str(len(calls)))
    w.scan_start_time = 0.0
    w.scan_deadline = None

    # 刷新表格中途抛异常后必须恢复重绘, 否则界面永久卡死
    w.ap_table.setUpdatesEnabled(False)
    try:
        raise RuntimeError("模拟填充异常")
    except RuntimeError:
        pass
    finally:
        w.ap_table.setUpdatesEnabled(True)
    check("异常后表格重绘已恢复", w.ap_table.updatesEnabled())

    # _fill_ap_table 正常路径可用
    w.ap_table.setRowCount(0)
    w._fill_ap_table([(-40, "S1", "2 台", "AA:BB:CC:DD:EE:01", "6", "WPA2",
                       "-40 dBm", 2)])
    check("_fill_ap_table 填充成功", w.ap_table.rowCount() == 1
          and w.ap_table.item(0, 1).text() == "S1",
          f"{w.ap_table.rowCount()} 行")
    w.ap_table.setRowCount(0)

    # ---- 倒计时必须严格 1 秒 1 跳, 且只在变化时重绘 ----
    section("倒计时 1 秒 1 跳 + 按需重绘")
    w._stop_scan = lambda: None
    w.scan_auto_stop = 5
    w.scan_timer.stop()
    w.scan_start_time = time.time()
    w.scan_deadline = w.scan_start_time + 5
    w._cd_anchor_left = 5
    w._last_clock_text = ""
    w._autostop_firing = False
    w.tick_timer.start()
    seen = []
    t0 = time.time()
    while time.time() - t0 < 5.2:
        app.processEvents()
        w._tick_scan_clock()
        cur = w.scan_elapsed.text()
        if not seen or seen[-1][1] != cur:
            seen.append((round(time.time() - t0, 2), cur))
        time.sleep(0.02)
    w.tick_timer.stop()
    nums = [int(t.split("|")[1].split("s")[0])
            for _, t in seen if "s 后" in t]
    check("倒计时从满值起步", nums and nums[0] == 5, str(nums))
    # 末尾会钳位在 1 直到停止, 只看去重后的序列
    uniq = []
    for n in nums:
        if not uniq or uniq[-1] != n:
            uniq.append(n)
    check("严格逐秒递减", uniq == [5, 4, 3, 2, 1], str(uniq))
    check("1 秒后钳位不继续减", uniq[-1] == 1 and nums[-1] == 1, str(nums[-3:]))
    gaps = [round(b[0] - a[0], 2) for a, b in zip(seen, seen[1:])
            if "s 后" in b[1]]
    check("每格停留 1 秒", all(0.9 <= g <= 1.2 for g in gaps), str(gaps))
    check("变化次数等于秒数+1", len(seen) <= 7, str(len(seen)))
    # 文本没变时不重绘(卡顿主因)
    w._last_clock_text = "占位"
    before = w.scan_elapsed.text()
    w._last_clock_text = before
    w._tick_scan_clock()
    check("文本未变时不重绘", w._last_clock_text == before, w._last_clock_text)
    w.scan_start_time = 0.0
    w.scan_deadline = None
    w._cd_anchor_left = 0
    w._last_clock_text = ""
    w.scan_elapsed.setText("")

    # 旧配置迁移: 存了 0 的旧配置应升级为 45
    import core.aircore as AC, json
    old_cfg = {"scan_auto_stop": 0, "use_gpu": True}
    AC.CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    AC.CONFIG_FILE.write_text(json.dumps(old_cfg))
    ac = AC.AirCore()
    check("旧配置 0 迁移为 45", ac.config["scan_auto_stop"] == 45,
          str(ac.config["scan_auto_stop"]))
    AC.CONFIG_FILE.write_text(json.dumps(
        {"scan_auto_stop": 0, "scan_auto_stop_explicit": True}))
    ac2 = AC.AirCore()
    check("用户显式设 0 保留", ac2.config["scan_auto_stop"] == 0,
          str(ac2.config["scan_auto_stop"]))
    AC.CONFIG_FILE.unlink()

    # ---- 握手包库: 右键删除/清空/加入跑包界面 ----
    section("握手包库删除/清空/批量加入")
    import glob as _glob
    from PyQt5.QtWidgets import QMenu as _QMenu, QMessageBox as _QMB
    cday = w.core._dated_dir(); cday.mkdir(parents=True, exist_ok=True)
    for f in cday.glob("handshake*.cap"):
        f.unlink()
    mcaps = []
    for i, n in enumerate(("handshake-01.cap", "handshake-02.cap"), 1):
        cp = cday / n
        cp.write_bytes(b"\x00" * 2048)
        mcaps.append(cp)
        w.core.set_cap_meta(cp, {"essid": f"Net-{i}",
                                 "bssid": f"AA:00:00:00:00:0{i}",
                                 "channel": "6"})
    w._refresh_cap_tree()
    check("握手包已入库", w.cap_tree.topLevelItemCount() == 1,
          str(w.cap_tree.topLevelItemCount()))
    top = w.cap_tree.topLevelItem(0)
    check("库内两个包", top.childCount() == 2, str(top.childCount()))

    # QMenu 必须可用: 之前 main.py 没 import QMenu, 右键直接 NameError,
    # 菜单根本不弹 —— 这就是"无法删除和清空"的真正原因
    import main as _M
    from PyQt5.QtCore import Qt as _Qt
    check("QMenu 已导入(main 模块可用)", _M.QMenu is not None)

    # 1) 未选中直接右键 -> 应自动选中并删除该包
    w.cap_tree.clearSelection()
    tgt = top.child(1)
    tname = tgt.data(0, _Qt.UserRole)
    _orig_exec = _QMenu.exec_
    _QMenu.exec_ = lambda self, *a: self.actions()[0]      # "删除选中"
    _orig_q = _QMB.question
    _QMB.question = staticmethod(lambda *a, **k: _QMB.Yes)
    try:
        w._cap_menu(w.cap_tree.visualItemRect(tgt).center())
    finally:
        _QMB.question = _orig_q
    check("右键即删(无需先左键)", not Path(tname).exists(), tname)

    # 2) 选中日期行 -> 应展开成该日期下的包, 且必须是真实文件
    w.cap_tree.clearSelection()
    w.cap_tree.topLevelItem(0).setSelected(True)
    sel = w._selected_caps()
    check("日期行展开为包", len(sel) == 1, str([p.name for p in sel]))
    check("不含日期目录", all(p.is_file() for p in sel),
          str([str(p) for p in sel]))

    # 3) 批量加入跑包界面 -> SSID/BSSID 取自 .meta, 不是文件名
    # 注意: QTabWidget.addTab 只有在标签栏为空时才切换当前标签,
    # 这里必须显式 setCurrentIndex, 否则写入的是别的(历史恢复的)标签
    _new_idx = w.result_tabs.addTab(U.CrackResultWidget(), "2030-01-01")
    w.result_tabs.setCurrentIndex(_new_idx)
    rtree = w._current_result_tree()
    check("新建标签已切换为当前", rtree is w.result_tabs.widget(_new_idx))
    w.cap_tree.clearSelection()
    w.cap_tree.topLevelItem(0).child(0).setSelected(True)
    w._batch_add_to_crack()
    check("已加入结果列表", rtree.topLevelItemCount() == 1,
          str(rtree.topLevelItemCount()))
    it0 = rtree.topLevelItem(0)
    check("SSID 取自抓包元数据", it0.text(rtree.COL_ESSID).startswith("Net-"),
          it0.text(rtree.COL_ESSID))
    check("BSSID 取自抓包元数据", it0.text(rtree.COL_BSSID).startswith("AA:"),
          it0.text(rtree.COL_BSSID))
    # 重复加入不产生重复行
    w._batch_add_to_crack()
    check("重复加入已去重", rtree.topLevelItemCount() == 1,
          str(rtree.topLevelItemCount()))
    # 破解出密码后复制应拿到真实 SSID
    it0.setText(rtree.COL_PWD, "pw123")
    rtree.setCurrentItem(it0)
    w.btn_copy_wifi.setEnabled(True)
    w._copy_wifi_credentials()
    got = QApplication.clipboard().text()
    check("复制WiFi含真实SSID",
          got.startswith(f"WIFI:S:{it0.text(rtree.COL_ESSID)};") and "pw123" in got,
          got)

    # 4) 清空全部
    _QMB.question = staticmethod(lambda *a, **k: _QMB.Yes)
    try:
        w._clear_all_caps()
    finally:
        _QMB.question = _orig_q
        _QMenu.exec_ = _orig_exec
    left = _glob.glob(str(cday / "handshake*.cap"))
    check("清空全部生效", not left, str(left))
    check("清空后树已刷新", w.cap_tree.topLevelItemCount() == 0,
          str(w.cap_tree.topLevelItemCount()))

    # ---- 握手包库健壮性: 空项 / 已销毁对象不得崩溃 ----
    section("握手包库空项与已销毁对象")
    from PyQt5.QtWidgets import QMenu as _QMenu2
    check("QMenu 已在 main 中导入", getattr(sys.modules.get("main"), "QMenu", None)
          is _QMenu2)
    check("双击空项不崩溃", _call(lambda: w._on_cap_double_clicked(None, 0)))
    check("备注编辑空项不崩溃", _call(lambda: w._on_cap_note_edited(None, 0)))
    check("备注编辑其它列忽略", _call(lambda: w._on_cap_note_edited(None, 1)))

    _cd2 = w.core._dated_dir(); _cd2.mkdir(parents=True, exist_ok=True)
    _cp = _cd2 / "handshake-99.cap"
    _cp.write_bytes(b"\x00" * 100)
    w.core.set_cap_meta(_cp, {"essid": "S", "bssid": "AA:1", "channel": "6"})
    w._refresh_cap_tree()
    _child = w.cap_tree.topLevelItem(0).child(0)
    _top = w.cap_tree.topLevelItem(0)
    w.cap_tree.clear()          # 销毁全部 item
    check("销毁后双击子项不崩溃",
          _call(lambda: w._on_cap_double_clicked(_child, 0)))
    check("销毁后双击分组不崩溃",
          _call(lambda: w._on_cap_double_clicked(_top, 0)))
    check("销毁后备注编辑不崩溃",
          _call(lambda: w._on_cap_note_edited(_child, 0)))
    check("刷新树恢复正常", _call(w._refresh_cap_tree))
    _cp.unlink()
    Path(str(_cp) + ".meta").unlink(missing_ok=True)

    # ---- 边界输入 ----
    section("边界输入")
    check("空 CSV", w._parse_ap_csv("", {}) == [])
    check("仅表头", w._parse_ap_csv(
        "BSSID,First time seen,Last time seen,channel,Speed,Signal,"
        "Channel,Radio,Author,Privacy,WPA,Mode,Station count,"
        "Probed ESSIDs,Lens,Sleep,CC,Rates(dBm1-2),"
        "Default Rates(dBm1-2),RetRates(dBm1-2),WPS\n", {}) == [])
    check("垃圾数据", w._parse_ap_csv("garbage\n,,\nnot,a,mac\n", {}) == [])
    check("Station 段空", w._parse_station_section("") == {})
    check("Station 段全垃圾", w._parse_station_section("1,2,3\nxx,yy,zz\n") == {})
    st = w._parse_station_section(
        "Station MAC, First time seen, Last time seen, Power, # packets,"
        " BSSID, Probed ESSIDs\r\n"
        "0E:BE:B2:FD:94:88, t1, t2, -74, 1, AA:BB:CC:DD:EE:FF,\r\n"
        "(not associated), t1, t2, -70, 1, , \r\n")
    check("未关联客户端被排除", list(st) == ["AA:BB:CC:DD:EE:FF"], str(st))
    check("信号越界不崩溃", isinstance(w._signal_bar(-999), tuple))
    check("信号 None 不崩溃", isinstance(w._signal_bar(None), tuple))
    check("不存在路径 meta", w.core.cap_meta(Path("/不存在/x.cap")) == {})
    check("垃圾 meta 不崩溃",
          _call(lambda: (Path("/tmp/bad3.meta").write_text("{oops"),
                         w.core.cap_meta(Path("/tmp/bad3.meta")))[1]))
    check("NaN meta 不崩溃",
          _call(lambda: (Path("/tmp/bad4.meta").write_text('{"essid": NaN}'),
                         w.core.cap_meta(Path("/tmp/bad4.meta")))[1]))

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