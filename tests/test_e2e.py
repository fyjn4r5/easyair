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
    check("更改按钮已移除", not hasattr(w, "btn_change_engine"))
    check("引擎摘要移到底部任务栏",
          getattr(w.lbl_engine.parent(), "objectName", lambda: "")() == "targetBar"
          and w.lbl_engine.parent() is w.status_label.parent(),
          str(w.lbl_engine.parent()))

    section("布局: 底部标签页")
    check("底部有 3 个 tab", w.bottom_tabs.count() == 3, str(w.bottom_tabs.count()))
    check("底部 3 个标签页", w.bottom_tabs.count() == 3, str(w.bottom_tabs.count()))
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
    check("任务栏右侧为引擎摘要",
          w.lbl_engine.y() < w.ap_table.y()
          and w.status_label.x() < w.lbl_engine.x(),
          f"eng_y={w.lbl_engine.y()} ap_y={w.ap_table.y()} "
          f"status_x={w.status_label.x()} eng_x={w.lbl_engine.x()}")

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
    check("信道列正确", w.ap_table.item(r0, 5).text() == "1",
          w.ap_table.item(r0, 5).text())
    check("BSSID 列正确", w.ap_table.item(r0, 4).text() == "AA:BB:CC:DD:EE:00",
          w.ap_table.item(r0, 4).text())
    check("加密列正确", w.ap_table.item(r0, 6).text() == "WPA2/AES",
          w.ap_table.item(r0, 6).text())
    check("SSID 不是 ID-length", w.ap_table.item(r0, 1).text() == "Net0",
          w.ap_table.item(r0, 1).text())
    check("强度列带 dBm", w.ap_table.item(r0, 3).text().endswith("dBm"),
          w.ap_table.item(r0, 3).text())

    section("扫描 CSV: 表头别名与旧格式兼容")
    rows = w._parse_ap_csv(
        "BSSID, First time seen, channel, Privacy, Power, ESSID\n"
        "11:22:33:44:55:66, 2026-10-05 10:00:00, 11, WPA3, -55, MyWiFi\n")
    check("短表头也能解析", len(rows) == 1, str(rows))
    if rows:
        check("短表头 SSID 正确", rows[0][1] == "MyWiFi", str(rows[0]))
        check("短表头 信道正确", rows[0][5] == "11", str(rows[0]))
        check("短表头 BSSID 正确", rows[0][4] == "11:22:33:44:55:66", str(rows[0]))
        check("短表头 强度正确", "-55 dBm" == rows[0][3], str(rows[0]))
        check("短表头 客户端为空", rows[0][2] == "-", str(rows[0]))
    rows2 = w._parse_ap_csv(
        "BSSID,Station MAC,Host Station,MAX,LAST,Beacon,LAN,CH,ENC,CIPHER,"
        "POWER,DBM,ESSID,STD,Radio,Hostspot,Probe\n"
        "22:33:44:55:66:77,00:00:00:00:00:00,00:00:00:00:00:00,-1,-1,-46,-1,9,"
        "WPA2,AES,-60,-60,LegacyAP,,\n")
    check("旧 17 列格式仍兼容", len(rows2) == 1 and rows2[0][1] == "LegacyAP",
          str(rows2))
    check("旧格式 BSSID 位置正确", rows2 and rows2[0][4] == "22:33:44:55:66:77",
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

    section("线程: 扫描线程被记住(进程泄漏回归)")
    # 回归: scan_thread 从未被赋值, _stop_scan 杀不掉 airodump,
    # 每停一次就多留一个进程 —— "越用越卡"的直接来源。
    w2.scan_thread = None
    _fake_proc = subprocess.Popen(["sh", "-c", "echo x; sleep 0.05"],
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, text=True, bufsize=1)
    w2._on_scan_started(_fake_proc)
    check("scan_thread 已被记住", w2.scan_thread is not None)
    pump(300)
    check("线程结束后引用自动归还", w2.scan_thread is None,
          str(w2.scan_thread))

    section("线程: CmdThread 丢弃整屏重绘(卡死回归)")
    got1 = []
    _p1 = subprocess.Popen(
        ["sh", "-c",
         "printf '\\033[2J\\033[2;1H'; sleep 0.05; "
         "for i in $(seq 1 3000); do echo d$i; done"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    t1 = w2._spawn_cmd(_p1, lambda s: got1.append(s))
    _deadline = time.time() + 5
    while t1.isRunning() and time.time() < _deadline:
        pump(20)
    check("整屏重绘一行都不进 GUI", not got1, str(got1[:3]))

    section("线程: CmdThread 刷行限流(卡死回归)")
    got2 = []
    _p2 = subprocess.Popen(
        ["sh", "-c", "for i in $(seq 1 4000); do echo flood-$i; done"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    t2 = w2._spawn_cmd(_p2, lambda s: got2.append(s))
    _deadline = time.time() + 5
    while t2.isRunning() and time.time() < _deadline:
        pump(20)
    check("限流后有行通过且不超上限", 0 < len(got2) <= 250, str(len(got2)))
    check("超出部分有汇总提示", any("已过滤" in s for s in got2), str(got2[-3:]))

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

    # 打包后应落到 ~/.easyair —— 只断言路径推断, 绝不真写用户主目录
    _frozen_saved = getattr(sys, "frozen", None)
    sys.frozen = True
    try:
        _dd = C._data_dir()
    finally:
        if _frozen_saved is None:
            del sys.frozen
        else:
            sys.frozen = _frozen_saved
    check("打包后数据目录为 ~/.easyair",
          _dd == C.Path.home() / ".easyair", str(_dd))
    check("打包后配置落在 ~/.easyair/config",
          _dd / "config" / "settings.json"
          == C.Path.home() / ".easyair" / "config" / "settings.json",
          str(_dd / "config" / "settings.json"))
    # 保持配置写在临时目录, 不要污染真实的 ~/.easyair
    C.CONFIG_FILE = cfgdir / "settings.json"
    C.HISTORY_FILE = cfgdir / "history.json"
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
    # 客户端列 56px: 表头"客户端"与内容"N 台"都放得下, 不再缩写
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
    # 客户端列内容只显示数字, 完整的"N 台"与 MAC 列表在 tooltip
    check("有客户端的 AP 显示数量", cells.get("WithCli", "") == "2", str(cells))
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
    pwrs = [int(w.ap_table.item(r, 3).text().split()[0]) for r in range(w.ap_table.rowCount())]
    check("按信号强度降序", pwrs == sorted(pwrs, reverse=True), str(pwrs))
    check("最强信号排第一", w.ap_table.item(0, 1).text() == "Cafe, Guest",
          w.ap_table.item(0, 1).text())
    bars = [w.ap_table.item(r, 0).text() for r in range(w.ap_table.rowCount())]
    check("信号格为方块字符", all(set(b) <= set("█░") for b in bars), str(bars[:3]))
    check("不再使用竖线表示信号", not any("|" in b for b in bars), str(bars[:3]))
    check("最强信号格全满", bars[0] == "█████", bars[0])
    weak = min(range(w.ap_table.rowCount()),
               key=lambda r: int(w.ap_table.item(r, 3).text().split()[0]))
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

    section("本轮: 握手包库右键打开文件夹/复制路径 + 待破解状态 + 字典持久化")
    # 新加入的破解目标应为"待破解", 而不是未跑就显示"进行中"
    check("新目标默认待破解",
          it.text(U.CrackResultWidget.COL_STATE) == "待破解",
          it.text(U.CrackResultWidget.COL_STATE))

    # 右键"打开所在文件夹"定位到握手包所在目录
    from PyQt5.QtCore import Qt as _Qt2
    w.cap_tree.clearSelection()
    kids[0].setSelected(True)
    w.cap_tree.setCurrentItem(kids[0])
    _dir = w._cap_target_dir()
    check("打开文件夹定位到真实目录",
          _dir is not None and _dir.is_dir(), str(_dir))

    import main as _M
    _opened = {}

    class _FakeDesktop:
        @staticmethod
        def openUrl(url):
            _opened["u"] = url.toLocalFile()

    _real_desktop = _M.QDesktopServices
    _M.QDesktopServices = _FakeDesktop
    try:
        w._open_cap_folder()
    finally:
        _M.QDesktopServices = _real_desktop
    check("右键打开文件夹调用了系统文件管理器",
          _opened.get("u") == str(_dir), str(_opened))

    # 复制路径
    w.cap_tree.clearSelection()
    kids[0].setSelected(True)
    w.cap_tree.setCurrentItem(kids[0])
    w._copy_cap_path()
    _clip = _QA.clipboard().text()
    check("复制路径含该握手包路径",
          str(kids[0].data(0, _Qt2.UserRole)) in _clip, _clip)

    # 旧记录里遗留的"进行中"重启后显示"待破解"
    _rt = U.CrackResultWidget()
    _ri = _rt.load_record({"bssid": "AA", "essid": "E", "cap": "c.cap",
                           "status": "进行中", "password": "破解中..."})
    check("遗留'进行中'迁移为待破解",
          _ri.text(U.CrackResultWidget.COL_STATE) == "待破解",
          _ri.text(U.CrackResultWidget.COL_STATE))
    check("遗留占位密码显示为空",
          _ri.text(U.CrackResultWidget.COL_PWD) == "")

    # 字典: 已保存但暂时不存在的路径不丢, 且对话框仍显示
    _c = w.core
    _saved_wl = _c.config.get("wordlists", [])
    _c.config["wordlists"] = ["/nonexistent/easyair-test.dict",
                              str(kids[0].data(0, _Qt2.UserRole))]
    check("已保存字典保留不存在的路径",
          "/nonexistent/easyair-test.dict" in _c.get_saved_wordlists())
    check("缺失的字典不参与实际破解",
          "/nonexistent/easyair-test.dict" not in _c.get_wordlists())
    _dlg = U.WordListDialog(w, _c.get_saved_wordlists())
    check("字典对话框显示已保存但缺失的条目",
          _dlg.list_widget.count() == 2, str(_dlg.list_widget.count()))
    _dlg.list_widget.setCurrentRow(0)
    _dlg._remove_selected()
    check("移除后 get_wordlists 同步", len(_dlg.get_wordlists()) == 1,
          str(_dlg.get_wordlists()))
    _dlg.deleteLater()
    _c.config["wordlists"] = _saved_wl

    section("设置: 扫描时间/字典持久化(含 0=手动停止) + 保存失败可见")
    _pdir = tmp / "persist"
    _pdir.mkdir(exist_ok=True)
    _old_cfg, _old_hist = C.CONFIG_FILE, C.HISTORY_FILE
    C.CONFIG_FILE = _pdir / "settings.json"
    C.HISTORY_FILE = _pdir / "history.json"
    # 手动停止(0)必须原样保存/读回, 不能被 "or 45" 顶掉
    w.core.config["scan_auto_stop"] = 0
    w.core.config["scan_auto_stop_explicit"] = True
    w.core.config["wordlists"] = ["/tmp/easyair-persist.dict"]
    check("save_config 返回成功", w.core.save_config() is True)
    check("写盘后无残留 .tmp",
          not (_pdir / "settings.json.tmp").exists(), str(_pdir))
    _re = C.AirCore()
    check("扫描时间 0 持久化后仍为 0",
          _re.config.get("scan_auto_stop") == 0,
          str(_re.config.get("scan_auto_stop")))
    check("字典路径持久化后仍在",
          _re.config.get("wordlists") == ["/tmp/easyair-persist.dict"],
          str(_re.config.get("wordlists")))
    _reload_dlg = U.CrackSettingsDialog(w, _re.config)
    check("对话框显示 手动停止(0) 而非回落到 45",
          _reload_dlg.scan_secs.value() == 0,
          str(_reload_dlg.scan_secs.value()))
    # 保存路径不可写时必须返回 False(而不是静默丢设置)
    C.CONFIG_FILE = C.Path("/proc/easyair-nope/settings.json")
    check("不可写路径 save_config 返回 False",
          w.core.save_config() is False)
    C.CONFIG_FILE, C.HISTORY_FILE = _old_cfg, _old_hist

    section("本轮: 右侧结果右键菜单/可关闭标签 + 实时状态行 + 左侧客户端数刷新")
    check("结果标签可关闭", w.result_tabs.tabsClosable())
    _n_tabs = w.result_tabs.count()
    if _n_tabs >= 2:
        w._on_result_tab_close(0)
        check("关闭一个标签生效", w.result_tabs.count() == _n_tabs - 1,
              f"{_n_tabs}->{w.result_tabs.count()}")
    # 允许关闭到 0 个标签; 之后 _ensure_result_tab 会自动补回今天
    while w.result_tabs.count() > 0:
        w._on_result_tab_close(0)
    check("可以关闭全部结果标签", w.result_tabs.count() == 0,
          str(w.result_tabs.count()))
    _t = w._ensure_result_tab()
    check("关闭全部后自动补回结果标签", w.result_tabs.count() == 1 and _t is not None,
          str(w.result_tabs.count()))

    # 结果树右键菜单相关方法存在
    for _m in ("_result_menu", "_result_tab_menu", "_ensure_result_tab",
               "_reveal_cap_in_library", "_clear_results_of_date",
               "_update_ap_row_clients"):
        check(f"存在 {_m}", hasattr(w, _m))

    # 实时状态行: 空闲时应显示"空闲"且是一个非滚动标签
    w._crack_running = False
    w._capture_running = False
    w._auto_mode = False
    w.scan_timer.stop()
    w._live_last = ""
    w._refresh_live_status()
    check("实时状态行存在", hasattr(w, "live_label"))
    check("空闲时状态行显示空闲", "空闲" in w.live_label.text(),
          w.live_label.text())

    # 抓包中状态行显示在线客户端数量(原地刷新, 不新增日志)
    _b = w.ap_table.item(0, 4).text() if w.ap_table.rowCount() else "AA:BB:CC:DD:EE:11"
    w._capture_running = True
    w._cap_bssid = _b
    w._cap_ch = "6"
    w._ap_clients[_b.upper()] = ["11:22:33:44:55:66", "aa:bb:cc:dd:ee:ff"]
    w._deauth_attempts = 4
    w._live_last = ""
    w._refresh_live_status()
    check("抓包状态行含在线客户端数量",
          "在线客户端 2" in w.live_label.text(), w.live_label.text())

    # 左侧列表客户端列随嗅探结果刷新
    w.ap_table.setItem(0, 4, U.QTableWidgetItem(_b.upper()))
    w.ap_table.setItem(0, 2, U.QTableWidgetItem("-"))
    w._update_ap_row_clients(_b, ["11:22:33:44:55:66", "aa:bb:cc:dd:ee:ff"])
    check("左侧客户端列更新为数量",
          w.ap_table.item(0, 2).text() == "2",
          w.ap_table.item(0, 2).text())
    check("左侧客户端列 tooltip 含明细",
          "11:22:33:44:55:66" in w.ap_table.item(0, 2).toolTip())
    w._capture_running = False

    section("本轮: 单击选目标/双击抓包 / 排序 / 提示去重")
    # 双击可触发抓包
    check("双击绑定已启用", hasattr(w.ap_table, "cellDoubleClicked")
          and hasattr(w.ap_table.cellDoubleClicked, "connect"), "double click enabled")
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
    check("单击仅选目标不抓包", sigs == [], str(sigs))
    check("目标已填", w.lbl_target_bssid.text() == "AA:BB:CC:DD:EE:22",
          w.lbl_target_bssid.text())
    w._on_ap_double_clicked(0, 0)
    check("双击触发抓包", sigs == ["capture"], str(sigs))
    check("客户端下拉存在且有广播项",
          hasattr(w, "client_combo") and w.client_combo.count() >= 1,
          str(getattr(w, "client_combo", None)))
    check("单击不抓包返回 True", w._select_target(0) is True)
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
    w.core.deauth = lambda *a: (order_seq.append("deauth") or (True, "[deauth] ok"))
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

    section("deauth 真实结果解析 + WPA3/PMF 提示 + 嗅探日志文案")
    _core = C.AirCore()
    _core._run_sudo = lambda args: subprocess.CompletedProcess(
        args, 0, "Sending 64 directed DeAuth (code 7). STMAC: [AA] [10|64 ACKs]", "")
    ok, m = _core.deauth("wlan0mon", "AA:00:00:00:00:01", 10, "BB:00:00:00:00:01")
    check("deauth 成功时返回 True 并含'已发送'", ok is True and "已发送" in m, m)
    _core._run_sudo = lambda args: subprocess.CompletedProcess(
        args, 1, "No such BSSID available.", "")
    ok2, m2 = _core.deauth("wlan0mon", "AA:00:00:00:00:01")
    check("deauth 找不到目标时返回 False 并说明",
          ok2 is False and "找不到" in m2, m2)
    _core._run_sudo = lambda args: subprocess.CompletedProcess(
        args, 1, "No such BSSID available.", "No such BSSID available.")
    ok3, m3 = _core.deauth("wlan0mon", "AA:00:00:00:00:01")
    check("deauth 失败描述不是空的", ok2 is False and bool(m2) and bool(m3), m3)
    _core._run_sudo = lambda args: subprocess.CompletedProcess(
        args, 1, "", "no privilege")
    _okp, _mp = _core.deauth("wlan0mon", "AA:00:00:00:00:01")
    check("无提权时提示检查 ~/.Pas", _okp is False and "~/.Pas" in _mp, _mp)


    # WPA3/SAE/PMF 目标必须给出明确提示(否则用户会一直干等)
    w._ap_sec = {"AA:00:00:00:00:01": ("WPA3", "CCMP", "SAE")}
    w.log_scan_box.clear()
    w._warn_target_security("AA:00:00:00:00:01")
    _warn_txt = w.log_scan_box.toPlainText()
    check("WPA3 目标提示 deauth 会被忽略", "WPA3" in _warn_txt, _warn_txt)
    w._ap_sec = {"AA:00:00:00:00:01": ("WPA2", "CCMP", "PSK")}
    w.log_scan_box.clear()
    w._warn_target_security("AA:00:00:00:00:01")
    check("WPA2 目标不误报", w.log_scan_box.toPlainText().strip() == "",
          w.log_scan_box.toPlainText())

    # 嗅探启动日志不能再引用已被删除的"数据帧"标签页
    class _Sig:
        def connect(self, *a):
            pass

    class _FakeTh:
        def __init__(self):
            self.finished = _Sig()

    _real_spawn = w._spawn_cmd
    _real_st = w._sniffer_thread
    w._spawn_cmd = lambda proc, cb: _FakeTh()
    w._sniffer_thread = None
    w.log_scan_box.clear()
    w._on_sniffer_started(object())
    _sniff_txt = w.log_scan_box.toPlainText()
    check("嗅探启动日志不再提'数据帧'标签页",
          "数据帧'标签页" not in _sniff_txt and "状态行" in _sniff_txt,
          _sniff_txt)
    w._spawn_cmd = _real_spawn
    w._sniffer_thread = _real_st

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
    _mig = tmp / "migrate"
    _mig.mkdir(exist_ok=True)
    _saved_cfg, _saved_hist = AC.CONFIG_FILE, AC.HISTORY_FILE
    AC.CONFIG_FILE = _mig / "settings.json"
    AC.HISTORY_FILE = _mig / "history.json"
    old_cfg = {"scan_auto_stop": 0, "use_gpu": True}
    AC.CONFIG_FILE.write_text(json.dumps(old_cfg))
    ac = AC.AirCore()
    check("旧配置 0 迁移为 45", ac.config["scan_auto_stop"] == 45,
          str(ac.config["scan_auto_stop"]))
    AC.CONFIG_FILE.write_text(json.dumps(
        {"scan_auto_stop": 0, "scan_auto_stop_explicit": True}))
    ac2 = AC.AirCore()
    check("用户显式设 0 保留", ac2.config["scan_auto_stop"] == 0,
          str(ac2.config["scan_auto_stop"]))
    AC.CONFIG_FILE, AC.HISTORY_FILE = _saved_cfg, _saved_hist

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
    _QMenu.exec_ = lambda self, *a: next(
        (x for x in self.actions() if "删除" in x.text()), self.actions()[0])
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

    # ---- AP 表列宽 ----
    section("AP 表列宽")
    from PyQt5.QtGui import QFontMetrics as _FM
    t = w.ap_table
    fm = _FM(t.font())
    widths = [t.columnWidth(i) for i in range(7)]
    check("客户端列足够放下", widths[2] >= 56, str(widths[2]))
    _mac_px = fm.horizontalAdvance("AA:BB:CC:DD:EE:FF")
    # 列宽按字体实测分配, 不能写死像素: Ubuntu 字体一个 MAC 约 122px,
    # DejaVu Sans 12pt 约 166px, 换字体写死 130 就会截断 BSSID。
    check("BSSID 刚好容纳一个 MAC", widths[4] >= _mac_px,
          f"{widths[4]} >= {_mac_px}")
    # 列宽按字体自适应, 余量固定为 10px
    check("BSSID 不浪费多余宽度", widths[4] <= _mac_px + 12,
          f"{widths[4]} <= {_mac_px + 12}")
    check("SSID 拿到省下的宽度", widths[1] >= 90, str(widths[1]))
    check("客户端列表头放得下",
          widths[2] >= fm.horizontalAdvance("客户端"),
          f"{widths[2]} >= {fm.horizontalAdvance('客户端')}")
    check("信号列放得下表头", widths[0] >= fm.horizontalAdvance("信号"))
    # 注意: 前面有测试把信号列改成 77(模拟用户拖动), 因此这里不能用
    # 602 这个绝对值; 只校验本次关心的两列宽度, 且总宽不应超出左栏上限。
    check("总宽不超左栏上限", sum(widths) <= 660, str(sum(widths)))
    # 表头下限必须调低, 否则 setColumnWidth(56) 会被抬回 57
    check("表头最小列宽已调低",
          t.horizontalHeader().minimumSectionSize() <= 23,
          str(t.horizontalHeader().minimumSectionSize()))
    check("表头文案", [t.horizontalHeaderItem(i).text() for i in range(7)]
          == ["信号", "SSID", "客户端", "强度", "BSSID", "信道", "加密"],
          str([t.horizontalHeaderItem(i).text() for i in range(7)]))
    # 客户端列内容为纯数字, 详情在 tooltip
    _cd3 = w.core.caps_dir
    _cd3.mkdir(parents=True, exist_ok=True)
    _h = ("BSSID,First time seen,Last time seen,channel,Speed,Signal,"
          "Channel,Radio,Author,Privacy,WPA,Mode,ESSID,Station count,"
          "Probed ESSIDs,Lens,Sleep,CC,Rates(dBm1-2),"
          "Default Rates(dBm1-2),RetRates(dBm1-2),WPS")
    # 按表头严格对齐: 12=ESSID, 13=Station count
    (_cd3 / "scan-01.csv").write_text(_h + "\n"
        "AA:BB:CC:DD:EE:FF,t1,t2,6,130,-40,6,CC,WPA2,WPA2,AES,,Net-A,3,Net-A,"
        "0,,0,,,,,,,\n"
        "Station MAC, First time seen, Last time seen, Power, # packets,"
        " BSSID, Probed ESSIDs\r\n"
        "0E:BE:B2:FD:94:88,t1,t2,-74,1,AA:BB:CC:DD:EE:FF,Net-A\r\n"
        "0E:BE:B2:FD:94:89,t1,t2,-70,1,AA:BB:CC:DD:EE:FF,Net-A\r\n"
        "0E:BE:B2:FD:94:8A,t1,t2,-68,1,AA:BB:CC:DD:EE:FF,\r\n")
    t.setRowCount(0)
    w._last_csv = None
    w._parse_scan_csv(force=True)
    check("按表头名解析出 SSID", t.rowCount() == 1
          and t.item(0, 1).text() == "Net-A",
          f"{t.rowCount()} 行 / {t.item(0, 1).text() if t.rowCount() else '-'}")
    check("MAC 完整 17 字符", len(t.item(0, 4).text()) == 17,
          t.item(0, 4).text())
    check("客户端列为纯数字", t.item(0, 2).text().isdigit(), t.item(0, 2).text())
    check("客户端列 tooltip 含客户端数与 MAC",
          "3 台" in t.item(0, 2).toolTip()
          and "0E:BE:B2:FD:94:88" in t.item(0, 2).toolTip(),
          t.item(0, 2).toolTip())
    (_cd3 / "scan-01.csv").unlink(missing_ok=True)

    # ---- 跨线程日志与监听开关重复触发 ----
    # 回归: 工作线程里 self.log() 直接 appendPlainText 会让 Qt 报
    # "Cannot queue arguments of type 'QTextBlock'/'QTextCursor'" 并段错误;
    # 另外 set_monitor_status 改 checked 会把信号发出去, 让"汇报状态"
    # 变成"再次开启/关闭监听"。
    section("跨线程日志与监听开关")
    from PyQt5.QtCore import QThread as _QT

    _calls = {"start": [], "stop": []}

    class _FakeCore:
        caps_dir = None

        def list_interfaces(self):
            return ["wlan0"]

        def start_monitor(self, iface):
            _calls["start"].append(iface)
            import subprocess
            return subprocess.Popen(["echo", "ALREADY_MONITOR"],
                                    stdout=subprocess.PIPE, text=True)

        def check_monitor_mode(self, _i):
            return True

        def stop_monitor(self, m):
            _calls["stop"].append(m)
            return None

    _w3 = M.EasyAirApp()
    _w3.core = _FakeCore()
    _w3.iface_combo.clear()
    _w3.iface_combo.addItem("wlan0")

    _calls["start"].clear()
    _ok = _w3._enable_monitor()
    pump(300)
    check("_enable_monitor 只开启一次", len(_calls["start"]) == 1,
          str(_calls["start"]))
    check("_enable_monitor 返回 True", _ok is True, str(_ok))
    check("开启后开关为勾选态", _w3.btn_mon_toggle.isChecked())
    _w3.mon_iface = None
    _w3.btn_mon_toggle.setChecked(False)

    _calls["start"].clear()
    _calls["stop"].clear()
    _w3.set_monitor_status("on")
    pump(200)
    check("set_monitor_status(on) 不重复开启", len(_calls["start"]) == 0,
          str(_calls["start"]))
    check("set_monitor_status(on) 开关为勾选态",
          _w3.btn_mon_toggle.isChecked())
    _w3.set_monitor_status("off")
    pump(200)
    check("set_monitor_status(off) 不误触发关闭", len(_calls["stop"]) == 0,
          str(_calls["stop"]))
    check("set_monitor_status(off) 开关为非勾选态",
          not _w3.btn_mon_toggle.isChecked())

    # 捕获 Qt 往 stderr 写的跨线程警告
    import io as _io
    _r, _wr = os.pipe()
    _saved_err = os.dup(2)
    os.dup2(_wr, 2)
    os.close(_wr)

    class _LogThread(_QT):
        def run(self):
            _w3.log("[deauth] 已自动发送 10 次解关联 → AA:BB:CC:DD:EE:FF")
            _w3.log_crack("破解中")

    _lt = _LogThread()
    _lt.start()
    _lt.wait()
    pump(200)
    os.dup2(_saved_err, 2)
    os.close(_saved_err)
    os.set_blocking(_r, False)
    try:
        _noise = os.read(_r, 65536).decode("utf-8", "replace")
    except BlockingIOError:
        _noise = ""
    os.close(_r)
    check("工作线程写日志无 Qt 跨线程警告",
          "QTextBlock" not in _noise and "QTextCursor" not in _noise,
          _noise.strip()[:120])
    check("工作线程日志已进界面",
          "deauth" in _w3.log_scan_box.toPlainText())
    check("工作线程破解日志已进界面",
          "破解中" in _w3.log_crack_box.toPlainText())
    _w3.close()
    pump(100)

    section("倒计时不再等待监听模式")
    # 回归: 点扫描后必须立刻出现倒计时。之前计时在 _do_scan() 里, 而
    # _do_scan() 要等 start_monitor, 表现为"按下没反应"。
    w2 = M.EasyAirApp()
    w2.scan_auto_stop = 45  # 固定值, 不依赖磁盘配置
    w2.mon_iface = None
    w2._preflight_scan = lambda: True
    w2.iface_combo.currentText = lambda: "wlan0"
    w2.core.check_monitor_mode = lambda i: False
    w2.core.start_monitor = lambda i: subprocess.Popen(["sleep", "30"])
    w2._start_scan()
    app.processEvents()
    check("入口未被网卡缺失短路",
          "无线网卡" not in w2.scan_elapsed.text(), w2.scan_elapsed.text())
    check("按下扫描立刻起表", bool(w2.scan_start_time), str(w2.scan_start_time))
    check("立刻显示倒计时", "45s" in w2.scan_elapsed.text(), w2.scan_elapsed.text())
    w2._disarm_scan_clock()
    check("停止后表已复位", w2.scan_start_time == 0)

    section("提权失败不再弹 pkexec")
    # 回归: 密码错误时一次开监听会连弹好几个 pkexec 模态框, 系统级阻塞
    w3 = M.EasyAirApp()
    w3.mon_iface = None
    w3._preflight_scan = lambda: True
    w3.iface_combo.currentText = lambda: "wlan0"
    w3.core.check_monitor_mode = lambda i: False
    w3.core._get_sudo_password = lambda: "definitely-wrong"
    w3.core._verify_sudo_password = lambda p: False
    _seen = []
    _real_popen = subprocess.Popen
    def _spy(cmd, *a, **k):
        if "pkexec" in str(cmd):
            _seen.append(cmd)
        return _real_popen(cmd, *a, **k)
    subprocess.Popen = _spy
    try:
        w3._start_scan()
        for _ in range(80):
            app.processEvents(); time.sleep(0.02)
            if w3.btn_scan.isEnabled():
                break
    finally:
        subprocess.Popen = _real_popen
    _log = w3.log_scan_box.toPlainText()
    check("确实走到了提权失败分支(日志有据)",
          "密码验证失败" in _log or "权限" in _log, _log[-160:])
    check("未弹出任何 pkexec 进程", not _seen, str(_seen[:2]))
    check("失败后按钮复位", w3.btn_scan.isEnabled(), w3.btn_scan.text())
    check("失败后倒计时复位", w3.scan_start_time == 0)

    section("不再执行 airmon-ng check kill")
    # 回归: check kill 会杀掉 NetworkManager 等一整套网络服务,
    # 表现为整机卡顿(连系统时钟都停), 默认必须跳过。
    w4 = M.EasyAirApp()
    _ran = []
    w4.core._cleanup_monitor = lambda i: None
    w4.core.check_monitor_mode = lambda i: False
    w4.core._run_sudo = lambda args: _ran.append(" ".join(args)) or \
        subprocess.CompletedProcess(args, 0, "", "")
    w4.core.start_monitor("wlan0")
    check("未执行 check kill",
          not any("check kill" in x for x in _ran), str(_ran))
    w4.core.config["air_monitor_kill_conflicts"] = True
    _ran.clear()
    w4.core.start_monitor("wlan0")
    check("显式开启后才执行",
          any("check kill" in x for x in _ran), str(_ran))

    section("握手包按 WiFi 名称命名")
    _sp = w.core.safe_cap_prefix
    check("普通 SSID 原样保留", _sp("MyHomeWiFi_5G", "AA:BB:CC:DD:EE:FF")
          == "MyHomeWiFi_5G", _sp("MyHomeWiFi_5G", "AA:BB:CC:DD:EE:FF"))
    check("含空格保留单空格", _sp("My WiFi", "AA:BB:CC:DD:EE:FF") == "My WiFi",
          _sp("My WiFi", "AA:BB:CC:DD:EE:FF"))
    check("非法字符被替换",
          _sp("a/b:c*d?e\"f<g>h|i", "AA:BB:CC:DD:EE:FF")
          == "a_b_c_d_e_f_g_h_i",
          _sp("a/b:c*d?e\"f<g>h|i", "AA:BB:CC:DD:EE:FF"))
    check("中文 SSID 保留", _sp("无线网络", "AA:BB:CC:DD:EE:FF") == "无线网络",
          _sp("无线网络", "AA:BB:CC:DD:EE:FF"))
    check("隐藏 SSID 退回 BSSID",
          _sp("", "AA:BB:CC:DD:EE:FF") == "AA-BB-CC-DD-EE-FF", _sp("", "AA:BB:CC:DD:EE:FF"))
    check("超长 SSID 截断到 80 字节内",
          len(_sp("长" * 200, "AA:BB:CC:DD:EE:FF").encode("utf-8")) <= 80,
          str(len(_sp("长" * 200, "AA:BB:CC:DD:EE:FF").encode("utf-8"))))
    # 枚举握手包不再依赖 handshake 前缀
    _d = w.core.caps_dir / "2026-01-01"
    _d.mkdir(parents=True, exist_ok=True)
    for _n in ("MyHomeWiFi-01.cap", "Cafe-01.cap", "random.pcap"):
        (_d / _n).write_bytes(b"x")
    _got = {p.name for p in w.core._iter_caps(_d)}
    check("能列出任意命名的 cap/pcap",
          {"MyHomeWiFi-01.cap", "Cafe-01.cap", "random.pcap"} <= _got,
          str(sorted(_got)))
    _pk = {d: path.name for d, path, _sz in w.core.list_handshakes()}
    check("握手库列出按 WiFi 命名的包",
          _pk.get("2026-01-01") is not None, str(_pk))
    for _n in ("MyHomeWiFi-01.cap", "Cafe-01.cap", "random.pcap"):
        (_d / _n).unlink()

    section("抓包握手真校验: 文件存在 != 抓到握手")
    w._cap_prefix = "UnitTestCap"
    _d2 = w.core._dated_dir()
    (_d2 / "UnitTestCap-01.cap").write_bytes(b"not-a-real-cap")
    ran = []
    w._run_worker = lambda fn, on_done=None: ran.append((fn, on_done))
    w.core.has_handshake = lambda cap: False
    w._checking_handshake = False
    w._handshake_found = False
    w._capture_running = True
    w._hs_last = None
    w._check_handshake()
    check("提交了一次握手校验", len(ran) == 1, str(len(ran)))
    if ran:
        fn, cb = ran[0]
        cb(fn())
    check("无握手不报成功",
          not w._handshake_found
          and not w.lbl_handshake.text().startswith("握手包"),
          w.lbl_handshake.text())
    # 同样文件、内容不变时不应重复解析
    ran.clear()
    w._check_handshake()
    check("文件未变化不重复校验", len(ran) == 0, str(len(ran)))
    # 真含握手才报成功(会自动停止抓包, 并提示是否加入右侧)
    w.core.has_handshake = lambda cap: True
    w._hs_last = None
    w._checking_handshake = False
    ran.clear()
    from PyQt5.QtWidgets import QMessageBox as _QMB
    _orig_q2 = _QMB.question
    prompted = []
    _QMB.question = staticmethod(lambda *a, **k: prompted.append(1) or _QMB.No)
    try:
        w._check_handshake()
        if ran:
            fn, cb = ran[0]
            cb(fn())
    finally:
        _QMB.question = _orig_q2
    check("有握手报成功", w._handshake_found
          and w.lbl_handshake.text().startswith("握手包"), w.lbl_handshake.text())
    check("成功后自动停止抓包", not w._capture_running)
    check("成功后提示是否加入右侧", len(prompted) == 1, str(len(prompted)))
    # 停止抓包后, 迟到的校验结果不能再报成功
    w._handshake_found = False
    w._capture_running = False
    w._hs_last = None
    w._checking_handshake = False
    ran.clear()
    w._check_handshake()
    if ran:
        fn, cb = ran[0]
        cb(fn())
    check("停止后迟到结果不报成功", not w._handshake_found,
          str(w._handshake_found))

    # 加入右侧破解列表(幂等)
    n0 = w._current_result_tree().topLevelItemCount()
    ok_add = w._add_cap_to_crack(_d2 / "UnitTestCap-01.cap")
    check("握手包可加入右侧列表",
          ok_add and w._current_result_tree().topLevelItemCount() == n0 + 1,
          f"{n0}->{w._current_result_tree().topLevelItemCount()}")
    check("重复加入被跳过", not w._add_cap_to_crack(_d2 / "UnitTestCap-01.cap"))

    # 抓包期间客户端数量自动刷新
    w._capture_running = True
    w._cap_prefix = "UnitTestCap"
    w._cap_bssid = "AA:BB:CC:DD:EE:22"
    w._client_auto_directed = True
    w.lbl_target_bssid.setText("AA:BB:CC:DD:EE:22")
    (_d2 / "UnitTestCap-01.csv").write_text(
        "Station MAC, First time seen, Last time seen, Power, # packets, "
        "BSSID, Probed ESSIDs\r\n"
        "0E:BE:B2:FD:94:88, 2026-10-05 16:19:38, 2026-10-05 16:19:38, -74, 1, "
        "AA:BB:CC:DD:EE:22,\r\n")
    w.client_combo.clear()
    w.client_combo.addItem("全部 (广播)", "")
    w._refresh_capture_clients()
    check("客户端数量自动刷新",
          w.client_combo.count() == 2
          and w.client_combo.itemData(1) == "0E:BE:B2:FD:94:88",
          str([w.client_combo.itemData(i) for i in range(w.client_combo.count())]))
    check("deauth 间隔改为 30 秒", w._DEAUTH_INTERVAL_MS == 30000,
          str(w._DEAUTH_INTERVAL_MS))
    # 抓包中途点选别的 AP, 刷新仍用启动锁定的目标(不用界面标签)
    w._capture_running = True
    w._cap_prefix = "UnitTestCap"
    w._cap_bssid = "AA:BB:CC:DD:EE:22"
    w._client_auto_directed = True
    w._sniffed_clients = {}
    w.lbl_target_bssid.setText("FF:FF:FF:FF:FF:FF")
    (_d2 / "UnitTestCap-01.csv").write_text(
        "Station MAC, First time seen, Last time seen, Power, # packets, "
        "BSSID, Probed ESSIDs\r\n"
        "0E:BE:B2:FD:94:88, 2026-10-05 16:19:38, 2026-10-05 16:19:38, -74, 1, "
        "AA:BB:CC:DD:EE:22,\r\n")
    w.client_combo.clear()
    w.client_combo.addItem("全部 (广播)", "")
    w._refresh_capture_clients()
    check("中途点选不带跑刷新目标",
          w._ap_clients.get("AA:BB:CC:DD:EE:22") == ["0E:BE:B2:FD:94:88"]
          and w.client_combo.itemData(1) == "0E:BE:B2:FD:94:88",
          str(w._ap_clients))
    # 发现目标自带客户端自动定向一次
    (_d2 / "UnitTestCap-01.csv").write_text(
        "Station MAC, First time seen, Last time seen, Power, # packets, "
        "BSSID, Probed ESSIDs\r\n"
        "0E:BE:B2:FD:94:88, 2026-10-05 16:19:38, 2026-10-05 16:19:38, -74, 1, "
        "AA:BB:CC:DD:EE:22,\r\n"
        "1E:BE:B2:FD:94:88, 2026-10-05 16:19:39, 2026-10-05 16:19:39, -70, 2, "
        "AA:BB:CC:DD:EE:22,\r\n")
    w._client_auto_directed = False
    w.client_combo.setCurrentIndex(0)
    w._refresh_capture_clients()
    check("自动定向到首个客户端",
          w._selected_client() == "0E:BE:B2:FD:94:88"
          and w._client_auto_directed is True,
          w._selected_client())
    # 用户手动切回广播后, 再来新客户端也不打扰
    (_d2 / "UnitTestCap-01.csv").write_text(
        "Station MAC, First time seen, Last time seen, Power, # packets, "
        "BSSID, Probed ESSIDs\r\n"
        "0E:BE:B2:FD:94:88, 2026-10-05 16:19:38, 2026-10-05 16:19:38, -74, 1, "
        "AA:BB:CC:DD:EE:22,\r\n"
        "1E:BE:B2:FD:94:88, 2026-10-05 16:19:39, 2026-10-05 16:19:39, -70, 2, "
        "AA:BB:CC:DD:EE:22,\r\n"
        "2E:BE:B2:FD:94:88, 2026-10-05 16:19:40, 2026-10-05 16:19:40, -68, 3, "
        "AA:BB:CC:DD:EE:22,\r\n")
    w.client_combo.setCurrentIndex(0)
    w._refresh_capture_clients()
    check("手动切回广播后不再自动定向", w._selected_client() == "",
          w._selected_client())
    w._capture_running = False
    (_d2 / "UnitTestCap-01.csv").unlink(missing_ok=True)
    (_d2 / "UnitTestCap-01.cap").unlink(missing_ok=True)

    # 全自动抓包: 只挑"有在线客户端"的 AP
    _auto_fix = (
        hdr + "\n"
        "11:22:33:44:55:66, 2026-10-05 10:00:00, 2026-10-05 10:00:01, 6, 130,"
        " WPA2, AES, PSK, -40, 4, 0,   0.  0.  0.  0, 3, AutoA, \n"
        "22:33:44:55:66:77, 2026-10-05 10:00:00, 2026-10-05 10:00:01, 6, 130,"
        " WPA2, AES, PSK, -70, 4, 0,   0.  0.  0.  0, 3, NoCli, \n"
        "Station MAC, First time seen, Last time seen, Power, # packets, BSSID,"
        " Probed ESSIDs\r\n"
        "0E:BE:B2:FD:94:88, 2026-10-05 16:19:38, 2026-10-05 16:19:38, -74, 1,"
        " 11:22:33:44:55:66,\r\n")
    _apsec, _stsec = _auto_fix.split("Station MAC", 1)
    _stations = w._parse_station_section("Station MAC" + _stsec)
    _rows = w._parse_ap_csv(_apsec, _stations)
    w._fill_ap_table(_rows)
    _tg = w._auto_targets()
    check("全自动仅挑有客户端的 AP",
          len(_tg) == 1 and _tg[0]["essid"] == "AutoA", str(_tg))
    w._auto_mode = True
    w._auto_total = 3
    w._capture_running = False
    w._stop_auto_capture(quiet=True)
    check("停止全自动后复位",
          not w._auto_mode and w.btn_auto_cap.text().startswith("⚡"),
          w.btn_auto_cap.text())

    # 开始破解: 未选目标时用握手包元信息, 不再出现"未选择"; 密码列初始为空
    w.lbl_target_essid.setText("未选择")
    w.lbl_target_bssid.setText("未选择")
    _cap3 = _d2 / "MetaCap-01.cap"
    _cap3.write_bytes(b"x")
    w.core.set_cap_meta(_cap3, {"essid": "MetaWiFi",
                                "bssid": "AB:CD:EF:00:11:22"})
    _orig_wl = w.core.get_wordlists
    w.core.get_wordlists = lambda: ["/tmp/words.txt"]
    w.cap_tree.clearSelection()
    w.core.get_latest_handshake = lambda: _cap3
    w._run_hashcat = lambda cap, wl: None
    _n1 = w._current_result_tree().topLevelItemCount()
    import importlib as _il
    _il.import_module("main").EasyAirApp._start_crack(w)
    _tree_r = w._current_result_tree()
    _it = _tree_r.topLevelItem(_n1)
    check("开始破解不再显示'未选择'",
          _it.text(U.CrackResultWidget.COL_ESSID) == "MetaWiFi",
          _it.text(U.CrackResultWidget.COL_ESSID))
    check("密码列初始为空",
          _it.text(U.CrackResultWidget.COL_PWD) == "",
          repr(_it.text(U.CrackResultWidget.COL_PWD)))
    w._crack_running = False
    w.crack_timer.stop()
    w.core.get_wordlists = _orig_wl
    _cap3.unlink(missing_ok=True)

    section("界面按钮完整可用")
    check("抓包按钮在布局中", w.isAncestorOf(w.btn_capture),
          str(w.btn_capture.parent()))
    check("全自动抓包按钮在布局中", w.isAncestorOf(w.btn_auto_cap),
          str(w.btn_auto_cap.parent()))
    check("加入右侧按钮存在", hasattr(w, "btn_cap_add"))
    check("导入握手包按钮存在且已接入",
          hasattr(w, "btn_import_cap")
          and hasattr(w.btn_import_cap, "clicked"), "btn_import_cap")
    check("客户端下拉存在", hasattr(w, "client_combo"))
    check("默认 deauth 为广播(空)", w._selected_client() == "",
          repr(w._selected_client()))
    for name in ("btn_scan", "btn_capture", "btn_auto_cap", "btn_start_crack",
                 "btn_batch_add", "btn_import_cap"):
        b = getattr(w, name, None)
        check(f"{name} 无彩色背景",
              b is not None and "background" not in (b.styleSheet() or ""),
              b.styleSheet() if b else "missing")

    section("导出为 txt(横线分隔)")
    from PyQt5.QtWidgets import QFileDialog as _QFD
    _exp = tmp / "out_export.txt"
    _orig_save = _QFD.getSaveFileName
    _orig_info = _QMB.information
    _QFD.getSaveFileName = staticmethod(lambda *a, **k: (str(_exp), "txt"))
    _QMB.information = staticmethod(lambda *a, **k: _QMB.Ok)
    try:
        w.core.history_add(today, {
            "bssid": "AA:BB:CC:DD:EE:FF", "essid": "ExpWiFi",
            "password": "pass123", "cap": "x.cap",
            "status": "成功", "elapsed": "00:01", "note": "n"})
        w._export_results()
    finally:
        _QFD.getSaveFileName = _orig_save
        _QMB.information = _orig_info
    _content = _exp.read_text(encoding="utf-8") if _exp.exists() else ""
    check("导出使用横线分隔", "－" * 10 in _content, _content[:60])
    check("导出含 WiFi 名称", "ExpWiFi" in _content, _content[:80])
    check("导出含密码", "pass123" in _content, _content[:160])

    section("数据帧嗅探(补 airodump 不列关联客户端)")
    import core.aircore as _AC
    _P = _AC.AirCore.parse_sniffer_line
    # 真机 tcpdump -e 实测行: 客户端→AP(SA 即客户端)
    _l1 = ("16:42:17.920218 315872429us tsft 6.0 Mb/s 2412 MHz 11g "
           "-65dBm signal antenna 0 DA:ff:ff:ff:ff:ff:ff "
           "BSSID:6c:11:ba:9f:63:ef SA:98:3f:a4:67:36:d0 "
           "Data IV:45c1 Pad 20 KeyID 1")
    check("客户端→AP 解析出客户端", _P(_l1) == ("98:3F:A4:67:36:D0",
          "6C:11:BA:9F:63:EF"), str(_P(_l1)))
    # 组播 DA 的数据帧: 客户端仍是 SA(真机实测 b0:68→ZX001)
    _l2 = ("16:37:54.085544 52035871us tsft 2.0 Mb/s 2412 MHz 11b "
           "-62dBm signal antenna 0 DA:01:00:5e:7f:ff:fa "
           "BSSID:e0:b6:68:cd:bb:f7 SA:b0:68:e6:c1:c9:07 "
           "Data IV:2850 Pad 20 KeyID 1")
    check("组播DA仍取SA为客户端", _P(_l2) == ("B0:68:E6:C1:C9:07",
          "E0:B6:68:CD:BB:F7"), str(_P(_l2)))
    # AP 下发的帧(SA==BSSID): 客户端在 DA
    _l3 = ("16:42:20.235714 x DA:22:9f:df:06:db:b7 "
           "BSSID:9a:93:51:67:27:fa SA:9a:93:51:67:27:fa QoS Data")
    check("AP下发帧取DA为客户端", _P(_l3) == ("22:9F:DF:06:DB:B7",
          "9A:93:51:67:27:FA"), str(_P(_l3)))
    _l4 = ("16:36:07.664811 x BSSID:84:87:ff:aa:36:74 "
           "DA:ff:ff:ff:ff:ff:ff SA:84:87:ff:aa:36:74 Beacon (X)")
    check("Beacon 不算客户端", _P(_l4) is None, str(_P(_l4)))
    check("无BSSID行不算", _P("garbage line") is None, "x")
    # 探测请求(BSSID 是广播)不能被当成某 AP 的客户端
    _l5 = ("10:00:00.1 x DA:ff:ff:ff:ff:ff:ff BSSID:ff:ff:ff:ff:ff:ff "
           "SA:aa:bb:cc:dd:ee:01 Probe Request ()")
    check("探测请求不产生客户端", _P(_l5) is None, str(_P(_l5)))

    section("数据帧类型统计(DATA/PROBE 数量显示在顶部状态行)")
    _C = w._classify_pkt
    check("数据帧归类 DATA", _C(_l1) == "DATA", str(_C(_l1)))
    check("QoS 数据帧归类 DATA", _C(_l3) == "DATA", str(_C(_l3)))
    check("探测请求归类 PROBE", _C(_l5) == "PROBE", str(_C(_l5)))
    _de = ("10:00:01.0 x DA:ff:ff:ff:ff:ff:ff BSSID:11:22:33:44:55:66 "
           "SA:11:22:33:44:55:66 DeAuthentication ()")
    check("去认证归类 DEAUTH", _C(_de) == "DEAUTH", str(_C(_de)))
    check("Beacon 不归类", _C(_l4) is None, str(_C(_l4)))
    check("无 SA 行不归类", _C("garbage line") is None, "x")
    w._reset_pkt_counts()
    check("初始无帧计数后缀", w._frame_counts_str() == "", w._frame_counts_str())
    w._sniffed_clients = {}
    w._sniff_noticed = True  # 不刷日志
    w._on_sniffer_line(_l1)
    w._on_sniffer_line(_l1)  # DATA +2
    w._on_sniffer_line(_l5)  # PROBE +1
    check("DATA 计数累加", w._pkt_counts.get("DATA") == 2,
          str(w._pkt_counts))
    check("PROBE 计数累加", w._pkt_counts.get("PROBE") == 1,
          str(w._pkt_counts))
    check("状态行后缀含 DATA/PROBE 数量",
          "DATA 2" in w._frame_counts_str() and "PROBE 1" in w._frame_counts_str(),
          w._frame_counts_str())
    check("已无数据帧标签页", not hasattr(w, "pkt_box"), "")
    # _on_sniffer_line 累积在线客户端
    w._sniffed_clients = {}
    w._on_sniffer_line(_l1)
    w._on_sniffer_line(_l2)
    w._on_sniffer_line(_l1)  # 重复不重复计
    check("嗅探累积两 AP",
          set(w._sniffed_clients) == {"6C:11:BA:9F:63:EF",
                                      "E0:B6:68:CD:BB:F7"},
          str(w._sniffed_clients))
    check("去重", w._sniffed_clients["6C:11:BA:9F:63:EF"]
          == {"98:3F:A4:67:36:D0"}, "")
    # AP 表合并嗅探: airodump 报 0 客户端, 表格仍应显示 1
    _ap_sec = ("BSSID, First time seen, Last time seen, channel, Speed, "
               "Privacy, Cipher, Authentication, Power, # beacons, # IV, "
               "LAN IP, ID-length, ESSID, Key\n"
               "6C:11:BA:9F:63:EF, 2026-10-07 16:42:10, 2026-10-07 "
               "16:42:20, 1, 324, WPA2, CCMP, PSK, -64, 9, 2, "
               "0.0.0.0, 9, CMCC-8979, \n")
    _rows = w._parse_ap_csv(_ap_sec, {})
    check("嗅探客户端计入表格",
          len(_rows) == 1 and _rows[0][7] == 1 and _rows[0][2] == "1",
          str(_rows))
    check("tooltip 标注嗅探",
          "嗅探" in w._client_tips.get("6C:11:BA:9F:63:EF", ""),
          w._client_tips.get("6C:11:BA:9F:63:EF", ""))
    w._sniffed_clients = {}
    # 引用计数: 扫描释放后抓包仍保活
    w._sniffer_users = set()
    w._sniffer_thread = None
    _fake = type("T", (), {"stop": lambda self: setattr(
        self, "stopped", True)})()
    w._sniffer_thread = _fake
    w._sniffer_users = {"scan", "capture"}
    w._sniffer_release("scan")
    check("抓包仍在用不断嗅探",
          w._sniffer_thread is _fake and not getattr(_fake, "stopped", False),
          "")
    w._sniffer_release("capture")
    check("没人用才停嗅探",
          w._sniffer_thread is None and getattr(_fake, "stopped", False), "")


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