#!/usr/bin/env python3
"""监听模式 + 扫描 独立诊断脚本

不依赖 PyQt / 不依赖主程序, 直接调 airmon-ng 与 airodump-ng,
用来判断「扫描不出 WIFI」到底是驱动、监听模式、还是权限问题。

用法:
    python3 tools/diagnose_scan.py                 # 自动挑网卡, 扫 15 秒
    python3 tools/diagnose_scan.py -i wlan0 -s 30  # 指定网卡与时长

退出码: 0=扫描正常  1=未检测到网卡  2=监听模式失败  3=扫描抓到 0 个 AP
"""

import argparse
import csv
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

OK, NO_IFACE, NO_MON, NO_AP = 0, 1, 2, 3

# 已通过验证的 root 执行包装, 由 require_root() 填充
SUDO = []


def hr(title=""):
    if title:
        print(f"\n\033[1m── {title} \033[0m" + "─" * max(0, 46 - len(title)))
    else:
        print("─" * 56)


def step(n, msg):
    print(f"\033[36m[{n}]\033[0m {msg}")


def ok(msg):
    print(f"    \033[32m✓\033[0m {msg}")


def bad(msg):
    print(f"    \033[31m✗\033[0m {msg}")


def warn(msg):
    print(f"    \033[33m!\033[0m {msg}")


def run(cmd, timeout=10, sudo=False):
    """执行命令, 返回 (returncode, stdout+stderr)"""
    if sudo:
        cmd = SUDO + cmd
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, encoding="utf-8", errors="replace")
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except FileNotFoundError:
        return 127, f"{cmd[0]}: 未安装"
    except subprocess.TimeoutExpired:
        return 124, f"{cmd[0]}: 执行超时"


def require_root():
    """确认可以拿到 root。非 TTY 环境则退回读取密码后用 sudo -S。"""
    global SUDO
    if os.geteuid() == 0:
        SUDO = []
        return True

    hr("权限")
    step(1, "当前不是 root, 需要 root 才能抓包")

    if sys.stdin.isatty():
        rc, _ = run(["sudo", "-v"], timeout=60)
        if rc == 0:
            SUDO = ["sudo", "-n"]
            ok("sudo 已授权")
            return True

    # 无 TTY: 要密码走 sudo -S
    warn("当前没有交互终端, 请输入 sudo 密码")
    try:
        import getpass
        pwd = getpass.getpass("sudo 密码: ")
    except (EOFError, KeyboardInterrupt):
        bad("未提供密码")
        return False

    rc, out = run(["sudo", "-S", "-v"], timeout=30)
    proc = subprocess.run(["sudo", "-S", "-v"], input=pwd + "\n",
                          capture_output=True, text=True, timeout=30)
    if proc.returncode != 0:
        bad("sudo 密码错误")
        print("      " + (proc.stderr or proc.stdout).strip()[:200])
        return False
    ok("sudo 密码正确")
    SUDO = ["sudo", "-S", "-p", ""]
    global _SUDO_PWD
    _SUDO_PWD = pwd
    return True


_SUDO_PWD = None


def popen(cmd, sudo=False):
    """Popen 版本, 带 sudo -S 时自动喂密码"""
    if sudo:
        cmd = SUDO + cmd
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, bufsize=1, encoding="utf-8",
                            errors="replace")
    if SUDO and _SUDO_PWD:
        try:
            proc.stdin = subprocess.PIPE
            proc.stdin.write(_SUDO_PWD + "\n")
            proc.stdin.flush()
            proc.stdin.close()
        except (OSError, ValueError):
            pass
    return proc


def list_ifaces():
    """从 iw dev 解析接口名"""
    rc, out = run(["iw", "dev"])
    if rc != 0:
        return []
    return re.findall(r"Interface\s+(\S+)", out)


def phy_of(iface):
    """取接口所属 phy, 如 phy0"""
    rc, out = run(["iw", "dev"])
    phy = None
    for line in out.splitlines():
        m = re.match(r"phy#(\d+)", line.strip())
        if m:
            phy = f"phy{m.group(1)}"
        if re.search(rf"Interface\s+{re.escape(iface)}\b", line):
            break
    return phy


def driver_of(iface):
    rc, out = run(["ethtool", "-i", iface])
    if rc == 0:
        m = re.search(r"driver:\s*(\S+)", out)
        if m:
            return m.group(1)
    return ""


def is_monitor(iface):
    """接口当前是否处于 monitor 模式"""
    rc, out = run(["iwconfig", iface])
    if rc == 0 and "Mode:Monitor" in out:
        return True
    rc, out = run(["iw", "dev", iface, "info"])
    return rc == 0 and "type monitor" in out


def mon_iface_for(iface):
    """airmon-ng 启动后, 找实际承载 monitor 模式的接口"""
    if is_monitor(iface):
        return iface
    rc, out = run(["iw", "dev"])
    for line in out.splitlines():
        m = re.search(r"Interface\s+(\S+)", line)
        if not m:
            continue
        name = m.group(1)
        if name != iface and "mon" in name and iface in name:
            if is_monitor(name):
                return name
    for cand in list_ifaces():
        if cand != iface and "mon" in cand:
            if is_monitor(cand):
                return cand
    return ""


def enable_monitor(iface):
    hr("开启监听模式")
    step(1, f"检查 {iface} 是否已处于监听模式")
    if is_monitor(iface):
        ok(f"{iface} 已经是 monitor 模式, 无需开启")
        return iface

    step(2, "调用 airmon-ng start")
    rc, out = run(["airmon-ng", "start", iface], timeout=30, sudo=True)
    print("      " + "\n      ".join(
        [l for l in out.splitlines() if l.strip()][:6]))

    step(3, "确认实际的 monitor 接口")
    mon = mon_iface_for(iface)
    if not mon:
        bad(f"{iface} 没有进入 monitor 模式")
        warn("常见原因: 网卡驱动不支持监听模式 / 虚拟机未直通网卡")
        return ""
    ok(f"监听接口 = {mon}")
    return mon


def stop_monitor(iface):
    run(["airmon-ng", "stop", iface], timeout=20, sudo=True)


def scan(mon, seconds):
    """跑 airodump-ng, 返回解析到的 AP 列表"""
    step(1, f"airodump-ng 扫描 {mon}, 持续 {seconds} 秒")
    tmp = Path(tempfile.mkdtemp(prefix="easyair-diag-"))
    prefix = tmp / "diag"

    try:
        proc = popen(["airodump-ng", mon, "--output-format", "csv",
                      "-w", str(prefix)], sudo=True)
    except FileNotFoundError:
        bad("airodump-ng 未安装")
        return [], "", tmp

    deadline = time.time() + seconds
    tail = []
    import threading

    def reader():
        try:
            for line in proc.stdout:
                tail.append(line.rstrip())
                del tail[:-15]
        except (OSError, ValueError):
            pass

    th = threading.Thread(target=reader, daemon=True)
    th.start()

    last = 0.0
    while time.time() < deadline:
        time.sleep(0.5)
        rows = read_csv(prefix)
        if rows and len(rows) != last:
            last = len(rows)
            print(f"    \033[32m✓\033[0m 已捕获 {len(rows)} 个 AP …")
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()

    rows = read_csv(prefix)
    beacon = 0
    for r in rows:
        try:
            if int(r.get("Beacon") or -1) > -60:
                beacon += 1
        except ValueError:
            pass
    return rows, "\n".join(tail), tmp


def read_csv(prefix):
    """读取 airodump 写出的 scan CSV"""
    for f in sorted(prefix.parent.glob(prefix.name + "*.csv")):
        try:
            with open(f, newline="", encoding="utf-8", errors="replace") as fp:
                return list(csv.DictReader(fp))
        except OSError:
            return []
    return []


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-i", "--iface", help="指定网卡, 默认自动选择")
    ap.add_argument("-s", "--seconds", type=int, default=15, help="扫描秒数")
    ap.add_argument("-k", "--keep", action="store_true", help="结束后不关闭监听")
    args = ap.parse_args()

    print("\033[1mEasyAir 监听模式 / 扫描诊断\033[0m")
    print(f"时间: {time.strftime('%Y-%m-%d %H:%M:%S')}   扫描时长: {args.seconds}s")

    hr("环境检查")
    step(1, "依赖工具")
    for tool, pkg in (("iw", "iw"), ("airmon-ng", "aircrack-ng"),
                      ("airodump-ng", "aircrack-ng")):
        p = shutil.which(tool)
        (ok if p else bad)(f"{tool:11s} {p or '未安装  → sudo apt install ' + pkg}")

    if not shutil.which("airodump-ng") or not shutil.which("airmon-ng"):
        print("\n结论: 缺少必要工具, 请先安装后重试")
        return NO_MON

    step(2, "无线网卡")
    ifaces = list_ifaces()
    if not ifaces:
        bad("未检测到任何无线接口")
        warn("虚拟机需直通 USB 无线网卡; 确认内核模块已加载(lsmod | grep rtl)")
        return NO_IFACE
    for i in ifaces:
        print(f"    · {i}   phy={phy_of(i)}   driver={driver_of(i) or '未知'}"
              f"   monitor={'是' if is_monitor(i) else '否'}")

    if not require_root():
        return NO_MON

    iface = args.iface or ifaces[0]
    if iface not in ifaces:
        bad(f"指定的网卡 {iface} 不存在, 可选: {', '.join(ifaces)}")
        return NO_IFACE
    print(f"\n使用网卡: \033[1m{iface}\033[0m")

    mon = enable_monitor(iface)
    if not mon:
        return NO_MON

    hr("扫描测试")
    rows, tail, tmp = scan(mon, args.seconds)

    if tail.strip():
        hr("airodump-ng 输出")
        for line in tail.splitlines():
            if re.search(r"monitor|error|fail|warn|chipset|unable", line, re.I):
                print(f"    {line}")

    hr("结果")
    if rows:
        ok(f"扫描正常, 共捕获 \033[1m{len(rows)}\033[0m 个 AP")
        print()
        print(f"    {'SSID':<22}{'BSSID':<20}{'CH':<5}{'ENC':<8}{'信号'}")
        print("    " + "─" * 66)
        for r in rows[:15]:
            print(f"    {(r.get('ESSID') or '(隐藏)')[:20]:<22}"
                  f"{(r.get('BSSID') or ''):<20}"
                  f"{(r.get('CH') or ''):<5}"
                  f"{(r.get('ENC') or ''):<8}"
                  f"{r.get('DBM') or r.get('POWER') or ''}")
        if len(rows) > 15:
            print(f"    … 另有 {len(rows) - 15} 个")
        print()
        print("\033[32m结论: 监听模式与扫描链路均正常, 问题在主程序或权限配置\033[0m")
        code = OK
    else:
        bad(f"{seconds} 秒内未捕获到任何 AP")
        print()
        print("    请按顺序排查:")
        print("      1) 附近是否有 2.4GHz 热点 —— 本机可能无信号")
        print("      2) 网卡是否支持监听模式 —— 部分 RTL/MTK 芯片需要专有驱动")
        print("      3) airodump 是否需要 -N 参数指定信道")
        print("      4) 虚拟机中 airodump 在宿主机执行更可靠")
        print(f"\n    CSV 目录: {tmp}")
        code = NO_AP

    if not args.keep and mon:
        hr("清理")
        stop_monitor(mon)
        ok(f"已关闭监听: {mon}")

    return code


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n已中断")
        sys.exit(1)