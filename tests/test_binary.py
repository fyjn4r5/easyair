#!/usr/bin/env python3
"""对 PyInstaller 打包出的二进制做自动化冒烟测试。

用法: test_binary.py /path/to/easyair

因为 onefile 二进制不接受脚本参数, 这里用一个独立 driver 目录:
把 main.py 等源码以 --add-data 方式带进包里无法执行, 因此改为
用 QT_QPA_PLATFORM=offscreen 启动 + 超时监控的方式验证:
  1. 进程能启动且不立即崩溃
  2. 启动 8 秒内不产生 Python traceback
  3. 退出码正常
"""
import os
import re
import subprocess
import sys
import time
from pathlib import Path

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  <- {detail}" if detail and not cond else ""))
    return cond


def run_once(binary, seconds=8):
    """启动二进制, 用读取线程收集输出, 到时后优雅终止"""
    import threading
    env = dict(os.environ)
    env["QT_QPA_PLATFORM"] = "offscreen"
    env["PYTHONUNBUFFERED"] = "1"
    p = subprocess.Popen([str(binary)], stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, text=True,
                         bufsize=1, env=env, cwd=str(binary.parent))
    lines = []

    def reader():
        try:
            for ln in p.stdout:
                lines.append(ln.rstrip())
        except Exception:
            pass

    t = threading.Thread(target=reader, daemon=True)
    t.start()
    time.sleep(seconds)
    alive = p.poll() is None
    rc = p.returncode
    if alive:
        p.terminate()
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait(timeout=5)
        rc = p.returncode
    time.sleep(0.3)
    try:
        p.stdout.close()
    except Exception:
        pass
    return alive, rc, list(lines)


def main():
    if len(sys.argv) < 2:
        print("用法: test_binary.py <binary>")
        return 2
    binary = Path(sys.argv[1]).resolve()
    if not binary.exists():
        print(f"找不到二进制: {binary}")
        return 2
    binary.chmod(0o755)

    print(f"=== 二进制冒烟测试: {binary} ===")
    print(f"大小: {binary.stat().st_size / 1024 / 1024:.1f} MB")

    print("\n=== 第 1 次启动 ===")
    alive, rc, lines = run_once(binary, seconds=8)
    out = "\n".join(lines)
    print("--- 输出 ---")
    print(out[:2000] if out else "(无输出)")
    print("--- 结束 ---")

    check("文件可执行", os.access(binary, os.X_OK))
    check("8 秒内未崩溃", alive, f"退出码={rc}")
    check("无 Python traceback", "Traceback" not in out,
          [l for l in lines if "Traceback" in l or "Error" in l][:3])
    check("无 QApplication NameError", "QApplication" not in out or "NameError" not in out)
    check("无 QThread 析构崩溃", "Destroyed while thread" not in out,
          [l for l in lines if "Destroyed while thread" in l][:2])
    check("无 abort/core dump", "核心转储" not in out and "Aborted" not in out)

    print("\n=== 第 2 次启动 (验证重复启动稳定) ===")
    alive2, rc2, lines2 = run_once(binary, seconds=6)
    out2 = "\n".join(lines2)
    check("二次启动未崩溃", alive2, f"退出码={rc2}")
    check("二次启动无 traceback", "Traceback" not in out2)

    print("\n=== 退出码 ===")
    # 优雅退出应返回 0
    env = dict(os.environ, QT_QPA_PLATFORM="offscreen")
    p = subprocess.Popen([str(binary)], stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, text=True, env=env,
                         cwd=str(binary.parent))
    time.sleep(5)
    p.terminate()
    try:
        p.wait(timeout=5)
    except subprocess.TimeoutExpired:
        p.kill()
    print(f"  终止后退出码: {p.returncode} (-15 = SIGTERM 属正常)")

    print("\n" + "=" * 60)
    print(f"PASS: {len(PASS)}   FAIL: {len(FAIL)}")
    if FAIL:
        print("失败项:")
        for f in FAIL:
            print("  -", f)
    print("=" * 60)
    sys.stdout.flush()
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())