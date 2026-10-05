import os
import re
import sys
import json
import shutil
import subprocess
import shlex
import time
import binascii
from pathlib import Path
from typing import List, Optional, Tuple

APP_NAME = "easyair"


def _data_dir() -> Path:
    """数据目录。

    打包成 onefile 后 `__file__` 位于 PyInstaller 的临时解压目录
    (/tmp/_MEIxxxxxx/), 重启即被删除 —— 配置/历史/抓包都会丢失。
    因此打包后一律放到用户主目录下的固定路径。"""
    if getattr(sys, "frozen", False):
        return Path.home() / f".{APP_NAME}"
    return Path(__file__).parent.parent


CONFIG_FILE = _data_dir() / "config" / "settings.json"
HISTORY_FILE = _data_dir() / "config" / "history.json"
PAS_FILE = Path.home() / ".Pas"

import datetime


def today_str() -> str:
    return datetime.date.today().isoformat()

class AirCore:
    def __init__(self, base_dir: Optional[Path] = None):
        self.base_dir = Path(base_dir) if base_dir else _data_dir()
        self.caps_dir = self.base_dir / "captures"
        self.wordlists_dir = self.base_dir / "wordlists"
        self.config_dir = self.base_dir / "config"
        # 必须 parents=True: 打包后 ~/.easyair 尚不存在时,
        # 否则 mkdir 会抛 FileNotFoundError 导致启动即崩溃
        for d in (self.caps_dir, self.wordlists_dir, self.config_dir):
            try:
                d.mkdir(parents=True, exist_ok=True)
            except OSError as e:  # 只读目录等极端情况不应阻止启动
                print(f"[目录创建失败] {d}: {e}")
        self._load_config()
        self._sudo_password = None
        self._password_verified = False

    def _load_config(self):
        self.config = {
            "wordlists": [],
            "use_gpu": True,
            "hashcat_extra_args": "",
            "auto_monitor": True,
            "scan_auto_stop": 45,
            "hashcat_temp_limit": 85,
            "crack_engine": "Hashcat (GPU/CPU)",
            "crack_device": "GPU + CPU (自动)",
        }
        if CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE) as f:
                    saved = json.load(f)
                self.config.update(saved)
                # 迁移: 早期默认是不自动停止(0), 配置文件里存了 0 会一直
                # 覆盖新默认值 45, 导致用户永远看不到倒计时。只在"从没
                # 主动设置过"的情况下补默认值, 用户自己设成 0 的尊重。
                if not saved.get("scan_auto_stop_explicit") and \
                        int(saved.get("scan_auto_stop", 0) or 0) == 0:
                    self.config["scan_auto_stop"] = 45
            except (json.JSONDecodeError, OSError, ValueError):
                pass

    def save_config(self):
        try:
            CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
            with open(CONFIG_FILE, 'w') as f:
                json.dump(self.config, f, indent=2, ensure_ascii=False)
        except OSError as e:
            print(f"[配置保存失败] {e}")

    def add_wordlist(self, path: str):
        p = str(Path(path).resolve())
        if p not in self.config["wordlists"]:
            self.config["wordlists"].append(p)
            self.save_config()

    def remove_wordlist(self, path: str):
        if path in self.config["wordlists"]:
            self.config["wordlists"].remove(path)
            self.save_config()

    def clear_wordlists(self):
        self.config["wordlists"] = []
        self.save_config()

    def reorder_wordlists(self, paths: List[str]):
        self.config["wordlists"] = paths
        self.save_config()

    def get_wordlists(self) -> List[str]:
        return [p for p in self.config["wordlists"] if Path(p).exists()]

    def set_use_gpu(self, use_gpu: bool):
        self.config["use_gpu"] = use_gpu
        self.save_config()

    def set_hashcat_extra_args(self, args: str):
        self.config["hashcat_extra_args"] = args
        self.save_config()

    # ===== 历史记录（按日期归类）=====
    def load_history(self) -> dict:
        if not HISTORY_FILE.exists():
            return {}
        try:
            with open(HISTORY_FILE, encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, dict) else {}
        except (json.JSONDecodeError, OSError):
            return {}

    def save_history(self, data: dict):
        try:
            with open(HISTORY_FILE, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except OSError as e:
            print(f"[历史保存失败] {e}")

    def history_dates(self) -> List[str]:
        return sorted(self.load_history().keys(), reverse=True)

    def history_records(self, date: str) -> List[dict]:
        return self.load_history().get(date, [])

    def history_add(self, date: str, record: dict):
        data = self.load_history()
        data.setdefault(date, []).append(record)
        self.save_history(data)

    def history_update(self, date: str, index: int, record: dict):
        data = self.load_history()
        if date in data and 0 <= index < len(data[date]):
            data[date][index] = record
            self.save_history(data)

    def history_delete(self, date: str, index: int) -> bool:
        data = self.load_history()
        if date in data and 0 <= index < len(data[date]):
            data[date].pop(index)
            if not data[date]:
                data.pop(date)
            self.save_history(data)
            return True
        return False

    def list_handshakes(self) -> List[Tuple[str, Path, int]]:
        """按日期倒序返回 (日期, 路径, 大小)"""
        out = []
        caps = list(self.caps_dir.glob("handshake*.cap"))
        for sub in sorted(self.caps_dir.glob("20??-??-??")):
            if sub.is_dir():
                caps.extend(sub.glob("handshake*.cap"))
        for cap in caps:
            try:
                st = cap.stat()
            except OSError:
                continue
            # 目录名即日期(抓包当天), 比文件 mtime 更可靠
            day = (cap.parent.name if cap.parent != self.caps_dir
                   else datetime.date.fromtimestamp(st.st_mtime).isoformat())
            out.append((day, cap, st.st_size, st.st_mtime))
        out.sort(key=lambda x: (x[0], x[3]), reverse=True)
        return [(d, p, s) for d, p, s, _ in out]

    def _get_sudo_password(self) -> Optional[str]:
        if self._sudo_password:
            return self._sudo_password
        if PAS_FILE.exists():
            try:
                content = PAS_FILE.read_text(encoding='utf-8', errors='ignore').strip()
                import base64
                try:
                    decoded = base64.b64decode(content).decode('utf-8')
                    self._sudo_password = decoded.strip()
                    return self._sudo_password
                except (binascii.Error, UnicodeDecodeError, ValueError):
                    self._sudo_password = content
                    return self._sudo_password
            except OSError:
                pass
        return None

    def _verify_sudo_password(self, pwd: str) -> bool:
        try:
            proc = subprocess.run(
                ["sudo", "-S", "-v"],
                input=pwd + "\n",
                capture_output=True,
                text=True,
                timeout=5
            )
            return proc.returncode == 0
        except (subprocess.TimeoutExpired, OSError, ValueError):
            return False

    def _run_sudo(self, args: List[str]) -> subprocess.CompletedProcess:
        pwd = self._get_sudo_password()
        if pwd and not self._password_verified:
            if self._verify_sudo_password(pwd):
                self._password_verified = True
                self.log(f"[sudo] 密码验证通过")
            else:
                self.log(f"[sudo] 密码验证失败")
                pwd = None
        
        if pwd:
            full_cmd = ["sudo", "-S", "-p", ""] + args
            return subprocess.run(
                full_cmd,
                input=pwd + "\n",
                capture_output=True,
                text=True,
                timeout=10,
                encoding='utf-8',
                errors='replace'
            )
        else:
            full_cmd = ["pkexec"] + args
            return subprocess.run(
                full_cmd,
                capture_output=True,
                text=True,
                timeout=10,
                encoding='utf-8',
                errors='replace'
            )

    def _run_sudo_cmd(self, cmd: str) -> subprocess.Popen:
        pwd = self._get_sudo_password()
        
        if pwd and not self._password_verified:
            if self._verify_sudo_password(pwd):
                self._password_verified = True
                self.log(f"[sudo] 密码验证通过")
            else:
                self.log(f"[sudo] 密码验证失败，将使用 pkexec")
                pwd = None
        
        if pwd:
            full_cmd = ["sudo", "-S", "-p", ""] + shlex.split(cmd)
            proc = subprocess.Popen(
                full_cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                encoding='utf-8',
                errors='replace'
            )
            proc.stdin.write(pwd + "\n")
            proc.stdin.close()
            return proc
        else:
            full_cmd = f"pkexec {cmd}"
            return subprocess.Popen(
                shlex.split(full_cmd),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                encoding='utf-8',
                errors='replace'
            )

    def run_cmd(self, cmd: str, sudo: bool = False, shell: bool = False):
        if sudo:
            return self._run_sudo_cmd(cmd)
        if not shell and isinstance(cmd, str):
            cmd = shlex.split(cmd)
        return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, 
                                text=True, bufsize=1, encoding='utf-8', errors='replace')

    def list_interfaces(self) -> List[str]:
        try:
            res = subprocess.run(["iw", "dev"], capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=5)
            if res.returncode != 0:
                return []
            return re.findall(r'Interface\s+(\w+)', res.stdout)
        except (subprocess.TimeoutExpired, OSError, ValueError):
            return []

    def get_monitor_interface(self, iface: str) -> Optional[str]:
        try:
            res = subprocess.run(["iw", "dev"], capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=5)
            for line in res.stdout.splitlines():
                if iface in line and "mon" in line:
                    parts = line.split()
                    for p in parts:
                        if p.startswith(iface) and "mon" in p:
                            return p
        except (subprocess.TimeoutExpired, OSError):
            pass
        return None

    def check_monitor_mode(self, iface: str) -> bool:
        try:
            res = subprocess.run(["iwconfig", iface], capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=5)
            if "Mode:Monitor" in res.stdout:
                return True
        except (subprocess.TimeoutExpired, OSError):
            pass
        try:
            res = subprocess.run(["iw", "dev", iface, "info"], capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=5)
            if "type monitor" in res.stdout:
                return True
        except (subprocess.TimeoutExpired, OSError):
            pass
        return False

    def _cleanup_monitor(self, iface: str):
        self.log(f"[清理] 检查残留监听接口: {iface}")
        
        mon = self.get_monitor_interface(iface)
        if mon and mon != iface:
            self.log(f"[清理] 停止残留 mon 接口: {mon}")
            self._run_sudo(["airmon-ng", "stop", mon])
        
        if self.check_monitor_mode(iface):
            self.log(f"[清理] 停止物理接口 monitor 模式: {iface}")
            self._run_sudo(["airmon-ng", "stop", iface])
        
        time.sleep(0.5)

    def start_monitor(self, iface: str):
        self.log(f"[监听模式] 准备开启: {iface}")
        
        self._cleanup_monitor(iface)
        
        if self.check_monitor_mode(iface):
            self.log(f"[监听模式] {iface} 清理后仍是 Monitor 模式，直接使用")
            return subprocess.Popen(["echo", "ALREADY_MONITOR"], stdout=subprocess.PIPE, text=True)
        
        self.log(f"[监听模式] 杀掉干扰进程...")
        self._run_sudo(["airmon-ng", "check", "kill"])
        
        self.log(f"[监听模式] 执行: airmon-ng start {iface}")
        p = self._run_sudo_cmd(f"airmon-ng start {iface}")
        return p

    def stop_monitor(self, mon_iface: str):
        self.log(f"[监听模式] 关闭: {mon_iface}")
        p = self._run_sudo_cmd(f"airmon-ng stop {mon_iface}")
        return p

    def ensure_monitor(self, iface: str) -> Tuple[bool, str]:
        self._password_verified = False
        self.log(f"[监听模式] 确保 {iface} 进入监听模式...")
        
        self._cleanup_monitor(iface)
        
        if self.check_monitor_mode(iface):
            self.log(f"[监听模式] {iface} 已经是 Monitor 模式，直接使用")
            return True, iface
        
        p = self.start_monitor(iface)
        start_time = time.time()
        output_lines = []
        while time.time() - start_time < 15:
            line = p.stdout.readline()
            if not line and p.poll() is not None:
                break
            if line:
                output_lines.append(line.strip())
                self.log(line.strip())
            time.sleep(0.1)
        p.wait()
        
        if self.check_monitor_mode(iface):
            self.log(f"[监听模式] 成功: {iface} (原接口直接切换)")
            return True, iface
        
        mon = self.get_monitor_interface(iface)
        if mon and self.check_monitor_mode(mon):
            self.log(f"[监听模式] 成功开启新接口: {mon}")
            return True, mon
        
        for line in output_lines:
            if "monitor mode enabled" in line.lower():
                match = re.search(r'(\w+mon\d*)', line)
                if match:
                    mon = match.group(1)
                    if self.check_monitor_mode(mon):
                        self.log(f"[监听模式] 从输出解析到: {mon}")
                        return True, mon
                if self.check_monitor_mode(iface):
                    return True, iface
        
        self.log(f"[监听模式] 开启失败，输出: {output_lines}")
        return False, ""

    def can_elevate(self) -> bool:
        """能否取得 root 权限: 已是 root / 有缓存密码 / 有 pkexec"""
        if os.geteuid() == 0:
            return True
        if self._get_sudo_password():
            return True
        return bool(shutil.which("pkexec"))

    def airodump_scan(self, mon_iface: str, outfile_prefix: str = "scan"):
        outpath = self.caps_dir / outfile_prefix
        cmd = f"airodump-ng {mon_iface} --write-interval 1 --output-format csv -w {outpath}"
        return self.run_cmd(cmd, sudo=True)

    def cap_note(self, cap: Path) -> str:
        """读取握手包备注(存在同名 .note 旁文件, 不污染 .cap)。"""
        try:
            return Path(str(cap) + ".note").read_text(
                encoding="utf-8", errors="ignore").strip()
        except OSError:
            return ""

    def set_cap_note(self, cap: Path, note: str):
        p = Path(str(cap) + ".note")
        try:
            if note:
                p.write_text(note, encoding="utf-8")
            elif p.exists():
                p.unlink()
        except OSError as e:
            print(f"[备注保存失败] {e}")

    def _dated_dir(self) -> Path:
        """当日握手包目录: captures/YYYY-MM-DD/
        握手包是需要长期留存的证据, 按日期分目录便于整理与长期保存。"""
        d = self.caps_dir / datetime.date.today().isoformat()
        try:
            d.mkdir(parents=True, exist_ok=True)
        except OSError:
            return self.caps_dir
        return d

    def airodump_capture(self, mon_iface: str, bssid: str, ch: str, outfile_prefix: str = "handshake"):
        outpath = self._dated_dir() / outfile_prefix
        cmd = f"airodump-ng --bssid {bssid} --channel {ch} --output-format pcap,csv -w {outpath} {mon_iface}"
        return self.run_cmd(cmd, sudo=True)

    def deauth(self, mon_iface: str, bssid: str, count: int = 10):
        cmd = f"aireplay-ng --deauth {count} -a {bssid} {mon_iface}"
        return self.run_cmd(cmd, sudo=True)

    def crack_aircrack(self, cap_file: str, wordlist: str):
        cmd = f"aircrack-ng '{cap_file}' -w '{wordlist}'"
        return self.run_cmd(cmd)

    def cap_to_hc22000(self, cap_file: str, out_hc: Optional[str] = None):
        cap = Path(cap_file)
        if out_hc is None:
            out_hc = cap.with_suffix(".hc22000")
        cmd = f"hcxpcapngtool '{cap}' -o '{out_hc}'"
        return self.run_cmd(cmd)

    def crack_hashcat(self, hc_file: str, wordlists: List[str], use_gpu: bool = True,
                      extra_args: str = "", temp_limit: int = 0):
        """temp_limit>0 时附加 --hwmon-temp-abort, 达到温度上限自动中止,
        避免长时间破解把 GPU 烤坏(0 表示不限温)。"""
        device_arg = "-D 1,2" if use_gpu else "-D 1"
        wl_args = " ".join(f"'{w}'" for w in wordlists)
        hwmon = ""
        try:
            tl = int(temp_limit)
        except (TypeError, ValueError):
            tl = 0
        if tl > 0:
            hwmon = f"--hwmon-temp-abort={tl} "
        cmd = (f"hashcat -m 22000 {device_arg} {hwmon}{extra_args} "
               f"'{hc_file}' {wl_args}")
        return self.run_cmd(cmd)

    def get_latest_handshake(self) -> Optional[Path]:
        caps = list(self.caps_dir.glob("handshake-*.cap"))
        for sub in sorted(self.caps_dir.glob("20??-??-??"), reverse=True):
            if sub.is_dir():
                caps.extend(sub.glob("handshake-*.cap"))
        if not caps:
            return None
        if not caps:
            return None
        return max(caps, key=lambda x: x.stat().st_mtime)

    def log(self, msg: str):
        print(msg)
