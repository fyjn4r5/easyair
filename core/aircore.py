import os
import re
import json
import subprocess
import shlex
import time
import binascii
from pathlib import Path
from typing import List, Optional, Tuple

CONFIG_FILE = Path(__file__).parent.parent / "config" / "settings.json"
HISTORY_FILE = Path(__file__).parent.parent / "config" / "history.json"
PAS_FILE = Path.home() / ".Pas"

import datetime


def today_str() -> str:
    return datetime.date.today().isoformat()

class AirCore:
    def __init__(self, base_dir: Path):
        self.base_dir = Path(base_dir)
        self.caps_dir = self.base_dir / "captures"
        self.wordlists_dir = self.base_dir / "wordlists"
        self.config_dir = self.base_dir / "config"
        self.caps_dir.mkdir(exist_ok=True)
        self.wordlists_dir.mkdir(exist_ok=True)
        self.config_dir.mkdir(exist_ok=True)
        self._load_config()
        self._sudo_password = None
        self._password_verified = False

    def _load_config(self):
        self.config = {
            "wordlists": [],
            "use_gpu": True,
            "hashcat_extra_args": "",
            "auto_monitor": True,
            "scan_auto_stop": 0,
            "crack_engine": "Hashcat (GPU/CPU)",
            "crack_device": "GPU + CPU (自动)",
        }
        if CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE) as f:
                    self.config.update(json.load(f))
            except (json.JSONDecodeError, OSError):
                pass

    def save_config(self):
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(self.config, f, indent=2)
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
        for cap in self.caps_dir.glob("handshake*.cap"):
            try:
                st = cap.stat()
            except OSError:
                continue
            day = datetime.date.fromtimestamp(st.st_mtime).isoformat()
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

    def airodump_scan(self, mon_iface: str, outfile_prefix: str = "scan"):
        outpath = self.caps_dir / outfile_prefix
        cmd = f"airodump-ng {mon_iface} --write-interval 1 --output-format csv -w {outpath}"
        return self.run_cmd(cmd, sudo=True)

    def airodump_capture(self, mon_iface: str, bssid: str, ch: str, outfile_prefix: str = "handshake"):
        outpath = self.caps_dir / outfile_prefix
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

    def crack_hashcat(self, hc_file: str, wordlists: List[str], use_gpu: bool = True, extra_args: str = ""):
        device_arg = "-D 1,2" if use_gpu else "-D 1"
        wl_args = " ".join(f"'{w}'" for w in wordlists)
        cmd = f"hashcat -m 22000 {device_arg} {extra_args} '{hc_file}' {wl_args}"
        return self.run_cmd(cmd)

    def get_latest_handshake(self) -> Optional[Path]:
        caps = list(self.caps_dir.glob("handshake-*.cap"))
        if not caps:
            return None
        return max(caps, key=lambda x: x.stat().st_mtime)

    def log(self, msg: str):
        print(msg)
