import os
import re
import json
import subprocess
import shlex
from pathlib import Path
from typing import List, Optional, Tuple

CONFIG_FILE = Path(__file__).parent.parent / "config" / "settings.json"
PAS_FILE = Path.home() / ".Pas"

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

    def _load_config(self):
        self.config = {
            "wordlists": [],
            "use_gpu": True,
            "hashcat_extra_args": "",
            "auto_monitor": True,
        }
        if CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE) as f:
                    self.config.update(json.load(f))
            except Exception:
                pass

    def save_config(self):
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
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

    def _get_sudo_password(self) -> Optional[str]:
        """尝试从 ~/.Pas 读取密码（简单加密或明文），失败返回 None"""
        if self._sudo_password:
            return self._sudo_password
        if PAS_FILE.exists():
            try:
                content = PAS_FILE.read_text(encoding='utf-8', errors='ignore').strip()
                # 简单尝试：如果是 base64 解码
                import base64
                try:
                    decoded = base64.b64decode(content).decode('utf-8')
                    self._sudo_password = decoded.strip()
                    return self._sudo_password
                except Exception:
                    # 当作明文
                    self._sudo_password = content
                    return self._sudo_password
            except Exception:
                pass
        return None

    def run_cmd(self, cmd: str, sudo: bool = False, shell: bool = False):
        if sudo and not str(cmd).startswith(("pkexec", "sudo")):
            pwd = self._get_sudo_password()
            if pwd:
                # 使用 sudo -S 从 stdin 读取密码
                cmd = f"echo '{pwd}' | sudo -S {cmd}"
            else:
                cmd = f"pkexec {cmd}"
        if not shell and isinstance(cmd, str):
            cmd = shlex.split(cmd)
        # 使用 locale 编码防止中文乱码
        return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, 
                                text=True, bufsize=1, encoding='utf-8', errors='replace')

    def list_interfaces(self) -> List[str]:
        try:
            res = subprocess.run(["iw", "dev"], capture_output=True, text=True, encoding='utf-8', errors='replace')
            if res.returncode != 0:
                return []
            return re.findall(r'Interface\s+(\w+)', res.stdout)
        except Exception:
            return []

    def get_monitor_interface(self, iface: str) -> Optional[str]:
        try:
            res = subprocess.run(["iw", "dev"], capture_output=True, text=True, encoding='utf-8', errors='replace')
            for line in res.stdout.splitlines():
                if iface in line and "mon" in line:
                    parts = line.split()
                    for p in parts:
                        if p.startswith(iface) and "mon" in p:
                            return p
        except Exception:
            pass
        return f"{iface}mon"

    def start_monitor(self, iface: str):
        self.log(f"[监听模式] 开启: {iface}")
        p = self.run_cmd(f"airmon-ng start {iface}", sudo=True)
        return p

    def stop_monitor(self, mon_iface: str):
        self.log(f"[监听模式] 关闭: {mon_iface}")
        p = self.run_cmd(f"airmon-ng stop {mon_iface}", sudo=True)
        return p

    def check_monitor_mode(self, iface: str) -> bool:
        try:
            res = subprocess.run(["iwconfig", iface], capture_output=True, text=True, encoding='utf-8', errors='replace')
            return "Mode:Monitor" in res.stdout
        except Exception:
            return False

    def ensure_monitor(self, iface: str) -> Tuple[bool, str]:
        if self.check_monitor_mode(iface):
            return True, iface
        p = self.start_monitor(iface)
        for _ in p.stdout:
            pass
        p.wait()
        mon = self.get_monitor_interface(iface)
        if mon and self.check_monitor_mode(mon):
            return True, mon
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
