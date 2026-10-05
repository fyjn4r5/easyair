import os
import re
import json
import subprocess
import shlex
import time
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
        self._password_verified = False

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
                except Exception:
                    self._sudo_password = content
                    return self._sudo_password
            except Exception:
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
        except Exception:
            return False

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
            res = subprocess.run(["iw", "dev"], capture_output=True, text=True, encoding='utf-8', errors='replace')
            if res.returncode != 0:
                return []
            return re.findall(r'Interface\s+(\w+)', res.stdout)
        except Exception:
            return []

    def get_monitor_interface(self, iface: str) -> Optional[str]:
        """获取对应的监听模式接口名（可能同名）"""
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
        return None  # 不再假设一定是 iface+mon

    def check_monitor_mode(self, iface: str) -> bool:
        """检查接口是否已在监听模式"""
        try:
            res = subprocess.run(["iwconfig", iface], capture_output=True, text=True, encoding='utf-8', errors='replace')
            return "Mode:Monitor" in res.stdout
        except Exception:
            return False

    def _cleanup_monitor(self, iface: str):
        """清理可能残留的监听接口"""
        mon = self.get_monitor_interface(iface)
        if mon and mon != iface:
            try:
                subprocess.run(["sudo", "airmon-ng", "stop", mon], capture_output=True, timeout=5)
            except Exception:
                pass
        try:
            subprocess.run(["sudo", "airmon-ng", "stop", iface], capture_output=True, timeout=5)
        except Exception:
            pass

    def start_monitor(self, iface: str):
        """开启监听模式"""
        self.log(f"[监听模式] 准备开启: {iface}")
        
        # 1. 先清理残留
        self._cleanup_monitor(iface)
        time.sleep(0.5)
        
        # 2. 检查是否已经在监听模式
        if self.check_monitor_mode(iface):
            self.log(f"[监听模式] {iface} 已经是 Monitor 模式")
            return subprocess.Popen(["echo", "already_monitor"], stdout=subprocess.PIPE, text=True)
        
        # 3. 杀掉干扰进程
        self._run_sudo_cmd("airmon-ng check kill").wait()
        
        # 4. 启动监听模式
        self.log(f"[监听模式] 执行: airmon-ng start {iface}")
        p = self._run_sudo_cmd(f"airmon-ng start {iface}")
        return p

    def stop_monitor(self, mon_iface: str):
        """关闭监听模式"""
        self.log(f"[监听模式] 关闭: {mon_iface}")
        p = self._run_sudo_cmd(f"airmon-ng stop {mon_iface}")
        return p

    def ensure_monitor(self, iface: str) -> Tuple[bool, str]:
        """确保接口在监听模式，返回(成功, 监听接口名)"""
        self._password_verified = False
        
        # 先清理
        self._cleanup_monitor(iface)
        time.sleep(0.3)
        
        # 检查物理接口是否已是监听模式
        if self.check_monitor_mode(iface):
            return True, iface
        
        # 启动
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
        
        # 关键：先检查原接口是否变成了 monitor 模式（rtl8723be 等驱动不改名）
        if self.check_monitor_mode(iface):
            self.log(f"[监听模式] 成功: {iface} (原接口直接切换)")
            return True, iface
        
        # 再检查是否生成了新的 mon 接口
        mon = self.get_monitor_interface(iface)
        if mon and self.check_monitor_mode(mon):
            self.log(f"[监听模式] 成功开启新接口: {mon}")
            return True, mon
        
        # 兜底：从输出中提取
        for line in output_lines:
            if "monitor mode enabled" in line.lower():
                match = re.search(r'(\w+mon\d*)', line)
                if match:
                    mon = match.group(1)
                    if self.check_monitor_mode(mon):
                        self.log(f"[监听模式] 从输出解析到: {mon}")
                        return True, mon
                # 输出里没 mon 但说 enabled，可能是原接口
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
