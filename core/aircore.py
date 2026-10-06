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
            # 默认关闭: airmon-ng check kill 会打断系统网络服务, 代价大
            "air_monitor_kill_conflicts": False,
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

    @staticmethod
    def _iter_caps(directory: Path):
        """列出目录下所有握手包, 与文件名无关(现在按 WiFi 名称命名)。"""
        return sorted(set(directory.glob("*.cap")) | set(directory.glob("*.pcap")))

    def list_handshakes(self) -> List[Tuple[str, Path, int]]:
        """按日期倒序返回 (日期, 路径, 大小)"""
        out = []
        # 文件名现在是 WiFi 名称, 因此不能按前缀匹配, 一律收 .cap/.pcap
        caps = list(self._iter_caps(self.caps_dir))
        for sub in sorted(self.caps_dir.glob("20??-??-??")):
            if sub.is_dir():
                caps.extend(self._iter_caps(sub))
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
                # 同 _run_sudo_cmd: 密码不可用时直接失败, 不用 pkexec 弹窗
                self.log(f"[sudo] 密码验证失败：请修正 ~/.Pas 中的密码后重试")
                raise PermissionError("sudo 密码验证失败")
        
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
            # 理论上不会走到(上面已 raise), 兜底不再用 pkexec 弹窗
            self.log(f"[sudo] 无可用提权方式，跳过: {' '.join(args)}")
            return subprocess.CompletedProcess(args, 1, "", "no privilege")

    def _run_sudo_cmd(self, cmd: str) -> subprocess.Popen:
        pwd = self._get_sudo_password()
        
        if pwd and not self._password_verified:
            if self._verify_sudo_password(pwd):
                self._password_verified = True
                self.log(f"[sudo] 密码验证通过")
            else:
                # 原来在这里回退 pkexec。密码不对时, 一次 start_monitor 会
                # 连开好几个 pkexec 模态密码框, 全部堆在桌面上, 系统级阻塞
                # (时钟都停), 用户必须逐个关掉。改为直接失败并给出明确
                # 提示, 不再弹窗。
                self.log(f"[sudo] 密码验证失败：请修正 ~/.Pas 中的密码后重试"
                         f"（已停用 pkexec 弹窗回退）")
                raise PermissionError("sudo 密码验证失败")
        
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
        
        # 这里原本无条件执行 "airmon-ng check kill"。它会连带杀掉
        # NetworkManager / wpa_supplicant / dhclient 等一整套网络服务,
        # 桌面环境的网络状态会长时间空转, 表现为"整机都卡住", 连状态栏
        # 的系统时钟都不再走动。绝大多数驱动并不需要它, 因此改为按需:
        # 只有显式开启 air_monitor_kill_conflicts 才执行。
        if self.config.get("air_monitor_kill_conflicts", False):
            self.log("[监听模式] 按配置杀掉冲突进程 (airmon-ng check kill)…")
            self._run_sudo(["airmon-ng", "check", "kill"])
        else:
            self.log("[监听模式] 跳过 airmon-ng check kill（会打断系统网络服务）")
        
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

    def cap_meta(self, cap: Path) -> dict:
        """读取抓包时记录的 AP 信息(ESSID/BSSID/信道)。

        .cap 文件本身不直接可读地存着 SSID, 而加入破解列表和"复制 WiFi"
        都需要 SSID, 所以抓包时把目标信息写进同名 .meta 旁文件。
        老包没有该文件时返回空 dict, 调用方需回退到文件名。"""
        try:
            return json.loads(
                Path(str(cap) + ".meta").read_text(
                    encoding="utf-8", errors="ignore")) or {}
        except (OSError, ValueError):
            return {}

    def set_cap_meta(self, cap: Path, meta: dict):
        try:
            Path(str(cap) + ".meta").write_text(
                json.dumps(meta, ensure_ascii=False), encoding="utf-8")
        except OSError as e:
            print(f"[抓包信息保存失败] {e}")

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

    @staticmethod
    def safe_cap_prefix(essid: str, bssid: str = "") -> str:
        """把 WiFi 名称(SSID)转成安全的抓包文件名前缀。

        抓包文件改用 WiFi 名称命名(如 "MyHomeWiFi-01.cap"), 但 SSID 由
        设备自行广播, 可以含空格、斜杠、冒号等在 Windows/FAT 上非法的
        字符, 因此必须净化后再拼路径。
        """
        name = (essid or "").strip()
        name = re.sub(r'[\\/:*?"<>|\x00-\x1f]', "_", name)
        name = re.sub(r"\s+", " ", name).strip(" .")
        if not name or name in ("<unknown>", "未选择", "-"):
            # 隐藏 SSID 没有可用名称, 退回 BSSID, 保证仍可辨识
            name = (bssid or "").strip().replace(":", "-") or "wifi"
        # 留出 airodump 自动追加的 "-01.cap" 余量, 并按字节限长
        while len(name.encode("utf-8")) > 80:
            name = name[:-1]
        return name.strip(" .") or "wifi"

    def airodump_capture(self, mon_iface: str, bssid: str, ch: str,
                         outfile_prefix: str = "", essid: str = ""):
        """开始抓包。默认用 WiFi 名称(SSID)作为输出文件名前缀。

        airodump 会自动在后面加 "-01", 因此同名 WiFi 重复抓取不会互相
        覆盖(依次变成 xxx-01.cap / xxx-02.cap)。
        """
        if not outfile_prefix:
            outfile_prefix = self.safe_cap_prefix(essid, bssid)
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
        caps = list(self._iter_caps(self.caps_dir))
        for sub in sorted(self.caps_dir.glob("20??-??-??"), reverse=True):
            if sub.is_dir():
                caps.extend(self._iter_caps(sub))
        if not caps:
            return None
        return max(caps, key=lambda x: x.stat().st_mtime)

    def log(self, msg: str):
        print(msg)
