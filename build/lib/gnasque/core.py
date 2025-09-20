#!/usr/bin/env python3
from __future__ import annotations

import base64
import concurrent.futures
import ipaddress
import json
import os
import random
import re
import shlex
import socket
import struct
import subprocess
import threading
import time
import logging
from logging.handlers import RotatingFileHandler
from collections import deque
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Callable, Dict, List, Optional, Tuple

IS_WINDOWS = (os.name == "nt")
ROOT_DIR = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))

DEFAULT_TEST_URL = "https://connectivity.cloudflareclient.com/cdn-cgi/trace"
DEFAULT_SNI = "consumer-masque.cloudflareclient.com"
DEFAULT_CONNECT_TIMEOUT_SEC = 180.0
DEFAULT_MASQUE_ENDPOINT = "162.159.198.2:443"

# WARP candidates
WARP_PREFIXES_V4 = [
    "162.159.192.0/24","162.159.193.0/24","162.159.195.0/24","162.159.204.0/24",
    "188.114.96.0/24","188.114.97.0/24","188.114.98.0/24","188.114.99.0/24",
]
WARP_PREFIXES_V6 = ["2606:4700:d0::/64","2606:4700:d1::/64","2606:4700:100::/48"]
WARP_PORTS = [2408, 500, 878, 8854, 8886, 4500]

V6_SAMPLE_CAP = 1024
V4_SAMPLE_CAP = 512

# Simple content block signatures for Iranian filters
BLOCK_SIGS = [
    "peyvandha.ir", "سامانه پیوندها", "access denied", "blocked", "filtered",
    "national information network", "safe surf", "forbidden", "این سایت مسدود است"
]

# Logging / in-memory ring
GLOB_LOG_RING = deque(maxlen=1000)

def xdg_config_dir() -> str:
    if IS_WINDOWS:
        appdata = os.environ.get("APPDATA") or os.path.expanduser("~\\AppData\\Roaming")
        return appdata
    return os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config"))

def cfg_dir() -> str:
    return os.path.join(xdg_config_dir(), "gnasque")

def ensure_dir(d: str):
    os.makedirs(d, exist_ok=True)

def ensure_parent_dir(p: str):
    os.makedirs(os.path.dirname(os.path.abspath(p)), exist_ok=True)

def get_logger() -> logging.Logger:
    lg = logging.getLogger("gnasque")
    if not lg.handlers:
        ensure_dir(cfg_dir())
        fh = RotatingFileHandler(os.path.join(cfg_dir(), "gnasque.log"),
                                 maxBytes=5*1024*1024, backupCount=3, encoding="utf-8")
        fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
        fh.setFormatter(fmt)
        lg.addHandler(fh)
        lg.setLevel(logging.INFO)
    return lg

LogCB = Callable[[str], None]

def _log(cb: Optional[LogCB], level: str, msg: str, **fields):
    line = f"[{level}] {msg}"
    if fields:
        line += " " + " ".join(f"{k}={v}" for k, v in fields.items())
    (cb or print)(line)
    try:
        logger = get_logger()
        logger.info(f"{level} {msg} " + (" ".join(f"{k}={v}" for k, v in fields.items()) if fields else ""))
    except Exception:
        pass
    try:
        GLOB_LOG_RING.append(line)
    except Exception:
        pass

def _path_exists_exec(p: str) -> bool:
    return os.path.exists(p) and os.access(p, os.X_OK)

def default_usque_path() -> str:
    env = os.environ.get("USQUE_PATH")
    if env: return env
    cands: List[str] = []
    if IS_WINDOWS:
        cands += [os.path.join(ROOT_DIR, "usque.exe"), os.path.join(os.getcwd(), "usque.exe")]
    cands += [os.path.join(ROOT_DIR, "usque"), os.path.join(os.getcwd(), "usque")]
    for c in cands:
        if _path_exists_exec(c): return c
    return "usque.exe" if IS_WINDOWS else "usque"

def default_sing_box_path() -> str:
    env = os.environ.get("SING_BOX_PATH")
    if env: return env
    cands: List[str] = []
    if IS_WINDOWS:
        cands += [os.path.join(ROOT_DIR, "sing-box.exe"), os.path.join(os.getcwd(), "sing-box.exe")]
    cands += [os.path.join(ROOT_DIR, "sing-box"), os.path.join(os.getcwd(), "sing-box")]
    for c in cands:
        if _path_exists_exec(c): return c
    return "sing-box.exe" if IS_WINDOWS else "sing-box"

def default_warp_plus_path() -> str:
    env = os.environ.get("WARP_PLUS_PATH")
    if env: return env
    cands: List[str] = []
    if IS_WINDOWS:
        cands += [os.path.join(ROOT_DIR, "warp-plus.exe"), os.path.join(os.getcwd(), "warp-plus.exe")]
    cands += [os.path.join(ROOT_DIR, "warp-plus"), os.path.join(os.getcwd(), "warp-plus")]
    for c in cands:
        if _path_exists_exec(c): return c
    return "warp-plus.exe" if IS_WINDOWS else "warp-plus"

def ip_is_v6(s: str) -> bool:
    try:
        return ipaddress.ip_address(s.strip("[]")).version == 6
    except Exception:
        return False

def parse_endpoint(ep: str) -> Tuple[str, Optional[int]]:
    if not ep: raise ValueError("empty endpoint")
    ep = ep.strip()
    if ep.startswith("["):
        m = re.match(r"^\[([^\]]+)\](?::(\d{1,5}))?$", ep)
        if not m: raise ValueError("invalid IPv6 endpoint format")
        return m.group(1), (int(m.group(2)) if m.group(2) else None)
    if ":" in ep and ep.count(":") == 1:
        h, p = ep.split(":", 1)
        return h, int(p)
    return ep, None

def parse_bind(b: str) -> Tuple[str, int]:
    if ":" not in b:
        raise ValueError("bind must be IP:Port")
    host, port = b.rsplit(":", 1)
    p = int(port)
    if not (1 <= p <= 65535): raise ValueError("invalid bind port")
    return host, p

def curl_path() -> str:
    return os.environ.get("CURL", "curl.exe" if IS_WINDOWS else "curl")

def _chmod_600(path: str):
    if not IS_WINDOWS:
        try: os.chmod(path, 0o600)
        except Exception: pass

# System proxy
def _proxy_backup_path() -> str:
    return os.path.join(cfg_dir(), "proxy_backup.json")

def backup_proxy_settings():
    try:
        ensure_dir(cfg_dir())
        backup: Dict[str, str] = {}
        if IS_WINDOWS:
            try:
                import winreg
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                     r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", 0, winreg.KEY_READ)
                for k in ("ProxyEnable","ProxyServer","AutoConfigURL"):
                    try: backup[k] = winreg.QueryValueEx(key, k)[0]
                    except Exception: pass
                key.Close()
            except Exception: pass
        else:
            try:
                out = subprocess.run(["gsettings","get","org.gnome.system.proxy","mode"], capture_output=True, text=True)
                if out.returncode == 0: backup["mode"] = out.stdout.strip()
                out = subprocess.run(["gsettings","get","org.gnome.system.proxy.socks","host"], capture_output=True, text=True)
                if out.returncode == 0: backup["socks_host"] = out.stdout.strip()
                out = subprocess.run(["gsettings","get","org.gnome.system.proxy.socks","port"], capture_output=True, text=True)
                if out.returncode == 0: backup["socks_port"] = out.stdout.strip()
            except Exception: pass
        if backup:
            with open(_proxy_backup_path(), "w", encoding="utf-8") as f:
                json.dump(backup, f, indent=2)
    except Exception:
        pass

def restore_proxy_settings() -> bool:
    try:
        p = _proxy_backup_path()
        if not os.path.exists(p): return False
        backup = json.load(open(p,"r",encoding="utf-8"))
        if IS_WINDOWS:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                 r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", 0, winreg.KEY_SET_VALUE)
            if "ProxyEnable" in backup:
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, int(backup["ProxyEnable"]))
            if "ProxyServer" in backup:
                winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, str(backup["ProxyServer"]))
            else:
                try: winreg.DeleteValue(key, "ProxyServer")
                except Exception: pass
            if "AutoConfigURL" in backup:
                winreg.SetValueEx(key, "AutoConfigURL", 0, winreg.REG_SZ, str(backup["AutoConfigURL"]))
            else:
                try: winreg.DeleteValue(key, "AutoConfigURL")
                except Exception: pass
            key.Close()
            try: subprocess.run(["netsh","winhttp","reset","proxy"], check=False)
            except Exception: pass
        else:
            if "mode" in backup:
                subprocess.run(["gsettings","set","org.gnome.system.proxy","mode", str(backup["mode"]).strip("'")], check=False)
            if "socks_host" in backup:
                subprocess.run(["gsettings","set","org.gnome.system.proxy.socks","host", str(backup["socks_host"]).strip("'")], check=False)
            if "socks_port" in backup:
                subprocess.run(["gsettings","set","org.gnome.system.proxy.socks","port", str(backup["socks_port"]).strip("'")], check=False)
        try: os.remove(p)
        except Exception: pass
        return True
    except Exception:
        return False

def set_system_proxy(host: str, port: int, use_pac: bool = False, pac_url: Optional[str] = None):
    backup_proxy_settings()
    if IS_WINDOWS:
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                 r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", 0, winreg.KEY_SET_VALUE)
            try: 
                winreg.DeleteValue(key, "AutoConfigURL")
            except Exception: 
                pass
            if use_pac and pac_url:
                winreg.SetValueEx(key, "AutoConfigURL", 0, winreg.REG_SZ, pac_url)
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
            else:
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
                winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, f"socks={host}:{port}")
            key.Close()
        except Exception:
            pass
        try:
            if not use_pac:
                subprocess.run(["netsh","winhttp","set","proxy", f"{host}:{port}"], check=False)
            else:
                subprocess.run(["netsh","winhttp","reset","proxy"], check=False)
        except Exception:
            pass
    else:
        try:
            subprocess.run(["gsettings","set","org.gnome.system.proxy","mode","manual"], check=False)
            if use_pac and pac_url:
                subprocess.run(["gsettings","set","org.gnome.system.proxy","autoconfig-url", pac_url], check=False)
            else:
                subprocess.run(["gsettings","reset","org.gnome.system.proxy","autoconfig-url"], check=False)
                subprocess.run(["gsettings","set","org.gnome.system.proxy.socks","host", host], check=False)
                subprocess.run(["gsettings","set","org.gnome.system.proxy.socks","port", str(port)], check=False)
        except Exception:
            pass

def clear_system_proxy():
    if restore_proxy_settings():
        return
    if IS_WINDOWS:
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                 r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", 0, winreg.KEY_SET_VALUE)
            for k in ("AutoConfigURL","ProxyServer"):
                try: winreg.DeleteValue(key, k)
                except Exception: pass
            try: winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
            except Exception: pass
            key.Close()
        except Exception:
            pass
        try: subprocess.run(["netsh","winhttp","reset","proxy"], check=False)
        except Exception: pass
    else:
        try:
            subprocess.run(["gsettings","set","org.gnome.system.proxy","mode","none"], check=False)
            subprocess.run(["gsettings","reset","org.gnome.system.proxy.socks","host"], check=False)
            subprocess.run(["gsettings","reset","org.gnome.system.proxy.socks","port"], check=False)
            subprocess.run(["gsettings","reset","org.gnome.system.proxy","autoconfig-url"], check=False)
        except Exception:
            pass

def generate_pac(socks_host: str, socks_port: int, direct_domains: List[str]) -> str:
    directs = [
        ".ir", "127.0.0.1", "localhost", "10.", "172.16.", "192.168."
    ] + [d.strip() for d in direct_domains if d.strip()]
    lines = ["function FindProxyForURL(url, host) {"]
    for d in directs:
        if d.startswith(".") or "*" in d:
            lines.append(f"  if (shExpMatch(host, '{d}')) return 'DIRECT';")
        else:
            lines.append(f"  if (dnsDomainIs(host, '{d}')) return 'DIRECT';")
    lines.append(f"  return 'SOCKS5 {socks_host}:{socks_port}; SOCKS {socks_host}:{socks_port}';")
    lines.append("}")
    return "\n".join(lines)

class PACHandler(BaseHTTPRequestHandler):
    pac_script = ""
    def do_GET(self):
        if self.path in ("/", "/proxy.pac") or self.path.endswith("/proxy.pac"):
            self.send_response(200)
            self.send_header("Content-Type", "application/x-ns-proxy-autoconfig")
            data = self.pac_script.encode("utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        else:
            self.send_error(404, "Not found")
    def log_message(self, *args, **kwargs):
        return

def serve_pac(host: str, port: int, pac_script: str) -> Tuple[HTTPServer, threading.Thread, str]:
    PACHandler.pac_script = pac_script
    httpd = HTTPServer((host, port), PACHandler)
    actual_port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return httpd, t, f"http://{host}:{actual_port}/proxy.pac"

# Connectivity checks
def check_connectivity_socks(proxies: List[str], hosts: List[str], timeout_sec: float, cb: Optional[LogCB] = None) -> bool:
    if not hosts:
        hosts = ["https://www.bbc.com", "https://www.voanews.com"]
    curl = curl_path()
    timeout = str(int(max(3, timeout_sec)))
    for p in proxies:
        for h in hosts:
            cmd = [curl, "-sS", "--max-time", timeout, "--socks5-hostname", p, "-L", h]
            try:
                res = subprocess.run(cmd, capture_output=True, text=True)
                if res.returncode != 0:
                    continue
                body = (res.stdout or "").lower()
                if any(sig in body for sig in (s.lower() for s in BLOCK_SIGS)):
                    continue
                return True
            except Exception:
                continue
    return False

def warp_check_over_socks(bind_addr: str, url: str, timeout_sec: float, cb: Optional[LogCB] = None) -> Tuple[str, Optional[str]]:
    cmd = [curl_path(), "-sS", "--max-time", str(int(max(1, timeout_sec))), "--socks5-hostname", bind_addr, "-L", url]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True)
    except Exception as e:
        _log(cb, "ERROR", "curl exec failed", err=str(e))
        return "CONN_FAIL", str(e)
    if res.returncode != 0:
        _log(cb, "WARN", "curl non-zero", code=res.returncode)
        return "HTTP_FAIL", res.stderr.strip()
    body = (res.stdout or "").lower()
    status = "OK" if "warp=on" in body else "NO_WARP"
    _log(cb, "INFO", "warp check", status=status)
    return status, None

# Geo
def check_ip_geolocation(cb: Optional[LogCB] = None) -> Tuple[str, Optional[str]]:
    urls = ["https://ifconfig.co/country", "https://ipinfo.io/country", "https://ipapi.co/country/"]
    for u in urls:
        try:
            res = subprocess.run([curl_path(), "-s", "--max-time", "10", u], capture_output=True, text=True, timeout=15)
            if res.returncode == 0:
                country = (res.stdout or "").strip()
                if country:
                    _log(cb, "INFO", "IP geolocation", source=u, country=country)
                    return country, None
        except Exception as e:
            _log(cb, "WARN", "geo check failed", err=str(e), url=u)
    return "UNKNOWN", "geo failed"

def verify_vpn_connection(before_country: str, cb: Optional[LogCB] = None) -> Tuple[bool, str, Optional[str]]:
    current, err = check_ip_geolocation(cb)
    if err:
        return False, current, err
    ok = (current != before_country) and (current != "UNKNOWN")
    _log(cb, "INFO", "VPN verification", before=before_country, after=current, connected=ok)
    return ok, current, None

# Metrics
def _metrics_path() -> str:
    return os.path.join(cfg_dir(), "metrics.json")

def _metrics_load() -> Dict[str, dict]:
    try:
        return json.load(open(_metrics_path(),"r",encoding="utf-8"))
    except Exception:
        return {}

def _metrics_save(m: Dict[str, dict]):
    ensure_dir(cfg_dir())
    json.dump(m, open(_metrics_path(),"w",encoding="utf-8"), indent=2)

def clear_metrics():
    try: os.remove(_metrics_path())
    except Exception: pass

def metrics_update_endpoint_success(endpoint: str, connect_ms: float):
    m = _metrics_load()
    key = f"endpoint_{endpoint}"
    r = m.get(key, {"success": 0, "fail": 0, "avg_ms": 0.0, "last_used": 0})
    r["success"] = int(r.get("success", 0)) + 1
    a = float(r.get("avg_ms", 0.0))
    r["avg_ms"] = (a * 0.7 + float(connect_ms) * 0.3) if a > 0 else float(connect_ms)
    r["last_used"] = int(time.time())
    m[key] = r
    _metrics_save(m)

def metrics_update_endpoint_failure(endpoint: str):
    m = _metrics_load(); key = f"endpoint_{endpoint}"
    r = m.get(key, {"success": 0, "fail": 0, "avg_ms": 0.0, "last_used": 0})
    r["fail"] = int(r.get("fail", 0)) + 1
    m[key] = r; _metrics_save(m)

# Adblock parsing
def parse_adblock_filter(file_path: str, cb: Optional[LogCB] = None) -> List[str]:
    blocked: set[str] = set()
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for raw in f:
                s = raw.strip()
                if not s or s.startswith("!") or s.startswith("[") or s.startswith(" @@"):
                    continue
                if s.startswith("||"):
                    token = s[2:]
                    token = re.split(r'[\^/$|]', token)[0]
                    token = token.lstrip(".")
                    if token.startswith("www."):
                        token = token[4:]
                    if token:
                        blocked.add(token)
                    continue
                if s.startswith("|http"):
                    try:
                        from urllib.parse import urlparse
                        u = s.lstrip("|")
                        host = urlparse(u).hostname
                        if host:
                            host = host.lstrip(".")
                            if host.startswith("www."):
                                host = host[4:]
                            blocked.add(host)
                    except Exception:
                        pass
                    continue
                if "*" in s or "/" in s:
                    m = re.search(r'([A-Za-z0-9.-]+\.[A-Za-z]{2,})', s)
                    if m:
                        dom = m.group(1).lstrip(".")
                        if dom.startswith("www."):
                            dom = dom[4:]
                        blocked.add(dom)
                else:
                    if re.match(r'^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$', s.lstrip(".")):
                        dom = s.lstrip(".")
                        if dom.startswith("www."):
                            dom = dom[4:]
                        blocked.add(dom)
    except FileNotFoundError:
        _log(cb, "WARN", "adblock filter not found", path=file_path)
    except Exception as e:
        _log(cb, "WARN", "adblock parse error", err=str(e))
    return sorted(blocked)

# Warp-Plus availability
def is_warp_plus_available(path: str) -> bool:
    return os.path.exists(path) and os.access(path, os.X_OK)

# MASQUE
@dataclass
class MasqueOptions:
    endpoint: str = DEFAULT_MASQUE_ENDPOINT
    bind: Tuple[str, int] = ("127.0.0.1", 1080)
    usque_path: str = field(default_factory=default_usque_path)
    config_path: str = field(default_factory=lambda: os.path.join(cfg_dir(), "usque_config.json"))
    sni: str = DEFAULT_SNI
    use_ipv6: bool = False
    connect_port: int = 443
    username: Optional[str] = None
    password: Optional[str] = None
    connect_timeout_sec: float = 30.0

def is_valid_usque_config(path: str) -> bool:
    try:
        if not os.path.exists(path): return False
        data = open(path,"r",encoding="utf-8").read()
        return ("private_key" in data and ("peers" in data or "endpoint_v4" in data or "endpoint_v6" in data)) or ("certificate" in data)
    except Exception:
        return False

def ensure_usque_config(usque_path: str, desired_path: str, renew: bool, cb: Optional[LogCB] = None) -> str:
    ensure_parent_dir(desired_path)
    target_dir = os.path.dirname(os.path.abspath(desired_path))
    if renew and os.path.exists(desired_path):
        try: os.remove(desired_path)
        except Exception: pass
    if not is_valid_usque_config(desired_path):
        _log(cb, "INFO", "running usque register", cwd=target_dir, usque_path=usque_path)
        try:
            proc = subprocess.Popen([usque_path, "register", "-n", "gnasque", "--accept-tos"],
                                    cwd=target_dir, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, text=True)
            out, err = proc.communicate(timeout=45)
            if proc.returncode != 0:
                _log(cb, "ERROR", "usque register failed", code=proc.returncode, stderr=(err or "").strip())
                raise RuntimeError("usque register failed")
        except Exception as e:
            raise RuntimeError(f"usque register error: {e}")
        # pick config.json produced
        cand: Optional[str] = None
        for p in [os.path.join(target_dir,"config.json"), os.path.join(os.getcwd(),"config.json")]:
            if os.path.exists(p) and is_valid_usque_config(p):
                cand = p; break
        if not cand:
            raise RuntimeError("usque register did not produce a valid config.json")
        src = open(cand,"r",encoding="utf-8").read()
        with open(desired_path,"w",encoding="utf-8") as f:
            f.write(src)
        _chmod_600(desired_path)
        _log(cb, "INFO", "copied usque config", src=cand, dst=desired_path)
    if not is_valid_usque_config(desired_path):
        raise RuntimeError(f"usque config invalid at {desired_path}")
    _chmod_600(desired_path)
    return desired_path

class Controller:
    def __init__(self, procs: List[subprocess.Popen]):
        self._procs = procs
    def stop(self):
        for p in self._procs:
            try:
                p.terminate()
                try: p.wait(timeout=2)
                except Exception: p.kill()
            except Exception:
                pass

def _usque_cmd(opts: MasqueOptions, is_v6: bool, masque_port: int) -> List[str]:
    args = [
        opts.usque_path, "socks",
        "--config", opts.config_path,
        "-b", opts.bind[0], "-p", str(opts.bind[1]),
        "-P", str(masque_port),
        "-s", opts.sni,
    ]
    if is_v6: args.append("-6")
    if opts.username and opts.password:
        args += ["-u", opts.username, "-w", opts.password]
    return args

def start_masque(opts: MasqueOptions, cb: Optional[LogCB] = None) -> Controller:
    cfg_path = ensure_usque_config(opts.usque_path, opts.config_path, renew=False, cb=cb)
    host, port = parse_endpoint(opts.endpoint)
    masque_port = port or opts.connect_port or 443
    # update config with endpoint ip/port
    try:
        cfg = {}
        if os.path.exists(cfg_path):
            cfg = json.load(open(cfg_path,"r",encoding="utf-8"))
    except Exception:
        cfg = {}
    if ip_is_v6(host):
        cfg["endpoint_v6"] = host; cfg["endpoint_v6_port"] = str(masque_port)
    else:
        cfg["endpoint_v4"] = host; cfg["endpoint_v4_port"] = str(masque_port)
    ensure_parent_dir(cfg_path)
    json.dump(cfg, open(cfg_path,"w",encoding="utf-8"), indent=2)

    cmd = _usque_cmd(opts, ip_is_v6(host), masque_port)
    _log(cb, "INFO", "starting usque", cmd=" ".join(shlex.quote(x) for x in cmd))
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)

    def pipe(stream, tag):
        for line in iter(stream.readline, ''):
            if "Connected to MASQUE server" in line:
                _log(cb, "INFO", "serving MASQUE", address=f"{opts.bind[0]}:{opts.bind[1]}")
            (cb or print)(f"[USQUE][{tag}] {line.rstrip()}")

    threading.Thread(target=pipe, args=(proc.stdout,"out"), daemon=True).start()
    threading.Thread(target=pipe, args=(proc.stderr,"err"), daemon=True).start()

    def watchdog():
        deadline = time.time() + min(20.0, opts.connect_timeout_sec)
        bind_addr = f"{opts.bind[0]}:{opts.bind[1]}"
        while time.time() < deadline and proc.poll() is None:
            status, _ = warp_check_over_socks(bind_addr, DEFAULT_TEST_URL, 5, cb)
            if status in ("OK","NO_WARP"):
                metrics_update_endpoint_success(opts.endpoint, 1000.0)
                return
            time.sleep(0.5)
        metrics_update_endpoint_failure(opts.endpoint)

    threading.Thread(target=watchdog, daemon=True).start()
    return Controller([proc])

# WARP (sing-box or Warp-Plus)
@dataclass
class WarpOptions:
    bind: Tuple[str, int] = ("127.0.0.1", 8086)
    sing_box_path: str = field(default_factory=default_sing_box_path)
    dns_ip: str = "1.1.1.1"
    endpoint: Optional[str] = None
    cache_dir: str = field(default_factory=lambda: os.path.join(cfg_dir(), "warp"))
    license_key: str = ""
    connect_timeout_sec: float = DEFAULT_CONNECT_TIMEOUT_SEC
    test_url: str = DEFAULT_TEST_URL
    prefer_country: Optional[str] = None
    socks_user: Optional[str] = None
    socks_pass: Optional[str] = None
    http_inbound_port: Optional[int] = None
    bind_all: bool = False
    monitor_interval_sec: int = 20
    auto_rotate: bool = True
    apply_iran_rules: bool = False
    rules_backend: str = "rule-set"
    sb_log_level: str = "info"
    sb_stack: str = "system"
    sb_address_type: str = "v64"
    sb_udp_block: bool = False
    sb_discord_bypass: bool = False
    tun_mode: bool = False
    tun_name: str = "gnasque-tun"
    tun_address: str = "172.16.0.2/24"
    tun_dns: str = "1.1.1.1"
    apply_adblock_rules: bool = False
    adblock_filter_path: str = ""
    use_warp_plus: bool = False
    warp_plus_path: str = field(default_factory=default_warp_plus_path)
    psiphon_mode: bool = False
    psiphon_country: Optional[str] = None
    gool_mode: bool = False

def singbox_version(sing_box_path: str) -> Tuple[int, int, int]:
    try:
        out = subprocess.run([sing_box_path, "version"], capture_output=True, text=True, timeout=2)
        m = re.search(r"(\d+)\.(\d+)\.(\d+)", (out.stdout or "") + (out.stderr or ""))
        if m: return int(m.group(1)), int(m.group(2)), int(m.group(3))
    except Exception:
        pass
    return (0, 0, 0)

def wg_keypair() -> Tuple[str, str]:
    gen = subprocess.run(["wg","genkey"], capture_output=True, text=True)
    if gen.returncode != 0:
        raise RuntimeError("wg genkey failed: " + gen.stderr.strip())
    priv = gen.stdout.strip()
    pub = subprocess.run(["wg","pubkey"], input=priv, capture_output=True, text=True)
    if pub.returncode != 0:
        raise RuntimeError("wg pubkey failed: " + pub.stderr.strip())
    return priv, pub.stdout.strip()

def cf_headers() -> Dict[str, str]:
    return {"User-Agent": "okhttp/3.12.1", "CF-Client-Version": "a-6.30-3596", "Content-Type": "application/json; charset=UTF-8"}

def http_json(method, url, headers, body) -> dict:
    import urllib.request, urllib.error
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.loads(resp.read().decode("utf-8"))

def warp_register_identity(cache_dir: str, license_key: str, cb: Optional[LogCB] = None) -> dict:
    ensure_dir(cache_dir)
    path = os.path.join(cache_dir, "warp_identity.json")
    if os.path.exists(path):
        try:
            ident = json.load(open(path,"r",encoding="utf-8"))
            if license_key and ident.get("account", {}).get("license") != license_key:
                api = "https://api.cloudflareclient.com/v0a4005"
                did, token = ident["id"], ident["token"]
                http_json("PUT", f"{api}/reg/{did}/account", {**cf_headers(), "Authorization": f"Bearer {token}"}, {"license": license_key})
                acc = http_json("GET", f"{api}/reg/{did}/account", {**cf_headers(), "Authorization": f"Bearer {token}"}, None)
                ident["account"] = acc
                json.dump(ident, open(path,"w",encoding="utf-8"), indent=2)
                _log(cb, "INFO", "updated license")
            _log(cb, "INFO", "loaded warp identity", path=path)
            return ident
        except Exception as e:
            _log(cb, "WARN", "failed to load identity, creating new", err=str(e))
    try:
        priv_b64, pub_b64 = wg_keypair()
    except Exception as e:
        raise RuntimeError("wireguard-tools not found ('wg'). Install wireguard-tools.") from e
    api = "https://api.cloudflareclient.com/v0a4005"
    reg = http_json("POST", f"{api}/reg", cf_headers(), {
        "install_id": "", "fcm_token": "", "tos": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
        "key": pub_b64, "type": "Android", "model": "PC", "locale": "en_US", "warp_enabled": True
    })
    if license_key:
        http_json("PUT", f"{api}/reg/{reg['id']}/account", {**cf_headers(), "Authorization": f"Bearer {reg['token']}"}, {"license": license_key})
        acc = http_json("GET", f"{api}/reg/{reg['id']}/account", {**cf_headers(), "Authorization": f"Bearer {reg['token']}"}, None)
        reg["account"] = acc
    reg["private_key"] = priv_b64
    json.dump(reg, open(path,"w",encoding="utf-8"), indent=2)
    _chmod_600(path)
    _log(cb, "INFO", "created warp identity", path=path)
    return reg

def warp_reserved_from_identity(ident: dict) -> str:
    cid = base64.b64decode(ident["config"]["client_id"])
    return base64.b64encode(cid[:3]).decode("ascii")

def build_singbox_config(
    ident: dict, host: str, port: int, socks_bind: Tuple[str, int], dns_ip: str,
    socks_user: Optional[str] = None, socks_pass: Optional[str] = None,
    http_inbound_port: Optional[int] = None, bind_all: bool = False,
    apply_iran_rules: bool = False, rules_backend: str = "rule-set",
    sb_log_level: str = "info", sb_stack: str = "system",
    sb_address_type: str = "v64", sb_udp_block: bool = False, sb_discord_bypass: bool = False,
    tun_mode: bool = False, tun_name: str = "gnasque-tun", tun_address: str = "172.16.0.2/24", tun_dns: str = "1.1.1.1",
    apply_adblock_rules: bool = False, adblock_filter_path: str = "", cb: Optional[LogCB] = None
) -> dict:
    v4 = ident["config"]["interface"]["addresses"]["v4"]
    v6 = ident["config"]["interface"]["addresses"]["v6"]
    peer_pub = ident["config"]["peers"][0]["public_key"]
    reserved = warp_reserved_from_identity(ident)

    listen_ip = "0.0.0.0" if bind_all else socks_bind[0]
    inbounds: List[dict] = [{
        "type": "socks", "listen": listen_ip, "listen_port": socks_bind[1], "udp": False
    }]
    if socks_user and socks_pass:
        inbounds[0]["users"] = [{"username": socks_user, "password": socks_pass}]
    if http_inbound_port:
        inbounds.append({"type": "http", "listen": listen_ip, "listen_port": http_inbound_port})
    if tun_mode:
        inbounds.append({
            "type": "tun",
            "tag": "tun-in",
            "interface_name": tun_name,
            "auto_route": True,
            "strict_route": True,
            "inet4_address": tun_address,
            "mtu": 1500
        })

    outbounds: List[dict] = [
        {
            "type": "wireguard",
            "tag": "wg",
            "server": host,
            "server_port": port,
            "local_address": [f"{v4}/32", f"{v6}/128"],
            "private_key": ident["private_key"],
            "peer_public_key": peer_pub,
            "reserved": reserved,
            "mtu": 1280,
            "workers": 1,
            "persistent_keepalive": 20,
            "domain_strategy": "prefer_ipv4",
            "system_interface": False,
            "stack": sb_stack,
            "address_type": sb_address_type
        },
        {"type": "direct", "tag": "direct"},
        {"type": "block", "tag": "block"},
    ]

    cfg: dict = {
        "log": {"level": sb_log_level},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "dns": {"servers": [{"address": dns_ip}]},
        "experimental": {"cache_file": {"enabled": True}}
    }

    if tun_mode:
        cfg["dns"] = {
            "servers": [
                {"address": tun_dns, "detour": "wg"},
                {"address": "local"}
            ],
            "query_strategy": "use_ip"
        }

    if apply_iran_rules:
        if rules_backend == "rule-set":
            cfg["route"] = {
                "rules": [
                    {"ip_is_private": True, "outbound": "direct"},
                    {"rule_set": ["geosite-category-ads-all","geosite-malware","geosite-phishing","geosite-cryptominers","geoip-malware","geoip-phishing"], "outbound": "block"},
                    {"rule_set": ["geosite-ir","geoip-ir"], "outbound": "direct"},
                ],
                "rule_set": [
                    {"tag":"geosite-ir","type":"remote","format":"binary","url":"https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-ir.srs"},
                    {"tag":"geosite-category-ads-all","type":"remote","format":"binary","url":"https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-category-ads-all.srs"},
                    {"tag":"geosite-malware","type":"remote","format":"binary","url":"https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-malware.srs"},
                    {"tag":"geosite-phishing","type":"remote","format":"binary","url":"https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-phishing.srs"},
                    {"tag":"geosite-cryptominers","type":"remote","format":"binary","url":"https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-cryptominers.srs"},
                    {"tag":"geoip-ir","type":"remote","format":"binary","url":"https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geoip-ir.srs"},
                    {"tag":"geoip-malware","type":"remote","format":"binary","url":"https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geoip-malware.srs"},
                    {"tag":"geoip-phishing","type":"remote","format":"binary","url":"https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geoip-phishing.srs"},
                ]
            }
        else:
            cfg["route"] = {
                "geoip": {"download_url": "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/release/geoip.db"},
                "geosite": {"download_url": "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/release/geosite.db"},
                "rules": [
                    {"ip_is_private": True, "outbound": "direct"},
                    {"geosite": ["category-ads-all","malware","phishing","cryptominers"], "outbound": "block"},
                    {"geoip": ["malware","phishing"], "outbound": "block"},
                    {"geosite": "ir", "outbound": "direct"},
                    {"geoip": ["ir","private"], "outbound": "direct"},
                ]
            }

    if apply_adblock_rules and adblock_filter_path:
        blocked_domains = parse_adblock_filter(adblock_filter_path, cb)
        if blocked_domains:
            cfg.setdefault("route", {}).setdefault("rules", [])
            cfg["route"]["rules"].insert(0, {"domain": blocked_domains, "outbound": "block"})
            _log(cb, "INFO", "adblock filter applied", count=len(blocked_domains))

    if sb_udp_block:
        cfg.setdefault("route", {}).setdefault("rules", []).append({"protocol": ["quic", "udp"], "outbound": "block"})
    if sb_discord_bypass:
        cfg.setdefault("route", {}).setdefault("rules", []).append({"domain_suffix": ["discord.com","discord.gg","discordapp.com","discord.media"], "outbound": "direct"})
    return cfg

def run_singbox(cfg: dict, sing_box_path: str, cb: Optional[LogCB] = None) -> subprocess.Popen:
    ensure_dir(cfg_dir())
    path = os.path.join(cfg_dir(), "singbox_warp.json")
    json.dump(cfg, open(path,"w",encoding="utf-8"), indent=2)
    cmd = [sing_box_path, "run", "-c", path]
    _log(cb, "INFO", "starting sing-box", cmd=" ".join(shlex.quote(x) for x in cmd))
    return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)

def get_trace_country(bind_addr: str, timeout_sec: float, cb: Optional[LogCB] = None) -> Optional[str]:
    cmd = [curl_path(), "-sS", "--max-time", str(int(max(1, timeout_sec))), "--socks5-hostname", bind_addr, "-L", DEFAULT_TEST_URL]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True)
        if out.returncode != 0:
            return None
        for line in (out.stdout or "").splitlines():
            if line.lower().startswith("loc="):
                return line.split("=", 1)[1].strip()
    except Exception:
        return None
    return None

def start_warp_plus(opts: WarpOptions, cb: Optional[LogCB] = None) -> Controller:
    if not is_warp_plus_available(opts.warp_plus_path):
        raise RuntimeError(f"Warp-Plus binary not found or not executable: {opts.warp_plus_path}")
    cmd = [opts.warp_plus_path, "--bind", f"{opts.bind[0]}:{opts.bind[1]}", "--dns", opts.dns_ip]
    if opts.endpoint: cmd += ["--endpoint", opts.endpoint]
    if opts.license_key: cmd += ["--key", opts.license_key]
    if opts.psiphon_mode:
        cmd.append("--cfon")
        if opts.psiphon_country: cmd += ["--country", opts.psiphon_country]
    if opts.gool_mode: cmd.append("--gool")
    if opts.sb_log_level == "debug": cmd.append("--verbose")
    _log(cb, "INFO", "starting warp-plus", cmd=" ".join(shlex.quote(x) for x in cmd))
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
    def pipe(stream, tag):
        for line in iter(stream.readline, ''):
            (cb or print)(f"[WARP-PLUS][{tag}] {line.rstrip()}")
    threading.Thread(target=pipe, args=(proc.stdout,"out"), daemon=True).start()
    threading.Thread(target=pipe, args=(proc.stderr,"err"), daemon=True).start()
    def readiness():
        bind_addr = f"{opts.bind[0]}:{opts.bind[1]}"
        deadline = time.time() + min(10.0, opts.connect_timeout_sec)
        while time.time() < deadline and proc.poll() is None:
            status, _ = warp_check_over_socks(bind_addr, opts.test_url, 5, cb)
            if status in ("OK","NO_WARP"):
                _log(cb, "INFO", "warp-plus ready", status=status); return
            time.sleep(0.5)
        _log(cb, "WARN", "warp-plus readiness uncertain")
    threading.Thread(target=readiness, daemon=True).start()
    return Controller([proc])

def start_warp(opts: WarpOptions, cb: Optional[LogCB] = None) -> Controller:
    ident = warp_register_identity(opts.cache_dir, opts.license_key, cb)
    endpoint = opts.endpoint
    if not endpoint:
        host = ident["config"]["peers"][0]["endpoint"]["host"]
        ports = ident["config"]["peers"][0]["endpoint"]["ports"] or [2408]
        endpoint = f"{host}:{random.choice(ports)}"
    host, port = parse_endpoint(endpoint); port = port or 2408
    cfg = build_singbox_config(
        ident, host.strip("[]"), port, opts.bind, opts.dns_ip,
        socks_user=opts.socks_user, socks_pass=opts.socks_pass,
        http_inbound_port=opts.http_inbound_port, bind_all=opts.bind_all,
        apply_iran_rules=opts.apply_iran_rules, rules_backend=opts.rules_backend,
        sb_log_level=opts.sb_log_level, sb_stack=opts.sb_stack,
        sb_address_type=opts.sb_address_type, sb_udp_block=opts.sb_udp_block, sb_discord_bypass=opts.sb_discord_bypass,
        tun_mode=opts.tun_mode, tun_name=opts.tun_name, tun_address=opts.tun_address, tun_dns=opts.tun_dns,
        apply_adblock_rules=opts.apply_adblock_rules, adblock_filter_path=opts.adblock_filter_path, cb=cb
    )
    proc = run_singbox(cfg, opts.sing_box_path, cb)
    def pipe(stream, tag):
        for line in iter(stream.readline, ''):
            (cb or print)(f"[SING-BOX][{tag}] {line.rstrip()}")
    threading.Thread(target=pipe, args=(proc.stdout,"out"), daemon=True).start()
    threading.Thread(target=pipe, args=(proc.stderr,"err"), daemon=True).start()
    def readiness():
        bind_addr = f"{opts.bind[0]}:{opts.bind[1]}"
        deadline = time.time() + min(10.0, opts.connect_timeout_sec)
        start_t = time.time()
        while time.time() < deadline and proc.poll() is None:
            status, _ = warp_check_over_socks(bind_addr, DEFAULT_TEST_URL, 5, cb)
            if status in ("OK","NO_WARP"):
                metrics_update_endpoint_success(endpoint, (time.time()-start_t)*1000.0)
                _log(cb, "INFO", "proxy ready", status=status); return
            time.sleep(0.5)
        metrics_update_endpoint_failure(endpoint)
        _log(cb, "WARN", "proxy readiness uncertain")
    threading.Thread(target=readiness, daemon=True).start()
    return Controller([proc])

def start_warp_with_monitor(opts: WarpOptions, cb: Optional[LogCB] = None) -> Controller:
    if opts.use_warp_plus:
        return start_warp_plus(opts, cb)
    ident = warp_register_identity(opts.cache_dir, opts.license_key, cb)

    def start_once(ep: Optional[str]) -> Tuple[Controller, str]:
        endpoint = ep
        if not endpoint:
            host = ident["config"]["peers"][0]["endpoint"]["host"]
            ports = ident["config"]["peers"][0]["endpoint"]["ports"] or [2408]
            endpoint = f"{host}:{random.choice(ports)}"
        host, port = parse_endpoint(endpoint); port = port or 2408
        cfg = build_singbox_config(
            ident, host.strip("[]"), port, opts.bind, opts.dns_ip,
            socks_user=opts.socks_user, socks_pass=opts.socks_pass,
            http_inbound_port=opts.http_inbound_port, bind_all=opts.bind_all,
            apply_iran_rules=opts.apply_iran_rules, rules_backend=opts.rules_backend,
            sb_log_level=opts.sb_log_level, sb_stack=opts.sb_stack,
            sb_address_type=opts.sb_address_type, sb_udp_block=opts.sb_udp_block, sb_discord_bypass=opts.sb_discord_bypass,
            tun_mode=opts.tun_mode, tun_name=opts.tun_name, tun_address=opts.tun_address, tun_dns=opts.tun_dns,
            apply_adblock_rules=opts.apply_adblock_rules, adblock_filter_path=opts.adblock_filter_path, cb=cb
        )
        proc = run_singbox(cfg, opts.sing_box_path, cb)
        def pipe(stream, tag):
            for line in iter(stream.readline, ''):
                (cb or print)(f"[SING-BOX][{tag}] {line.rstrip()}")
        threading.Thread(target=pipe, args=(proc.stdout,"out"), daemon=True).start()
        threading.Thread(target=pipe, args=(proc.stderr,"err"), daemon=True).start()
        return Controller([proc]), endpoint

    ctl, endpoint = start_once(opts.endpoint)
    if not opts.auto_rotate:
        return ctl

    stop_ev = threading.Event()
    def monitor():
        nonlocal ctl, endpoint
        bind_addr = f"{opts.bind[0]}:{opts.bind[1]}"
        failures = 0
        while not stop_ev.is_set():
            status, _ = warp_check_over_socks(bind_addr, opts.test_url, 8, cb)
            if status in ("OK","NO_WARP"):
                failures = 0
            else:
                failures += 1
                _log(cb, "WARN", "health check failed", failures=failures)
                if failures >= 2:
                    ctl.stop()
                    time.sleep(1.0)
                    ctl, endpoint = start_once(None)
                    failures = 0
            time.sleep(max(5, opts.monitor_interval_sec))
    t = threading.Thread(target=monitor, daemon=True); t.start()
    class MonCtl(Controller):
        def stop(self):
            stop_ev.set()
            super().stop()
    return MonCtl(ctl._procs)

# UDP probe scanner (simple)
WARP_HANDSHAKE_HEX = "013cbdafb4135cac96a29484d7a0175ab152dd3e59be35049beadf758b8d48af14ca65f25a168934746fe8bc8867b1c17113d71c0fac5c141ef9f35783ffa5357c9871f4a006662b83ad71245a862495376a5fe3b4f2e1f06974d748416670e5f9b086297f652e6dfbf742fbfc63c3d8aeb175a3e9b7582fbc67c77577e4c0b32b05f92900000000000000000000000000000000"
WARP_HANDSHAKE = bytes.fromhex(WARP_HANDSHAKE_HEX)
WARP_RESP_LEN = 92

def _best_family(host: str) -> int:
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
        return socket.AF_INET6 if ip.version == 6 else socket.AF_INET
    except Exception:
        return socket.AF_UNSPEC

def _wg_udp_probe_once(host: str, port: int, timeout_ms: int) -> Optional[float]:
    fam = _best_family(host); addr = host.strip("[]"); sock = None
    try:
        if fam == socket.AF_INET6:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM); dest = (addr, port, 0, 0)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); dest = (addr, port)
        sock.settimeout(timeout_ms/1000.0)
        t0 = time.time()
        sock.sendto(WARP_HANDSHAKE, dest)
        data, _ = sock.recvfrom(256)
        dt = (time.time() - t0) * 1000.0
        if len(data) == WARP_RESP_LEN:
            return dt
        return None
    except Exception:
        return None
    finally:
        try:
            if sock: sock.close()
        except Exception: pass

def warp_udp_probe_endpoint(ep: str, attempts: int = 3, timeout_ms: int = 1000) -> Dict:
    host, port = parse_endpoint(ep); port = port or 2408
    sent = 0; recv = 0; total = 0.0
    for _ in range(max(1, attempts)):
        sent += 1
        rtt = _wg_udp_probe_once(host, port, timeout_ms)
        if rtt is not None:
            recv += 1; total += rtt
    avg_ms = (total/recv) if recv > 0 else None
    return {"endpoint": ep, "sent": sent, "recv": recv, "avg_ms": avg_ms}

def base_build_warp_candidates(v4: bool, v6: bool, ports: Optional[List[int]], max_total: int) -> List[str]:
    out: List[str] = []; ports = ports or WARP_PORTS
    if v4:
        for cidr in WARP_PREFIXES_V4:
            n = ipaddress.ip_network(cidr, strict=False)
            ips = list(n.hosts())
            random.shuffle(ips)
            for ip in ips[:V4_SAMPLE_CAP]:
                out.append(f"{ip}:{random.choice(ports)}")
    if v6:
        for cidr in WARP_PREFIXES_V6:
            n = ipaddress.ip_network(cidr, strict=False)
            count = 0
            for ip in n.hosts():
                out.append(f"[{ip}]:{random.choice(ports)}"); count += 1
                if count >= V6_SAMPLE_CAP: break
    random.shuffle(out)
    if max_total > 0: out = out[:max_total]
    return out

def warp_udp_probe_scan(candidates: List[str], attempts: int = 3, timeout_ms: int = 1000, concurrency: int = 200) -> List[Dict]:
    """Scan multiple WARP endpoints concurrently and return results sorted by latency."""
    def worker(ep):
        return warp_udp_probe_endpoint(ep, attempts, timeout_ms)
    
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        future_to_ep = {executor.submit(worker, ep): ep for ep in candidates}
        for future in concurrent.futures.as_completed(future_to_ep):
            try:
                result = future.result()
                if result.get("avg_ms") is not None:  # Only include successful probes
                    results.append(result)
            except Exception:
                pass
    
    # Sort by latency (avg_ms)
    results.sort(key=lambda x: x["avg_ms"])
    return results

# Web UI log ring accessor
def read_log_ring() -> List[str]:
    return list(GLOB_LOG_RING)

# WARP-over-MASQUE (UDP over SOCKS relay)
class SocksUDPForwarder:
    def __init__(self, socks_host: str, socks_port: int, target_host: str, target_port: int,
                 bind_ip: str = "127.0.0.1", bind_port: int = 0, cb: Optional[LogCB] = None):
        self.socks_host = socks_host; self.socks_port = socks_port
        self.target_host = target_host; self.target_port = target_port
        self.bind_ip = bind_ip; self.bind_port = bind_port; self.cb = cb
        self.tcp = None; self.udp = None; self.local = None
        self.stop_ev = threading.Event(); self.th_send = None; self.th_recv = None
        self.relay_addr = None; self.client_addr = None

    def log(self, level, msg, **kv):
        (self.cb or print)(f"[{level}] {msg} " + (" ".join(f"{k}={v}" for k, v in kv.items()) if kv else ""))

    def _socks5_udp_associate(self):
        self.tcp = socket.create_connection((self.socks_host, self.socks_port), timeout=10)
        self.tcp.sendall(b"\x05\x01\x00")
        resp = self.tcp.recv(2)
        if len(resp) != 2 or resp[0] != 0x05 or resp[1] != 0x00:
            raise RuntimeError("SOCKS5 server did not accept no-auth")
        self.tcp.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        h = self.tcp.recv(4)
        if len(h) < 4 or h[1] != 0x00:
            raise RuntimeError("SOCKS5 UDP associate failed")
        atyp = h[3]
        if atyp == 0x01:
            addr = self.tcp.recv(4); port = struct.unpack("!H", self.tcp.recv(2))[0]
            bnd_addr = socket.inet_ntop(socket.AF_INET, addr)
        elif atyp == 0x04:
            addr = self.tcp.recv(16); port = struct.unpack("!H", self.tcp.recv(2))[0]
            bnd_addr = socket.inet_ntop(socket.AF_INET6, addr)
        elif atyp == 0x03:
            ln = self.tcp.recv(1)[0]; host = self.tcp.recv(ln).decode("utf-8","ignore")
            port = struct.unpack("!H", self.tcp.recv(2))[0]; bnd_addr = host
        else:
            raise RuntimeError("Unknown ATYP in SOCKS5 reply")
        self.relay_addr = (bnd_addr, port)

    def _build_udp_header(self, host: str, port: int) -> bytes:
        try:
            ip = ipaddress.ip_address(host)
            if ip.version == 4:
                return b"\x00\x00\x00\x01" + ip.packed + struct.pack("!H", port)
            else:
                return b"\x00\x00\x00\x04" + ip.packed + struct.pack("!H", port)
        except ValueError:
            hb = host.encode("utf-8")
            return b"\x00\x00\x00\x03" + bytes([len(hb)]) + hb + struct.pack("!H", port)

    def _send_loop(self, header: bytes):
        while not self.stop_ev.is_set():
            try:
                data, addr = self.local.recvfrom(65535)
            except Exception:
                if self.stop_ev.is_set(): break
                continue
            if self.client_addr is None:
                self.client_addr = addr
            try:
                self.udp.sendto(header + data, self.relay_addr)
            except Exception as e:
                self.log("WARN", "udp send error", err=str(e))

    def _recv_loop(self):
        while not self.stop_ev.is_set():
            try:
                data, _ = self.udp.recvfrom(65535)
            except Exception:
                if self.stop_ev.is_set(): break
                continue
            if len(data) < 10: continue
            atyp = data[3]; p = 4
            try:
                if atyp == 0x01: p += 4
                elif atyp == 0x04: p += 16
                elif atyp == 0x03:
                    ln = data[p]; p += 1 + ln
                else: continue
                p += 2
                payload = data[p:]
                if self.client_addr:
                    self.local.sendto(payload, self.client_addr)
            except Exception:
                continue

    def start(self) -> Tuple[str, int]:
        self._socks5_udp_associate()
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.local = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.local.bind((self.bind_ip, self.bind_port))
        laddr = self.local.getsockname()
        header = self._build_udp_header(self.target_host, self.target_port)
        self.th_send = threading.Thread(target=self._send_loop, args=(header,), daemon=True)
        self.th_recv = threading.Thread(target=self._recv_loop, daemon=True)
        self.th_send.start(); self.th_recv.start()
        self.log("INFO", "udp forwarder started", local=f"{laddr[0]}:{laddr[1]}", socks=f"{self.socks_host}:{self.socks_port}", target=f"{self.target_host}:{self.target_port}")
        return laddr

    def stop(self):
        self.stop_ev.set()
        for s in [self.local, self.udp, self.tcp]:
            try:
                if s: s.close()
            except Exception: pass
        self.log("INFO", "udp forwarder stopped")

def start_warp_over_masque(masque_socks_bind: Tuple[str, int], warp_opts: WarpOptions, warp_endpoint: Optional[str], cb: Optional[LogCB] = None) -> Controller:
    ident = warp_register_identity(warp_opts.cache_dir, warp_opts.license_key, cb)
    if not warp_endpoint:
        host = ident["config"]["peers"][0]["endpoint"]["host"]
        ports = ident["config"]["peers"][0]["endpoint"]["ports"] or [2408]
        warp_endpoint = f"{host}:{random.choice(ports)}"
    thost, tport = parse_endpoint(warp_endpoint); tport = tport or 2408
    fwd = SocksUDPForwarder(masque_socks_bind[0], masque_socks_bind[1], thost.strip("[]"), tport, bind_ip="127.0.0.1", bind_port=0, cb=cb)
    lhost, lport = fwd.start()
    cfg = build_singbox_config(
        ident, lhost, lport, warp_opts.bind, warp_opts.dns_ip,
        socks_user=warp_opts.socks_user, socks_pass=warp_opts.socks_pass,
        http_inbound_port=warp_opts.http_inbound_port, bind_all=warp_opts.bind_all,
        apply_iran_rules=warp_opts.apply_iran_rules, rules_backend=warp_opts.rules_backend,
        sb_log_level=warp_opts.sb_log_level, sb_stack=warp_opts.sb_stack,
        sb_address_type=warp_opts.sb_address_type, sb_udp_block=warp_opts.sb_udp_block, sb_discord_bypass=warp_opts.sb_discord_bypass,
        tun_mode=warp_opts.tun_mode, tun_name=warp_opts.tun_name, tun_address=warp_opts.tun_address, tun_dns=warp_opts.tun_dns,
        apply_adblock_rules=warp_opts.apply_adblock_rules, adblock_filter_path=warp_opts.adblock_filter_path, cb=cb
    )
    proc = run_singbox(cfg, warp_opts.sing_box_path, cb)
    def pipe(stream, tag):
        for line in iter(stream.readline, ''):
            (cb or print)(f"[SING-BOX][{tag}] {line.rstrip()}")
    threading.Thread(target=pipe, args=(proc.stdout,"out"), daemon=True).start()
    threading.Thread(target=pipe, args=(proc.stderr,"err"), daemon=True).start()
    def readiness():
        bind_addr = f"{warp_opts.bind[0]}:{warp_opts.bind[1]}"
        deadline = time.time() + min(12.0, warp_opts.connect_timeout_sec)
        while time.time() < deadline and proc.poll() is None:
            status, _ = warp_check_over_socks(bind_addr, DEFAULT_TEST_URL, 5, cb)
            if status in ("OK","NO_WARP"):
                _log(cb, "INFO", "WARP-over-MASQUE ready", status=status); return
            time.sleep(0.5)
        _log(cb, "WARN", "WARP-over-MASQUE readiness uncertain")
    threading.Thread(target=readiness, daemon=True).start()
    class ComboCtl(Controller):
        def stop(self):
            try:
                proc.terminate(); proc.wait(timeout=2)
            except Exception:
                try: proc.kill()
                except Exception: pass
            fwd.stop()
    return ComboCtl([proc])

def start_resilient(cb: Optional[LogCB] = None,
                    masque_endpoint: Optional[str] = None,
                    masque_bind: Tuple[str, int] = ("127.0.0.1", 1080),
                    usque_path: str = default_usque_path(),
                    snowflake_enabled: bool = False,
                    snowflake_path: str = "snowflake-client",
                    warp_opts: Optional[WarpOptions] = None) -> Controller:
    if masque_endpoint:
        try:
            mo = MasqueOptions(endpoint=masque_endpoint, bind=masque_bind, usque_path=usque_path, connect_timeout_sec=15)
            ctl_m = start_masque(mo, cb); _log(cb, "INFO", "MASQUE started", bind=f"{masque_bind[0]}:{masque_bind[1]}")
            return ctl_m
        except Exception as e:
            _log(cb, "WARN", "MASQUE failed", err=str(e))
    try:
        if not warp_opts:
            warp_opts = WarpOptions(bind=("127.0.0.1", 8086), connect_timeout_sec=20)
        mo = MasqueOptions(endpoint=DEFAULT_MASQUE_ENDPOINT, bind=masque_bind, usque_path=usque_path, connect_timeout_sec=12)
        ctl_m = start_masque(mo, cb)
        ctl_w = start_warp_over_masque(masque_bind, warp_opts, warp_opts.endpoint, cb)
        _log(cb, "INFO", "WARP-over-MASQUE started", socks=f"{warp_opts.bind[0]}:{warp_opts.bind[1]}")
        class ChainCtl(Controller):
            def __init__(self, a, b): self.a=a; self.b=b
            def stop(self):
                try: self.b.stop()
                finally: self.a.stop()
        return ChainCtl(ctl_m, ctl_w)
    except Exception as e:
        _log(cb, "WARN", "WARP-over-MASQUE failed", err=str(e))
    _log(cb, "INFO", "trying WARP direct")
    ctl = start_warp_with_monitor(warp_opts or WarpOptions(), cb)
    return ctl

# Server parser and tester (Barry lists)
def fetch_remote_configs(url: str, cb: Optional[LogCB] = None) -> List[Dict]:
    _log(cb, "INFO", "fetching remote configs", url=url)
    try:
        import urllib.request
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=20) as resp:
            content = resp.read().decode("utf-8", "ignore")
    except Exception as e:
        _log(cb, "ERROR", "failed to fetch url", url=url, err=str(e))
        return []
    lines: List[str] = []
    # Some subscription files are base64-packed
    def looks_b64(s: str) -> bool:
        return bool(re.fullmatch(r"[A-Za-z0-9+/=_-]+", s.strip())) and len(s.strip()) > 128
    raw = content.strip()
    if looks_b64(raw) and "\n" not in raw:
        try:
            decoded = base64.b64decode(raw + "===")
            content2 = decoded.decode("utf-8","ignore")
            if any(x in content2 for x in ("vmess://","vless://","trojan://","ss://","hysteria2://","hy2://")):
                lines = [ln.strip() for ln in content2.splitlines() if ln.strip()]
        except Exception:
            pass
    if not lines:
        lines = [ln.strip() for ln in content.splitlines() if ln.strip()]
    servers: List[Dict] = []
    for line in lines:
        if not (line.startswith("vmess://") or line.startswith("vless://") or
                line.startswith("trojan://") or line.startswith("ss://") or
                line.startswith("hysteria2://") or line.startswith("hy2://")):
            continue
        servers.append({"protocol": line.split("://",1)[0], "host": "", "port": 0, "original_link": line})
    _log(cb, "INFO", "fetched entries", count=len(servers))
    return servers

@dataclass
class ServerTestOptions:
    sing_box_path: str = field(default_factory=default_sing_box_path)
    bind: Tuple[str, int] = ("127.0.0.1", 8086)
    test_url: str = DEFAULT_TEST_URL
    connect_timeout_sec: float = 15.0
    dns_ip: str = "1.1.1.1"
    sb_log_level: str = "warn"

def parse_vpn_uri_to_singbox_outbound(uri: str, cb: Optional[LogCB] = None) -> Optional[dict]:
    from urllib.parse import urlparse, parse_qs, unquote
    import base64 as _b64, json as _json
    def b64_to_str(s: str) -> str:
        s = s.strip().replace("-", "+").replace("_", "/")
        s += "=" * ((4 - len(s) % 4) % 4)
        return _b64.b64decode(s).decode("utf-8", errors="ignore")
    try:
        u = urlparse(uri)
        scheme = u.scheme.lower()
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        host = u.hostname or ""
        port = u.port or (443 if q.get("security","").lower() in ("tls","reality") else 80)
        def tls_block(default_sni: Optional[str] = None):
            server_name = q.get("sni") or q.get("serverName") or default_sni or host
            insecure = q.get("allowInsecure","0") in ("1","true","yes")
            alpn = q.get("alpn","")
            alpn_list = [x for x in alpn.split(",") if x] if alpn else None
            out = {"enabled": True, "server_name": server_name or host, "insecure": insecure}
            if alpn_list: out["alpn"] = alpn_list
            return out
        def ws_transport():
            path = q.get("path","/") or "/"; host_hdr = q.get("host") or q.get("Host")
            t = {"type":"ws","path":path}
            if host_hdr: t["headers"]={"Host": host_hdr}
            return t
        if scheme == "vmess":
            data = b64_to_str(uri.split("://",1)[1])
            node = _json.loads(data)
            host = node.get("add") or host
            port = int(node.get("port") or port)
            tls_enabled = (node.get("tls","").lower() == "tls")
            sni = node.get("sni")
            outbound = {
                "type": "vmess",
                "server": host, "server_port": port,
                "uuid": node.get("id",""),
                "alter_id": int(node.get("aid") or 0),
                "security": node.get("scy") or "auto",
            }
            if tls_enabled: outbound["tls"] = tls_block(sni)
            net = (node.get("net") or "").lower()
            if net == "ws":
                t = {"type":"ws","path":node.get("path") or "/"}
                host_hdr = node.get("host")
                if host_hdr: t["headers"]={"Host": host_hdr}
                outbound["transport"] = t
            return outbound
        if scheme == "vless":
            uuid = (u.username or "").strip()
            outbound = {"type":"vless","server":host,"server_port":int(port),"uuid":uuid}
            flow = q.get("flow"); 
            if flow: outbound["flow"] = flow
            sec = q.get("security","").lower()
            if sec == "reality":
                outbound["reality"] = {
                    "enabled": True,
                    "public_key": q.get("pbk",""),
                    "short_id": q.get("sid","") or q.get("shortId",""),
                    "server_name": q.get("sni") or host,
                }
            elif sec == "tls":
                outbound["tls"] = tls_block()
            net = (q.get("type") or q.get("net") or "").lower()
            if net == "ws": outbound["transport"] = ws_transport()
            return outbound
        if scheme == "trojan":
            password = unquote(u.username or "")
            outbound = {"type":"trojan","server":host,"server_port":int(port),"password":password}
            if (q.get("security") or "tls").lower() == "tls":
                outbound["tls"] = tls_block()
            net = (q.get("type") or q.get("net") or "").lower()
            if net == "ws": outbound["transport"] = ws_transport()
            sni = q.get("sni")
            if sni: outbound["sni"] = sni
            return outbound
        if scheme in ("ss","shadowsocks"):
            rest = uri.split("://",1)[1]
            if " @" not in rest:
                decoded = b64_to_str(rest.split("#",1)[0].split("?",1)[0])
                creds, addr = decoded.rsplit(" @",1)
                method, password = creds.split(":",1)
                host2, port2 = addr.split(":",1)
                host, port = host2, int(port2)
            else:
                auth, addr = rest.split(" @",1)
                method, password = auth.split(":",1)
                host = addr.split("#",1)[0].split("?",1)[0]
                if ":" in host:
                    host, port = host.split(":",1); port = int(port)
                else:
                    port = 8388
            return {"type":"shadowsocks","server":host,"server_port":int(port),"method":method,"password":password}
        if scheme in ("hysteria2","hy2"):
            password = unquote(u.username or q.get("password",""))
            outbound = {"type":"hysteria2","server":host,"server_port":int(port),"password":password,"tls": tls_block(q.get("sni"))}
            if q.get("obfs") in ("salamander",):
                outbound["obfs"]={"type":"salamander","password": q.get("obfs-password","")}
            return outbound
        if scheme in ("ssr","shadowsocksr"):
            _log(cb, "WARN", "SSR not supported by sing-box", uri=uri); return None
        _log(cb, "WARN", "unsupported scheme", scheme=scheme); return None
    except Exception as e:
        _log(cb, "ERROR", "parse vpn uri failed", err=str(e), uri=uri); return None

def test_and_geo_locate_server(server: Dict, opts: ServerTestOptions, cb: Optional[LogCB] = None) -> Dict:
    _log(cb, "INFO", "testing server", protocol=server.get("protocol"))
    outbound = None
    if server.get("original_link"):
        outbound = parse_vpn_uri_to_singbox_outbound(server["original_link"], cb)
    if not outbound:
        return {"server": server, "success": False, "latency_ms": None, "country": None, "error": "unparsable/unsupported"}
    temp_config_path = os.path.join(cfg_dir(), f"singbox_test_{os.getpid()}_{time.time_ns()}.json")
    ensure_parent_dir(temp_config_path)
    cfg = {
        "log": {"level": opts.sb_log_level},
        "inbounds": [{"type": "socks", "listen": opts.bind[0], "listen_port": opts.bind[1], "udp": True}],
        "outbounds": [outbound, {"type": "direct", "tag": "direct"}, {"type": "block", "tag": "block"}],
        "route": {"auto_detect_interface": True},
        "dns": {"servers": [{"address": opts.dns_ip}]}
    }
    json.dump(cfg, open(temp_config_path,"w",encoding="utf-8"), indent=2)
    proc: Optional[subprocess.Popen] = None
    latency_ms: Optional[float] = None
    country: Optional[str] = None
    success = False
    error_msg: Optional[str] = None
    try:
        cmd = [opts.sing_box_path, "run", "-c", temp_config_path]
        _log(cb, "DEBUG", "starting sing-box for test", cmd=" ".join(shlex.quote(x) for x in cmd))
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        bind_addr = f"{opts.bind[0]}:{opts.bind[1]}"
        deadline = time.time() + max(8.0, float(opts.connect_timeout_sec))
        while time.time() < deadline and proc.poll() is None:
            try:
                t0 = time.time()
                curl_cmd = [curl_path(), "-sS", "--max-time", "5", "--socks5-hostname", bind_addr, "-L", opts.test_url]
                res = subprocess.run(curl_cmd, capture_output=True, text=True, timeout=6)
                if res.returncode == 0:
                    latency_ms = (time.time() - t0) * 1000.0
                    success = True; break
            except subprocess.TimeoutExpired:
                pass
            except Exception as e:
                _log(cb, "WARN", "curl during test", err=str(e))
            time.sleep(0.4)
        if success:
            geo_cmd = [curl_path(), "-s", "--max-time", "5", "--socks5-hostname", bind_addr, "https://ifconfig.co/country"]
            geo_res = subprocess.run(geo_cmd, capture_output=True, text=True, timeout=6)
            if geo_res.returncode == 0:
                country = (geo_res.stdout or "").strip()
            else:
                error_msg = f"geolocation failed: {geo_res.stderr.strip()}"
        else:
            error_msg = "URL test failed or timed out"
    except Exception as e:
        _log(cb, "ERROR", "server test error", err=str(e))
        error_msg = str(e)
    finally:
        if proc:
            try:
                proc.terminate(); proc.wait(timeout=2)
            except Exception:
                try: proc.kill()
                except Exception: pass
        try:
            if os.path.exists(temp_config_path):
                os.remove(temp_config_path)
        except Exception:
            pass
    return {"server": server, "success": success, "latency_ms": latency_ms, "country": country, "error": error_msg}