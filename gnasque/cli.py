#!/usr/bin/env python3
from __future__ import annotations
import argparse, os, sys, time, csv, re, concurrent.futures, subprocess

from gnasque.core import (
    DEFAULT_TEST_URL, DEFAULT_MASQUE_ENDPOINT,
    cfg_dir, ensure_dir, parse_bind, parse_endpoint,
    base_build_warp_candidates, warp_udp_probe_scan,
    WarpOptions, MasqueOptions,
    start_warp_with_monitor, start_warp, start_resilient, start_masque,
    default_usque_path, default_sing_box_path, default_warp_plus_path,
    set_system_proxy, clear_system_proxy, backup_proxy_settings, restore_proxy_settings,
    read_log_ring,
    _metrics_load, get_logger, clear_metrics, fetch_remote_configs,
    ServerTestOptions, test_and_geo_locate_server, singbox_version,
    load_profiles, save_profile, delete_profile
)

version = "2.1.0"

def require_tool(binary: str, hint: str):
    from shutil import which
    if which(binary) is None:
        print(f"[ERROR] Required tool not found: {binary}\nHint: {hint}", file=sys.stderr)
        sys.exit(1)

def _warn_tun_privileges(sing_box_path: str):
    try:
        if os.name == "nt":
            try:
                import ctypes
                if not ctypes.windll.shell32.IsUserAnAdmin():
                    print("[WARN] TUN mode likely requires Administrator privileges on Windows.")
            except Exception:
                print("[WARN] TUN mode may require Administrator privileges on Windows.")
        else:
            if hasattr(os, "geteuid") and os.geteuid() != 0:
                try:
                    out = subprocess.run(["getcap", sing_box_path], capture_output=True, text=True)
                    if "cap_net_admin" not in (out.stdout or ""):
                        print(f"[WARN] TUN mode requires CAP_NET_ADMIN; grant with: sudo setcap cap_net_admin,cap_net_raw+ep {sing_box_path}")
                except Exception:
                    print("[WARN] TUN mode may require root or CAP_NET_ADMIN. Example: sudo setcap cap_net_admin,cap_net_raw+ep /usr/bin/sing-box")
    except Exception:
        pass

def add_masque_subparser(sub):
    p = sub.add_parser("masque", help="Run MASQUE proxy (usque)")
    p.add_argument("--endpoint", default=DEFAULT_MASQUE_ENDPOINT, help="MASQUE endpoint (host:port or [v6]:port)")
    p.add_argument("--bind", default="127.0.0.1:1080", help="IP:Port for local SOCKS proxy")
    p.add_argument("--usque-path", default="", help="Path to usque binary (default: auto)")
    p.add_argument("--sni", default="", help="Override SNI (default: consumer-masque.cloudflareclient.com)")
    return p

def add_warp_subparser(sub):
    p = sub.add_parser("warp", help="Run WARP via sing-box or Warp-Plus (SOCKS proxy)")
    p.add_argument("--bind", default="127.0.0.1:8086", help="IP:Port for local SOCKS proxy")
    p.add_argument("--license", default="", help="WARP+ license key (optional)")
    p.add_argument("--endpoint", default="", help="warp endpoint host:port (optional)")
    p.add_argument("--dns", default="1.1.1.1", help="DNS IP for sing-box WG outbound")
    p.add_argument("--connect-timeout", default="180", help="Overall timeout seconds")
    p.add_argument("--cache-dir", default=os.path.join(cfg_dir(), "warp"), help="Cache dir for identity/configs")
    p.add_argument("--sing-box-path", default="", help="Path to sing-box binary (default: auto)")
    p.add_argument("--warp-plus-path", default="", help="Path to warp-plus binary (default: auto)")
    p.add_argument("--use-warp-plus", action="store_true", help="Use Warp-Plus instead of sing-box")
    p.add_argument("--psiphon-mode", action="store_true", help="Enable Psiphon mode (Warp-Plus)")
    p.add_argument("--psiphon-country", default="", help="Psiphon country code (e.g., US, GB, IR)")
    p.add_argument("--gool-mode", action="store_true", help="Enable Gool mode (Warp-in-Warp, Warp-Plus)")
    p.add_argument("--iran-rules", action="store_true", help="Apply Iran sing-box rules")
    p.add_argument("--rules-backend", choices=["rule-set","db"], default="rule-set", help="Rules backend")
    p.add_argument("--prefer-country", default="", help="Prefer endpoints from country code (e.g., FR)")
    p.add_argument("--adblock", action="store_true", help="Enable ad-blocking using filter.txt")
    p.add_argument("--adblock-filter", default="filter.txt", help="Path to ad-blocking filter file (default: filter.txt)")
    p.add_argument("--tun", action="store_true", help="Enable TUN mode (system tunnel)")
    p.add_argument("--tun-name", default="gnasque-tun", help="TUN interface name")
    p.add_argument("--tun-addr", default="172.16.0.2/24", help="TUN IPv4/CIDR")
    p.add_argument("--tun-dns", default="1.1.1.1", help="DNS to use in TUN mode")
    return p

def add_warp_scan_subparser(sub):
    p = sub.add_parser("warp-scan", help="Fast WARP UDP scan (no sing-box)")
    p.add_argument("-4", dest="v4only", action="store_true", help="Scan IPv4")
    p.add_argument("-6", dest="v6only", action="store_true", help="Scan IPv6")
    p.add_argument("-n", "--concurrency", type=int, default=200, help="Worker threads")
    p.add_argument("-t", "--attempts", type=int, default=3, help="UDP attempts per endpoint")
    p.add_argument("--timeout-ms", type=int, default=1000, help="Per-attempt timeout (ms)")
    p.add_argument("-c", "--count", type=int, default=1000, help="Max endpoints to probe")
    p.add_argument("-p", "--print", dest="print_n", type=int, default=20, help="How many results to print")
    return p

def add_resilient_subparser(sub):
    p = sub.add_parser("resilient", help="Resilient mode: MASQUE → WARP-over-MASQUE → WARP/Warp-Plus")
    p.add_argument("--masque-endpoint", default="", help="MASQUE endpoint to try first (optional)")
    p.add_argument("--masque-bind", default="127.0.0.1:1080", help="MASQUE SOCKS bind (IP:Port)")
    p.add_argument("--warp-bind", default="127.0.0.1:8086", help="WARP SOCKS bind (IP:Port)")
    p.add_argument("--usque-path", default="", help="Path to usque binary (default: auto)")
    p.add_argument("--sing-box-path", default="", help="Path to sing-box binary (default: auto)")
    p.add_argument("--warp-plus-path", default="", help="Path to warp-plus binary (default: auto)")
    p.add_argument("--use-warp-plus", action="store_true", help="Use Warp-Plus instead of sing-box")
    p.add_argument("--psiphon-mode", action="store_true", help="Enable Psiphon mode")
    p.add_argument("--psiphon-country", default="", help="Psiphon country code")
    p.add_argument("--gool-mode", action="store_true", help="Enable Gool mode")
    p.add_argument("--cache-dir", default=os.path.join(cfg_dir(), "warp"), help="Cache dir for identity/configs")
    p.add_argument("--license", default="", help="WARP+ license key (optional)")
    p.add_argument("--dns", default="1.1.1.1", help="DNS IP for sing-box WG")
    p.add_argument("--endpoint", default="", help="warp endpoint host:port (optional)")
    p.add_argument("--iran-rules", action="store_true", help="Apply Iran sing-box rules")
    p.add_argument("--rules-backend", choices=["rule-set","db"], default="rule-set", help="Rules backend")
    p.add_argument("--adblock", action="store_true", help="Enable ad-blocking using filter.txt")
    p.add_argument("--adblock-filter", default="filter.txt", help="Path to ad-blocking filter file (default: filter.txt)")
    p.add_argument("--tun", action="store_true", help="Enable TUN mode (system tunnel)")
    p.add_argument("--tun-name", default="gnasque-tun")
    p.add_argument("--tun-addr", default="172.16.0.2/24")
    p.add_argument("--tun-dns", default="1.1.1.1")
    return p

def add_web_subparser(sub):
    p = sub.add_parser("web", help="Start Web UI server")
    p.add_argument("--bind", default="127.0.0.1:8080", help="IP:Port to bind Web UI server")
    p.add_argument("--web-dir", default="", help="Directory with Web UI files (default: package static)")
    return p

def add_profiles_subparser(sub):
    p = sub.add_parser("profiles", help="Manage connection profiles")
    sp = p.add_subparsers(dest="profiles_action", required=True)
    sp.add_parser("list", help="List profiles")
    addp = sp.add_parser("add", help="Add profile")
    addp.add_argument("name"); addp.add_argument("address")
    remp = sp.add_parser("remove", help="Remove profile"); remp.add_argument("name")
    return p

def add_metrics_subparser(sub):
    p = sub.add_parser("metrics", help="Display/Reset metrics")
    sp = p.add_subparsers(dest="metrics_action", required=True)
    sp.add_parser("show", help="Show metrics")
    best = sp.add_parser("reset", help="Reset metrics")
    return p

def add_proxy_subparser(sub):
    p = sub.add_parser("proxy", help="Manage system proxy")
    sp = p.add_subparsers(dest="proxy_action", required=True)
    setp = sp.add_parser("set", help="Set system proxy")
    setp.add_argument("--host", default="127.0.0.1")
    setp.add_argument("--port", type=int, default=1080)
    setp.add_argument("--pac", default="", help="PAC URL (optional)")
    sp.add_parser("clear", help="Clear system proxy")
    sp.add_parser("backup", help="Backup current proxy settings")
    sp.add_parser("restore", help="Restore proxy from backup")
    return p

def add_diag_subparser(sub):
    return sub.add_parser("diag", help="Run diagnostics")

def add_servers_subparser(sub):
    p = sub.add_parser("servers", help="Manage and test VPN servers")
    sp = p.add_subparsers(dest="servers_action", required=True)
    fetch_p = sp.add_parser("fetch", help="Fetch VPN server configurations from URLs")
    fetch_p.add_argument("urls", nargs='+', help="URLs to fetch server configurations from")
    test_p = sp.add_parser("test", help="Test fetched VPN servers for connectivity and geolocation")
    test_p.add_argument("--url", default="", help="URL to fetch servers from before testing (optional)")
    test_p.add_argument("--file", default="", help="File containing server links to test (one per line, optional)")
    test_p.add_argument("--bind", default="127.0.0.1:8090", help="IP:Port for local SOCKS proxy for testing")
    test_p.add_argument("--test-url", default=DEFAULT_TEST_URL, help="URL to use for connectivity test")
    test_p.add_argument("--timeout", type=float, default=15.0, help="Connection timeout in seconds")
    test_p.add_argument("--dns", default="1.1.1.1", help="DNS IP for sing-box during test")
    test_p.add_argument("--sing-box-path", default="", help="Path to sing-box binary (default: auto)")
    test_p.add_argument("--output", default="", help="Output file for test results (CSV format)")
    test_p.add_argument("--concurrency", type=int, default=4, help="Parallel tests")
    return p

def json_dumps(o) -> str:
    import json
    return json.dumps(o, indent=2, ensure_ascii=False)

def run_mode_masque(args):
    try:
        bind_ip, bind_port = parse_bind(args.bind)
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr); sys.exit(1)
    mo = MasqueOptions(
        endpoint=args.endpoint or DEFAULT_MASQUE_ENDPOINT,
        bind=(bind_ip, bind_port),
        usque_path=args.usque_path or default_usque_path(),
        sni=args.sni or ""
    )
    ctl = start_masque(mo, cb=lambda s: print(s))
    print(f"[INFO] serving MASQUE SOCKS on {bind_ip}:{bind_port}")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        ctl.stop(); sys.exit(0)

def run_mode_warp(args):
    try:
        bind_ip, bind_port = parse_bind(args.bind)
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr); sys.exit(1)
    ensure_dir(args.cache_dir)
    if args.use_warp_plus:
        opts = WarpOptions(
            bind=(bind_ip, bind_port),
            warp_plus_path=args.warp_plus_path or default_warp_plus_path(),
            use_warp_plus=True,
            dns_ip=args.dns,
            endpoint=args.endpoint or None,
            cache_dir=args.cache_dir,
            license_key=args.license,
            connect_timeout_sec=float(args.connect_timeout),
            psiphon_mode=args.psiphon_mode,
            psiphon_country=args.psiphon_country or None,
            gool_mode=args.gool_mode,
            apply_iran_rules=args.iran_rules
        )
    else:
        rules_backend = args.rules_backend
        if rules_backend == "rule-set":
            try:
                major, minor, patch = singbox_version(args.sing_box_path or "sing-box")
                if (major, minor) < (1, 8):
                    print("[WARN] sing-box < 1.8 detected; switching rules backend to 'db'")
                    rules_backend = "db"
            except Exception as e:
                print(f"[WARN] Could not detect sing-box version: {e}; using 'rule-set' backend")
        opts = WarpOptions(
            bind=(bind_ip, bind_port),
            sing_box_path=args.sing_box_path or default_sing_box_path(),
            dns_ip=args.dns,
            endpoint=args.endpoint or None,
            cache_dir=args.cache_dir,
            license_key=args.license,
            connect_timeout_sec=float(args.connect_timeout),
            apply_iran_rules=args.iran_rules,
            rules_backend=rules_backend,
            prefer_country=args.prefer_country or None,
            apply_adblock_rules=args.adblock,
            adblock_filter_path=args.adblock_filter,
            tun_mode=args.tun,
            tun_name=args.tun_name,
            tun_address=args.tun_addr,
            tun_dns=args.tun_dns
        )
        if args.tun:
            _warn_tun_privileges(opts.sing_box_path)
    try:
        ctl = start_warp_with_monitor(opts, cb=lambda s: print(s))
    except Exception as e:
        print(f"[ERROR] Failed to start WARP: {e}", file=sys.stderr); sys.exit(1)
    print(f"[INFO] serving WARP/Warp-Plus SOCKS on {bind_ip}:{bind_port}")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        ctl.stop(); sys.exit(0)

def run_mode_warp_scan(args):
    if args.v4only and args.v6only:
        print("[ERROR] can't set both -4 and -6", file=sys.stderr); sys.exit(1)
    v4 = True if not args.v6only else False
    v6 = True if not args.v4only else False
    ports = None
    cands = base_build_warp_candidates(v4, v6, ports, args.count)
    print(f"[INFO] starting UDP probe scan over {len(cands)} candidates...")
    results = warp_udp_probe_scan(cands, attempts=args.attempts, timeout_ms=args.timeout_ms, concurrency=args.concurrency)
    if not results:
        print("No responsive endpoints found"); return
    print("endpoint,avg_ms,recv,sent,loss")
    for r in results[:max(1, args.print_n)]:
        loss = 1.0 - (r["recv"]/r["sent"] if r["sent"] else 1.0)
        print(f"{r['endpoint']},{r['avg_ms']:.1f},{r['recv']},{r['sent']},{loss:.2f}")

def run_mode_resilient(args):
    try:
        masque_bind_ip, masque_bind_port = parse_bind(args.masque_bind)
        warp_bind_ip, warp_bind_port = parse_bind(args.warp_bind)
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr); sys.exit(1)
    if args.use_warp_plus:
        warp_opts = WarpOptions(
            bind=(warp_bind_ip, warp_bind_port),
            warp_plus_path=args.warp_plus_path or default_warp_plus_path(),
            use_warp_plus=True,
            dns_ip=args.dns,
            endpoint=args.endpoint or None,
            cache_dir=args.cache_dir,
            license_key=args.license,
            psiphon_mode=args.psiphon_mode,
            psiphon_country=args.psiphon_country or None,
            gool_mode=args.gool_mode,
            apply_iran_rules=args.iran_rules
        )
    else:
        rules_backend = args.rules_backend
        if rules_backend == "rule-set":
            try:
                major, minor, patch = singbox_version(args.sing_box_path or "sing-box")
                if (major, minor) < (1, 8):
                    print("[WARN] sing-box < 1.8 detected; switching rules backend to 'db'")
                    rules_backend = "db"
            except Exception as e:
                print(f"[WARN] Could not detect sing-box version: {e}; using 'rule-set' backend")
        warp_opts = WarpOptions(
            bind=(warp_bind_ip, warp_bind_port),
            sing_box_path=args.sing_box_path or default_sing_box_path(),
            dns_ip=args.dns,
            endpoint=args.endpoint or None,
            cache_dir=args.cache_dir,
            license_key=args.license,
            apply_iran_rules=args.iran_rules,
            rules_backend=rules_backend,
            apply_adblock_rules=args.adblock,
            adblock_filter_path=args.adblock_filter,
            tun_mode=args.tun,
            tun_name=args.tun_name,
            tun_address=args.tun_addr,
            tun_dns=args.tun_dns
        )
        if args.tun:
            _warn_tun_privileges(warp_opts.sing_box_path)
    ctl = start_resilient(
        cb=lambda s: print(s),
        masque_endpoint=args.masque_endpoint or None,
        masque_bind=(masque_bind_ip, masque_bind_port),
        usque_path=args.usque_path or default_usque_path(),
        snowflake_enabled=False,
        warp_opts=warp_opts
    )
    print(f"[INFO] resilient mode active")
    print(f"  MASQUE: {masque_bind_ip}:{masque_bind_port}")
    print(f"  WARP:   {warp_bind_ip}:{warp_bind_port}")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        ctl.stop(); sys.exit(0)

def run_mode_web(args):
    from gnasque.webui.server import WebUIServer
    try:
        bind_ip, bind_port = parse_bind(args.bind)
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr); sys.exit(1)
    webui = WebUIServer(host=bind_ip, port=bind_port, web_dir=(args.web_dir or ""))
    if not webui.start():
        print("[ERROR] Failed to start Web UI server", file=sys.stderr); sys.exit(1)
    print(f"[INFO] Web UI running at http://{bind_ip}:{bind_port}/")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        webui.stop(); print("[INFO] Web UI stopped"); sys.exit(0)

def run_mode_profiles(args):
    from gnasque.core import load_profiles, save_profile, delete_profile
    if args.profiles_action == "list":
        profiles = load_profiles()
        if not profiles: print("No profiles found.")
        else:
            for name, address in profiles.items():
                print(f"{name}: {address}")
    elif args.profiles_action == "add":
        save_profile(args.name, args.address); print("OK")
    elif args.profiles_action == "remove":
        delete_profile(args.name); print("OK")
    sys.exit(0)

def run_mode_metrics(args):
    if args.metrics_action == "show":
        metrics = _metrics_load()
        print(json_dumps(metrics))
    elif args.metrics_action == "reset":
        clear_metrics(); print("OK")
    sys.exit(0)

def run_mode_proxy(args):
    if args.proxy_action == "set":
        if args.pac:
            set_system_proxy(args.host, args.port, use_pac=True, pac_url=args.pac); print("Set system proxy with PAC")
        else:
            set_system_proxy(args.host, args.port); print("Set system proxy")
    elif args.proxy_action == "clear":
        clear_system_proxy(); print("Cleared")
    elif args.proxy_action == "backup":
        backup_proxy_settings(); print("Backed up")
    elif args.proxy_action == "restore":
        ok = restore_proxy_settings(); print("Restored" if ok else "No backup")
    sys.exit(0)

def run_mode_diag(_args):
    import platform
    from shutil import which
    print("Gnasque diagnostics")
    print("====================")
    print(f"Python: {sys.version.split()[0]} on {sys.platform} ({platform.platform()})")
    def check(b, hint):
        path = which(b)
        print(f"- {b}: {'OK' if path else 'MISSING'}" + (f" ({path})" if path else f" — {hint}"))
    check("curl", "Install curl (Linux: pacman -S curl / apt install curl; Windows includes curl.exe)")
    check("wg", "Install wireguard-tools")
    check("usque" if os.name != "nt" else "usque.exe", "Place ./usque(.exe) or install system-wide")
    check("sing-box" if os.name != "nt" else "sing-box.exe", "Place ./sing-box(.exe) or install system-wide")
    if which("gsettings"): print("- gsettings: OK (GNOME proxy may work)")
    else: print("- gsettings: MISSING (GNOME proxy auto may not work)")
    try:
        v = singbox_version(os.environ.get("SING_BOX_PATH", "sing-box"))
        print(f"- sing-box version: {v[0]}.{v[1]}.{v[2]}")
    except Exception as e:
        print(f"- sing-box version: error: {e}")
    print("Done."); sys.exit(0)

def run_mode_servers(args):
    servers: list[dict] = []
    if args.servers_action == "fetch":
        for url in args.urls:
            servers.extend(fetch_remote_configs(url, cb=lambda s: print(s)))
        if servers:
            print("Fetched servers:")
            for s in servers:
                print(f"  {s.get('protocol','unknown')} -> {s.get('original_link','')[:90]}...")
        else:
            print("No servers fetched.")
        sys.exit(0)
    elif args.servers_action == "test":
        if args.url:
            servers.extend(fetch_remote_configs(args.url, cb=lambda s: print(s)))
        if args.file:
            try:
                with open(args.file, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            servers.append({"protocol": "unknown", "host": "", "port": 0, "original_link": line})
            except Exception as e:
                print(f"[ERROR] Failed to read server file {args.file}: {e}", file=sys.stderr); sys.exit(1)
        if not servers:
            print("No servers to test.", file=sys.stderr); sys.exit(1)
        print(f"[INFO] Testing {len(servers)} servers...")
        test_opts = ServerTestOptions(
            sing_box_path=args.sing_box_path or default_sing_box_path(),
            bind=parse_bind(args.bind),
            test_url=args.test_url,
            connect_timeout_sec=args.timeout,
            dns_ip=args.dns,
        )
        results: list[dict] = []
        def _worker(s):
            return test_and_geo_locate_server(s, test_opts, cb=lambda m: None)
        conc = max(1, int(args.concurrency))
        with concurrent.futures.ThreadPoolExecutor(max_workers=conc) as ex:
            futs = [ex.submit(_worker, s) for s in servers]
            for fut in concurrent.futures.as_completed(futs):
                r = fut.result(); results.append(r)
                s = r["server"]
                proto = s.get('protocol','unknown')
                succ = r.get("success"); lat = r.get("latency_ms"); lat_s = f"{lat:.1f}ms" if isinstance(lat,(int,float)) else "N/A"
                country = r.get("country") or "N/A"; err = r.get("error") or "N/A"
                if s.get("original_link"):
                    print(f"  [{proto}] {s.get('original_link')[:80]}... -> Success: {succ}, Latency: {lat_s}, Country: {country}, Error: {err}")
        if args.output:
            try:
                with open(args.output, "w", encoding="utf-8", newline="") as f:
                    w = csv.writer(f)
                    w.writerow(["protocol","host","port","success","latency_ms","country","error","original_link"])
                    for r in results:
                        s = r["server"]
                        w.writerow([
                            s.get("protocol","unknown"), s.get("host",""), s.get("port",""),
                            r.get("success"), r.get("latency_ms") if r.get("latency_ms") is not None else "",
                            r.get("country") or "", r.get("error") or "", s.get("original_link","")
                        ])
                print(f"[INFO] Test results saved to {args.output}")
            except Exception as e:
                print(f"[ERROR] Failed to write results to {args.output}: {e}", file=sys.stderr)
        sys.exit(0)

def main():
    parser = argparse.ArgumentParser(prog="gnasque", description="Gnasque - MASQUE + WARP toolkit")
    parser.add_argument("--version", action="version", version=f"Gnasque {version}")
    sub = parser.add_subparsers(dest="mode", required=False)
    add_masque_subparser(sub)
    add_warp_subparser(sub)
    add_warp_scan_subparser(sub)
    add_resilient_subparser(sub)
    add_web_subparser(sub)
    add_profiles_subparser(sub)
    add_metrics_subparser(sub)
    add_proxy_subparser(sub)
    add_diag_subparser(sub)
    add_servers_subparser(sub)
    args = parser.parse_args()

    # Default: MASQUE on default endpoint
    if args.mode is None:
        print("[INFO] No mode specified; starting MASQUE with default endpoint.")
        class Obj: pass
        args = argparse.Namespace(endpoint=DEFAULT_MASQUE_ENDPOINT, bind="127.0.0.1:1080", usque_path="", sni="")
        require_tool("curl" if os.name != "nt" else "curl.exe", "Install curl")
        return run_mode_masque(args)

    # Ensure curl exists
    require_tool("curl" if os.name != "nt" else "curl.exe", "Install curl")

    if args.mode == "masque": run_mode_masque(args)
    elif args.mode == "warp": run_mode_warp(args)
    elif args.mode == "warp-scan": run_mode_warp_scan(args)
    elif args.mode == "resilient": run_mode_resilient(args)
    elif args.mode == "web": run_mode_web(args)
    elif args.mode == "profiles": run_mode_profiles(args)
    elif args.mode == "metrics": run_mode_metrics(args)
    elif args.mode == "proxy": run_mode_proxy(args)
    elif args.mode == "diag": run_mode_diag(args)
    elif args.mode == "servers": run_mode_servers(args)
    else:
        parser.print_help(); sys.exit(1)

if __name__ == "__main__":
    main()