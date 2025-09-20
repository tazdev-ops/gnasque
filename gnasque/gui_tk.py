#!/usr/bin/env python3
from __future__ import annotations
import os, queue, threading, time, json, tkinter as tk
from tkinter import ttk, messagebox, filedialog

from shutil import which
from gnasque.core import (
    MasqueOptions, WarpOptions,
    start_masque, start_warp_with_monitor, start_resilient,
    parse_bind, DEFAULT_TEST_URL, warp_check_over_socks,
    cfg_dir, generate_pac, serve_pac, set_system_proxy, clear_system_proxy,
    default_sing_box_path, default_usque_path, default_warp_plus_path,
)

APP_TITLE = "Gnasque GUI"

class GnasqueGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("980x700")
        self.minsize(820, 560)
        self.log_q = queue.Queue()
        self.controller = None
        self._pac_server = None
        self._settings_path = os.path.join(cfg_dir(), "ui.json")
        self._build_ui()
        self._load_settings()
        self.after(100, self._drain_logs)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_ui(self):
        nb = ttk.Notebook(self)
        self.masque_tab = ttk.Frame(nb)
        self.warp_tab = ttk.Frame(nb)
        nb.add(self.masque_tab, text="MASQUE")
        nb.add(self.warp_tab, text="WARP")
        nb.pack(fill="both", expand=True)

        self._build_masque_tab(self.masque_tab)
        self._build_warp_tab(self.warp_tab)

        log_frame = ttk.Frame(self)
        log_frame.pack(fill="both", expand=True, side="bottom")
        ttk.Label(log_frame, text="Logs").pack(anchor="w")
        self.log_text = tk.Text(log_frame, height=14, wrap="word", font=("Consolas", 10))
        self.log_text.pack(fill="both", expand=True, padx=6, pady=4)

    def _log(self, line: str):
        self.log_q.put(line)

    def _drain_logs(self):
        try:
            while True:
                line = self.log_q.get_nowait()
                self.log_text.insert("end", line + "\n")
                self.log_text.see("end")
        except queue.Empty:
            pass
        self.after(100, self._drain_logs)

    # MASQUE tab
    def _build_masque_tab(self, root):
        frm = ttk.Frame(root); frm.pack(fill="both", expand=True, padx=10, pady=10)
        left = ttk.LabelFrame(frm, text="Settings"); left.pack(side="left", fill="y", padx=4, pady=4)

        self.m_endpoint = tk.StringVar(value="162.159.198.2:443")
        self.m_bind = tk.StringVar(value="127.0.0.1:1080")
        self.m_usque = tk.StringVar(value=default_usque_path())
        self.m_sni = tk.StringVar(value="consumer-masque.cloudflareclient.com")
        self.m_test_url = tk.StringVar(value=DEFAULT_TEST_URL)
        self.m_confpath = tk.StringVar(value=os.path.join(cfg_dir(), "usque_config.json"))

        row = 0
        ttk.Label(left, text="Endpoint (host[:port] or [v6]:port)").grid(row=row, column=0, sticky="w", padx=4, pady=2); row += 1
        ttk.Entry(left, textvariable=self.m_endpoint, width=35).grid(row=row-1, column=1, padx=4, pady=2)

        ttk.Label(left, text="Bind (IP:Port)").grid(row=row, column=0, sticky="w", padx=4, pady=2)
        ttk.Entry(left, textvariable=self.m_bind, width=20).grid(row=row, column=1, padx=4, pady=2, sticky="w"); row += 1

        ttk.Label(left, text="usque path").grid(row=row, column=0, sticky="w", padx=4, pady=2)
        ttk.Entry(left, textvariable=self.m_usque, width=30).grid(row=row, column=1, padx=4, pady=2, sticky="w")
        ttk.Button(left, text="Browse", command=lambda: self._pick_file(self.m_usque)).grid(row=row, column=2, padx=4); row += 1

        ttk.Label(left, text="SNI").grid(row=row, column=0, sticky="w", padx=4, pady=2)
        ttk.Entry(left, textvariable=self.m_sni, width=30).grid(row=row, column=1, padx=4, pady=2, sticky="w"); row += 1

        ttk.Label(left, text="Config path").grid(row=row, column=0, sticky="w", padx=4, pady=2)
        ttk.Entry(left, textvariable=self.m_confpath, width=30).grid(row=row, column=1, padx=4, pady=2, sticky="w")
        ttk.Button(left, text="Browse", command=lambda: self._pick_file(self.m_confpath)).grid(row=row, column=2, padx=4); row += 1

        btns = ttk.Frame(left); btns.grid(row=row, column=0, columnspan=3, sticky="w", pady=6); row += 1
        ttk.Button(btns, text="Start", command=self._start_masque).pack(side="left", padx=8)
        ttk.Button(btns, text="Stop", command=self._stop_all).pack(side="left", padx=2)
        ttk.Button(btns, text="Warp Check", command=self._warp_check_masque).pack(side="left", padx=8)

        right = ttk.LabelFrame(frm, text="Status"); right.pack(side="left", fill="both", expand=True, padx=4, pady=4)
        self.m_status = tk.StringVar(value="Idle")
        ttk.Label(right, textvariable=self.m_status).pack(anchor="w", padx=4, pady=4)

    def _start_masque(self):
        if self.controller:
            messagebox.showinfo("Gnasque", "A session is already running."); return
        if not os.path.exists(self.m_usque.get()):
            messagebox.showerror("usque not found", f"usque binary not found:\n{self.m_usque.get()}"); return
        if which("curl") is None:
            messagebox.showwarning("curl missing", "curl was not found on PATH. Some checks may fail.")
        try:
            bind = parse_bind(self.m_bind.get())
            endpoint = self.m_endpoint.get().strip()
            if not endpoint:
                messagebox.showerror("Error", "Please set MASQUE Endpoint"); return
            opts = MasqueOptions(endpoint=endpoint, bind=bind, usque_path=self.m_usque.get(), sni=self.m_sni.get(),
                                 connect_timeout_sec=20, config_path=self.m_confpath.get())
            self.controller = start_masque(opts, self._log)
            self.m_status.set(f"Running MASQUE at {self.m_bind.get()}")
        except Exception as e:
            messagebox.showerror("Start error", str(e))

    # WARP tab
    def _build_warp_tab(self, root):
        frm = ttk.Frame(root); frm.pack(fill="both", expand=True, padx=10, pady=10)
        left = ttk.LabelFrame(frm, text="Settings"); left.pack(side="left", fill="y", padx=4, pady=4)

        self.w_bind = tk.StringVar(value="127.0.0.1:8086")
        self.w_sing = tk.StringVar(value=default_sing_box_path())
        self.w_warp_plus = tk.StringVar(value=default_warp_plus_path())
        self.w_endpoint = tk.StringVar(value="")
        self.w_dns = tk.StringVar(value="1.1.1.1")
        self.w_license = tk.StringVar(value="")
        self.w_test_url = tk.StringVar(value=DEFAULT_TEST_URL)
        self.w_http_port = tk.StringVar(value="")
        self.w_bind_all = tk.BooleanVar(value=False)
        self.w_use_warp_plus = tk.BooleanVar(value=False)
        self.w_psiphon_mode = tk.BooleanVar(value=False)
        self.w_gool_mode = tk.BooleanVar(value=False)
        self.w_psiphon_country = tk.StringVar(value="")
        self.w_iran_rules = tk.BooleanVar(value=False)
        self.w_rules_backend = tk.StringVar(value="rule-set")
        self.w_adblock = tk.BooleanVar(value=False)
        self.w_adblock_filter = tk.StringVar(value="filter.txt")

        row = 0
        ttk.Label(left, text="Bind (IP:Port)").grid(row=row, column=0, sticky="w", padx=4, pady=2)
        ttk.Entry(left, textvariable=self.w_bind, width=20).grid(row=row, column=1, padx=4, pady=2, sticky="w"); row += 1

        ttk.Label(left, text="Backend").grid(row=row, column=0, sticky="w", padx=4, pady=2)
        backend_frame = ttk.Frame(left)
        backend_frame.grid(row=row, column=1, sticky="w", padx=4, pady=2)
        self.w_backend_var = tk.StringVar(value="sing-box")
        ttk.Radiobutton(backend_frame, text="sing-box", variable=self.w_backend_var, value="sing-box").pack(side="left")
        ttk.Radiobutton(backend_frame, text="Warp-Plus", variable=self.w_backend_var, value="warp-plus").pack(side="left", padx=(10, 0))
        row += 1

        self.w_sing_label = ttk.Label(left, text="sing-box path")
        self.w_sing_label.grid(row=row, column=0, sticky="w", padx=4, pady=2)
        self.w_sing_entry = ttk.Entry(left, textvariable=self.w_sing, width=30)
        self.w_sing_entry.grid(row=row, column=1, padx=4, pady=2, sticky="w")
        self.w_sing_browse = ttk.Button(left, text="Browse", command=lambda: self._pick_file(self.w_sing))
        self.w_sing_browse.grid(row=row, column=2, padx=4)
        self.w_warp_plus_label = ttk.Label(left, text="Warp-Plus path")
        self.w_warp_plus_label.grid(row=row, column=0, sticky="w", padx=4, pady=2)
        self.w_warp_plus_entry = ttk.Entry(left, textvariable=self.w_warp_plus, width=30)
        self.w_warp_plus_entry.grid(row=row, column=1, padx=4, pady=2, sticky="w")
        self.w_warp_plus_browse = ttk.Button(left, text="Browse", command=lambda: self._pick_file(self.w_warp_plus))
        self.w_warp_plus_browse.grid(row=row, column=2, padx=4)
        row += 1

        ttk.Label(left, text="Endpoint (optional)").grid(row=row, column=0, sticky="w", padx=4, pady=2)
        ttk.Entry(left, textvariable=self.w_endpoint, width=30).grid(row=row, column=1, padx=4, pady=2, sticky="w"); row += 1

        ttk.Label(left, text="DNS").grid(row=row, column=0, sticky="w", padx=4, pady=2)
        ttk.Entry(left, textvariable=self.w_dns, width=20).grid(row=row, column=1, padx=4, pady=2, sticky="w"); row += 1

        ttk.Label(left, text="WARP License (optional)").grid(row=row, column=0, sticky="w", padx=4, pady=2)
        ttk.Entry(left, textvariable=self.w_license, width=30).grid(row=row, column=1, padx=4, pady=2, sticky="w"); row += 1

        ttk.Label(left, text="HTTP inbound port (optional)").grid(row=row, column=0, sticky="w", padx=4, pady=2)
        ttk.Entry(left, textvariable=self.w_http_port, width=10).grid(row=row, column=1, padx=4, pady=2, sticky="w"); row += 1

        ttk.Checkbutton(left, text="Bind on all interfaces (0.0.0.0)", variable=self.w_bind_all).grid(row=row, column=1, sticky="w", padx=4, pady=2); row += 1

        self.w_psiphon_frame = ttk.LabelFrame(left, text="Warp-Plus Options")
        self.w_psiphon_frame.grid(row=row, column=0, columnspan=3, sticky="ew", padx=4, pady=4)
        ttk.Checkbutton(self.w_psiphon_frame, text="Enable Psiphon mode", variable=self.w_psiphon_mode).grid(row=0, column=0, sticky="w", padx=4, pady=2)
        ttk.Label(self.w_psiphon_frame, text="Country code:").grid(row=0, column=1, sticky="w", padx=4, pady=2)
        ttk.Entry(self.w_psiphon_frame, textvariable=self.w_psiphon_country, width=10).grid(row=0, column=2, padx=4, pady=2, sticky="w")
        ttk.Checkbutton(self.w_psiphon_frame, text="Enable Gool mode (Warp-in-Warp)", variable=self.w_gool_mode).grid(row=1, column=0, columnspan=3, sticky="w", padx=4, pady=2)
        row += 1

        ttk.Checkbutton(left, text="Apply Iran sing-box rules", variable=self.w_iran_rules).grid(row=row, column=0, sticky="w", padx=4, pady=2)
        ttk.Combobox(left, textvariable=self.w_rules_backend, values=["rule-set", "db"], width=10).grid(row=row, column=1, padx=4, pady=2, sticky="w"); row += 1

        ttk.Checkbutton(left, text="Enable Ad-blocking", variable=self.w_adblock).grid(row=row, column=0, sticky="w", padx=4, pady=2)
        ttk.Entry(left, textvariable=self.w_adblock_filter, width=30).grid(row=row, column=1, padx=4, pady=2, sticky="w")
        ttk.Button(left, text="Browse", command=lambda: self._pick_file(self.w_adblock_filter)).grid(row=row, column=2, padx=4); row += 1

        proxy_btns = ttk.Frame(left); proxy_btns.grid(row=row, column=0, columnspan=3, sticky="w", pady=6); row += 1
        self.set_proxy_btn = ttk.Button(proxy_btns, text="Set System Proxy (PAC)", command=self._set_system_proxy)
        self.set_proxy_btn.pack(side="left", padx=2)
        self.clear_proxy_btn = ttk.Button(proxy_btns, text="Clear System Proxy", command=self._clear_system_proxy, state="disabled")
        self.clear_proxy_btn.pack(side="left", padx=2)

        btns = ttk.Frame(left); btns.grid(row=row, column=0, columnspan=3, sticky="w", pady=6); row += 1
        ttk.Button(btns, text="Start", command=self._start_warp).pack(side="left", padx=8)
        ttk.Button(btns, text="Resilient", command=self._start_resilient).pack(side="left", padx=2)
        ttk.Button(btns, text="Stop", command=self._stop_all).pack(side="left", padx=8)
        ttk.Button(btns, text="Warp Check", command=self._warp_check_warp).pack(side="left", padx=2)

        right = ttk.LabelFrame(frm, text="Status"); right.pack(side="left", fill="both", expand=True, padx=4, pady=4)
        self.w_status = tk.StringVar(value="Idle")
        ttk.Label(right, textvariable=self.w_status).pack(anchor="w", padx=4, pady=4)

        self.w_backend_var.trace_add("write", lambda *args: self._update_backend_visibility())
        self._update_backend_visibility()

    def _update_backend_visibility(self):
        backend = self.w_backend_var.get()
        is_sing = (backend == "sing-box")
        for w in (self.w_sing_label, self.w_sing_entry, self.w_sing_browse):
            (w.grid if is_sing else w.grid_remove)()
        for w in (self.w_warp_plus_label, self.w_warp_plus_entry, self.w_warp_plus_browse, self.w_psiphon_frame):
            (w.grid if not is_sing else w.grid_remove)()
        if not is_sing:
            self.w_iran_rules.set(False)
            self.w_adblock.set(False)

    def _set_system_proxy(self):
        try:
            bind_ip, bind_port = parse_bind(self.w_bind.get())
            pac = generate_pac(bind_ip, bind_port, direct_domains=["*.ir"])
            srv, t, url = serve_pac("127.0.0.1", 0, pac)
            self._pac_server = srv
            self._log(f"[UI] PAC served at {url}")
            set_system_proxy(bind_ip, bind_port, use_pac=True, pac_url=url)
            self.w_status.set("System proxy set (PAC)")
            self.set_proxy_btn.config(state="disabled")
            self.clear_proxy_btn.config(state="normal")
        except Exception as e:
            messagebox.showerror("Proxy error", str(e))

    def _clear_system_proxy(self):
        try:
            clear_system_proxy()
            if self._pac_server:
                try:
                    self._pac_server.shutdown()
                    self._pac_server.server_close()
                except Exception:
                    pass
                self._pac_server = None
            self.w_status.set("System proxy cleared")
            self.set_proxy_btn.config(state="normal")
            self.clear_proxy_btn.config(state="disabled")
        except Exception as e:
            messagebox.showerror("Proxy error", str(e))

    def _warp_check_masque(self):
        try:
            status, _ = warp_check_over_socks(self.m_bind.get(), self.m_test_url.get(), 6, self._log)
            self.m_status.set(f"Warp check: {status}")
        except Exception as e:
            messagebox.showerror("Warp check error", str(e))

    def _warp_check_warp(self):
        try:
            status, _ = warp_check_over_socks(self.w_bind.get(), self.w_test_url.get(), 6, self._log)
            self.w_status.set(f"Warp check: {status}")
        except Exception as e:
            messagebox.showerror("Warp check error", str(e))

    def _start_warp(self):
        if self.controller:
            messagebox.showinfo("Gnasque", "A session is already running."); return
        backend = self.w_backend_var.get()
        if backend == "sing-box":
            if not os.path.exists(self.w_sing.get()):
                messagebox.showerror("sing-box not found", f"sing-box binary not found:\n{self.w_sing.get()}"); return
        else:
            if not os.path.exists(self.w_warp_plus.get()):
                messagebox.showerror("Warp-Plus not found", f"Warp-Plus binary not found:\n{self.w_warp_plus.get()}"); return
        if which("curl") is None:
            messagebox.showwarning("curl missing", "curl was not found on PATH. Some checks may fail.")
        try:
            bind = parse_bind(self.w_bind.get())
            http_port = int(self.w_http_port.get()) if self.w_http_port.get().strip() else None
            if backend == "warp-plus":
                opts = WarpOptions(
                    bind=bind,
                    warp_plus_path=self.w_warp_plus.get(),
                    use_warp_plus=True,
                    dns_ip=self.w_dns.get(),
                    endpoint=self.w_endpoint.get().strip() or None,
                    license_key=self.w_license.get().strip(),
                    http_inbound_port=http_port,
                    bind_all=self.w_bind_all.get(),
                    psiphon_mode=self.w_psiphon_mode.get(),
                    psiphon_country=self.w_psiphon_country.get().strip() or None,
                    gool_mode=self.w_gool_mode.get()
                )
                self.controller = start_warp_with_monitor(opts, self._log)
                self.w_status.set(f"Running Warp-Plus at {self.w_bind.get()}")
            else:
                opts = WarpOptions(
                    bind=bind,
                    sing_box_path=self.w_sing.get(),
                    dns_ip=self.w_dns.get(),
                    endpoint=self.w_endpoint.get().strip() or None,
                    license_key=self.w_license.get().strip(),
                    http_inbound_port=http_port,
                    bind_all=self.w_bind_all.get(),
                    apply_iran_rules=self.w_iran_rules.get(),
                    rules_backend=self.w_rules_backend.get(),
                    apply_adblock_rules=self.w_adblock.get(),
                    adblock_filter_path=self.w_adblock_filter.get()
                )
                self.controller = start_warp_with_monitor(opts, self._log)
                self.w_status.set(f"Running WARP at {self.w_bind.get()}")
        except Exception as e:
            messagebox.showerror("Start error", str(e))

    def _start_resilient(self):
        if self.controller:
            messagebox.showinfo("Gnasque", "A session is already running."); return
        try:
            bind = parse_bind(self.w_bind.get())
            http_port = int(self.w_http_port.get()) if self.w_http_port.get().strip() else None
            backend = self.w_backend_var.get()
            if backend == "warp-plus":
                warp_opts = WarpOptions(
                    bind=bind,
                    warp_plus_path=self.w_warp_plus.get(),
                    use_warp_plus=True,
                    dns_ip=self.w_dns.get(),
                    endpoint=self.w_endpoint.get().strip() or None,
                    license_key=self.w_license.get().strip(),
                    http_inbound_port=http_port,
                    bind_all=self.w_bind_all.get(),
                    psiphon_mode=self.w_psiphon_mode.get(),
                    psiphon_country=self.w_psiphon_country.get().strip() or None,
                    gool_mode=self.w_gool_mode.get()
                )
            else:
                warp_opts = WarpOptions(
                    bind=bind,
                    sing_box_path=self.w_sing.get(),
                    dns_ip=self.w_dns.get(),
                    endpoint=self.w_endpoint.get().strip() or None,
                    license_key=self.w_license.get().strip(),
                    http_inbound_port=http_port,
                    bind_all=self.w_bind_all.get(),
                    apply_iran_rules=self.w_iran_rules.get(),
                    rules_backend=self.w_rules_backend.get(),
                    apply_adblock_rules=self.w_adblock.get(),
                    adblock_filter_path=self.w_adblock_filter.get()
                )
            masque_bind = parse_bind("127.0.0.1:1080")
            masque_ep = self.m_endpoint.get().strip() or None
            self.controller = start_resilient(cb=self._log, masque_endpoint=masque_ep, masque_bind=masque_bind,
                                              usque_path=self.m_usque.get(), warp_opts=warp_opts)
            self.w_status.set("Resilient mode running")
            self.m_status.set("Resilient mode running")
        except Exception as e:
            messagebox.showerror("Resilient error", str(e))

    def _stop_all(self):
        if self.controller:
            self.controller.stop()
            self.controller = None
            self.m_status.set("Stopped")
            self.w_status.set("Stopped")
            self._log("[UI] Stopped")

    def _pick_file(self, var):
        path = filedialog.askopenfilename()
        if path: var.set(path)

    def _load_settings(self):
        try:
            d = json.load(open(self._settings_path, "r", encoding="utf-8"))
            self.m_endpoint.set(d.get("m_endpoint", self.m_endpoint.get()))
            self.m_bind.set(d.get("m_bind", self.m_bind.get()))
            self.m_usque.set(d.get("m_usque", self.m_usque.get()))
            self.m_sni.set(d.get("m_sni", self.m_sni.get()))
            self.w_bind.set(d.get("w_bind", self.w_bind.get()))
            self.w_backend_var.set(d.get("w_backend", self.w_backend_var.get()))
            self.w_sing.set(d.get("w_sing", self.w_sing.get()))
            self.w_warp_plus.set(d.get("w_warp_plus", self.w_warp_plus.get()))
            self.w_iran_rules.set(d.get("w_iran_rules", self.w_iran_rules.get()))
            self.w_rules_backend.set(d.get("w_rules_backend", self.w_rules_backend.get()))
            self.w_adblock.set(d.get("w_adblock", self.w_adblock.get()))
            self.w_adblock_filter.set(d.get("w_adblock_filter", self.w_adblock_filter.get()))
        except Exception:
            pass

    def _save_settings(self):
        d = {
            "m_endpoint": self.m_endpoint.get(),
            "m_bind": self.m_bind.get(),
            "m_usque": self.m_usque.get(),
            "m_sni": self.m_sni.get(),
            "w_bind": self.w_bind.get(),
            "w_backend": self.w_backend_var.get(),
            "w_sing": self.w_sing.get(),
            "w_warp_plus": self.w_warp_plus.get(),
            "w_iran_rules": self.w_iran_rules.get(),
            "w_rules_backend": self.w_rules_backend.get(),
            "w_adblock": self.w_adblock.get(),
            "w_adblock_filter": self.w_adblock_filter.get(),
        }
        from gnasque.core import ensure_parent_dir
        ensure_parent_dir(self._settings_path)
        json.dump(d, open(self._settings_path,"w",encoding="utf-8"), indent=2)

    def _on_close(self):
        try:
            self._save_settings()
            if self._pac_server:
                self._clear_system_proxy()
        finally:
            self._stop_all()
            self.destroy()

def main():
    app = GnasqueGUI()
    app.mainloop()

if __name__ == "__main__":
    main()