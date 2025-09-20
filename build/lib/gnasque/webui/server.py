#!/usr/bin/env python3
from __future__ import annotations
import os, json, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Optional, Dict

from gnasque.core import (
    parse_bind, MasqueOptions, WarpOptions, start_masque, start_warp_with_monitor,
    read_log_ring
)

class WebUIServer:
    def __init__(self, host: str = "127.0.0.1", port: int = 8080, web_dir: str = ""):
        self.host = host; self.port = port
        # If not provided, use package static
        if not web_dir:
            web_dir = os.path.join(os.path.dirname(__file__), "static")
        self.web_dir = web_dir
        self.httpd: Optional[HTTPServer] = None
        self.thread: Optional[threading.Thread] = None
        self.masque_controller = None
        self.warp_controller = None

    def start(self):
        try:
            self.httpd = HTTPServer((self.host, self.port), WebUIHandler)
            WebUIHandler.webui_server = self
            self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
            self.thread.start()
            return True
        except Exception as e:
            print(f"Failed to start Web UI server: {e}")
            return False

    def stop(self):
        try:
            if self.httpd:
                self.httpd.shutdown()
                self.httpd.server_close()
            if self.thread:
                self.thread.join(timeout=2)
        except Exception:
            pass

    def get_status(self):
        return {"masque": {"running": self.masque_controller is not None},
                "warp": {"running": self.warp_controller is not None}}

    def start_masque(self, options: Dict) -> Dict:
        try:
            if self.masque_controller:
                self.masque_controller.stop(); self.masque_controller = None
            bind_ip, bind_port = parse_bind(options.get("bind", "127.0.0.1:1080"))
            masque_opts = MasqueOptions(
                endpoint=options.get("endpoint", ""),
                bind=(bind_ip, bind_port),
                usque_path=options.get("usque_path", "")
            )
            self.masque_controller = start_masque(masque_opts)
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def stop_masque(self) -> Dict:
        try:
            if self.masque_controller:
                self.masque_controller.stop()
                self.masque_controller = None
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def start_warp(self, options: Dict) -> Dict:
        try:
            if self.warp_controller:
                self.warp_controller.stop(); self.warp_controller = None
            bind_ip, bind_port = parse_bind(options.get("bind", "127.0.0.1:8086"))
            warp_opts = WarpOptions(
                bind=(bind_ip, bind_port),
                sing_box_path=options.get("sing_box_path", ""),
                endpoint=options.get("endpoint", None) or None,
                license_key=options.get("license", "")
            )
            self.warp_controller = start_warp_with_monitor(warp_opts)
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def stop_warp(self) -> Dict:
        try:
            if self.warp_controller:
                self.warp_controller.stop()
                self.warp_controller = None
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}

class WebUIHandler(BaseHTTPRequestHandler):
    webui_server: Optional[WebUIServer] = None

    def do_GET(self):
        if self.path in ("/","/index.html"):
            return self._serve_file("index.html","text/html")
        if self.path == "/style.css":
            return self._serve_file("style.css","text/css")
        if self.path == "/script.js":
            return self._serve_file("script.js","application/javascript")
        if self.path == "/api/status":
            return self._serve_json(self.webui_server.get_status() if self.webui_server else {"error": "not initialized"})
        if self.path == "/api/logs/stream":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            for line in read_log_ring():
                try:
                    self.wfile.write(f"data: {line}\n\n".encode("utf-8"))
                except Exception:
                    break
            return
        self.send_error(404, "Not found")

    def do_POST(self):
        if self.path == "/api/masque/start":
            data = self._get_json()
            return self._serve_json(self.webui_server.start_masque(data) if self.webui_server else {"success": False, "error": "not initialized"})
        if self.path == "/api/masque/stop":
            return self._serve_json(self.webui_server.stop_masque() if self.webui_server else {"success": False, "error": "not initialized"})
        if self.path == "/api/warp/start":
            data = self._get_json()
            return self._serve_json(self.webui_server.start_warp(data) if self.webui_server else {"success": False, "error": "not initialized"})
        if self.path == "/api/warp/stop":
            return self._serve_json(self.webui_server.stop_warp() if self.webui_server else {"success": False, "error": "not initialized"})
        self.send_error(404, "Not found")

    def _serve_file(self, filename: str, content_type: str):
        try:
            base = self.webui_server.web_dir if self.webui_server else os.path.join(os.path.dirname(__file__),"static")
            full = os.path.join(base, filename)
            with open(full, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(content)))
            self.end_headers(); self.wfile.write(content)
        except FileNotFoundError:
            self.send_error(404, "Not found")
        except Exception as e:
            self.send_error(500, f"Internal error: {e}")

    def _serve_json(self, data: dict):
        try:
            raw = json.dumps(data).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers(); self.wfile.write(raw)
        except Exception as e:
            self.send_error(500, f"Internal error: {e}")

    def _get_json(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length else b"{}"
            return json.loads(body.decode("utf-8"))
        except Exception:
            return {}

    def log_message(self, *args, **kwargs):
        return