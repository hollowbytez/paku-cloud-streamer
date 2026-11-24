from __future__ import annotations

import json
import os
import signal
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from stream import Console, MiniWebSocket, Session, State, ensure_token
from run_headless_stream import HeadlessGatewayStreamEngine

PORT = int(os.environ.get("PORT", 10000))
BRIDGE_HOST = os.environ.get("BRIDGE_HOST", "paku-prime-cloudflare.pagalonetap7770.workers.dev")
ACCOUNT_ID = os.environ.get("ACCOUNT_ID", "811953657170886766")
BRIDGE_PATH = f"/stream/bridge/{ACCOUNT_ID}"

DEFAULT_TOKEN = os.environ.get("DISCORD_USER_TOKEN", "")
DEFAULT_GUILD_ID = os.environ.get("GUILD_ID", "1532381427906380021")
DEFAULT_CHANNEL_ID = os.environ.get("CHANNEL_ID", "1574696579963559996")
DEFAULT_CHANNEL_NAME = os.environ.get("CHANNEL_NAME", "Farm V1")
AUTO_STREAM = os.environ.get("AUTO_STREAM", "false").strip().lower() in ("true", "1", "yes")

START_TIME = time.time()


class PakuCloudBridgeDaemon:
    def __init__(self) -> None:
        self.console = Console()
        self.running = True
        self.bridge_connected = False
        self.is_streaming = False
        self.current_guild_id = DEFAULT_GUILD_ID
        self.current_channel_id = DEFAULT_CHANNEL_ID
        self.current_channel_name = DEFAULT_CHANNEL_NAME
        self.stream_start_time: float | None = None
        self.current_engine: HeadlessGatewayStreamEngine | None = None
        self.engine_thread: threading.Thread | None = None
        self.ws: MiniWebSocket | None = None
        self._lock = threading.Lock()

    def log(self, tag: str, msg: str) -> None:
        self.console.info(tag, msg)

    def stop_current_stream(self) -> None:
        with self._lock:
            if self.current_engine and self.current_engine.running:
                self.console.warn("bridge", "Stopping active headless stream session...")
                self.current_engine.running = False
                if self.current_engine.voice_conn:
                    try:
                        self.current_engine.voice_conn.close()
                    except Exception:
                        pass
                if self.current_engine.stream_conn:
                    try:
                        self.current_engine.stream_conn.close()
                    except Exception:
                        pass
                if self.current_engine.ws:
                    try:
                        self.current_engine.ws.close()
                    except Exception:
                        pass
                self.current_engine = None
                self.is_streaming = False
                self.stream_start_time = None
                self.console.ok("bridge", "Headless stream session stopped.")

    def handle_start_stream(self, data: dict | None = None) -> None:
        if data is None:
            data = {}
        self.stop_current_stream()

        token = data.get("token") or DEFAULT_TOKEN
        guild_id = str(data.get("guild_id") or DEFAULT_GUILD_ID)
        channel_id = str(data.get("channel_id") or DEFAULT_CHANNEL_ID)
        channel_name = str(data.get("channel_name") or DEFAULT_CHANNEL_NAME)

        self.current_guild_id = guild_id
        self.current_channel_id = channel_id
        self.current_channel_name = channel_name

        self.console.ok(
            "bridge",
            f"START_STREAM -> Launching Live Stream for #{channel_name} ({channel_id}) in Guild {guild_id}",
        )

        state = State(
            token=token,
            last_guild_id=guild_id,
            last_channel_id=channel_id,
        )
        session = Session.new()
        try:
            ensure_token(state, session.super_props)
        except Exception as exc:
            self.console.warn("token", f"ensure_token notice: {exc}")

        engine = HeadlessGatewayStreamEngine(state, session, self.console)
        with self._lock:
            self.current_engine = engine
            self.is_streaming = True
            self.stream_start_time = time.time()

        def _runner():
            try:
                engine.start_stream_headless(guild_id, channel_id, channel_name)
            except Exception as exc:
                self.console.err("stream", f"Stream engine terminated with error: {exc}")
            finally:
                with self._lock:
                    if self.current_engine is engine:
                        self.is_streaming = False
                        self.stream_start_time = None

        self.engine_thread = threading.Thread(target=_runner, daemon=True)
        self.engine_thread.start()

    def run_bridge_loop(self) -> None:
        C = self.console
        C.rule()
        C.info(f"{C.MAGENTA}Paku Cloud · 24/7 Render Stream Engine Active{C.WHITE}")
        C.rule()
        C.info(f"Target Account: {ACCOUNT_ID}")
        C.info(f"Bridge Endpoint: wss://{BRIDGE_HOST}{BRIDGE_PATH}")
        C.info(f"Auto Stream on Boot: {AUTO_STREAM}")
        C.rule()

        if AUTO_STREAM:
            C.info("AUTO_STREAM enabled: Launching stream immediately...")
            self.handle_start_stream({})

        while self.running:
            try:
                self.ws = MiniWebSocket(BRIDGE_HOST, path=BRIDGE_PATH)
                self.ws.connect()
                self.bridge_connected = True
                C.ok("bridge", "Connected to Cloudflare Edge Bridge WebSocket!")

                last_ping = time.time()
                while self.running and not self.ws.closed:
                    now = time.time()
                    if now - last_ping > 20.0:
                        try:
                            self.ws.send(json.dumps({"type": "ping", "timestamp": int(now)}))
                            last_ping = now
                        except Exception:
                            break

                    msg = self.ws.recv(timeout=1.0)
                    if not msg:
                        continue

                    if isinstance(msg, dict):
                        if msg.get("op") == "close":
                            C.warn("bridge", "Cloudflare closed bridge connection")
                            break

                        op = msg.get("op")
                        if op == "START_STREAM":
                            self.handle_start_stream(msg)
                            try:
                                self.ws.send(
                                    json.dumps(
                                        {
                                            "type": "ACK_START",
                                            "channel_id": msg.get("channel_id"),
                                            "status": "streaming",
                                        }
                                    )
                                )
                            except Exception:
                                pass
                        elif op == "STOP_STREAM":
                            self.stop_current_stream()
                            try:
                                self.ws.send(
                                    json.dumps({"type": "ACK_STOP", "status": "stopped"})
                                )
                            except Exception:
                                pass
            except Exception as exc:
                self.bridge_connected = False
                C.warn("bridge", f"Bridge connection dropped ({exc}). Reconnecting in 3s...")
                time.sleep(3.0)


daemon = PakuCloudBridgeDaemon()


class HealthAndControlHandler(BaseHTTPRequestHandler):
    def _send_json(self, status: int, payload: dict) -> None:
        raw = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:
        path = self.path.split("?")[0]
        if path in ("/", "/health", "/status"):
            uptime = round(time.time() - START_TIME, 1)
            stream_duration = (
                round(time.time() - daemon.stream_start_time, 1)
                if daemon.stream_start_time
                else 0.0
            )
            self._send_json(
                200,
                {
                    "ok": True,
                    "service": "paku-cloud-streamer",
                    "status": "online",
                    "bridge_connected": daemon.bridge_connected,
                    "streaming": daemon.is_streaming,
                    "stream_duration_seconds": stream_duration,
                    "guild_id": daemon.current_guild_id,
                    "channel_id": daemon.current_channel_id,
                    "channel_name": daemon.current_channel_name,
                    "uptime_seconds": uptime,
                },
            )
        else:
            self._send_json(404, {"error": "Not Found"})

    def do_POST(self) -> None:
        path = self.path.split("?")[0]
        content_len = int(self.headers.get("Content-Length", 0))
        post_body = {}
        if content_len > 0:
            try:
                post_body = json.loads(self.rfile.read(content_len).decode("utf-8"))
            except Exception:
                post_body = {}

        if path == "/start":
            daemon.handle_start_stream(post_body)
            self._send_json(
                200,
                {
                    "ok": True,
                    "message": "Stream started",
                    "channel_id": daemon.current_channel_id,
                    "channel_name": daemon.current_channel_name,
                },
            )
        elif path == "/stop":
            daemon.stop_current_stream()
            self._send_json(200, {"ok": True, "message": "Stream stopped"})
        else:
            self._send_json(404, {"error": "Not Found"})

    def log_message(self, format: str, *args) -> None:
        # Avoid flood of ping logs on stdout
        pass


def run_http_server():
    server_address = ("0.0.0.0", PORT)
    httpd = ThreadingHTTPServer(server_address, HealthAndControlHandler)
    print(f"[HTTP] Paku Cloud Health Server listening on http://0.0.0.0:{PORT}", flush=True)
    httpd.serve_forever()


def main():
    bridge_thread = threading.Thread(target=daemon.run_bridge_loop, daemon=True)
    bridge_thread.start()

    run_http_server()


if __name__ == "__main__":
    main()
