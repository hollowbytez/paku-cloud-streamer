import os
import sys
import time
import json
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from stream import State, Session, Console, GatewayStreamEngine, ensure_token

TOKEN = os.environ.get("DISCORD_USER_TOKEN", "")
GUILD_ID = os.environ.get("GUILD_ID", "1532381427906380021")
CHANNEL_ID = os.environ.get("CHANNEL_ID", "1574696579963559996")
CHANNEL_NAME = os.environ.get("CHANNEL_NAME", "Farm V1")

class HeadlessGatewayStreamEngine(GatewayStreamEngine):
    def start_stream_headless(self, target_guild_id: str, target_channel_id: str, ch_name: str) -> None:
        C = self.console
        C.rule()
        C.info(f"{C.MAGENTA}Automated Headless Gateway Live Streamer{C.WHITE}")
        C.rule()
        C.info(f"Target: Guild {target_guild_id} · Channel #{ch_name} ({target_channel_id})")

        from stream import GATEWAY_URL, MiniWebSocket, _user_id_from_token
        self.ws = MiniWebSocket(GATEWAY_URL, path="/?v=9&encoding=json")
        try:
            self.ws.connect()
        except Exception as exc:
            C.err("gateway", f"connection failed: {exc}")
            return

        C.ok("gateway", "connected")
        self.running = True
        self.start_time = time.time()
        self.counted_stream_seconds = 0.0
        self.user_id = _user_id_from_token(self.state.token) or ""
        self.stream_ever_active = False
        self._stream_recreate_attempts = 0
        self._user_left_vc = False
        self._was_already_in_vc = False
        self.ready_received.clear()

        event_thread = threading.Thread(target=self._event_loop, daemon=True)
        event_thread.start()

        self.ready_received.wait(timeout=6.0)
        if not self.running:
            C.err("gateway", "ready not received or engine stopped")
            return

        self.guild_id = target_guild_id
        self.channel_id = target_channel_id
        self.channel_name = ch_name

        try:
            self.ws.send(json.dumps({
                "op": 4,
                "d": {
                    "guild_id": self.guild_id,
                    "channel_id": self.channel_id,
                    "self_mute": False,
                    "self_deaf": False,
                    "self_video": False,
                },
            }))
            C.ok("voice", f"joining voice channel #{self.channel_name} ({self.channel_id})")
        except Exception as exc:
            C.err("voice", f"failed to join voice channel: {exc}")
            self._cleanup(self.guild_id)
            return

        self._ticker_thread = threading.Thread(target=self._stream_ticker, daemon=True)
        self._ticker_thread.start()

        self._status_thread = threading.Thread(target=self._status_display, daemon=True)
        self._status_thread.start()

        C.ok("stream", "HEADLESS ENGINE RUNNING - PRODUCING REAL H.264 VIDEO & OPUS AUDIO")
        while self.running:
            time.sleep(1.0)

def main():
    console = Console()
    state = State(
        token=TOKEN,
        last_guild_id=GUILD_ID,
        last_channel_id=CHANNEL_ID,
    )
    session = Session.new()

    engine = HeadlessGatewayStreamEngine(state, session, console)
    engine.start_stream_headless(GUILD_ID, CHANNEL_ID, CHANNEL_NAME)

if __name__ == "__main__":
    main()
