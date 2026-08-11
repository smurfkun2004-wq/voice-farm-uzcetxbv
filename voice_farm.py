import asyncio, json, logging, os, socket, struct, time, random, sys
from logging.handlers import RotatingFileHandler

import aiohttp
import nacl.secret, nacl.bindings

TOKEN = os.environ.get("DISCORD_TOKEN", "")
GUILD_ID = os.environ.get("GUILD_ID", "")
CHANNEL_ID = os.environ.get("CHANNEL_ID", "")
API_BASE = "https://discord.com/api/v10"
GATEWAY_URL = "wss://gateway.discord.gg/?v=10&encoding=json"
VOICE_GATEWAY_VERSION = 4
SAMPLE_RATE = 48000
CHANNELS_AUDIO = 2
FRAME_SIZE_AUDIO = 960
SILENCE_FRAME = bytes([0xf8, 0xff, 0xfe])
SILENCE_INTERVAL = 5.0

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("voice-farm")

from flask import Flask
app_flask = Flask(__name__)

@app_flask.route("/")
def home():
    return '{"status":"alive"}'

@app_flask.route("/health")
def health():
    return "OK", 200

class VoiceClient:
    def __init__(self):
        self.gw_ws = None
        self.voice_ws = None
        self.udp_sock = None
        self.ssrc = 0
        self.voice_ip = None
        self.voice_port = None
        self.encryption_key = None
        self.encryption_mode = "xsalsa20_poly1305"
        self.seq = 0
        self.timestamp = 0
        self.session_id = None
        self.sequence = None
        self.running = True
        self.connected = False
        self.reconnect_count = 0

    async def connect_gateway(self, session):
        self.gw_ws = await session.ws_connect(GATEWAY_URL, max_msg_size=0, heartbeat=None)
        hello = json.loads((await self.gw_ws.receive(timeout=30)).data)
        if hello.get("op") != 10:
            logger.error("Gateway: expected HELLO")
            return False
        hb_interval = hello["d"]["heartbeat_interval"] / 1000.0
        await self.gw_ws.send_json({
            "op": 2, "d": {
                "token": TOKEN,
                "properties": {"$os": "linux", "$browser": "voice-farm", "$device": "voice-farm"},
                "compress": False, "large_threshold": 50, "shard": [0, 1]
            }
        })
        ready = json.loads((await self.gw_ws.receive(timeout=30)).data)
        if ready.get("t") != "READY":
            return False
        self.session_id = ready["d"]["session_id"]
        self.sequence = ready.get("s")
        self.gw_hb = asyncio.create_task(self._gw_heartbeat(hb_interval))
        await self.gw_ws.send_json({
            "op": 4, "d": {"guild_id": GUILD_ID, "channel_id": CHANNEL_ID, "self_mute": False, "self_deaf": True}
        })
        async for msg in self.gw_ws:
            if not self.running or msg.type != aiohttp.WSMsgType.TEXT:
                continue
            data = json.loads(msg.data)
            s = data.get("s")
            if s is not None:
                self.sequence = s
            t, op = data.get("t"), data.get("op")
            if op == 0 and t == "VOICE_SERVER_UPDATE":
                d = data["d"]
                self.voice_token = d.get("token", "")
                self.voice_endpoint = d.get("endpoint", "")
                return await self._connect_voice(session)
            elif op == 9:
                return False
        return False

    async def _gw_heartbeat(self, interval):
        try:
            await asyncio.sleep(interval * random.random())
            while self.running and self.gw_ws and not self.gw_ws.closed:
                try:
                    seq = self.sequence if self.sequence is not None else 0
                    await self.gw_ws.send_json({"op": 1, "d": seq})
                except Exception:
                    break
                await asyncio.sleep(interval)
        except asyncio.CancelledError:
            pass

    async def _connect_voice(self, session):
        if not self.voice_endpoint or not self.voice_token:
            return False
        vurl = "wss://{}/?v={}".format(self.voice_endpoint, VOICE_GATEWAY_VERSION)
        self.voice_ws = await session.ws_connect(vurl, max_msg_size=0)
        hello = json.loads((await self.voice_ws.receive(timeout=30)).data)
        if hello.get("op") != 8:
            return False
        hb_int = hello["d"]["heartbeat_interval"] / 1000.0
        self.voice_hb = asyncio.create_task(self._voice_heartbeat(hb_int))
        await self.voice_ws.send_json({
            "op": 0, "d": {"server_id": GUILD_ID, "user_id": None, "session_id": self.voice_token, "token": self.voice_token}
        })
        vready = json.loads((await self.voice_ws.receive(timeout=30)).data)
        if vready.get("op") != 2:
            return False
        self.ssrc = vready["d"]["ssrc"]
        self.voice_ip = vready["d"]["ip"]
        self.voice_port = vready["d"]["port"]
        for m in ["xsalsa20_poly1305", "xsalsa20_poly1305_suffix", "xsalsa20_poly1305_lite"]:
            if m in vready["d"]["modes"]:
                self.encryption_mode = m
                break
        loop = asyncio.get_running_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        sock.bind(("0.0.0.0", 0))
        sock.sendto(struct.pack(">I", self.ssrc) + bytes(70), (self.voice_ip, self.voice_port))
        data, _ = await loop.sock_recvfrom(sock, 256)
        our_ip = data[8:].split(bytes(1))[0].decode()
        our_port = struct.unpack_from(">H", data, 6)[0]
        await self.voice_ws.send_json({
            "op": 1, "d": {"protocol": "udp", "data": {"address": our_ip, "port": our_port, "mode": self.encryption_mode}}
        })
        sd = json.loads((await self.voice_ws.receive(timeout=30)).data)
        if sd.get("op") != 4:
            return False
        self.encryption_key = bytes(sd["d"]["secret_key"])
        self.udp_sock = sock
        self.connected = True
        self.silence_task = asyncio.create_task(self._silence_loop())
        return True

    async def _voice_heartbeat(self, interval):
        try:
            while self.running and self.voice_ws and not self.voice_ws.closed:
                try:
                    await self.voice_ws.send_json({"op": 3, "d": int(time.time() * 1000)})
                except Exception:
                    break
                await asyncio.sleep(interval)
        except asyncio.CancelledError:
            pass

    def _encrypt(self, opus_frame):
        hdr = bytearray(12)
        hdr[0], hdr[1] = 0x80, 0x78
        struct.pack_into(">H", hdr, 2, self.seq)
        struct.pack_into(">I", hdr, 4, self.timestamp)
        struct.pack_into(">I", hdr, 8, self.ssrc)
        if self.encryption_mode == "xsalsa20_poly1305":
            box = nacl.secret.SecretBox(self.encryption_key)
            return box.encrypt(bytes(hdr) + opus_frame, bytes(12)).ciphertext
        elif self.encryption_mode == "xsalsa20_poly1305_suffix":
            nonce = nacl.bindings.randombytes(24)
            box = nacl.secret.SecretBox(self.encryption_key)
            return bytes(hdr) + box.encrypt(bytes(hdr) + opus_frame, nonce).ciphertext + nonce
        return bytes(hdr) + opus_frame

    async def _silence_loop(self):
        loop = asyncio.get_running_loop()
        count = 0
        while self.running and self.connected and self.udp_sock:
            try:
                pkt = self._encrypt(SILENCE_FRAME)
                await loop.sock_sendto(self.udp_sock, pkt, (self.voice_ip, self.voice_port))
                self.seq = (self.seq + 1) % 65536
                self.timestamp = (self.timestamp + FRAME_SIZE_AUDIO) % 4294967296
                count += 1
                if count % 60 == 0:
                    logger.info("Alive - {} frames".format(count))
                await asyncio.sleep(SILENCE_INTERVAL)
            except Exception as e:
                logger.error("Silence error: {}".format(e))
                self.connected = False
                break

    async def shutdown(self):
        self.running = False
        self.connected = False
        for t in [self.silence_task, self.voice_hb, self.gw_hb]:
            if t and not t.done():
                t.cancel()
                try:
                    await t
                except:
                    pass
        for ws in [self.voice_ws, self.gw_ws]:
            if ws and not ws.closed:
                try:
                    await ws.close()
                except:
                    pass
        if self.udp_sock:
            try:
                self.udp_sock.close()
            except:
                pass

    async def run(self):
        timeout = aiohttp.ClientTimeout(total=60, connect=30)
        while self.running:
            try:
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    ok = await self.connect_gateway(session)
                    if not ok:
                        await asyncio.sleep(10)
                        continue
                    while self.running and self.connected:
                        await asyncio.sleep(10)
                    if not self.running:
                        break
                    self.reconnect_count += 1
                    wait = min(5 * self.reconnect_count, 30)
                    await self._cleanup_voice()
                    await asyncio.sleep(wait)
            except asyncio.CancelledError:
                break
            except Exception as e:
                err_type = type(e).__name__
                logger.warning("Run restarting after {}: {}".format(err_type, e))
                self.reconnect_count += 1
                wait = min(5 * self.reconnect_count, 30)
                await asyncio.sleep(wait)

    async def _cleanup_voice(self):
        for t in [self.silence_task, self.voice_hb]:
            if t and not t.done():
                t.cancel()
                try:
                    await t
                except:
                    pass
        if self.voice_ws and not self.voice_ws.closed:
            try:
                await self.voice_ws.close()
            except:
                pass
        self.voice_ws = None
        if self.udp_sock:
            try:
                self.udp_sock.close()
            except:
                pass
        self.udp_sock = None

async def main():
    if not TOKEN or not GUILD_ID or not CHANNEL_ID:
        logger.error("Missing env vars")
        return
    from threading import Thread
    Thread(target=lambda: app_flask.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080))), daemon=True).start()
    client = VoiceClient()
    try:
        await client.run()
    finally:
        await client.shutdown()

if __name__ == "__main__":
    asyncio.run(main())

