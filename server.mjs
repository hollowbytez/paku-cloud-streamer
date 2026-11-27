import crypto from "node:crypto";
import dgram from "node:dgram";
import http from "node:http";
import tls from "node:tls";
import WebSocket from "ws";
import { DAVESession, ProposalsOperationType } from "@snazzah/davey";

const PORT = Number(process.env.PORT || 10000);
const SECRET = (process.env.EGRESS_RELAY_SECRET || "").trim();
const DEFAULT_WEBHOOK_URL = (process.env.PAKU_WEBHOOK_URL || "").trim();
const DEFAULT_VIEWER_TOKEN = (process.env.ALT_VIEWER_TOKEN || "").trim();

if (!SECRET) {
  console.error("EGRESS_RELAY_SECRET is required.");
  process.exit(1);
}

const activeStreams = new Map();
const identifyHistory = new Map();
const startedAtMs = Date.now();
let lastKnownWebhookUrl = DEFAULT_WEBHOOK_URL;
const DEFAULT_UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36";

function signRelayPayloadSync(timestamp, body) {
  return crypto
    .createHmac("sha256", SECRET)
    .update(`${timestamp}.${body}`)
    .digest("hex");
}

function sendRelayWebhook(webhookUrl, payload) {
  const url = String(webhookUrl || lastKnownWebhookUrl || "").trim();
  if (!url || !url.startsWith("https://")) {
    return Promise.resolve();
  }
  const body = JSON.stringify(payload);
  const ts = String(Math.floor(Date.now() / 1000));
  const sig = signRelayPayloadSync(ts, body);
  return fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Paku-Timestamp": ts,
      "X-Paku-Signature": sig,
    },
    body,
    signal: AbortSignal.timeout(5000),
  }).catch(() => {});
}

function allowIdentifyForAccount(accountId) {
  const now = Math.floor(Date.now() / 1000);
  const windowSec = 900;
  const stamps = (identifyHistory.get(accountId) || []).filter((t) => now - t < windowSec);
  if (stamps.length >= 2) {
    identifyHistory.set(accountId, stamps);
    return false;
  }
  stamps.push(now);
  identifyHistory.set(accountId, stamps);
  return true;
}

function openDiscordWs(url, userAgent, cookieJar) {
  const headers = {
    Origin: "https://discord.com",
    "User-Agent": userAgent || DEFAULT_UA,
    "Accept-Language": "en-US,en;q=0.9",
    Pragma: "no-cache",
    "Cache-Control": "no-cache",
  };
  if (cookieJar) {
    headers.Cookie = cookieJar;
  }
  return new WebSocket(url, { headers });
}

function constantTimeHexEqual(a, b) {
  if (!a || !b || a.length !== b.length) {
    return false;
  }
  return crypto.timingSafeEqual(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));
}

function verifySignature(timestamp, payload, providedHex) {
  const ts = Number(timestamp);
  if (!Number.isFinite(ts)) {
    return false;
  }
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - ts) > 60) {
    return false;
  }
  const expected = crypto
    .createHmac("sha256", SECRET)
    .update(`${timestamp}.${payload}`)
    .digest("hex");
  return constantTimeHexEqual(providedHex.toLowerCase(), expected.toLowerCase());
}

export function isAllowedHttpTarget(rawUrl) {
  try {
    const parsed = new URL(rawUrl);
    if (parsed.protocol !== "https:") {
      return false;
    }
    return parsed.hostname === "discord.com" || parsed.hostname.endsWith(".discord.com");
  } catch {
    return false;
  }
}

export function isAllowedWsTarget(rawUrl) {
  try {
    const parsed = new URL(rawUrl);
    if (parsed.protocol !== "wss:") {
      return null;
    }
    const h = parsed.hostname;
    const valid =
      h === "gateway.discord.gg" ||
      h.endsWith(".discord.gg") ||
      h.endsWith(".discord.media") ||
      h === "discord.com";
    if (!valid) {
      return null;
    }
    return {
      host: parsed.hostname,
      port: Number(parsed.port || 443),
      path: `${parsed.pathname || "/"}${parsed.search || ""}`,
    };
  } catch {
    return null;
  }
}

function normalizeEndpointUrl(endpoint, query) {
  let clean = String(endpoint || "")
    .replace(/^wss?:\/\//i, "")
    .replace(/^https?:\/\//i, "")
    .replace(/\/+$/, "");
  if (!clean.includes(":")) {
    clean = `${clean}:443`;
  }
  return `wss://${clean}/${query}`;
}

function discoverUdpEndpoint(ip, port, ssrc) {
  return new Promise((resolve) => {
    const sock = dgram.createSocket("udp4");
    let settled = false;
    const done = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ sock, ...result });
    };

    const timer = setTimeout(() => {
      done({ address: "127.0.0.1", port: 1234 });
    }, 2000);

    sock.on("error", () => {
      done({ address: "127.0.0.1", port: 1234 });
    });

    sock.once("message", (msg) => {
      if (msg.length >= 74 && msg.readUInt16BE(0) === 2) {
        const nullIdx = msg.indexOf(0, 8);
        const end = nullIdx > 8 && nullIdx < 72 ? nullIdx : 72;
        const address = msg.subarray(8, end).toString("utf8").trim() || "127.0.0.1";
        const extPort = msg.readUInt16BE(72) || 1234;
        done({ address, port: extPort });
        return;
      }
      done({ address: "127.0.0.1", port: 1234 });
    });

    const packet = Buffer.alloc(74);
    packet.writeUInt16BE(1, 0);
    packet.writeUInt16BE(70, 2);
    packet.writeUInt32BE(ssrc >>> 0, 4);
    sock.send(packet, port, ip, (err) => {
      if (err) {
        done({ address: "127.0.0.1", port: 1234 });
      }
    });
  });
}

function pickAeadMode(modes) {
  if (!Array.isArray(modes)) {
    return "aead_aes256_gcm_rtpsize";
  }
  if (modes.includes("aead_aes256_gcm_rtpsize")) {
    return "aead_aes256_gcm_rtpsize";
  }
  if (modes.includes("aead_xchacha20_poly1305_rtpsize")) {
    return "aead_xchacha20_poly1305_rtpsize";
  }
  return modes[0] || "aead_aes256_gcm_rtpsize";
}

function sendUdpKeepalive(sock, ip, port, seq = 0) {
  try {
    const keepalive = Buffer.alloc(8);
    keepalive.writeBigUInt64LE(BigInt(seq >>> 0), 0);
    sock.send(keepalive, port, ip);
  } catch {
  }
}

const OPUS_SILENCE = Buffer.from([0xf8, 0xff, 0xfe]);

function sendEncryptedOpusSilence(sock, ip, port, secretKey, ssrc, state, rawFrame = OPUS_SILENCE) {
  if (!sock || !secretKey || secretKey.length !== 32) {
    return;
  }
  try {
    const rtp = Buffer.alloc(12);
    rtp[0] = 0x80;
    rtp[1] = 120;
    rtp.writeUInt16BE(state.seq & 0xffff, 2);
    rtp.writeUInt32BE(state.ts >>> 0, 4);
    rtp.writeUInt32BE(ssrc >>> 0, 8);
    const nonce = Buffer.alloc(12);
    nonce.writeUInt32BE(state.nonce >>> 0, 0);
    const cipher = crypto.createCipheriv("aes-256-gcm", secretKey, nonce);
    cipher.setAAD(rtp);
    const encrypted = Buffer.concat([cipher.update(rawFrame), cipher.final()]);
    const tag = cipher.getAuthTag();
    const tail = Buffer.alloc(4);
    tail.writeUInt32BE(state.nonce >>> 0, 0);
    sock.send(Buffer.concat([rtp, encrypted, tag, tail]), port, ip);
    state.seq = (state.seq + 1) & 0xffff;
    state.ts = (state.ts + 960) >>> 0;
    state.nonce = (state.nonce + 1) >>> 0;
  } catch {
  }
}

class DaveController {
  constructor(userId, channelId, sendBinary, sendJson) {
    this.userId = String(userId);
    this.channelId = String(channelId);
    this.sendBinary = sendBinary;
    this.sendJson = sendJson;
    this.session = null;
    this.protocolVersion = 0;
    this.recognizedUsers = new Set([this.userId]);
  }

  initVersion(version) {
    const v = Number(version || 0);
    this.protocolVersion = v;
    if (v <= 0) {
      if (this.session) {
        try {
          this.session.reset();
        } catch {
        }
      }
      return;
    }
    if (!this.session) {
      this.session = new DAVESession(v, this.userId, this.channelId);
    } else {
      this.session.reinit(v, this.userId, this.channelId);
    }
    this.pushKeyPackage();
  }

  pushKeyPackage() {
    if (!this.session || this.protocolVersion <= 0) return;
    try {
      const pkg = this.session.getSerializedKeyPackage();
      this.sendBinary(Buffer.concat([Buffer.from([26]), pkg]));
    } catch {
    }
  }

  encryptOpus(frame) {
    if (this.protocolVersion > 0 && this.session?.canEncrypt) {
      try {
        return this.session.encryptOpus(frame);
      } catch {
      }
    }
    return frame;
  }

  handleJson(msg) {
    const op = msg?.op;
    const d = msg?.d;
    if (op === 11 && Array.isArray(d?.user_ids)) {
      for (const uid of d.user_ids) {
        this.recognizedUsers.add(String(uid));
      }
      return;
    }
    if (op === 13 && d?.user_id) {
      this.recognizedUsers.delete(String(d.user_id));
      return;
    }
    if (op === 4) {
      this.initVersion(Number(d?.dave_protocol_version ?? 0));
      return;
    }
    if (op === 24) {
      if (Number(d?.epoch ?? 0) === 1) {
        this.initVersion(Number(d?.protocol_version ?? 1));
      }
      return;
    }
    if (op === 21) {
      const tid = Number(d?.transition_id ?? 0);
      const pv = Number(d?.protocol_version ?? 0);
      if (pv === 0) {
        this.protocolVersion = 0;
        try {
          this.session?.reset();
        } catch {
        }
      } else if (this.session) {
        this.protocolVersion = pv;
        try {
          this.session.prepareTransition(tid, pv);
        } catch {
        }
      }
      if (tid !== 0) {
        this.sendJson({ op: 23, d: { transition_id: tid } });
      }
      return;
    }
    if (op === 22 && this.session) {
      try {
        this.session.executeTransition(Number(d?.transition_id ?? 0));
      } catch {
      }
    }
  }

  handleBinary(buf) {
    if (!buf || buf.length < 3 || !this.session) return;
    const op = buf.readUInt8(2);
    const recognized = Array.from(this.recognizedUsers);

    if (op === 25) {
      try {
        this.session.setExternalSender(buf.subarray(3));
        this.pushKeyPackage();
      } catch {
      }
      return;
    }

    if (op === 27 && buf.length >= 4) {
      try {
        const opType = buf.readUInt8(3) === 1 ? ProposalsOperationType.REVOKE : ProposalsOperationType.APPEND;
        const res = this.session.processProposals(opType, buf.subarray(4), recognized);
        if (res?.commit) {
          const parts = [Buffer.from([28]), res.commit];
          if (res.welcome) {
            parts.push(res.welcome);
          }
          this.sendBinary(Buffer.concat(parts));
        }
      } catch {
      }
      return;
    }

    if (op === 29 && buf.length >= 5) {
      const tid = buf.readUInt16BE(3);
      try {
        if (this.session.processCommit(buf.subarray(5))) {
          this.session.prepareTransition(tid, this.protocolVersion || 1);
          this.sendJson({ op: 23, d: { transition_id: tid } });
        }
      } catch {
        this.sendJson({ op: 31, d: { transition_id: tid } });
      }
      return;
    }

    if (op === 30 && buf.length >= 5) {
      const tid = buf.readUInt16BE(3);
      try {
        this.session.processWelcome(buf.subarray(5), recognized);
        this.session.prepareTransition(tid, this.protocolVersion || 1);
        this.sendJson({ op: 23, d: { transition_id: tid } });
      } catch {
        this.sendJson({ op: 31, d: { transition_id: tid } });
      }
    }
  }
}

function buildSuperPropertiesBase64(properties) {
  return Buffer.from(JSON.stringify(properties || {})).toString("base64");
}

function extractSnowflakeFromToken(token) {
  try {
    const clean = String(token || "").trim().replace(/^Bot\s+/i, "").replace(/"/g, "");
    const first = clean.split(".")[0];
    if (!first) return "";
    const norm = first.replace(/-/g, "+").replace(/_/g, "/");
    const padded = norm + "=".repeat((4 - (norm.length % 4)) % 4);
    const decoded = Buffer.from(padded, "base64").toString("utf8");
    return /^\d{17,20}$/.test(decoded) ? decoded : "";
  } catch {
    return "";
  }
}

class AltViewerSession {
  constructor({ token, guildId, channelId, streamKey, userAgent, properties, onStatusChange }) {
    this.token = String(token || "").trim();
    this.guildId = String(guildId);
    this.rtcServerId = String(guildId);
    this.channelId = String(channelId);
    this.streamKey = String(streamKey);
    this.userAgent = userAgent || DEFAULT_UA;
    this.properties = {
      ...(properties || { os: "Windows", browser: "Discord Client", release_channel: "stable" }),
      client_launch_id: crypto.randomUUID(),
      launch_signature: crypto.randomUUID(),
      client_heartbeat_session_id: crypto.randomUUID(),
    };
    this.onStatusChange = typeof onStatusChange === "function" ? onStatusChange : () => {};
    this.userId = extractSnowflakeFromToken(this.token);
    this.stopped = false;
    this.connected = false;
    this.fatal = false;
    this.mainWs = null;
    this.roomVoiceWs = null;
    this.watchRtcWs = null;
    this.roomUdp = null;
    this.watchUdp = null;
    this.timers = [];
    this.sessionId = "";
    this.resumeGatewayUrl = null;
    this.lastSeq = null;
    this.watched = false;
    this.watchRequested = false;
    this.keepaliveSeq = 0;
  }

  start() {
    if (this.stopped || !this.token) return;
    const ws = openDiscordWs("wss://gateway.discord.gg/?v=10&encoding=json", this.userAgent);
    this.mainWs = ws;
    let hbInterval = null;

    ws.on("message", (raw) => {
      if (this.stopped) return;
      let msg;
      try {
        msg = JSON.parse(typeof raw === "string" ? raw : raw.toString("utf8"));
      } catch {
        return;
      }
      if (msg.s !== undefined && msg.s !== null) {
        this.lastSeq = msg.s;
      }
      if (msg.op === 1 && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ op: 1, d: this.lastSeq }));
        return;
      }
      if (msg.op === 7 || msg.op === 9) {
        if (msg.op === 9 && !msg.d) {
          this.sessionId = "";
          this.lastSeq = null;
        }
        try {
          ws.close(4000, "reconnect");
        } catch {
        }
        return;
      }
      if (msg.op === 10) {
        const ms = Number(msg.d?.heartbeat_interval || 41250);
        hbInterval = setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ op: 1, d: this.lastSeq }));
          }
        }, Math.floor(ms * 0.85));
        this.timers.push(hbInterval);
        ws.send(
          JSON.stringify({
            op: 2,
            d: {
              token: this.token,
              capabilities: 30717,
              properties: this.properties,
              presence: { status: "online", since: 0, activities: [], afk: false },
              compress: false,
              client_state: { guild_versions: {} },
            },
          })
        );
        return;
      }
      if (msg.t === "READY") {
        this.sessionId = String(msg.d?.session_id || "");
        if (typeof msg.d?.resume_gateway_url === "string") {
          this.resumeGatewayUrl = msg.d.resume_gateway_url;
        }
        if (msg.d?.user?.id) {
          this.userId = String(msg.d.user.id);
        }
        ws.send(
          JSON.stringify({
            op: 4,
            d: {
              guild_id: this.guildId,
              channel_id: this.channelId,
              self_mute: true,
              self_deaf: true,
              self_video: false,
            },
          })
        );
        return;
      }
      if (msg.t === "VOICE_STATE_UPDATE" && String(msg.d?.user_id || "") === this.userId) {
        if (msg.d?.session_id) {
          this.sessionId = String(msg.d.session_id);
        }
        return;
      }
      if (msg.t === "VOICE_SERVER_UPDATE") {
        const ep = String(msg.d?.endpoint || "");
        const vtok = String(msg.d?.token || "");
        if (ep && vtok && this.sessionId) {
          this.connectVoice(ep, vtok, false);
        }
        return;
      }
      if (msg.t === "STREAM_CREATE" && msg.d?.rtc_server_id) {
        if (String(msg.d?.stream_key || "") === this.streamKey) {
          this.rtcServerId = String(msg.d.rtc_server_id);
        }
        return;
      }
      if (msg.t === "STREAM_SERVER_UPDATE" && !this.watched) {
        const sep = String(msg.d?.endpoint || "");
        const stok = String(msg.d?.token || "");
        if (sep && stok && this.sessionId) {
          this.watched = true;
          this.connectVoice(sep, stok, true);
        }
      }
    });

    ws.on("close", (code) => {
      if (hbInterval) clearInterval(hbInterval);
      if (code !== 1000 && !this.stopped) {
        console.log(`[viewer] ws_close uid=${this.userId} code=${code}`);
      }
      if (code === 4004) {
        this.fatal = true;
      }
      this.stop();
    });
    ws.on("error", () => {});
  }

  updateStreamKey(nextKey, nextRtcServerId) {
    if (nextRtcServerId) {
      this.rtcServerId = String(nextRtcServerId);
    }
    if (!nextKey || nextKey === this.streamKey) return;
    this.streamKey = String(nextKey);
    if (!this.stopped && this.mainWs?.readyState === WebSocket.OPEN && this.watchRequested) {
      try {
        this.mainWs.send(JSON.stringify({ op: 20, d: { stream_key: this.streamKey } }));
      } catch {
      }
    }
  }

  connectVoice(endpoint, voiceToken, isStream) {
    if (this.stopped) return;
    const wsKey = isStream ? "watchRtcWs" : "roomVoiceWs";
    const udpKey = isStream ? "watchUdp" : "roomUdp";
    try {
      this[wsKey]?.close(1000, "reset");
    } catch {
    }
    try {
      this[udpKey]?.close();
    } catch {
    }
    const vWs = openDiscordWs(normalizeEndpointUrl(endpoint, "?v=8"), this.userAgent);
    this[wsKey] = vWs;
    const dave = new DaveController(
      this.userId,
      this.channelId,
      (buf) => {
        if (vWs.readyState === WebSocket.OPEN) vWs.send(buf);
      },
      (obj) => {
        if (vWs.readyState === WebSocket.OPEN) vWs.send(JSON.stringify(obj));
      }
    );
    let hb = null;
    let ka = null;
    let ssrc = isStream ? 3001 : 3000;
    let seq = -1;

    vWs.on("message", async (raw, isBinary) => {
      if (this.stopped) return;
      if (isBinary) {
        const buf = Buffer.isBuffer(raw) ? raw : Buffer.from(raw);
        if (buf.length >= 2) seq = buf.readUInt16BE(0);
        dave.handleBinary(buf);
        return;
      }
      let msg;
      try {
        msg = JSON.parse(typeof raw === "string" ? raw : raw.toString("utf8"));
      } catch {
        return;
      }
      if (typeof msg.seq === "number") seq = msg.seq;
      dave.handleJson(msg);

      if (msg.op === 8) {
        const hbMs = Number(msg.d?.heartbeat_interval || 13750);
        hb = setInterval(() => {
          if (vWs.readyState === WebSocket.OPEN) {
            vWs.send(JSON.stringify({ op: 3, d: { t: Date.now(), seq_ack: seq } }));
          }
        }, Math.floor(hbMs * 0.85));
        this.timers.push(hb);
        const ident = {
          server_id: isStream ? this.rtcServerId : this.guildId,
          user_id: this.userId,
          session_id: this.sessionId,
          token: voiceToken,
          max_dave_protocol_version: 1,
        };
        if (isStream) {
          ident.channel_id = this.channelId;
          ident.stream_key = this.streamKey;
          ident.video = true;
        }
        vWs.send(JSON.stringify({ op: 0, d: ident }));
      } else if (msg.op === 2) {
        ssrc = Number(msg.d?.ssrc || ssrc);
        const ip = String(msg.d?.ip || "127.0.0.1");
        const port = Number(msg.d?.port || 1234);
        const mode = pickAeadMode(msg.d?.modes);
        const udp = await discoverUdpEndpoint(ip, port, ssrc);
        if (this.stopped) {
          udp.sock.close();
          return;
        }
        this[udpKey] = udp.sock;
        sendUdpKeepalive(udp.sock, ip, port, ++this.keepaliveSeq);
        ka = setInterval(() => sendUdpKeepalive(udp.sock, ip, port, ++this.keepaliveSeq), 5000);
        this.timers.push(ka);
        vWs.send(
          JSON.stringify({
            op: 1,
            d: {
              protocol: "udp",
              data: { address: udp.address, port: udp.port, mode },
              codecs: [{ name: "opus", type: "audio", priority: 1000, payload_type: 120 }],
            },
          })
        );
      } else if (msg.op === 4) {
        vWs.send(JSON.stringify({ op: 5, d: { speaking: 0, delay: 0, ssrc } }));
        if (!isStream && !this.watchRequested && this.mainWs?.readyState === WebSocket.OPEN) {
          this.watchRequested = true;
          this.mainWs.send(JSON.stringify({ op: 20, d: { stream_key: this.streamKey } }));
        } else if (isStream) {
          this.connected = true;
          this.onStatusChange(true);
        }
      }
    });

    vWs.on("close", (code) => {
      if (hb) clearInterval(hb);
      if (ka) clearInterval(ka);
      if (code !== 1000 && !this.stopped) {
        console.log(`[viewer] voice_close stream=${isStream} uid=${this.userId} code=${code}`);
      }
    });
    vWs.on("error", () => {});
  }

  stop() {
    if (this.stopped) return;
    this.stopped = true;
    const wasConnected = this.connected;
    this.connected = false;
    for (const t of this.timers) {
      clearInterval(t);
      clearTimeout(t);
    }
    this.timers = [];
    if (this.mainWs?.readyState === WebSocket.OPEN) {
      try {
        if (this.watchRequested) {
          this.mainWs.send(JSON.stringify({ op: 19, d: { stream_key: this.streamKey } }));
        }
        this.mainWs.send(
          JSON.stringify({
            op: 4,
            d: {
              guild_id: this.guildId,
              channel_id: null,
              self_mute: false,
              self_deaf: false,
              self_video: false,
            },
          })
        );
      } catch {
      }
    }
    for (const ws of [this.watchRtcWs, this.roomVoiceWs, this.mainWs]) {
      try {
        if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) {
          ws.close(1000, "closed");
        }
      } catch {
      }
    }
    for (const sock of [this.watchUdp, this.roomUdp]) {
      try {
        sock?.close();
      } catch {
      }
    }
    this.watchRtcWs = null;
    this.roomVoiceWs = null;
    this.mainWs = null;
    this.watchUdp = null;
    this.roomUdp = null;
    if (wasConnected) {
      this.onStatusChange(false);
    }
  }
}

class CloudStreamSession {
  constructor(params) {
    this.params = params;
    this.accountId = String(params.accountId);
    this.fenceToken = Number(params.fenceToken);
    this.streamKey = `guild:${params.guildId}:${params.channelId}:${this.accountId}`;
    this.viewerToken = String(params.viewerToken || DEFAULT_VIEWER_TOKEN || "").trim();
    this.viewerId = extractSnowflakeFromToken(this.viewerToken);
    if (this.viewerId && this.viewerId === this.accountId) {
      this.viewerToken = "";
    }
    this.webhookUrl = String(params.webhookUrl || DEFAULT_WEBHOOK_URL || "").trim();
    if (this.webhookUrl) {
      lastKnownWebhookUrl = this.webhookUrl;
    }
    this.stopped = false;
    this.phase = "connecting";
    this.lastError = null;
    this.fatal = false;
    this.startedAtMs = Date.now();
    this.expiresAtMs = this.startedAtMs + Math.max(3600, Math.floor(Number(params.durationHours || 4) * 3600)) * 1000;
    this.mainWs = null;
    this.voiceWs = null;
    this.rtcWs = null;
    this.voiceUdp = null;
    this.rtcUdp = null;
    this.altViewer = null;
    this.timers = [];
    this.gatewaySessionId = null;
    this.resumeGatewayUrl = null;
    this.lastSeq = null;
    this.analyticsToken = params.analyticsToken || null;
    this.scienceSeq = 1;
    this.rtcServerId = String(params.guildId);
    this.voiceSessionId = "";
    this.voiceEndpoint = "";
    this.voiceToken = "";
    this.activeVoiceSig = "";
    this.streamAnnounced = false;
    this.pendingStreamServer = null;
    this.streamRecreates = 0;
    this.reconnectCount = 0;
    this.keepaliveSeq = 0;
    this.voiceMembers = new Set();
    this.streamViewers = new Set();
    this.lastNotifiedViewers = -1;
    this.pendingWebhook = Promise.resolve();
  }

  getViewerCount() {
    const combined = new Set([...this.voiceMembers, ...this.streamViewers]);
    combined.delete(this.accountId);
    if (this.altViewer?.connected) {
      combined.add(this.altViewer.userId || "alt_viewer");
    }
    return combined.size;
  }

  notifyViewerChange() {
    if (this.stopped) return;
    const count = this.getViewerCount();
    if (count === this.lastNotifiedViewers) return;
    this.lastNotifiedViewers = count;
    sendRelayWebhook(this.webhookUrl, {
      event: "viewer_update",
      accountId: this.accountId,
      fenceToken: this.fenceToken,
      viewerCount: count,
      altViewerActive: Boolean(this.altViewer?.connected),
      phase: this.phase,
    });
  }

  maybeEnsureViewer() {
    if (this.stopped || !this.viewerToken) return;
    if (this.getViewerCount() > 0) return;
    if (this.altViewer && !this.altViewer.stopped) return;
    if (this.altViewer?.fatal) return;
    this.altViewer = new AltViewerSession({
      token: this.viewerToken,
      guildId: this.params.guildId,
      channelId: this.params.channelId,
      streamKey: this.streamKey,
      userAgent: this.params.browserUserAgent,
      properties: this.params.properties,
      onStatusChange: (connected) => {
        if (connected && this.altViewer?.userId) {
          this.streamViewers.add(this.altViewer.userId);
        } else if (!connected && this.altViewer?.userId) {
          this.streamViewers.delete(this.altViewer.userId);
        }
        this.notifyViewerChange();
      },
    });
    this.altViewer.start();
  }

  start() {
    console.log(`[stream] start account=${this.accountId} guild=${this.params.guildId} channel=${this.params.channelId}`);
    const durationMs = Math.max(60_000, this.expiresAtMs - Date.now());
    const expTimer = setTimeout(() => {
      this.stop("Stream duration reached");
    }, durationMs);
    this.timers.push(expTimer);

    const handshakeTimer = setTimeout(() => {
      if (!this.stopped && this.phase !== "live") {
        const detail =
          this.phase === "connecting"
            ? "Discord Gateway connect timed out"
            : "Voice join or Go Live timed out — verify account can Connect & Stream in the voice room";
        console.log(`[stream] handshake_timeout account=${this.accountId} phase=${this.phase}`);
        this.stop(detail, false);
      }
    }, 25_000);
    this.timers.push(handshakeTimer);

    const hbScience = setInterval(() => {
      if (!this.stopped && this.phase === "live") {
        const elapsedMs = Math.max(60_000, Date.now() - this.startedAtMs);
        this.emitScience("video_stream_heartbeat", elapsedMs).catch(() => {});
      }
    }, 60_000);
    this.timers.push(hbScience);

    if (this.viewerToken) {
      const viewerCheck = setTimeout(() => {
        this.maybeEnsureViewer();
      }, 5_000);
      this.timers.push(viewerCheck);
    }

    this.connectGateway(false);
  }

  clearTimers() {
    for (const t of this.timers) {
      clearTimeout(t);
      clearInterval(t);
    }
    this.timers = [];
  }

  closeSockets(sendLeave) {
    if (sendLeave && this.mainWs && this.mainWs.readyState === WebSocket.OPEN) {
      try {
        this.mainWs.send(JSON.stringify({ op: 19, d: { stream_key: this.streamKey } }));
        this.mainWs.send(
          JSON.stringify({
            op: 4,
            d: {
              guild_id: String(this.params.guildId),
              channel_id: null,
              self_mute: false,
              self_deaf: false,
              self_video: false,
            },
          })
        );
      } catch {
      }
    }
    for (const ws of [this.rtcWs, this.voiceWs, this.mainWs]) {
      try {
        if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) {
          ws.close(1000, "closed");
        }
      } catch {
      }
    }
    for (const sock of [this.rtcUdp, this.voiceUdp]) {
      try {
        sock?.close();
      } catch {
      }
    }
    this.rtcWs = null;
    this.voiceWs = null;
    this.mainWs = null;
    this.rtcUdp = null;
    this.voiceUdp = null;
  }

  stop(reason = "Stopped", fatal = false) {
    if (this.stopped) return this.pendingWebhook;
    this.stopped = true;
    this.phase = "stopped";
    this.lastError = reason;
    this.fatal = fatal;
    console.log(`[stream] stop account=${this.accountId} fatal=${fatal} reason=${reason}`);
    this.clearTimers();
    if (this.altViewer) {
      this.altViewer.stop();
      this.altViewer = null;
    }
    this.closeSockets(true);
    if (activeStreams.get(this.accountId) === this) {
      activeStreams.delete(this.accountId);
    }
    const consumedSeconds = Math.max(0, Math.floor((Date.now() - this.startedAtMs) / 1000));
    this.pendingWebhook = sendRelayWebhook(this.webhookUrl, {
      event: fatal ? "stream_fatal" : "stream_stopped",
      accountId: this.accountId,
      fenceToken: this.fenceToken,
      reason,
      fatal,
      transient:
        !fatal &&
        (reason.includes("restarting") ||
          reason.includes("disconnected") ||
          reason.includes("Gateway")),
      consumedSeconds,
    });
    return this.pendingWebhook;
  }

  status() {
    return {
      active: !this.stopped,
      phase: this.phase,
      lastError: this.lastError,
      fatal: this.fatal,
      consumedSeconds: Math.max(0, Math.floor((Date.now() - this.startedAtMs) / 1000)),
      fenceToken: this.fenceToken,
      gatewayConnected: this.mainWs?.readyState === WebSocket.OPEN,
      voiceConnected: this.voiceWs?.readyState === WebSocket.OPEN,
      rtcConnected: this.rtcWs?.readyState === WebSocket.OPEN,
      viewerCount: this.getViewerCount(),
      altViewerActive: Boolean(this.altViewer?.connected),
    };
  }

  async emitScience(eventType, totalDurationMs) {
    if (!this.analyticsToken) return;
    const now = Date.now();
    const superProps = buildSuperPropertiesBase64(this.params.properties);
    const headers = {
      Accept: "*/*",
      Authorization: this.params.token,
      "Content-Type": "application/json",
      "User-Agent": this.params.browserUserAgent || "Mozilla/5.0",
      Origin: "https://discord.com",
      Referer: "https://discord.com/channels/@me",
      "X-Super-Properties": superProps,
      "X-Discord-Locale": "en-US",
      "X-Discord-Timezone": "America/New_York",
    };
    if (this.params.cookieJar) {
      headers.Cookie = this.params.cookieJar;
    }
    await fetch("https://discord.com/api/v9/science", {
      method: "POST",
      headers,
      body: JSON.stringify({
        token: this.analyticsToken,
        events: [
          {
            type: eventType,
            properties: {
              client_track_timestamp: now,
              client_send_timestamp: now,
              client_heartbeat_session_id: this.params.hbSession,
              launch_signature: this.params.launchSig,
              event_sequence_number: ++this.scienceSeq,
              guild_id: String(this.params.guildId),
              channel_id: String(this.params.channelId),
              channel_type: 2,
              total_duration_ms: totalDurationMs,
              ...(eventType === "video_stream_heartbeat" ? { duration_tracked_ms: 60_000 } : {}),
            },
          },
        ],
      }),
      signal: AbortSignal.timeout(8000),
    }).catch(() => {});
  }

  connectGateway(isResume) {
    if (this.stopped) return;
    this.closeSockets(false);
    this.activeVoiceSig = "";
    this.streamAnnounced = false;
    this.voiceEndpoint = "";
    this.voiceToken = "";

    const canActuallyResume = Boolean(
      isResume && this.gatewaySessionId && this.resumeGatewayUrl && this.lastSeq !== null
    );
    if (!canActuallyResume && !allowIdentifyForAccount(this.accountId)) {
      this.stop("Rate safety pause to protect account session", false);
      return;
    }

    const endpoint =
      canActuallyResume && this.resumeGatewayUrl
        ? normalizeEndpointUrl(this.resumeGatewayUrl, "?v=10&encoding=json")
        : "wss://gateway.discord.gg/?v=10&encoding=json";

    const ws = openDiscordWs(endpoint, this.params.browserUserAgent, this.params.cookieJar);
    this.mainWs = ws;
    let hbInterval = null;

    ws.on("message", (raw) => {
      if (this.stopped) return;
      const text = typeof raw === "string" ? raw : raw.toString("utf8");
      let msg;
      try {
        msg = JSON.parse(text);
      } catch {
        return;
      }

      if (msg.s !== undefined && msg.s !== null) {
        this.lastSeq = msg.s;
      }

      if (msg.op === 1) {
        if (ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ op: 1, d: this.lastSeq }));
        }
        return;
      }

      if (msg.op === 7) {
        try {
          ws.close(4000, "reconnect");
        } catch {
        }
        return;
      }

      if (msg.op === 9) {
        if (!msg.d) {
          this.gatewaySessionId = null;
          this.resumeGatewayUrl = null;
          this.lastSeq = null;
        }
        try {
          ws.close(4000, "invalid");
        } catch {
        }
        return;
      }

      if (msg.op === 10) {
        const ms = Number(msg.d?.heartbeat_interval || 41250);
        hbInterval = setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ op: 1, d: this.lastSeq }));
          }
        }, Math.floor(ms * 0.85));
        this.timers.push(hbInterval);

        if (canActuallyResume && this.gatewaySessionId && this.lastSeq !== null) {
          ws.send(
            JSON.stringify({
              op: 6,
              d: {
                token: this.params.token,
                session_id: this.gatewaySessionId,
                seq: this.lastSeq,
              },
            })
          );
        } else {
          ws.send(
            JSON.stringify({
              op: 2,
              d: {
                token: this.params.token,
                capabilities: 30717,
                properties: this.params.properties,
                presence: this.params.presence || {
                  status: "online",
                  since: 0,
                  activities: [],
                  afk: false,
                },
                compress: false,
                client_state: {
                  guild_versions: {},
                  highest_last_message_id: "0",
                  read_state_version: 0,
                  user_guild_settings_version: -1,
                  user_settings_version: -1,
                  private_channels_version: "0",
                  api_code_version: 0,
                },
              },
            })
          );
        }
        return;
      }

      if (msg.t === "READY") {
        this.reconnectCount = 0;
        this.gatewaySessionId = String(msg.d?.session_id || "");
        this.voiceSessionId = this.gatewaySessionId;
        if (typeof msg.d?.resume_gateway_url === "string") {
          this.resumeGatewayUrl = msg.d.resume_gateway_url;
        }
        if (typeof msg.d?.analytics_token === "string") {
          this.analyticsToken = msg.d.analytics_token;
        }
        const targetGuild = Array.isArray(msg.d?.guilds)
          ? msg.d.guilds.find((g) => String(g.id) === String(this.params.guildId))
          : null;
        if (targetGuild && Array.isArray(targetGuild.voice_states)) {
          this.voiceMembers.clear();
          for (const vs of targetGuild.voice_states) {
            if (String(vs.channel_id) === String(this.params.channelId) && String(vs.user_id) !== this.accountId) {
              this.voiceMembers.add(String(vs.user_id));
            }
          }
        }
        this.joinVoiceRoom();
        return;
      }

      if (msg.t === "RESUMED") {
        this.reconnectCount = 0;
        this.joinVoiceRoom();
        return;
      }

      if (msg.t === "VOICE_STATE_UPDATE") {
        const uid = String(msg.d?.user_id || "");
        const ch = msg.d?.channel_id ? String(msg.d.channel_id) : "";
        const gId = msg.d?.guild_id ? String(msg.d.guild_id) : "";
        if (uid && uid !== this.accountId && gId === String(this.params.guildId)) {
          if (ch === String(this.params.channelId)) {
            this.voiceMembers.add(uid);
          } else {
            this.voiceMembers.delete(uid);
          }
          if (this.phase === "live") {
            this.notifyViewerChange();
            if (this.getViewerCount() === 0) {
              this.maybeEnsureViewer();
            }
          }
        }
        if (uid === this.accountId) {
          if (!ch && this.phase === "live") {
            this.joinVoiceRoom();
            return;
          }
          if (msg.d?.session_id) {
            this.voiceSessionId = String(msg.d.session_id);
          }
          this.maybeStartVoice();
        }
        return;
      }

      if (msg.t === "VOICE_SERVER_UPDATE") {
        this.voiceEndpoint = String(msg.d?.endpoint || "");
        this.voiceToken = String(msg.d?.token || "");
        this.maybeStartVoice();
        return;
      }

      if (msg.t === "STREAM_CREATE" || msg.t === "STREAM_UPDATE") {
        if (msg.d?.stream_key && String(msg.d.stream_key).includes(this.accountId)) {
          this.streamKey = String(msg.d.stream_key);
          this.altViewer?.updateStreamKey(this.streamKey, msg.d?.rtc_server_id);
          if (Array.isArray(msg.d?.viewer_ids)) {
            this.streamViewers = new Set(msg.d.viewer_ids.map(String));
          }
          if (this.phase === "live") {
            this.notifyViewerChange();
          }
        }
        if (msg.t === "STREAM_CREATE") {
          if (msg.d?.rtc_server_id) {
            this.rtcServerId = String(msg.d.rtc_server_id);
          }
          if (!this.streamAnnounced && ws.readyState === WebSocket.OPEN) {
            this.streamAnnounced = true;
            ws.send(JSON.stringify({ op: 22, d: { stream_key: this.streamKey, paused: false } }));
          }
          if (this.pendingStreamServer && this.voiceSessionId) {
            const p = this.pendingStreamServer;
            this.pendingStreamServer = null;
            this.connectStreamRtc(p.ep, p.stok);
          }
          this.maybeEnsureViewer();
        }
        return;
      }

      if (msg.t === "STREAM_DELETE") {
        if (this.stopped) return;
        if (this.streamRecreates >= 3) {
          console.log(`[stream] stream_delete_limit account=${this.accountId}`);
          this.stop("Discord closed the Go Live stream repeatedly", false);
          return;
        }
        if (ws.readyState === WebSocket.OPEN) {
          this.streamRecreates += 1;
          this.streamAnnounced = false;
          const retryTimer = setTimeout(() => {
            if (!this.stopped && this.mainWs && this.mainWs.readyState === WebSocket.OPEN) {
              this.mainWs.send(
                JSON.stringify({
                  op: 18,
                  d: {
                    type: "guild",
                    guild_id: String(this.params.guildId),
                    channel_id: String(this.params.channelId),
                    preferred_region: null,
                  },
                })
              );
            }
          }, 2000);
          this.timers.push(retryTimer);
        }
        return;
      }

      if (msg.t === "STREAM_SERVER_UPDATE") {
        const ep = String(msg.d?.endpoint || "");
        const stok = String(msg.d?.token || "");
        if (msg.d?.stream_key) {
          this.streamKey = String(msg.d.stream_key);
        }
        if (ep && stok && this.voiceSessionId) {
          if (!this.streamAnnounced && this.rtcServerId === String(this.params.guildId)) {
            this.pendingStreamServer = { ep, stok };
            const fbTimer = setTimeout(() => {
              if (!this.stopped && this.pendingStreamServer) {
                const p = this.pendingStreamServer;
                this.pendingStreamServer = null;
                this.connectStreamRtc(p.ep, p.stok);
              }
            }, 350);
            this.timers.push(fbTimer);
          } else {
            this.connectStreamRtc(ep, stok);
          }
        }
      }
    });

    ws.on("close", (code) => {
      if (hbInterval) {
        clearInterval(hbInterval);
        hbInterval = null;
      }
      if (this.stopped) return;
      console.log(`[stream] gw_close account=${this.accountId} code=${code}`);
      if (code === 4004) {
        this.stop("TOKEN_INVALID", true);
        return;
      }
      this.reconnectCount += 1;
      if (this.reconnectCount > 4) {
        this.stop("Gateway disconnected repeatedly", false);
        return;
      }
      const canResume = Boolean(this.gatewaySessionId && this.resumeGatewayUrl && this.lastSeq !== null);
      const t = setTimeout(() => {
        this.connectGateway(canResume);
      }, 3500 + Math.floor(Math.random() * 1500));
      this.timers.push(t);
    });

    ws.on("error", () => {});
  }

  joinVoiceRoom() {
    if (this.stopped || !this.mainWs || this.mainWs.readyState !== WebSocket.OPEN) return;
    this.phase = "voice_joining";
    this.mainWs.send(
      JSON.stringify({
        op: 4,
        d: {
          guild_id: String(this.params.guildId),
          channel_id: String(this.params.channelId),
          self_mute: false,
          self_deaf: false,
          self_video: false,
        },
      })
    );
  }

  maybeStartVoice() {
    if (this.stopped || !this.voiceSessionId || !this.voiceEndpoint || !this.voiceToken) {
      return;
    }
    const sig = `${this.voiceEndpoint}:${this.voiceToken}:${this.voiceSessionId}`;
    if (this.activeVoiceSig === sig && this.voiceWs && this.voiceWs.readyState === WebSocket.OPEN) {
      return;
    }
    this.activeVoiceSig = sig;
    this.connectRoomVoice();
  }

  connectRoomVoice() {
    if (this.stopped) return;
    if (this.voiceWs) {
      try {
        this.voiceWs.close(1000, "reconnecting");
      } catch {
      }
    }
    if (this.voiceUdp) {
      try {
        this.voiceUdp.close();
      } catch {
      }
      this.voiceUdp = null;
    }
    const url = normalizeEndpointUrl(this.voiceEndpoint, "?v=8");
    const vWs = openDiscordWs(url, this.params.browserUserAgent);
    this.voiceWs = vWs;
    const dave = new DaveController(
      this.accountId,
      this.params.channelId,
      (buf) => {
        if (vWs.readyState === WebSocket.OPEN) vWs.send(buf);
      },
      (obj) => {
        if (vWs.readyState === WebSocket.OPEN) vWs.send(JSON.stringify(obj));
      }
    );
    let hbInterval = null;
    let keepaliveInterval = null;
    let ssrc = 1000;
    let announcedGoLive = false;
    let voiceSeq = -1;
    let roomSecretKey = null;
    const roomRtpState = { seq: 1, ts: 960, nonce: 1 };

    vWs.on("message", async (raw, isBinary) => {
      if (this.stopped) return;
      if (isBinary) {
        const buf = Buffer.isBuffer(raw) ? raw : Buffer.from(raw);
        if (buf.length >= 2) {
          voiceSeq = buf.readUInt16BE(0);
        }
        dave.handleBinary(buf);
        return;
      }
      let msg;
      try {
        msg = JSON.parse(typeof raw === "string" ? raw : raw.toString("utf8"));
      } catch {
        return;
      }
      if (typeof msg.seq === "number") {
        voiceSeq = msg.seq;
      }
      dave.handleJson(msg);

      if (msg.op === 8) {
        const hbMs = Number(msg.d?.heartbeat_interval || 13750);
        hbInterval = setInterval(() => {
          if (vWs.readyState === WebSocket.OPEN) {
            vWs.send(JSON.stringify({ op: 3, d: { t: Date.now(), seq_ack: voiceSeq } }));
          }
        }, Math.floor(hbMs * 0.85));
        this.timers.push(hbInterval);

        vWs.send(
          JSON.stringify({
            op: 0,
            d: {
              server_id: String(this.params.guildId),
              user_id: this.accountId,
              session_id: this.voiceSessionId,
              token: this.voiceToken,
              max_dave_protocol_version: 1,
            },
          })
        );
      } else if (msg.op === 2) {
        ssrc = Number(msg.d?.ssrc || 1000);
        const ip = String(msg.d?.ip || "127.0.0.1");
        const port = Number(msg.d?.port || 1234);
        const mode = pickAeadMode(msg.d?.modes);
        const udp = await discoverUdpEndpoint(ip, port, ssrc);
        if (this.stopped) {
          udp.sock.close();
          return;
        }
        this.voiceUdp = udp.sock;
        sendUdpKeepalive(udp.sock, ip, port, ++this.keepaliveSeq);
        keepaliveInterval = setInterval(() => {
          sendUdpKeepalive(udp.sock, ip, port, ++this.keepaliveSeq);
          if (roomSecretKey) {
            sendEncryptedOpusSilence(
              udp.sock,
              ip,
              port,
              roomSecretKey,
              ssrc,
              roomRtpState,
              dave.encryptOpus(OPUS_SILENCE)
            );
          }
        }, 5_000);
        this.timers.push(keepaliveInterval);

        vWs.send(
          JSON.stringify({
            op: 1,
            d: {
              protocol: "udp",
              data: { address: udp.address, port: udp.port, mode },
              codecs: [{ name: "opus", type: "audio", priority: 1000, payload_type: 120 }],
            },
          })
        );
      } else if (msg.op === 4) {
        if (Array.isArray(msg.d?.secret_key) && msg.d.secret_key.length === 32) {
          roomSecretKey = Buffer.from(msg.d.secret_key);
        }
        vWs.send(JSON.stringify({ op: 5, d: { speaking: 0, delay: 0, ssrc } }));
        if (!announcedGoLive && this.mainWs && this.mainWs.readyState === WebSocket.OPEN) {
          announcedGoLive = true;
          this.mainWs.send(
            JSON.stringify({
              op: 18,
              d: {
                type: "guild",
                guild_id: String(this.params.guildId),
                channel_id: String(this.params.channelId),
                preferred_region: null,
              },
            })
          );
        }
      }
    });

    vWs.on("close", (code) => {
      if (hbInterval) clearInterval(hbInterval);
      if (keepaliveInterval) clearInterval(keepaliveInterval);
      if (code !== 1000 && !this.stopped) {
        console.log(`[stream] room_voice_close account=${this.accountId} code=${code}`);
      }
    });
    vWs.on("error", () => {});
  }

  connectStreamRtc(endpoint, streamToken) {
    if (this.stopped) return;
    if (this.rtcWs) {
      try {
        this.rtcWs.close(1000, "restarting");
      } catch {
      }
    }
    if (this.rtcUdp) {
      try {
        this.rtcUdp.close();
      } catch {
      }
      this.rtcUdp = null;
    }

    const url = normalizeEndpointUrl(endpoint, "?v=8");
    const sWs = openDiscordWs(url, this.params.browserUserAgent);
    this.rtcWs = sWs;
    const dave = new DaveController(
      this.accountId,
      this.params.channelId,
      (buf) => {
        if (sWs.readyState === WebSocket.OPEN) sWs.send(buf);
      },
      (obj) => {
        if (sWs.readyState === WebSocket.OPEN) sWs.send(JSON.stringify(obj));
      }
    );
    let hbInterval = null;
    let keepaliveInterval = null;
    let ssrc = 2000;
    let videoSsrc = 2001;
    let rtcSeq = -1;

    sWs.on("message", async (raw, isBinary) => {
      if (this.stopped) return;
      if (isBinary) {
        const buf = Buffer.isBuffer(raw) ? raw : Buffer.from(raw);
        if (buf.length >= 2) {
          rtcSeq = buf.readUInt16BE(0);
        }
        dave.handleBinary(buf);
        return;
      }
      let msg;
      try {
        msg = JSON.parse(typeof raw === "string" ? raw : raw.toString("utf8"));
      } catch {
        return;
      }
      if (typeof msg.seq === "number") {
        rtcSeq = msg.seq;
      }
      dave.handleJson(msg);

      if (msg.op === 8) {
        const hbMs = Number(msg.d?.heartbeat_interval || 13750);
        hbInterval = setInterval(() => {
          if (sWs.readyState === WebSocket.OPEN) {
            sWs.send(JSON.stringify({ op: 3, d: { t: Date.now(), seq_ack: rtcSeq } }));
          }
        }, Math.floor(hbMs * 0.85));
        this.timers.push(hbInterval);

        sWs.send(
          JSON.stringify({
            op: 0,
            d: {
              server_id: this.rtcServerId,
              channel_id: String(this.params.channelId),
              user_id: this.accountId,
              session_id: this.voiceSessionId,
              token: streamToken,
              stream_key: this.streamKey,
              video: true,
              streams: [{ type: "screen", rid: "100", quality: 100 }],
              max_dave_protocol_version: 1,
            },
          })
        );
      } else if (msg.op === 2) {
        ssrc = Number(msg.d?.ssrc || 2000);
        const streams = Array.isArray(msg.d?.streams) ? msg.d.streams : [];
        videoSsrc = Number(streams[0]?.ssrc || ssrc + 1);
        const ip = String(msg.d?.ip || "127.0.0.1");
        const port = Number(msg.d?.port || 1234);
        const mode = pickAeadMode(msg.d?.modes);
        const udp = await discoverUdpEndpoint(ip, port, ssrc);
        if (this.stopped) {
          udp.sock.close();
          return;
        }
        this.rtcUdp = udp.sock;
        let secretKey = null;
        const rtpState = { seq: 1, ts: 960, nonce: 1 };
        sendUdpKeepalive(udp.sock, ip, port, ++this.keepaliveSeq);
        keepaliveInterval = setInterval(() => {
          sendUdpKeepalive(udp.sock, ip, port, ++this.keepaliveSeq);
          if (secretKey) {
            sendEncryptedOpusSilence(
              udp.sock,
              ip,
              port,
              secretKey,
              ssrc,
              rtpState,
              dave.encryptOpus(OPUS_SILENCE)
            );
          }
        }, 2_000);
        this.timers.push(keepaliveInterval);

        sWs.send(
          JSON.stringify({
            op: 1,
            d: {
              protocol: "udp",
              data: { address: udp.address, port: udp.port, mode },
              codecs: [
                { name: "opus", type: "audio", priority: 1000, payload_type: 120 },
                {
                  name: "H264",
                  type: "video",
                  priority: 1000,
                  payload_type: 101,
                  rtx_payload_type: 102,
                  encode: true,
                  decode: true,
                },
              ],
            },
          })
        );
        sWs._setKey = (k) => {
          secretKey = k;
        };
      } else if (msg.op === 4) {
        if (Array.isArray(msg.d?.secret_key) && msg.d.secret_key.length === 32 && typeof sWs._setKey === "function") {
          sWs._setKey(Buffer.from(msg.d.secret_key));
        }
        sWs.send(JSON.stringify({ op: 5, d: { speaking: 2, delay: 0, ssrc } }));
        sWs.send(
          JSON.stringify({
            op: 12,
            d: {
              audio_ssrc: ssrc,
              video_ssrc: videoSsrc,
              rtx_ssrc: videoSsrc + 1,
              streams: [
                {
                  type: "video",
                  rid: "100",
                  ssrc: videoSsrc,
                  rtx_ssrc: videoSsrc + 1,
                  quality: 100,
                  active: true,
                  max_bitrate: 2500000,
                  max_framerate: 30,
                  max_resolution: { type: "fixed", width: 1280, height: 720 },
                },
              ],
            },
          })
        );
        this.phase = "live";
        console.log(`[stream] live account=${this.accountId} dave=${dave.protocolVersion}`);
        this.notifyViewerChange();
        this.maybeEnsureViewer();
        this.emitScience("media_session_joined", 0).catch(() => {});
        this.emitScience("video_stream_started", 0).catch(() => {});
      }
    });

    sWs.on("close", (code) => {
      if (hbInterval) clearInterval(hbInterval);
      if (keepaliveInterval) clearInterval(keepaliveInterval);
      if (code !== 1000 && !this.stopped) {
        console.log(`[stream] rtc_close account=${this.accountId} code=${code}`);
        if (this.phase === "live" && this.mainWs?.readyState === WebSocket.OPEN && this.streamRecreates < 3) {
          this.streamRecreates += 1;
          this.streamAnnounced = false;
          this.mainWs.send(
            JSON.stringify({
              op: 18,
              d: {
                type: "guild",
                guild_id: String(this.params.guildId),
                channel_id: String(this.params.channelId),
                preferred_region: null,
              },
            })
          );
        }
      }
    });
    sWs.on("error", () => {});
  }
}

async function readJsonBody(req) {
  const chunks = [];
  let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > 1024 * 1024) {
      throw Object.assign(new Error("Payload too large"), { statusCode: 413 });
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url || "/", "http://localhost");

  if (url.pathname === "/health" && req.method === "GET") {
    let activeViewers = 0;
    for (const s of activeStreams.values()) {
      activeViewers += s.getViewerCount();
    }
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(
      JSON.stringify({
        ok: true,
        activeStreams: activeStreams.size,
        activeViewers,
        uptimeSec: Math.floor((Date.now() - startedAtMs) / 1000),
      })
    );
    return;
  }

  if (url.pathname === "/stream/status" && req.method === "GET") {
    const accountId = String(url.searchParams.get("accountId") || "");
    const ts = String(req.headers["x-paku-timestamp"] || "");
    const sig = String(req.headers["x-paku-signature"] || "");
    if (!accountId || !verifySignature(ts, `status:${accountId}`, sig)) {
      res.writeHead(401);
      res.end();
      return;
    }
    const existing = activeStreams.get(accountId);
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(
      JSON.stringify(
        existing
          ? existing.status()
          : {
              active: false,
              phase: "idle",
              lastError: null,
              fatal: false,
              consumedSeconds: 0,
              viewerCount: 0,
              altViewerActive: false,
            }
      )
    );
    return;
  }

  if (req.method !== "POST") {
    res.writeHead(404);
    res.end();
    return;
  }

  let rawBody;
  try {
    rawBody = await readJsonBody(req);
  } catch (err) {
    res.writeHead(err.statusCode || 400);
    res.end();
    return;
  }

  const ts = String(req.headers["x-paku-timestamp"] || "");
  const sig = String(req.headers["x-paku-signature"] || "");
  if (!verifySignature(ts, rawBody, sig)) {
    res.writeHead(401);
    res.end();
    return;
  }

  let job;
  try {
    job = JSON.parse(rawBody);
  } catch {
    res.writeHead(400);
    res.end();
    return;
  }

  if (url.pathname === "/stream/start") {
    if (!job?.accountId || !job?.guildId || !job?.channelId || !job?.token) {
      res.writeHead(400);
      res.end();
      return;
    }
    const prior = activeStreams.get(String(job.accountId));
    if (prior) {
      prior.stop("Superseded by new stream");
    }
    const session = new CloudStreamSession(job);
    activeStreams.set(session.accountId, session);
    session.start();
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ ok: true, status: "starting", streamKey: session.streamKey }));
    return;
  }

  if (url.pathname === "/stream/stop") {
    const accountId = String(job?.accountId || "");
    const existing = activeStreams.get(accountId);
    if (existing && (job.fenceToken === undefined || existing.fenceToken === Number(job.fenceToken))) {
      existing.stop(String(job.reason || "Stopped"));
    }
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ ok: true }));
    return;
  }

  if (url.pathname !== "/forward") {
    res.writeHead(404);
    res.end();
    return;
  }

  if (!job?.url || !isAllowedHttpTarget(job.url)) {
    res.writeHead(403);
    res.end();
    return;
  }

  try {
    const upstream = await fetch(job.url, {
      method: String(job.method || "GET").toUpperCase(),
      headers: job.headers || {},
      body: job.body ?? undefined,
      signal: AbortSignal.timeout(14_000),
    });
    const setCookies =
      typeof upstream.headers.getSetCookie === "function" ? upstream.headers.getSetCookie() : [];
    const text = await upstream.text();
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ status: upstream.status, setCookies, text }));
  } catch {
    res.writeHead(502, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ status: 502, setCookies: [], text: "" }));
  }
});

server.on("upgrade", (req, socket, head) => {
  if (!req.url?.startsWith("/ws")) {
    socket.write("HTTP/1.1 404 Not Found\r\n\r\n");
    socket.destroy();
    return;
  }

  const targetRaw = String(req.headers["x-paku-target"] || "");
  const ts = String(req.headers["x-paku-timestamp"] || "");
  const sig = String(req.headers["x-paku-signature"] || "");
  const target = isAllowedWsTarget(targetRaw);

  if (!target || !verifySignature(ts, targetRaw, sig)) {
    socket.write("HTTP/1.1 401 Unauthorized\r\n\r\n");
    socket.destroy();
    return;
  }

  const wsKey = String(req.headers["sec-websocket-key"] || crypto.randomBytes(16).toString("base64")).replace(/[\r\n]/g, "");
  const ua = String(req.headers["x-paku-ua"] || "Mozilla/5.0").replace(/[\r\n]/g, "");
  const cookie = String(req.headers["x-paku-cookie"] || "").replace(/[\r\n]/g, "");

  const upstream = tls.connect({ host: target.host, port: target.port, servername: target.host }, () => {
    const lines = [
      `GET ${target.path} HTTP/1.1`,
      `Host: ${target.port === 443 ? target.host : `${target.host}:${target.port}`}`,
      "Upgrade: websocket",
      "Connection: Upgrade",
      `Sec-WebSocket-Key: ${wsKey}`,
      "Sec-WebSocket-Version: 13",
      "Origin: https://discord.com",
      `User-Agent: ${ua}`,
    ];
    if (cookie) {
      lines.push(`Cookie: ${cookie}`);
    }
    upstream.write(`${lines.join("\r\n")}\r\n\r\n`);
    if (head?.length) {
      upstream.write(head);
    }
    upstream.pipe(socket);
    socket.pipe(upstream);
  });

  const killBoth = () => {
    upstream.destroy();
    socket.destroy();
  };
  upstream.on("error", killBoth);
  socket.on("error", killBoth);
  upstream.on("close", () => socket.end());
  socket.on("close", () => upstream.end());
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`Paku Render cloud engine listening on port ${PORT}`);
  if (lastKnownWebhookUrl) {
    sendRelayWebhook(lastKnownWebhookUrl, {
      event: "relay_boot",
      accountId: "0",
      fenceToken: 0,
      uptimeSec: 0,
    });
  }
});

let shuttingDown = false;
async function gracefulShutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(`Received ${signal}, shutting down active streams cleanly...`);
  const waits = [];
  for (const session of Array.from(activeStreams.values())) {
    waits.push(session.stop("Stream relay restarting — auto-recovering", false));
  }
  await Promise.race([
    Promise.allSettled(waits),
    new Promise((resolve) => setTimeout(resolve, 2500)),
  ]);
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 500);
}

process.on("SIGTERM", () => void gracefulShutdown("SIGTERM"));
process.on("SIGINT", () => void gracefulShutdown("SIGINT"));
