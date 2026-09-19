/**
 * dsh-ui-auth — DSH Web UI 认证网关（精简版：仅登录功能）。
 *
 * 在 DSH Web UI 的 node:http 服务器层拦截全部 HTTP 请求与 WebSocket 升级：
 * 未登录一律拒绝（页面请求重定向到登录页，API 返回 401，WS 升级销毁连接）。
 *
 * 仅保留核心登录功能：用户名+密码登录、会话管理、DSH Token 授权处理。
 * 移除：用户管理、邀请码、TOTP、通行密钥、审计日志、多用户隔离。
 */
import { createHash, randomUUID } from 'node:crypto';
import { createModernGateway } from './modern-gateway.js';
export const name = 'dsh-ui-auth';
export const inject = ['webServer', 'connection'];
// ============ WebSocket 工具（RFC 6455 最小实现，零依赖） ============
const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
/** 纯 JS SHA-1（crypto.createHash 不可用时的兜底；仅用于 WS 握手指纹）。 */
function sha1Fallback(data) {
    const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
    const ml = bytes.length;
    const padded = new Uint8Array((((ml + 8) >> 6) + 1) * 64);
    padded.set(bytes);
    padded[ml] = 0x80;
    const dv = new DataView(padded.buffer);
    dv.setUint32(padded.length - 4, (ml * 8) >>> 0, false);
    let h0 = 0x67452301, h1 = 0xefcdab89, h2 = 0x98badcfe, h3 = 0x10325476, h4 = 0xc3d2e1f0;
    const w = new Uint32Array(80);
    for (let i = 0; i < padded.length; i += 64) {
        for (let j = 0; j < 16; j++)
            w[j] = dv.getUint32(i + j * 4, false);
        for (let j = 16; j < 80; j++) {
            const n = w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16];
            w[j] = ((n << 1) | (n >>> 31)) >>> 0;
        }
        let a = h0, b = h1, c = h2, d = h3, e = h4;
        for (let j = 0; j < 80; j++) {
            let f, k;
            if (j < 20) {
                f = (b & c) | (~b & d);
                k = 0x5a827999;
            }
            else if (j < 40) {
                f = b ^ c ^ d;
                k = 0x6ed9eba1;
            }
            else if (j < 60) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8f1bbcdc;
            }
            else {
                f = b ^ c ^ d;
                k = 0xca62c1d6;
            }
            const temp = (((a << 5) | (a >>> 27)) + f + e + k + w[j]) >>> 0;
            e = d;
            d = c;
            c = ((b << 30) | (b >>> 2)) >>> 0;
            b = a;
            a = temp;
        }
        h0 = (h0 + a) >>> 0;
        h1 = (h1 + b) >>> 0;
        h2 = (h2 + c) >>> 0;
        h3 = (h3 + d) >>> 0;
        h4 = (h4 + e) >>> 0;
    }
    const out = new Uint8Array(20);
    const odv = new DataView(out.buffer);
    odv.setUint32(0, h0, false);
    odv.setUint32(4, h1, false);
    odv.setUint32(8, h2, false);
    odv.setUint32(12, h3, false);
    odv.setUint32(16, h4, false);
    return out;
}
function wsSha1(data) {
    try {
        return createHash('sha1').update(data).digest();
    }
    catch (err) {
        return sha1Fallback(data);
    }
}
/** 计算 Sec-WebSocket-Accept（base64(SHA1(key + GUID))）。 */
function wsAccept(key) {
    const digest = wsSha1(String(key) + WS_GUID);
    const b64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    let out = '';
    for (let i = 0; i < digest.length; i += 3) {
        const a = digest[i], b = digest[i + 1] === undefined ? 0 : digest[i + 1], c = digest[i + 2] === undefined ? 0 : digest[i + 2];
        out += b64[a >> 2] + b64[((a & 3) << 4) | (b >> 4)] + (digest[i + 1] === undefined ? '=' : b64[((b & 15) << 2) | (c >> 6)]) + (digest[i + 2] === undefined ? '=' : b64[c & 63]);
    }
    return out;
}
/** 编码一个服务端 → 客户端数据帧（FIN=1, opcode, 无掩码；支持 64 位扩展长度）。 */
function encodeWsText(text) {
    const payload = new TextEncoder().encode(text);
    const len = payload.length;
    let head;
    if (len < 126) {
        head = new Uint8Array([0x81, len]);
    }
    else if (len < 65536) {
        head = new Uint8Array([0x81, 126, (len >> 8) & 0xff, len & 0xff]);
    }
    else {
        head = new Uint8Array([0x81, 127, 0, 0, 0, 0, 0, 0, 0, 0]);
        const dv = new DataView(head.buffer);
        dv.setUint32(2, Math.floor(len / 0x100000000), false);
        dv.setUint32(6, len >>> 0, false);
    }
    const out = new Uint8Array(head.length + len);
    out.set(head, 0);
    out.set(payload, head.length);
    return out;
}
/** 编码一个控制帧（close=8 / ping=9 / pong=10；可带 1-125 字节负载）。 */
function encodeWsControl(opcode, payload) {
    const p = payload === undefined ? new Uint8Array(0) : (payload instanceof Uint8Array ? payload : new TextEncoder().encode(String(payload)));
    const head = new Uint8Array([0x80 | opcode, p.length]);
    const out = new Uint8Array(head.length + p.length);
    out.set(head, 0);
    out.set(p, head.length);
    return out;
}
/** 客户端 → 服务端帧流式解析器（浏览器下行通道只应出现 close/ping，仍完整支持掩码与分片）。 */
class WsFrameReader {
    constructor() { this.buf = new Uint8Array(0); this.done = false; }
    push(chunk) {
        const merged = new Uint8Array(this.buf.length + chunk.length);
        merged.set(this.buf, 0);
        merged.set(chunk, this.buf.length);
        this.buf = merged;
    }
    /** 尝试取出一帧；不足一帧返回 null；连接关闭帧返回 {close: true}。 */
    read() {
        while (this.buf.length >= 2 && !this.done) {
            const b0 = this.buf[0], b1 = this.buf[1];
            const fin = (b0 & 0x80) !== 0;
            const opcode = b0 & 0x0f;
            const masked = (b1 & 0x80) !== 0;
            let len = b1 & 0x7f;
            let off = 2;
            if (len === 126) {
                if (this.buf.length < 4)
                    return null;
                len = (this.buf[2] << 8) | this.buf[3];
                off = 4;
            }
            else if (len === 127) {
                if (this.buf.length < 10)
                    return null;
                const dv = new DataView(this.buf.buffer, this.buf.byteOffset, this.buf.byteLength);
                len = Number(dv.getBigUint64(2, false));
                off = 10;
            }
            const maskBytes = masked ? 4 : 0;
            if (this.buf.length < off + maskBytes + len)
                return null;
            let payload = this.buf.slice(off + maskBytes, off + maskBytes + len);
            if (masked) {
                const key = this.buf.slice(off, off + 4);
                const unmasked = new Uint8Array(len);
                for (let i = 0; i < len; i++)
                    unmasked[i] = payload[i] ^ key[i % 4];
                payload = unmasked;
            }
            this.buf = this.buf.slice(off + maskBytes + len);
            if (opcode === 0x8) {
                this.done = true;
                return { close: true };
            }
            if (opcode === 0x9)
                return { ping: payload };
            if (opcode === 0xa)
                return { pong: payload };
            if (!fin)
                continue;
            return { opcode, payload };
        }
        return null;
    }
}
/** 从环境变量解析限流配置（DSH_AUTH_MAX_FAILS / DSH_AUTH_LOCK_MS / DSH_AUTH_TRUST_PROXY）。 */
export function readLockConfig(env) {
    const e = env !== undefined && env !== null ? env : {};
    const num = (v, d) => { const n = Number(v); return Number.isInteger(n) && n > 0 ? n : d; };
    return {
        maxFails: num(e.DSH_AUTH_MAX_FAILS, 5),
        lockMs: num(e.DSH_AUTH_LOCK_MS, 30 * 1000),
        trustProxy: ['1', 'true', 'yes', 'on'].includes(String(e.DSH_AUTH_TRUST_PROXY || '').trim().toLowerCase()),
    };
}
/**
 * 客户端来源 IP：默认取 socket.remoteAddress；仅当显式配置 DSH_AUTH_TRUST_PROXY=1
 * 时才信任 X-Forwarded-For（取最左，反代按 客户端→代理 顺序追加）。默认不信任，
 * 防止未配置反代时伪造 XFF 绕过/污染限流计数。
 */
export function clientIp(req, trustProxy) {
    try {
        const addr = req !== undefined && req.socket !== undefined ? req.socket.remoteAddress : undefined;
        if (trustProxy && req !== undefined && req.headers !== undefined && typeof req.headers['x-forwarded-for'] === 'string') {
            const parts = req.headers['x-forwarded-for'].split(',');
            for (let i = parts.length - 1; i >= 0; i--) {
                const p = parts[i].trim();
                if (p !== '')
                    return p;
            }
        }
        return typeof addr === 'string' ? addr : 'unknown';
    }
    catch (err) {
        return 'unknown';
    }
}
export function apply(ctx) {
    // ============ 配置常量 ============
    const COOKIE_NAME = 'dsh_auth';
    const SCOPE = 'dsh-auth';
    const SESSION_TTL_MS = 12 * 60 * 60 * 1000; // 会话 12 小时，滑动续期
    const SESSION_SWEEP_MS = 5 * 60 * 1000;
    const PBKDF2_ITERATIONS = 60000;
    const MIN_PASSWORD = 6;
    const MAX_PASSWORD = 128;
    const MAX_BODY_BYTES = 64 * 1024;
    const USERNAME_RE = /^[A-Za-z0-9_.-]{2,32}$/;
    // 限流配置：环境变量覆盖（DSH_AUTH_MAX_FAILS / DSH_AUTH_LOCK_MS / DSH_AUTH_TRUST_PROXY）
    const lock = readLockConfig(typeof process !== 'undefined' && process.env !== undefined ? process.env : {});
    const LOCKOUT_MAX_FAILS = lock.maxFails;
    const LOCKOUT_MS = lock.lockMs;
    const TRUST_PROXY = lock.trustProxy;
    const userRecordKey = (username) => SCOPE + '/' + (/^[a-z][a-z0-9-]*$/.test(username) ? username : 'user-' + createHash('sha256').update(username).digest('hex'));
    // ============ 纯 JS 密码学（沙箱无 crypto/Buffer） ============
    function rotr(x, n) { return ((x >>> n) | (x << (32 - n))) >>> 0; }
    const K = new Uint32Array([
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ]);
    function sha256(data) {
        const len = data.length;
        const bitLenHi = Math.floor(len / 0x20000000);
        const bitLenLo = (len << 3) >>> 0;
        const padded = new Uint8Array(((len + 8) >> 6 << 6) + 64);
        padded.set(data);
        padded[len] = 0x80;
        const dv = new DataView(padded.buffer);
        dv.setUint32(padded.length - 8, bitLenHi);
        dv.setUint32(padded.length - 4, bitLenLo);
        const w = new Uint32Array(64);
        let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
        let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
        for (let i = 0; i < padded.length; i += 64) {
            for (let j = 0; j < 16; j++)
                w[j] = dv.getUint32(i + j * 4);
            for (let j = 16; j < 64; j++) {
                const s0 = rotr(w[j - 15], 7) ^ rotr(w[j - 15], 18) ^ (w[j - 15] >>> 3);
                const s1 = rotr(w[j - 2], 17) ^ rotr(w[j - 2], 19) ^ (w[j - 2] >>> 10);
                w[j] = (w[j - 16] + s0 + w[j - 7] + s1) >>> 0;
            }
            let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
            for (let j = 0; j < 64; j++) {
                const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
                const ch = (e & f) ^ (~e & g);
                const t1 = (h + S1 + ch + K[j] + w[j]) >>> 0;
                const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
                const maj = (a & b) ^ (a & c) ^ (b & c);
                const t2 = (S0 + maj) >>> 0;
                h = g;
                g = f;
                f = e;
                e = (d + t1) >>> 0;
                d = c;
                c = b;
                b = a;
                a = (t1 + t2) >>> 0;
            }
            h0 = (h0 + a) >>> 0;
            h1 = (h1 + b) >>> 0;
            h2 = (h2 + c) >>> 0;
            h3 = (h3 + d) >>> 0;
            h4 = (h4 + e) >>> 0;
            h5 = (h5 + f) >>> 0;
            h6 = (h6 + g) >>> 0;
            h7 = (h7 + h) >>> 0;
        }
        const out = new Uint8Array(32);
        const odv = new DataView(out.buffer);
        odv.setUint32(0, h0);
        odv.setUint32(4, h1);
        odv.setUint32(8, h2);
        odv.setUint32(12, h3);
        odv.setUint32(16, h4);
        odv.setUint32(20, h5);
        odv.setUint32(24, h6);
        odv.setUint32(28, h7);
        return out;
    }
    function hmacSha256(key, msg) {
        const blockSize = 64;
        let k = key;
        if (k.length > blockSize)
            k = sha256(k);
        const iKey = new Uint8Array(blockSize);
        const oKey = new Uint8Array(blockSize);
        for (let i = 0; i < blockSize; i++) {
            const kb = i < k.length ? k[i] : 0;
            iKey[i] = kb ^ 0x36;
            oKey[i] = kb ^ 0x5c;
        }
        const inner = new Uint8Array(blockSize + msg.length);
        inner.set(iKey);
        inner.set(msg, blockSize);
        const innerHash = sha256(inner);
        const outer = new Uint8Array(blockSize + innerHash.length);
        outer.set(oKey);
        outer.set(innerHash, blockSize);
        return sha256(outer);
    }
    function pbkdf2(password, salt, iterations) {
        const block = new Uint8Array(salt.length + 4);
        block.set(salt);
        block[salt.length + 3] = 1;
        let u = hmacSha256(password, block);
        const result = new Uint8Array(u);
        for (let i = 1; i < iterations; i++) {
            u = hmacSha256(password, u);
            for (let j = 0; j < result.length; j++)
                result[j] ^= u[j];
        }
        return result;
    }
    function toHex(bytes) {
        let s = '';
        for (let i = 0; i < bytes.length; i++) {
            const b = bytes[i];
            s += (b < 16 ? '0' : '') + b.toString(16);
        }
        return s;
    }
    function hexToBytes(hex) {
        const out = new Uint8Array(Math.floor(String(hex).length / 2));
        for (let i = 0; i < out.length; i++) {
            const byte = parseInt(String(hex).slice(i * 2, i * 2 + 2), 16);
            out[i] = Number.isNaN(byte) ? 0 : byte;
        }
        return out;
    }
    function utf8(str) {
        return new TextEncoder().encode(str);
    }
    function randomBytes(n) {
        if (typeof crypto !== 'undefined' && crypto !== null && typeof crypto.getRandomValues === 'function') {
            const out = new Uint8Array(n);
            crypto.getRandomValues(out);
            return out;
        }
        const out = new Uint8Array(n);
        for (let i = 0; i < n; i++)
            out[i] = Math.floor(Math.random() * 256);
        return out;
    }
    function randomHex(nBytes) {
        return toHex(randomBytes(nBytes));
    }
    function randomPassword(len) {
        const alphabet = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*';
        const bytes = randomBytes(len);
        let out = '';
        for (let i = 0; i < len; i++)
            out += alphabet[bytes[i] % alphabet.length];
        return out;
    }
    function constantTimeEqual(a, b) {
        if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length)
            return false;
        let diff = 0;
        for (let i = 0; i < a.length; i++)
            diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
        return diff === 0;
    }
    function hashPassword(password, saltHex, iterations) {
        return toHex(pbkdf2(utf8(password), hexToBytes(saltHex), iterations));
    }
    function newPasswordRecord(password) {
        const salt = randomHex(16);
        return { salt, hash: hashPassword(password, salt, PBKDF2_ITERATIONS), iterations: PBKDF2_ITERATIONS };
    }
    function verifyPassword(record, password) {
        if (record === undefined || typeof record.hash !== 'string' || typeof record.salt !== 'string')
            return false;
        const iters = typeof record.iterations === 'number' && record.iterations > 0 ? record.iterations : PBKDF2_ITERATIONS;
        return constantTimeEqual(hashPassword(password, record.salt, iters), record.hash);
    }
    // ============ 运行时状态 ============
    const state = {
        users: new Map(),
        sessions: new Map(),
        fails: new Map(),
        ready: false,
        fatal: null,
    };
    let creds = ctx.get('credentials');
    let store = null;
    // 用注入的服务构建持久化 store
    function buildStore(c) {
        return {
            async load() {
                const prefix = SCOPE + '/';
                const entries = await c.listRecords();
                for (const entry of entries) {
                    if (typeof entry.key !== 'string' || !entry.key.startsWith(prefix))
                        continue;
                    const rec = await c.readRecord(entry.key);
                    if (rec === undefined || rec.kind !== 'grant' || typeof rec.payload !== 'string')
                        continue;
                    let p;
                    try {
                        p = JSON.parse(rec.payload);
                    }
                    catch (err) {
                        continue;
                    }
                    if (p !== null && typeof p === 'object' && typeof p.v === 'number'
                        && typeof p.hash === 'string' && typeof p.salt === 'string') {
                        const username = typeof p.username === 'string' ? p.username : entry.key.slice(prefix.length);
                        state.users.set(username, p);
                    }
                }
            },
            async create(rec) {
                const key = userRecordKey(rec.username);
                const jsonString = JSON.stringify(rec);
                const written = await c.modifyRecord(key, async (current) => {
                    if (current !== undefined)
                        return undefined;
                    return { kind: 'grant', payload: jsonString };
                });
                if (written === undefined || written.kind !== 'grant' || written.payload !== jsonString)
                    return false;
                state.users.set(rec.username, rec);
                return true;
            },
            async mutate(username, fn) {
                const key = userRecordKey(username);
                const written = await c.modifyRecord(key, async (current) => {
                    if (current === undefined || current.kind !== 'grant' || typeof current.payload !== 'string')
                        return undefined;
                    let parsed;
                    try {
                        parsed = JSON.parse(current.payload);
                    }
                    catch (err) {
                        return undefined;
                    }
                    if (parsed === null || typeof parsed !== 'object')
                        return undefined;
                    const next = await fn(parsed);
                    if (next === undefined)
                        return undefined;
                    return { kind: 'grant', payload: JSON.stringify(next) };
                });
                if (written !== undefined && written.kind === 'grant' && typeof written.payload === 'string') {
                    let parsed;
                    try {
                        parsed = JSON.parse(written.payload);
                    }
                    catch (err) {
                        return undefined;
                    }
                    state.users.set(username, parsed);
                    return parsed;
                }
                return undefined;
            },
            async remove(username) {
                state.users.delete(username);
                await c.deleteRecord(userRecordKey(username));
            },
            async readRaw(key) {
                const rec = await c.readRecord(key);
                if (rec === undefined || rec.kind !== 'grant' || typeof rec.payload !== 'string')
                    return undefined;
                return rec.payload;
            },
            async writeRaw(key, payload) {
                await c.modifyRecord(key, async (current) => {
                    if (current !== undefined && current.kind === 'grant') {
                        return { kind: 'grant', payload: current.payload === payload ? current.payload : payload };
                    }
                    return { kind: 'grant', payload };
                });
            },
        };
    }
    async function acquireCredentials(timeoutMs) {
        if (creds !== undefined)
            return;
        const deadline = Date.now() + timeoutMs;
        while (creds === undefined && Date.now() < deadline) {
            creds = ctx.get('credentials');
            if (creds !== undefined)
                break;
            await new Promise(resolve => setTimeout(resolve, 200));
        }
        if (creds !== undefined && store === null)
            store = buildStore(creds);
    }
    if (creds !== undefined)
        store = buildStore(creds);
    async function storeMutate(username, fn) {
        if (store !== null)
            return store.mutate(username, fn);
        const cur = state.users.get(username);
        if (cur === undefined)
            return undefined;
        const next = await fn(cur);
        if (next === undefined)
            return undefined;
        state.users.set(username, next);
        return next;
    }
    async function storeCreate(rec) {
        if (store !== null)
            return store.create(rec);
        if (state.users.has(rec.username))
            return false;
        state.users.set(rec.username, rec);
        return true;
    }
    // ============ 会话 ============
    const SESSIONS_FILE = 'dsh-ui-auth-sessions.json';
    let sessionsDirty = false;
    function persistSessions() {
        if (!sessionsDirty)
            return;
        try {
            const fsSvc = ctx.get('fs');
            if (fsSvc === undefined)
                return;
            const data = { v: 1, sessions: {} };
            for (const [token, s] of state.sessions)
                data.sessions[token] = { username: s.username, expiresAt: s.expiresAt };
            sessionsDirty = false;
            fsSvc.resolve(SESSIONS_FILE).then((t) => fsSvc.writeText(t, JSON.stringify(data))).catch((err) => console.error('[dsh-ui-auth] 写入会话文件失败: ' + String(err)));
        }
        catch (err) { /* ignore */ }
    }
    async function loadSessions() {
        try {
            const fsSvc = ctx.get('fs');
            if (fsSvc === undefined)
                return;
            const t = await fsSvc.resolve(SESSIONS_FILE);
            const text = await fsSvc.readText(t);
            const data = JSON.parse(text);
            if (data === null || typeof data !== 'object' || data.v !== 1 || typeof data.sessions !== 'object' || data.sessions === null)
                return;
            const now = Date.now();
            let loaded = 0;
            for (const [key, s] of Object.entries(data.sessions)) {
                if (typeof key !== 'string' || !/^[0-9a-f]{64}$/.test(key))
                    continue;
                if (typeof s !== 'object' || s === null || typeof s.username !== 'string' || typeof s.expiresAt !== 'number')
                    continue;
                if (s.expiresAt <= now)
                    continue;
                if (!state.users.has(s.username))
                    continue;
                state.sessions.set(key, { username: s.username, expiresAt: Math.min(s.expiresAt, now + SESSION_TTL_MS) });
                loaded++;
            }
            if (loaded > 0)
                console.log('[dsh-ui-auth] 已恢复 ' + loaded + ' 个持久化会话（重启不掉线）');
        }
        catch (err) { /* 文件不存在/损坏：从空会话开始 */ }
    }
    /** 会话 token 哈希（内存 key 与落盘均用哈希，磁盘不存明文 token）。 */
    function hashToken(token) {
        return toHex(sha256(new TextEncoder().encode(String(token))));
    }
    function createSession(username) {
        let token = randomHex(24);
        while (state.sessions.has(hashToken(token)))
            token = randomHex(24);
        state.sessions.set(hashToken(token), { username, expiresAt: Date.now() + SESSION_TTL_MS });
        sessionsDirty = true;
        persistSessions();
        return token;
    }
    function resolveSession(token, touch = true) {
        if (token === undefined)
            return undefined;
        const key = hashToken(token);
        const s = state.sessions.get(key);
        if (s === undefined)
            return undefined;
        const now = Date.now();
        if (s.expiresAt <= now) {
            state.sessions.delete(key);
            sessionsDirty = true;
            return undefined;
        }
        if (touch)
            s.expiresAt = now + SESSION_TTL_MS;
        return s.username;
    }
    function destroySession(token) {
        if (token !== undefined && state.sessions.delete(hashToken(token))) {
            sessionsDirty = true;
            persistSessions();
        }
    }
    function invalidateSessions(username, exceptToken) {
        const exceptKey = exceptToken !== undefined ? hashToken(exceptToken) : undefined;
        let changed = false;
        for (const [token, s] of state.sessions) {
            if (s.username === username && token !== exceptKey) {
                state.sessions.delete(token);
                changed = true;
            }
        }
        if (changed) {
            sessionsDirty = true;
            persistSessions();
        }
    }
    // ============ HTTP 工具 ============
    function pathnameOf(rawUrl) {
        if (typeof rawUrl !== 'string')
            return '/';
        const q = rawUrl.indexOf('?');
        const p = q === -1 ? rawUrl : rawUrl.slice(0, q);
        try {
            return decodeURIComponent(p);
        }
        catch (err) {
            return p;
        }
    }
    function readCookie(req, name) {
        const header = req.headers !== undefined ? req.headers.cookie : undefined;
        if (typeof header !== 'string')
            return undefined;
        const prefix = name + '=';
        for (const part of header.split(';')) {
            const t = part.trim();
            if (t.startsWith(prefix))
                return t.slice(prefix.length);
        }
        return undefined;
    }
    function readBody(req, limit) {
        return new Promise((resolve, reject) => {
            let size = 0;
            let text = '';
            const dec = new TextDecoder();
            req.on('data', (chunk) => {
                size += chunk.length;
                if (size > limit) {
                    reject(new Error('body too large'));
                    try {
                        req.destroy();
                    }
                    catch (e) { /* ignore */ }
                    return;
                }
                text += dec.decode(chunk, { stream: true });
            });
            req.on('end', () => { text += dec.decode(); resolve(text); });
            req.on('error', reject);
        });
    }
    function clientIpOf(req) {
        return clientIp(req, TRUST_PROXY);
    }
    function sendJson(res, status, obj) {
        if (res.headersSent) {
            try {
                res.destroy();
            }
            catch (e) { /* ignore */ }
            return;
        }
        try {
            res.writeHead(status, {
                'content-type': 'application/json; charset=utf-8',
                'cache-control': 'no-store',
            });
            res.end(JSON.stringify(obj));
        }
        catch (err) {
            try {
                res.destroy();
            }
            catch (e) { /* ignore */ }
        }
    }
    function redirect(res, location) {
        if (res.headersSent) {
            try {
                res.destroy();
            }
            catch (e) { /* ignore */ }
            return;
        }
        try {
            res.writeHead(302, { location, 'cache-control': 'no-store' });
            res.end();
        }
        catch (err) {
            try {
                res.destroy();
            }
            catch (e) { /* ignore */ }
        }
    }
    function isSecureRequest(req) {
        try {
            if (req.socket !== undefined && req.socket.encrypted === true)
                return true;
            if (TRUST_PROXY && req.headers !== undefined && req.headers['x-forwarded-proto'] === 'https')
                return true;
        }
        catch (err) { /* ignore */ }
        return false;
    }
    function setAuthCookie(res, token, secure) {
        try {
            res.setHeader('set-cookie', COOKIE_NAME + '=' + token + '; Path=/; HttpOnly; SameSite=Strict' + (secure ? '; Secure' : '') + '; Max-Age=' + Math.floor(SESSION_TTL_MS / 1000));
        }
        catch (err) { /* ignore */ }
    }
    function clearAuthCookie(res, secure) {
        try {
            res.setHeader('set-cookie', COOKIE_NAME + '=; Path=/; HttpOnly; SameSite=Strict' + (secure ? '; Secure' : '') + '; Max-Age=0');
        }
        catch (err) { /* ignore */ }
    }
    function passwordError(pw) {
        if (typeof pw !== 'string')
            return '密码格式错误';
        if (pw.length < MIN_PASSWORD)
            return '密码至少 ' + MIN_PASSWORD + ' 位';
        if (pw.length > MAX_PASSWORD)
            return '密码过长（最多 ' + MAX_PASSWORD + ' 位）';
        return null;
    }
    function recordFail(ip) {
        const cur = state.fails.get(ip);
        const count = (cur === undefined ? 0 : cur.count) + 1;
        state.fails.set(ip, count >= LOCKOUT_MAX_FAILS
            ? { count, until: Date.now() + LOCKOUT_MS }
            : { count, until: 0 });
    }
    // ============ 登录页 ============
    function escapeHtml(value) {
        return value
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }
    function loginPage() {
        return '<!DOCTYPE html>' +
            '<html lang="zh-CN"><head><meta charset="utf-8">' +
            '<meta name="viewport" content="width=device-width, initial-scale=1">' +
            '<title>登录 · DeepSeek Harness</title><style>' +
            '*{box-sizing:border-box;margin:0;padding:0}' +
            'body{font-family:system-ui,-apple-system,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;' +
            'min-height:100vh;display:flex;align-items:center;justify-content:center;' +
            'background:#0f1115;color:#e6e6e6}' +
            '.card{width:360px;max-width:calc(100vw - 40px);background:#171a21;border:1px solid #2a2f3a;' +
            'border-radius:12px;padding:32px 28px;box-shadow:0 12px 40px rgba(0,0,0,.45)}' +
            '.brand{font-size:20px;font-weight:700;letter-spacing:.3px;margin-bottom:4px}' +
            '.sub{font-size:13px;color:#8b93a7;margin-bottom:24px}' +
            'label{display:block;font-size:13px;color:#aab2c3;margin:14px 0 6px}' +
            'input{width:100%;padding:10px 12px;border-radius:8px;border:1px solid #333a47;' +
            'background:#101318;color:#f0f0f0;font-size:14px;outline:none}' +
            'input:focus{border-color:#4f7cff}' +
            '.pw{position:relative}' +
            '.pw input{padding-right:46px}' +
            '.eye{position:absolute;right:6px;top:50%;transform:translateY(-50%);width:auto;margin:0;padding:6px 8px;' +
            'background:none;border:0;border-radius:6px;font-size:15px;line-height:1;cursor:pointer;color:#8b93a7}' +
            '.eye:hover{color:#c9d1e3}' +
            'button{width:100%;margin-top:22px;padding:11px;border:0;border-radius:8px;' +
            'background:#4f7cff;color:#fff;font-size:15px;font-weight:600;cursor:pointer}' +
            'button:hover{background:#3d6bff}button:disabled{opacity:.6;cursor:default}' +
            '.err{margin-top:14px;font-size:13px;color:#ff6b6b;min-height:18px}' +
            '.foot{margin-top:22px;font-size:12px;color:#5c6472;text-align:center}' +
            '@media (prefers-color-scheme: light){' +
            'body{background:#f4f6f9;color:#1f2329}' +
            '.card{background:#ffffff;border:1px solid #dfe3ea;box-shadow:0 8px 24px rgba(31,35,41,.08)}' +
            '.sub{color:#5c6472}' +
            'label{color:#5c6472}' +
            'input{background:#ffffff;border:1px solid #d2d7df;color:#1f2329}' +
            'input:focus{border-color:#3b6ee0}' +
            '.eye{color:#8a92a0}.eye:hover{color:#3a4150}' +
            'button{background:#3b6ee0}' +
            'button:hover{background:#315fd0}' +
            '.foot{color:#8a92a0}' +
            '}' +
            '</style></head><body><div class="card">' +
            '<div class="brand">DeepSeek Harness</div>' +
            '<div class="sub">请登录后继续访问</div>' +
            '<form id="f">' +
            '<label for="u">用户名</label><input id="u" name="username" autocomplete="username" required autofocus>' +
            '<label for="p">密码</label><div class="pw"><input id="p" name="password" type="password" autocomplete="current-password">' +
            '<button type="button" class="eye" id="pe" aria-label="显示/隐藏密码">👁</button></div>' +
            '<button id="b" type="submit">登 录</button>' +
            '<div class="err" id="e"></div>' +
            '</form>' +
            '</div>' +
            '<script>' +
            '(function(){' +
            'var f=document.getElementById("f"),e=document.getElementById("e"),b=document.getElementById("b"),' +
            'p=document.getElementById("p");' +
            'var params=new URLSearchParams(location.search),next=params.get("next");' +
            'function okPath(v){return v&&v.charAt(0)==="/"&&v.indexOf("//")===-1&&v.indexOf(":")===-1}' +
            'function done(j){location.href=okPath(j.redirect)?j.redirect:(okPath(next)?next:"/")}' +
            'function busy(on){b.disabled=on}' +
            'function post(url,body){return fetch(url,{method:"POST",headers:{"content-type":"application/json"},' +
            'body:JSON.stringify(body)}).then(function(r){return r.json().catch(function(){return {}})' +
            '.then(function(j){return {status:r.status,json:j}})})}' +
            'function fail(err){busy(false);e.textContent=err&&err.message?err.message:"网络错误，请重试"}' +
            'document.getElementById("pe").addEventListener("click",function(){' +
            'var on=p.type==="password";p.type=on?"text":"password";this.textContent=on?"🙈":"👁"});' +
            'f.addEventListener("submit",function(ev){' +
            'ev.preventDefault();busy(true);e.textContent="";' +
            'post("/auth/login",{username:document.getElementById("u").value,password:p.value})' +
            '.then(function(r){' +
            'busy(false);' +
            'if(r.status===200&&r.json.ok){done(r.json);return}' +
            'e.textContent=r.json.error||("登录失败 ("+r.status+")")}).catch(fail)});' +
            '})()' +
            '</script></body></html>';
    }
    // ============ 认证端点 ============
    function safeNext(query) {
        let next = '/';
        if (typeof query === 'string') {
            const m = query.match(/(?:^|[?&])next=([^&]+)/);
            if (m !== null) {
                try {
                    const p = decodeURIComponent(m[1]);
                    if (p.charAt(0) === '/' && p.indexOf('//') === -1 && p.indexOf(':') === -1)
                        next = p;
                }
                catch (err) { /* ignore */ }
            }
        }
        return next;
    }
    async function handleLogin(req, res) {
        const q = typeof req.url === 'string' ? req.url.split('?').slice(1).join('?') : '';
        if (req.method === 'GET' || req.method === 'HEAD') {
            const token = readCookie(req, COOKIE_NAME);
            if (resolveSession(token) !== undefined) {
                redirect(res, safeNext(q));
                return;
            }
            if (req.method === 'HEAD') {
                res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
                res.end();
                return;
            }
            try {
                res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
                res.end(loginPage());
            }
            catch (err) {
                try {
                    res.destroy();
                }
                catch (e) { /* ignore */ }
            }
            return;
        }
        if (req.method === 'POST') {
            if (!state.ready) {
                sendJson(res, 503, { error: '服务初始化中，请稍后重试' });
                return;
            }
            let body;
            try {
                const raw = await readBody(req, MAX_BODY_BYTES);
                body = raw.trim() === '' ? {} : JSON.parse(raw);
            }
            catch (err) {
                sendJson(res, 400, { error: '请求体格式错误' });
                return;
            }
            const username = typeof body.username === 'string' ? body.username.trim() : '';
            const password = typeof body.password === 'string' ? body.password : '';
            const ip = clientIpOf(req);
            if (username === '' || password === '') {
                sendJson(res, 400, { error: '请输入用户名和密码' });
                return;
            }
            const lock = state.fails.get(ip);
            if (lock !== undefined && lock.until > Date.now()) {
                sendJson(res, 429, { error: '尝试次数过多，请 ' + Math.ceil((lock.until - Date.now()) / 1000) + ' 秒后再试' });
                return;
            }
            if (lock !== undefined && lock.until > 0 && lock.until <= Date.now())
                state.fails.delete(ip);
            const rec = state.users.get(username);
            if (rec === undefined || !verifyPassword(rec, password)) {
                recordFail(ip);
                sendJson(res, 401, { error: '用户名或密码错误' });
                return;
            }
            state.fails.delete(ip);
            const token = createSession(username);
            setAuthCookie(res, token, isSecureRequest(req));
            sendJson(res, 200, { ok: true, redirect: safeNext(q) });
            return;
        }
        sendJson(res, 405, { error: 'method not allowed' });
    }
    async function handleAuthPath(req, res, pathname) {
        if (pathname === '/auth/login') {
            await handleLogin(req, res);
            return;
        }
        if (pathname === '/auth/logout') {
            if (req.method !== 'POST') {
                sendJson(res, 405, { error: 'method not allowed' });
                return;
            }
            const token = readCookie(req, COOKIE_NAME);
            destroySession(token);
            clearAuthCookie(res, isSecureRequest(req));
            sendJson(res, 200, { ok: true });
            return;
        }
        if (pathname === '/auth/status') {
            const token = readCookie(req, COOKIE_NAME);
            const who = resolveSession(token);
            if (who === undefined) {
                sendJson(res, 200, { authenticated: false });
                return;
            }
            const me = state.users.get(who);
            if (me === undefined) {
                sendJson(res, 200, { authenticated: false });
                return;
            }
            sendJson(res, 200, { authenticated: true, username: me.username });
            return;
        }
        if (pathname === '/auth/change-password') {
            if (req.method !== 'POST') {
                sendJson(res, 405, { error: 'method not allowed' });
                return;
            }
            const token = readCookie(req, COOKIE_NAME);
            const who = resolveSession(token);
            if (who === undefined) {
                sendJson(res, 401, { error: '未登录或会话已过期' });
                return;
            }
            let body;
            try {
                const raw = await readBody(req, MAX_BODY_BYTES);
                body = raw.trim() === '' ? {} : JSON.parse(raw);
            }
            catch (err) {
                sendJson(res, 400, { error: '请求体格式错误' });
                return;
            }
            const newPassword = typeof body.newPassword === 'string' ? body.newPassword : '';
            const pwErr = passwordError(newPassword);
            if (pwErr !== null) {
                sendJson(res, 400, { error: pwErr });
                return;
            }
            const rec = newPasswordRecord(newPassword);
            await storeMutate(who, (p) => ({ ...p, salt: rec.salt, hash: rec.hash, iterations: rec.iterations, updatedAt: Date.now() }));
            invalidateSessions(who, token); // 让当前会话外的其他会话失效
            sendJson(res, 200, { ok: true });
            return;
        }
        sendJson(res, 404, { error: 'not found' });
    }
    // ============ 首次启动引导 ============
    function trace(msg) {
        try {
            const fsSvc = ctx.get('fs');
            if (fsSvc === undefined)
                return;
            fsSvc.resolve('dsh-ui-auth-init.log').then((t) => fsSvc.writeText(t, msg + '\n', undefined)).catch(() => { });
        }
        catch (err) { /* ignore */ }
    }
    async function bootstrap() {
        if (state.users.size > 0)
            return;
        if (store === null) {
            console.log('[dsh-ui-auth] 检测到 credentials 服务缺失，用户数据仅保存在内存中，重启后将丢失');
        }
        const username = 'admin';
        const password = randomPassword(16);
        const rec = newPasswordRecord(password);
        const now = Date.now();
        const ok = await storeCreate({ v: 1, username, role: 'admin', ...rec, createdAt: now, updatedAt: now });
        if (!ok) {
            console.error('[dsh-ui-auth] 引导创建管理员失败（用户名已存在？）');
            return;
        }
        console.log('[dsh-ui-auth] ================================================');
        console.log('[dsh-ui-auth] 首次启动：已创建管理员账号');
        console.log('[dsh-ui-auth]   用户名: ' + username);
        console.log('[dsh-ui-auth]   密码:   ' + password);
        console.log('[dsh-ui-auth] 请立即登录并修改密码。');
        console.log('[dsh-ui-auth] ================================================');
        try {
            const fsSvc = ctx.get('fs');
            if (fsSvc !== undefined) {
                const lines = [
                    'DeepSeek Harness UI 认证插件 - 初始管理员账号',
                    '================================================',
                    '用户名: ' + username,
                    '密码:   ' + password,
                    '',
                    '请在登录后立即修改该密码，然后删除本文件。',
                ];
                const target = await fsSvc.resolve('dsh-ui-auth-bootstrap.txt');
                await fsSvc.writeText(target, lines.join('\n'));
                console.log('[dsh-ui-auth] 初始账号已写入文件 dsh-ui-auth-bootstrap.txt（进程工作目录）');
            }
        }
        catch (err) {
            console.error('[dsh-ui-auth] 写入初始账号文件失败: ' + String(err));
        }
    }
    async function init() {
        try {
            await acquireCredentials(10000);
            if (store !== null) {
                await store.load();
            }
            await bootstrap();
            await loadSessions();
            state.ready = true;
        }
        catch (err) {
            trace('step=error: ' + String(err) + (err && err.stack ? '\n' + err.stack : ''));
            throw err;
        }
    }
    const initialized = init();
    initialized.catch((err) => {
        state.fatal = String(err);
        trace('step=fatal: ' + String(err));
        console.error('[dsh-ui-auth] 初始化失败（保持 fail-closed，所有非登录请求返回 503）: ' + (err instanceof Error ? (err.stack || err.message) : String(err)));
    });
    // ============ 网关：包装 node:http 服务器 ============
    const ws = ctx.get('webServer');
    const server = ws !== undefined && ws.server !== undefined ? ws.server : undefined;
    if (server === undefined) {
        console.error('[dsh-ui-auth] webServer 不可用，认证网关未启用（当前环境可能不提供 HTTP 服务）');
        return;
    }
    const origReq = server.listeners('request');
    const origUp = server.listeners('upgrade');
    const modern = typeof ctx.get('connection')?.authorizeIndex === 'function'
        ? createModernGateway(ctx, {
            ready: initialized,
            user(username) {
                const user = state.users.get(username);
                return state.ready && user !== undefined ? Object.freeze({ username, role: user.role }) : undefined;
            },
            principal(req) {
                if (!state.ready)
                    return undefined;
                const username = resolveSession(readCookie(req, COOKIE_NAME), false);
                const user = state.users.get(username);
                return user === undefined ? undefined : Object.freeze({ username: username, role: user.role });
            },
            loginKey: req => hashToken(readCookie(req, COOKIE_NAME) ?? ''),
            session(_id) { return 'admin'; },
            workspace(_id) { return 'admin'; },
            async sessionExists(_id) { return true; },
            async claimSession() { },
            async claimWorkspace() { },
        })
        : undefined;
    server.removeAllListeners('request');
    server.removeAllListeners('upgrade');
    function readBodyChunks(req, limit) {
        return new Promise((resolve, reject) => {
            const chunks = [];
            let size = 0;
            req.on('data', (chunk) => {
                size += chunk.length;
                if (size > limit) {
                    reject(new Error('body too large'));
                    try {
                        req.destroy();
                    }
                    catch (e) { /* ignore */ }
                    return;
                }
                chunks.push(chunk);
            });
            req.on('end', () => resolve(chunks));
            req.on('error', reject);
        });
    }
    function decodeChunks(chunks) {
        let text = '';
        const dec = new TextDecoder();
        for (const c of chunks)
            text += dec.decode(c, { stream: true });
        return text + dec.decode();
    }
    function replayRequest(original, chunks) {
        let i = 0;
        return {
            url: original.url,
            method: original.method,
            headers: original.headers,
            socket: original.socket,
            httpVersion: original.httpVersion,
            httpVersionMajor: original.httpVersionMajor,
            httpVersionMinor: original.httpVersionMinor,
            destroy: () => { try {
                original.destroy();
            }
            catch (e) { /* ignore */ } },
            [Symbol.asyncIterator]() {
                return {
                    next() {
                        if (i < chunks.length)
                            return Promise.resolve({ value: chunks[i++], done: false });
                        return Promise.resolve({ value: undefined, done: true });
                    },
                };
            },
        };
    }
    async function handleGate(req, res) {
        const pathname = pathnameOf(req.url);
        if (pathname === '/auth' || pathname.startsWith('/auth/')) {
            await handleAuthPath(req, res, pathname);
            return;
        }
        if (!state.ready) {
            sendJson(res, 503, { error: '服务初始化中，请稍后重试' });
            return;
        }
        const token = readCookie(req, COOKIE_NAME);
        const who = resolveSession(token);
        if (who !== undefined) {
            if (modern !== undefined && await modern.handleHttp(req, res, (request, response) => {
                for (const fn of origReq)
                    fn.call(server, request, response);
            }))
                return;
            for (const fn of origReq)
                fn.call(server, req, res);
            return;
        }
        const method = typeof req.method === 'string' ? req.method.toUpperCase() : 'GET';
        if (method === 'GET' || method === 'HEAD') {
            const accept = typeof req.headers.accept === 'string' ? req.headers.accept : '';
            const isApi = pathname === '/api' || pathname.startsWith('/api/')
                || pathname === '/plugins' || pathname.startsWith('/plugins/')
                || pathname === '/hmr' || pathname.startsWith('/hmr/');
            const lastSlash = pathname.lastIndexOf('/');
            const lastSeg = lastSlash === -1 ? pathname : pathname.slice(lastSlash + 1);
            const looksLikeAsset = lastSeg.indexOf('.') !== -1;
            const looksLikePage = !isApi && (accept.indexOf('text/html') !== -1 || !looksLikeAsset);
            if (looksLikePage) {
                const next = pathname !== '/' && pathname !== '/index.html' ? '?next=' + encodeURIComponent(pathname) : '';
                redirect(res, '/auth/login' + next);
                return;
            }
        }
        sendJson(res, 401, { error: 'unauthorized' });
    }
    const gate = (req, res) => {
        handleGate(req, res).catch((err) => {
            console.error('[dsh-ui-auth] 网关处理异常: ' + (err instanceof Error ? (err.stack || err.message) : String(err)));
            if (res.headersSent) {
                try {
                    res.destroy();
                }
                catch (e) { /* ignore */ }
                return;
            }
            try {
                res.writeHead(500);
                res.end();
            }
            catch (e) {
                try {
                    res.destroy();
                }
                catch (x) { /* ignore */ }
            }
        });
    };
    function handleEventUpgrade(req, socket, who, pathname, head) {
        const key = req.headers !== undefined ? req.headers['sec-websocket-key'] : undefined;
        if (typeof key !== 'string' || key === '') {
            try {
                socket.destroy();
            }
            catch (e) { /* ignore */ }
            return;
        }
        try {
            socket.write('HTTP/1.1 101 Switching Protocols\r\n' +
                'Upgrade: websocket\r\n Connection: Upgrade\r\n' +
                'Sec-WebSocket-Accept: ' + wsAccept(key) + '\r\n\r\n');
        }
        catch (err) {
            try {
                socket.destroy();
            }
            catch (e) { /* ignore */ }
            return;
        }
        const apiProxy = ctx.get('apiProxy');
        const events = apiProxy !== undefined ? apiProxy.events : undefined;
        if (events === undefined) {
            try {
                socket.destroy();
            }
            catch (e) { /* ignore */ }
            return;
        }
        const isMux = pathname === '/api/events.mux';
        const controller = new AbortController();
        const signal = controller.signal;
        const reader = new WsFrameReader();
        const closeBoth = () => {
            try {
                controller.abort();
            }
            catch (e) { /* ignore */ }
            try {
                socket.end();
            }
            catch (e) { /* ignore */ }
        };
        const processIncoming = (bytes) => {
            reader.push(bytes);
            let frame;
            while ((frame = reader.read()) !== null) {
                if (frame.close) {
                    closeBoth();
                    return;
                }
                if (frame.ping !== undefined) {
                    try {
                        socket.write(encodeWsControl(0xa, frame.ping));
                    }
                    catch (e) { /* ignore */ }
                    continue;
                }
                try {
                    socket.write(encodeWsControl(0x8, new Uint8Array([0x03, 0xf0])));
                }
                catch (e) { /* ignore */ }
                closeBoth();
                return;
            }
        };
        socket.on('data', (chunk) => { try {
            processIncoming(new Uint8Array(chunk));
        }
        catch (e) { /* ignore */ } });
        socket.on('close', () => { try {
            controller.abort();
        }
        catch (e) { /* ignore */ } });
        socket.on('error', () => { try {
            controller.abort();
        }
        catch (e) { /* ignore */ } });
        if (head !== undefined && head.length > 0) {
            try {
                processIncoming(new Uint8Array(head));
            }
            catch (e) { /* ignore */ }
        }
        const pump = (async () => {
            try {
                const iterable = isMux
                    ? events.mux({ rpcId: randomUUID(), payload: {} }, signal)
                    : events.host({ rpcId: randomUUID(), payload: {} }, signal);
                for await (const envelope of iterable) {
                    if (socket.destroyed || socket.writableEnded)
                        break;
                    const text = JSON.stringify({
                        type: 'server-request',
                        rpcId: envelope.rpcId,
                        method: envelope.payload !== undefined && typeof envelope.payload === 'object' ? envelope.payload.type : undefined,
                        payload: envelope.payload,
                    });
                    await new Promise((resolve) => {
                        const chunk = encodeWsText(text);
                        try {
                            if (socket.write(chunk)) {
                                resolve(undefined);
                                return;
                            }
                            let settled = false;
                            const onDrain = () => { if (!settled) {
                                settled = true;
                                resolve(undefined);
                            } };
                            const onErr = () => { if (!settled) {
                                settled = true;
                                resolve(undefined);
                            } };
                            socket.once('drain', onDrain);
                            socket.once('error', onErr);
                            setTimeout(() => { socket.removeListener('drain', onDrain); socket.removeListener('error', onErr); resolve(undefined); }, 5000);
                        }
                        catch (e) {
                            resolve(undefined);
                        }
                    });
                }
            }
            catch (err) {
                if (!signal.aborted) {
                    try {
                        socket.write(encodeWsText(JSON.stringify({
                            type: 'server-request',
                            rpcId: randomUUID(),
                            method: 'stream/error',
                            payload: { type: 'stream/error', error: { code: 'internal', message: String(err instanceof Error ? err.message : err), details: {} } },
                        })));
                    }
                    catch (e) { /* ignore */ }
                }
            }
            finally {
                closeBoth();
            }
        })();
        void pump;
    }
    const gateUp = (req, socket, head) => {
        try {
            const pathname = pathnameOf(req.url);
            if (pathname === '/auth' || pathname.startsWith('/auth/') || !state.ready) {
                socket.destroy();
                return;
            }
            const token = readCookie(req, COOKIE_NAME);
            const who = resolveSession(token);
            if (who === undefined) {
                socket.destroy();
                return;
            }
            if (modern !== undefined) {
                modern.handleUpgrade(req, socket, head, (request, stream, bytes) => {
                    for (const fn of origUp)
                        fn.call(server, request, stream, bytes);
                });
                return;
            }
            if (pathname === '/api/events.mux' || pathname === '/api/events.host') {
                handleEventUpgrade(req, socket, who, pathname, head);
                return;
            }
            for (const fn of origUp)
                fn.call(server, req, socket, head);
        }
        catch (err) {
            try {
                socket.destroy();
            }
            catch (e) { /* ignore */ }
        }
    };
    server.on('request', gate);
    server.on('upgrade', gateUp);
    ctx.effect(() => () => {
        server.removeListener('request', gate);
        server.removeListener('upgrade', gateUp);
        for (const fn of origReq)
            server.on('request', fn);
        for (const fn of origUp)
            server.on('upgrade', fn);
    }, 'dsh-ui-auth: 还原网关监听器');
    // 会话与失败计数清理
    const sweep = () => {
        const now = Date.now();
        let changed = false;
        for (const [token, s] of state.sessions) {
            if (s.expiresAt <= now) {
                state.sessions.delete(token);
                changed = true;
            }
        }
        if (changed) {
            sessionsDirty = true;
            persistSessions();
        }
        for (const [ip, f] of state.fails) {
            if (f.until > 0 && f.until <= now)
                state.fails.delete(ip);
        }
    };
    const timer = setInterval(sweep, SESSION_SWEEP_MS);
    timer.unref?.();
    ctx.effect(() => () => clearInterval(timer), 'dsh-ui-auth: session cleanup timer');
}
