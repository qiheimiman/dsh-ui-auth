import { WebSocketServer, WebSocket } from 'ws';
import { createModernPolicy, remoteArgs, object, nonempty } from './modern-policy.js';
/**
 * DSH 0.1.2+ transport adapter: slash Remote (`/api/<ns>/<method>`), the
 * `/api/remote.mux` stream mux, and the native browser carrier.
 *
 * 精简版：移除多用户隔离、事件流过滤，仅保留登录验证和 DSH Token 授权。
 */
const MAX_BODY = 16 * 1024 * 1024;
const MAX_STREAMS = 64;
const MUX_PATH = '/api/remote.mux';
const json = (res, status, value) => {
    res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
    res.end(JSON.stringify(value));
};
const denial = () => new Error('Access denied');
async function bodyOf(req) {
    const chunks = [];
    let size = 0;
    for await (const chunk of req) {
        const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        size += buffer.length;
        if (size > MAX_BODY)
            throw new Error('Request too large');
        chunks.push(buffer);
    }
    const body = Buffer.concat(chunks);
    return { body, envelope: JSON.parse(body.toString('utf8')) };
}
/** Replay once, preserving IncomingMessage events used by downstream HTTP bridges. */
function replay(req, body) {
    const proxy = Object.create(req);
    proxy[Symbol.asyncIterator] =
        async function* () { if (body.length)
            yield body; };
    return proxy;
}
/** Delay success until ownership has persisted; never forward an unfiltered prefix. */
async function forwardJson(forward, req, res, transform) {
    const original = { writeHead: res.writeHead, write: res.write, end: res.end };
    let status = 200;
    let size = 0;
    const chunks = [];
    const headers = {};
    await new Promise((resolve, reject) => {
        const restore = () => { Object.assign(res, original); };
        const capture = (chunk) => {
            if (chunk === null || chunk === undefined)
                return;
            const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
            size += buffer.length;
            if (size > MAX_BODY)
                throw new Error('Response too large');
            chunks.push(buffer);
        };
        res.writeHead = ((code, reason, fields) => {
            status = code;
            Object.assign(headers, typeof reason === 'object' && reason !== null ? reason : fields);
            return res;
        });
        res.write = ((chunk, encoding, callback) => {
            try {
                capture(chunk);
            }
            catch (error) {
                restore();
                reject(error);
                return false;
            }
            if (typeof encoding === 'function')
                encoding();
            else
                callback?.();
            return true;
        });
        res.end = ((chunk, encoding, callback) => {
            void (async () => {
                try {
                    capture(chunk);
                    let body = Buffer.concat(chunks);
                    if (status >= 200 && status < 300) {
                        const envelope = JSON.parse(body.toString('utf8'));
                        if (envelope?.result?.ok === true)
                            envelope.result.value = await transform(envelope.result.value);
                        body = Buffer.from(JSON.stringify(envelope));
                    }
                    restore();
                    for (const header of ['content-length', 'Content-Length', 'content-encoding', 'Content-Encoding', 'transfer-encoding', 'Transfer-Encoding']) {
                        delete headers[header];
                        res.removeHeader?.(header);
                    }
                    res.writeHead(status, headers);
                    res.end(body);
                    if (typeof encoding === 'function')
                        encoding();
                    else
                        callback?.();
                    resolve();
                }
                catch (error) {
                    restore();
                    reject(error);
                }
            })();
            return res;
        });
        try {
            forward(req, res);
        }
        catch (error) {
            restore();
            reject(error);
        }
        res.once('close', () => { restore(); resolve(); });
    });
}
function errorMessage(error) {
    return error instanceof Error ? error.message : String(error);
}
export function createModernGateway(ctx, auth) {
    const policy = createModernPolicy(auth);
    const policies = new Map();
    const principalByRequest = new WeakMap();
    const downstreamSockets = new Set();
    const sockets = new WebSocketServer({ noServer: true, maxPayload: MAX_BODY });
    const principal = (req) => auth.principal(req);
    const publicApi = Object.freeze({
        ready: auth.ready,
        user: auth.user,
        principal: (req) => principalByRequest.get(req),
        ownerOfSession: auth.session,
        ownerOfWorkspace: auth.workspace,
        async claimSession(id, username) { await auth.ready; return auth.claimSession(id, username); },
        async claimWorkspace(id, username) { await auth.ready; return auth.claimWorkspace(id, username); },
        registerPolicy(id, rules) {
            if (!nonempty(id) || policies.has(id))
                throw new Error('Duplicate or invalid auth policy');
            policies.set(id, rules);
            return () => { policies.delete(id); };
        },
    });
    ctx.provide?.('uiAuth', publicApi);
    function extension(kind, target) {
        const matches = [...policies.values()].filter(rule => {
            const section = rule[kind];
            return section?.matches?.(target) === true;
        });
        if (matches.length > 1)
            throw new Error('Ambiguous authorization policy');
        return matches[0]?.[kind];
    }
    function prepare(req) {
        const who = principal(req);
        if (who === undefined)
            return { status: 401 };
        const connection = ctx.get('connection');
        if (connection === undefined)
            return { status: 503 };
        const host = req.headers.host;
        if (typeof host !== 'string')
            return { status: 403 };
        // Mint only an internal carrier cookie. The browser never receives it;
        // every outer request still needs a live dsh-ui-auth session.
        let cookie;
        try {
            const url = new URL(connection.authenticatedUrl(`http://${host}`));
            connection.authorizeIndex({ method: 'GET', url: url.pathname + url.search, headers: { host } }, {
                writeHead(_status, headers) { cookie = headers?.['set-cookie']?.split(';')[0]; }, end() { },
            });
        }
        catch {
            return { status: 403 };
        }
        if (cookie === undefined)
            return { status: 503 };
        // Ignore client-supplied native carrier cookies; use only this process's freshly issued one.
        const retained = (req.headers.cookie ?? '').split(';').filter(part => !part.trim().startsWith('dsh-auth-')).join(';');
        req.headers.cookie = `${retained}; ${cookie}`;
        const rejected = connection.requestRejection(req);
        if (rejected !== undefined)
            return { status: rejected };
        principalByRequest.set(req, who);
        return { who };
    }
    async function handleHttp(req, res, forward) {
        const admitted = prepare(req);
        if (admitted.status !== undefined) {
            json(res, admitted.status, { error: 'Access denied' });
            return true;
        }
        const who = admitted.who;
        const url = new URL(req.url, 'http://local');
        const pathname = url.pathname;
        const rule = extension('http', { pathname, method: req.method });
        if (rule !== undefined) {
            if (!(await rule.authorize(who, req)))
                json(res, 403, { error: 'Access denied' });
            else
                forward(req, res);
            return true;
        }
        if (!pathname.startsWith('/api/'))
            return false;
        if (req.method !== 'POST') {
            // Simplified: allow GET requests for admin-only paths (model settings etc)
            return false;
        }
        const endpoint = pathname.slice('/api/'.length);
        let decoded;
        try {
            decoded = await bodyOf(req);
        }
        catch {
            json(res, 400, { error: 'Invalid request' });
            return true;
        }
        const { envelope, body } = decoded;
        if (envelope?.type !== 'client-request' || envelope.method !== endpoint || !nonempty(envelope.rpcId)) {
            json(res, 400, { error: 'Invalid request' });
            return true;
        }
        let allowed;
        for (const rules of policies.values()) {
            const remote = rules.remote;
            if (remote?.matches(endpoint) === true && !(await remote.authorize(who, envelope.payload))) {
                json(res, 403, { error: 'Access denied' });
                return true;
            }
        }
        if (endpoint === '$events/result') {
            const args = remoteArgs(envelope.payload);
            allowed = object(args) && who !== undefined;
        }
        else {
            const rule = extension('rpc', endpoint);
            allowed = rule ? await rule.authorize(who, envelope.payload) : await policy.authorize(who, endpoint, envelope.payload);
        }
        if (!allowed) {
            json(res, 403, { error: 'Access denied' });
            return true;
        }
        req.headers['accept-encoding'] = 'identity';
        const request = replay(req, body);
        principalByRequest.set(request, who);
        try {
            await forwardJson(forward, request, res, async (value) => {
                const rule = endpoint === '$events/result' ? undefined : extension('rpc', endpoint);
                const projected = rule ? await rule.project(who, value) : await policy.result(who, endpoint, value);
                const current = principal(req);
                if (current?.role !== who.role || current.username !== who.username)
                    throw denial();
                return projected;
            });
        }
        catch (error) {
            for (const header of ['content-length', 'Content-Length', 'content-encoding', 'Content-Encoding', 'transfer-encoding', 'Transfer-Encoding']) {
                delete (res.getHeaders?.())[header];
                res.removeHeader?.(header);
            }
            console.error('[dsh-ui-auth] modern gateway projection failed: ' + errorMessage(error));
            if (!res.headersSent)
                json(res, 502, { error: 'Could not persist or project response' });
            else
                res.destroy();
        }
        return true;
    }
    function handleUpgrade(req, socket, head, forward) {
        const admitted = prepare(req);
        const reject = (status) => { socket.end(`HTTP/1.1 ${status} Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`); };
        if (admitted.status !== undefined) {
            reject(admitted.status);
            return;
        }
        const who = admitted.who;
        const pathname = new URL(req.url, 'http://local').pathname;
        if (pathname !== MUX_PATH) {
            const rule = extension('upgrade', { pathname });
            const pass = () => {
                downstreamSockets.add(socket);
                const timer = setInterval(() => {
                    const current = principal(req);
                    if (current?.username !== who.username || current.role !== who.role)
                        socket.destroy();
                }, 1000);
                timer.unref();
                socket.once('close', () => { clearInterval(timer); downstreamSockets.delete(socket); });
                forward(req, socket, head);
            };
            if (rule === undefined) {
                pass();
                return;
            }
            Promise.resolve(rule.authorize(who, req)).then(granted => {
                if (granted && principal(req) !== undefined)
                    pass();
                else
                    reject(403);
            }, () => reject(403));
            return;
        }
        const gateway = ctx.get('typertGateway');
        const wireStream = gateway?.wireStream;
        if (wireStream?.open === undefined) {
            reject(503);
            return;
        }
        sockets.handleUpgrade(req, socket, head, (ws) => {
            const active = new Map();
            const login = auth.loginKey(req);
            const initialRole = who.role;
            let writes = Promise.resolve();
            const alive = () => {
                const current = principal(req);
                return current?.username === who.username && current.role === initialRole && auth.loginKey(req) === login ? current : undefined;
            };
            const send = (value) => {
                writes = writes.then(() => new Promise((resolve, rejectSend) => {
                    if (alive() === undefined || ws.readyState !== WebSocket.OPEN) {
                        rejectSend(denial());
                        return;
                    }
                    const serialized = JSON.stringify(value);
                    if (Buffer.byteLength(serialized) > MAX_BODY || ws.bufferedAmount > MAX_BODY) {
                        ws.close(1009, 'Stream limit exceeded');
                        rejectSend(denial());
                        return;
                    }
                    ws.send(serialized, (error) => error ? rejectSend(error) : resolve());
                }));
                return writes;
            };
            const timer = setInterval(() => { if (alive() === undefined)
                ws.close(1008, 'Login expired'); }, 1000);
            timer.unref();
            ws.on('error', () => ws.terminate());
            ws.on('close', () => {
                clearInterval(timer);
                for (const work of active.values()) {
                    work.abort.abort();
                }
            });
            ws.on('message', (bytes, binary) => {
                let message;
                try {
                    message = JSON.parse(bytes.toString());
                }
                catch {
                    ws.close(1008, 'Invalid stream request');
                    return;
                }
                if (binary || alive() === undefined || !nonempty(message?.streamId)) {
                    ws.close(1008, 'Invalid stream request');
                    return;
                }
                if (message.type === 'cancel' && Object.keys(message).length === 2) {
                    active.get(message.streamId)?.abort.abort();
                    return;
                }
                if (message.type !== 'open' || Object.keys(message).length !== 4 || typeof message.endpoint !== 'string'
                    || active.has(message.streamId) || active.size >= MAX_STREAMS) {
                    ws.close(1008, 'Invalid stream request');
                    return;
                }
                const streamId = message.streamId;
                const endpoint = message.endpoint;
                const payload = message.payload;
                const work = { abort: new AbortController(), correlation: { login, events: new Set() } };
                active.set(streamId, work);
                void (async () => {
                    try {
                        const current = alive();
                        const rule = extension('stream', endpoint);
                        if (current === undefined || !(rule ? await rule.authorize(current, payload) : await policy.authorize(current, endpoint, payload, true)))
                            throw denial();
                        const source = await wireStream.open(endpoint, payload, work.abort.signal);
                        for await (const value of source) {
                            if (work.abort.signal.aborted)
                                break;
                            const watcher = alive();
                            if (watcher === undefined)
                                throw denial();
                            if (rule !== undefined && extension('stream', endpoint) !== rule)
                                throw denial();
                            if (!(rule ? await rule.authorize(watcher, payload) : await policy.authorize(watcher, endpoint, payload, true)))
                                throw denial();
                            const output = rule ? await rule.project(watcher, value) : policy.frame(watcher, endpoint, value, work.correlation);
                            if (output !== null)
                                await send({ type: 'item', streamId, value: output });
                        }
                        if (!work.abort.signal.aborted)
                            await send({ type: 'end', streamId });
                    }
                    catch {
                        if (!work.abort.signal.aborted) {
                            await send({ type: 'error', streamId, error: { code: 'auth/forbidden', message: 'Stream unavailable or access denied', details: {} } })
                                .catch(() => ws.close(1008));
                        }
                    }
                    finally {
                        active.delete(streamId);
                    }
                })();
            });
        });
    }
    ctx.effect(() => () => {
        for (const socket of sockets.clients)
            socket.terminate();
        for (const socket of downstreamSockets)
            socket.destroy();
        sockets.close();
        policies.clear();
    }, 'dsh-ui-auth: modern gateway');
    return { handleHttp, handleUpgrade, publicApi };
}
