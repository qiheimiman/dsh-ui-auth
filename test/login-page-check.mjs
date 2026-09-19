// Login-page check: boots the deployed lib/index.js against
// mock cordis services, then asserts the rendered login page
// and basic authentication flow work correctly.
import { EventEmitter } from 'node:events'
import vm from 'node:vm'
import { apply } from '../lib/index.js'

let failures = 0
function check(label, cond, extra) {
  if (cond) { console.log('PASS ' + label) } else { failures++; console.error('FAIL ' + label + (extra !== undefined ? ' :: ' + extra : '')) }
}

// ---- fake http server + mock services ----
const server = new EventEmitter()
server.on('request', () => {})

const records = new Map()
const creds = {
  async listRecords() { return [...records.keys()].map((key) => ({ key, kind: records.get(key).kind })) },
  async readRecord(key) { return records.get(key) },
  async modifyRecord(key, mutate) {
    const current = records.get(key)
    const next = await mutate(current)
    if (next === undefined) return current
    records.set(key, next)
    return next
  },
  async deleteRecord(key) { records.delete(key) },
}
const fsFiles = new Map()
const fsMock = {
  async resolve(p) { return { path: p } },
  async writeText(target, content) { fsFiles.set(target.path, content) },
  async readText(target) { const v = fsFiles.get(target.path); if (v === undefined) throw Object.assign(new Error('not found'), { code: 'FS_NOT_FOUND' }); return v },
  async unlink(target) { fsFiles.delete(target.path) },
}
const ctx = {
  get(name) {
    if (name === 'credentials') return creds
    if (name === 'fs') return fsMock
    if (name === 'webServer') return { server }
    return undefined
  },
  effect() {},
  interval() { return () => {} },
}

function makeReq(method, url, body, host, cookie) {
  const req = new EventEmitter()
  req.method = method
  req.url = url
  req.headers = { host: host ?? 'localhost:3080' }
  if (cookie !== undefined && cookie !== '') req.headers.cookie = 'dsh_auth=' + cookie
  req.socket = { remoteAddress: '127.0.0.1' }
  req.destroy = () => {}
  const chunks = body !== undefined ? [Buffer.from(body)] : []
  req[Symbol.asyncIterator] = () => {
    let i = 0
    return { next: () => Promise.resolve(i < chunks.length ? { value: chunks[i++], done: false } : { value: undefined, done: true }) }
  }
  if (body !== undefined) process.nextTick(() => { req.emit('data', Buffer.from(body)); req.emit('end') })
  return req
}
function makeRes() {
  const res = { headersSent: false, status: 0, headers: {}, body: '' }
  res.writeHead = (s, h) => { res.status = s; Object.assign(res.headers, h || {}); res.headersSent = true }
  res.setHeader = (k, v) => { res.headers[k] = v }
  res.write = (b) => { res.body += (b === undefined ? '' : String(b)); return true }
  res.end = (b) => { if (b !== undefined) res.body += String(b); res.ended = true }
  res.destroy = () => {}
  return res
}
const settle = (ms = 0) => ms > 0 ? new Promise((r) => setTimeout(r, ms)) : new Promise((r) => setImmediate(r))
async function call(method, url, body, host, waitMs = 0, cookie) {
  const res = makeRes()
  server.emit('request', makeReq(method, url, body, host, cookie), res)
  await settle(waitMs)
  return res
}
const json = (res) => { try { return JSON.parse(res.body) } catch (e) { return {} } }

apply(ctx)
await new Promise((r) => setTimeout(r, 300))

// ---- 1) login page renders ----
const page = await call('GET', '/auth/login', undefined, 'localhost:3080')
check('GET /auth/login (localhost) → 200 html', page.status === 200 && (page.headers['content-type'] || '').includes('text/html'), `status=${page.status}`)
check('登录页有用户名输入框', page.body.includes('id="u"') && page.body.includes('name="username"'))
check('登录页有密码输入框', page.body.includes('id="p"') && page.body.includes('name="password"'))
check('登录页有提交按钮', page.body.includes('type="submit"'))

// ---- 2) inline script parses ----
const inline = /<script>([\s\S]*?)<\/script><\/body>/.exec(page.body)
check('登录页存在内联脚本', inline !== null)
if (inline !== null) {
  let parsed = true
  let detail = ''
  try { new vm.Script(inline[1], { filename: 'login-inline.js' }) } catch (e) { parsed = false; detail = String(e && e.message) }
  check('登录页内联脚本可解析（括号/语法正确）', parsed, detail)
}

// ---- 3) get bootstrap admin password and login ----
const bootstrap = fsFiles.get('dsh-ui-auth-bootstrap.txt') ?? ''
const adminPassword = (/密码:\s+(\S+)/.exec(bootstrap) ?? [])[1]
check('引导页用例：已取得一次性管理员口令', typeof adminPassword === 'string' && adminPassword !== '')

const login = await call('POST', '/auth/login', JSON.stringify({ username: 'admin', password: adminPassword }), 'localhost:3080')
const cookieMatch = /dsh_auth=([^;]+)/.exec(login.headers['set-cookie'] ?? '')
const adminCookie = cookieMatch === null ? '' : cookieMatch[1]
check('管理员登录成功', login.status === 200 && adminCookie !== '', `status=${login.status}`)
if (adminCookie !== '') {
  const body = json(login)
  check('登录成功返回 ok:true', body.ok === true)
  check('登录成功返回 redirect', typeof body.redirect === 'string')
}

// ---- 4) auth/status endpoint ----
const status = await call('GET', '/auth/status', undefined, 'localhost:3080', 0, adminCookie)
check('已登录用户 /auth/status 返回 authenticated:true', status.status === 200 && json(status).authenticated === true)

const statusNoCookie = await call('GET', '/auth/status', undefined, 'localhost:3080')
check('未登录用户 /auth/status 返回 authenticated:false', statusNoCookie.status === 200 && json(statusNoCookie).authenticated === false)

// ---- 5) change password ----
const newPassword = 'NewPass!234'
const changePw = await call('POST', '/auth/change-password', JSON.stringify({ newPassword }), 'localhost:3080', 0, adminCookie)
check('修改密码成功', changePw.status === 200 && json(changePw).ok === true)

// 用新密码登录验证
const loginNew = await call('POST', '/auth/login', JSON.stringify({ username: 'admin', password: newPassword }), 'localhost:3080')
const cookieMatchNew = /dsh_auth=([^;]+)/.exec(loginNew.headers['set-cookie'] ?? '')
const newCookie = cookieMatchNew === null ? '' : cookieMatchNew[1]
check('新密码登录成功', loginNew.status === 200 && newCookie !== '', `status=${loginNew.status}`)

// 用旧密码登录应该失败
const loginOld = await call('POST', '/auth/login', JSON.stringify({ username: 'admin', password: adminPassword }), 'localhost:3080')
check('旧密码登录失败', loginOld.status === 401)

// 弱密码应该被拒绝
const weakPw = await call('POST', '/auth/change-password', JSON.stringify({ newPassword: 'weak' }), 'localhost:3080', 0, newCookie)
check('弱密码被拒绝', weakPw.status === 400)

// 未登录修改密码应该失败
const changeNoLogin = await call('POST', '/auth/change-password', JSON.stringify({ newPassword: 'Test!2345678' }), 'localhost:3080')
check('未登录修改密码失败', changeNoLogin.status === 401)

// ---- 6) logout ----
const logout = await call('POST', '/auth/logout', undefined, 'localhost:3080', 0, newCookie)
check('登出成功', logout.status === 200 && json(logout).ok === true)
check('登出后 Cookie 被清除', (logout.headers['set-cookie'] || '').includes('dsh_auth=;'))

// ---- 7) login with wrong password ----
const wrongLogin = await call('POST', '/auth/login', JSON.stringify({ username: 'admin', password: 'wrongpassword' }), 'localhost:3080')
check('错误密码登录失败', wrongLogin.status === 401)

// ---- 8) redirect for unauthenticated page requests ----
const redirectPage = await call('GET', '/api/session.list', undefined, 'localhost:3080')
check('未登录访问 API 返回 401', redirectPage.status === 401)

console.log(failures === 0 ? '\nLOGIN PAGE CHECK PASSED' : `\n${failures} CHECK(S) FAILED`)
process.exit(failures === 0 ? 0 : 1)
