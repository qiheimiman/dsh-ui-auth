// Smoke test: load lib/client.js through a mock of the client module loader,
// then run apply() against mock ctxs to verify:
//   - the settings.section「修改密码」registration path
const fs = require('fs')
const path = require('path')

const registrations = []
const mockReact = {
  createElement: (type, props, ...children) => ({ type, props: props || {}, children }),
  useState: (init) => [typeof init === 'function' ? init() : init, () => {}],
  useEffect: () => {},
}

const window = {
  __ModuleLoader__: {
    load(reg) { registrations.push(reg) },
  },
}

const code = fs.readFileSync(path.join(__dirname, '..', 'lib', 'client.js'), 'utf8')
new Function('window', code)(window)

if (registrations.length !== 1) {
  console.error('FAIL: expected exactly 1 __ModuleLoader__.load registration, got', registrations.length)
  process.exit(1)
}
const reg = registrations[0]
console.log('registration id:', reg.id)

const seed = new Map(Object.entries({ 'react': mockReact }))
const exp = reg.factory((spec) => {
  if (seed.has(spec)) return seed.get(spec)
  throw new Error('require("' + spec + '") missed the module table')
})

if (exp.name !== 'dsh-ui-auth' || typeof exp.apply !== 'function') {
  console.error('FAIL: bundle did not export the cordis plugin face')
  process.exit(1)
}

let failures = 0
function check(label, cond, extra) {
  if (cond) { console.log('PASS ' + label) } else { failures++; console.error('FAIL ' + label + (extra !== undefined ? ' :: ' + extra : '')) }
}

// ---- scenario helpers ----
function makeCtx() {
  const recorded = []
  const slots = {
    inject(key, cb) { cb() },
    register(opts, render) { recorded.push({ opts, render }) },
  }
  return {
    ctx: { get: (n) => (n === 'slots' ? slots : undefined) },
    recorded,
  }
}

const tick = () => new Promise((r) => setTimeout(r, 20))

// ---- 1) Module loads and exports correct interface ----
;(async () => {
  const s1 = makeCtx()
  exp.apply(s1.ctx)
  await tick()

  // Settings panel registered with id 'dsh-auth-password'
  check('settings: 修改密码 panel registered', s1.recorded.some((r) => r.opts.id === 'dsh-auth-password'))
  check('settings: panel label is 修改密码', s1.recorded.some((r) => r.opts.id === 'dsh-auth-password' && r.opts.label() === '修改密码'))

  // Verify the render function returns a React element with ChangePassword form
  const pwPanel = s1.recorded.find((r) => r.opts.id === 'dsh-auth-password')
  if (pwPanel) {
    const rendered = pwPanel.render()
    check('settings: panel renders a React element', rendered && rendered.type)
    check('settings: panel has password form elements', code.includes('newPassword') && code.includes('confirmPassword'))
    check('settings: panel has validation', code.includes('validatePassword'))
    check('settings: panel calls change-password API', code.includes('/auth/change-password'))
  }

  console.log(failures === 0 ? '\nCLIENT BUNDLE SMOKE TEST PASSED' : `\n${failures} FAILURES`)
  process.exit(failures === 0 ? 0 : 1)
})()
