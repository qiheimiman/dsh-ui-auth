/**
 * dsh-ui-auth 客户端源码（精简版：登录 + 修改密码设置面板 + 侧边栏退出登录按钮）
 *
 * 登录功能由 Host 半区的 /auth/login 页面处理（HTML 内联在 index.ts）。
 * 设置面板提供修改密码功能，侧边栏底部添加退出登录按钮。
 */

declare const require: (id: string) => any
declare const exports: Record<string, any>
declare const module: { exports: Record<string, any> }

interface PluginContext {
  get(name: string): any
}

exports.name = 'dsh-ui-auth'
exports.inject = ['slots']
exports.apply = function apply(ctx: PluginContext) {
  mountSettings(ctx, 0)
  mountSidebarLogout(ctx, 0)
}

// ============ 修改密码设置面板 ============
function mountSettings(ctx: PluginContext, attempt: number) {
  const slots = ctx.get('slots')
  if (slots === undefined) {
    if (attempt < 40) { setTimeout(function () { mountSettings(ctx, attempt + 1) }, 250); return }
    console.error('[dsh-ui-auth] slots 服务不可用：设置面板未能注册')
    return
  }
  slots.inject('settings.section', function () {
    return slots!.register(
      { name: 'settings.section', id: 'dsh-auth-password', order: 100, label: function () { return '修改密码' } },
      function () { return createChangePasswordPage() }
    )
  })
}

function createChangePasswordPage(): any {
  const React = require('react')

  function ChangePasswordPage() {
    const [newPassword, setNewPassword] = React.useState('')
    const [confirmPassword, setConfirmPassword] = React.useState('')
    const [error, setError] = React.useState('')
    const [success, setSuccess] = React.useState('')
    const [busy, setBusy] = React.useState(false)

    function validatePassword(pw: string): string | null {
      if (pw.length < 6) return '密码至少 6 位'
      return null
    }

    async function handleSubmit(e: Event) {
      e.preventDefault()
      setError('')
      setSuccess('')

      const pwErr = validatePassword(newPassword)
      if (pwErr !== null) { setError(pwErr); return }

      if (newPassword !== confirmPassword) { setError('两次输入的密码不一致'); return }

      setBusy(true)
      try {
        const res = await fetch('/auth/change-password', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ newPassword: newPassword })
        })
        const data = await res.json()
        if (res.ok && data.ok) {
          setSuccess('密码修改成功！')
          setNewPassword('')
          setConfirmPassword('')
        } else {
          setError(data.error || '修改失败')
        }
      } catch (err) {
        setError('网络错误，请重试')
      } finally {
        setBusy(false)
      }
    }

    return React.createElement('div', { className: 'dshua-change-pw' },
      React.createElement('h2', { style: { fontSize: '18px', fontWeight: 600, marginBottom: '24px', color: 'var(--dsw-alias-label-primary, #e6e6e6)' } }, '修改密码'),
      React.createElement('form', { onSubmit: handleSubmit, style: { display: 'flex', flexDirection: 'column', gap: '16px' } },
        React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: '8px' } },
          React.createElement('label', { style: { fontSize: '13px', color: 'var(--dsw-alias-label-secondary, #aab2c3)' } }, '新密码'),
          React.createElement('input', {
            type: 'password',
            value: newPassword,
            onChange: function(e: any) { setNewPassword(e.target.value) },
            placeholder: '至少 6 位',
            autoComplete: 'new-password',
            style: {
              padding: '10px 12px',
              borderRadius: '8px',
              border: '1px solid var(--dsw-alias-border-l2, #333a47)',
              background: 'var(--dsw-alias-bg-layer-1, #101318)',
              color: 'var(--dsw-alias-label-primary, #f0f0f0)',
              fontSize: '14px',
              outline: 'none',
              boxSizing: 'border-box',
            }
          })
        ),
        React.createElement('div', { style: { display: 'flex', flexDirection: 'column', gap: '8px' } },
          React.createElement('label', { style: { fontSize: '13px', color: 'var(--dsw-alias-label-secondary, #aab2c3)' } }, '确认密码'),
          React.createElement('input', {
            type: 'password',
            value: confirmPassword,
            onChange: function(e: any) { setConfirmPassword(e.target.value) },
            placeholder: '再次输入新密码',
            autoComplete: 'new-password',
            style: {
              padding: '10px 12px',
              borderRadius: '8px',
              border: '1px solid var(--dsw-alias-border-l2, #333a47)',
              background: 'var(--dsw-alias-bg-layer-1, #101318)',
              color: 'var(--dsw-alias-label-primary, #f0f0f0)',
              fontSize: '14px',
              outline: 'none',
              boxSizing: 'border-box',
            }
          })
        ),
        error ? React.createElement('div', {
          style: {
            padding: '10px 12px',
            borderRadius: '8px',
            fontSize: '13px',
            background: 'rgba(255, 107, 107, 0.15)',
            color: '#ff6b6b',
            border: '1px solid rgba(255, 107, 107, 0.3)',
          }
        }, error) : null,
        success ? React.createElement('div', {
          style: {
            padding: '10px 12px',
            borderRadius: '8px',
            fontSize: '13px',
            background: 'rgba(82, 197, 94, 0.15)',
            color: '#52c55e',
            border: '1px solid rgba(82, 197, 94, 0.3)',
          }
        }, success) : null,
        React.createElement('button', {
          type: 'submit',
          disabled: busy,
          style: {
            padding: '11px',
            border: 'none',
            borderRadius: '8px',
            background: 'var(--dsw-alias-button-primary-fill, #4f7cff)',
            color: 'var(--dsw-alias-label-primary-foreground, #fff)',
            fontSize: '14px',
            fontWeight: 600,
            cursor: busy ? 'not-allowed' : 'pointer',
            opacity: busy ? 0.6 : 1,
            marginTop: '8px',
          }
        }, busy ? '提交中...' : '修改密码')
      )
    )
  }

  return React.createElement(ChangePasswordPage)
}

// ============ 侧边栏退出登录按钮 ============
function mountSidebarLogout(ctx: PluginContext, attempt: number) {
  if (typeof document === 'undefined') return

  function tryInject() {
    // 查找设置区域（settingsArea 或包含 settings 的元素），在其下方插入退出登录按钮
    var settingsArea = document.querySelector('[class*="settingsArea"], [class*="settings"]')

    if (!settingsArea) {
      if (attempt < 20) { setTimeout(function() { tryInject() }, 500); return }
      console.warn('[dsh-ui-auth] 未找到设置区域')
      return
    }

    // 找到 footArea（设置区域的父元素）
    var footArea = settingsArea.closest('[class*="footArea"], [class*="footer"]')
    if (!footArea) {
      console.warn('[dsh-ui-auth] 未找到 footArea')
      return
    }

    if (document.getElementById('dshua-logout-btn')) return

    // 找到设置按钮，克隆其结构和样式
    var settingsBtn = document.querySelector('[class*="OUW6dW_trigger"]') as HTMLElement
    if (!settingsBtn) {
      if (attempt < 20) { setTimeout(function() { tryInject() }, 500); return }
      console.warn('[dsh-ui-auth] 未找到设置按钮')
      return
    }

    // 克隆设置按钮
    var btn = settingsBtn.cloneNode(true) as HTMLElement
    btn.id = 'dshua-logout-btn'
    btn.setAttribute('aria-label', '退出登录')

    // 修改文字
    var labelSpan = btn.querySelector('span')
    if (labelSpan) {
      labelSpan.textContent = '退出'
    }

    // 替换图标为退出图标（找到 div[data-slot] 内的 svg）
    var slotDiv = btn.querySelector('div[data-slot]')
    if (slotDiv) {
      var svg = slotDiv.querySelector('svg')
      if (svg) {
        svg.outerHTML = '<svg width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M10 13H12.6667C13.0203 13 13.3595 12.8595 13.6095 12.6095C13.8595 12.3594 14 12.0203 14 11.6667V4.33333C14 3.97971 13.8595 3.64057 13.6095 3.39052C13.3595 3.14048 13.0203 3 12.6667 3H10M6.66667 11.3333L3.33333 8M3.33333 8L6.66667 4.66667M3.33333 8H10.6667" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>'
      }
    }

    btn.addEventListener('click', async function() {
      if (!confirm('确定要退出登录吗？')) return
      try {
        await fetch('/auth/logout', { method: 'POST' })
        window.location.href = '/auth/login'
      } catch (e) {
        window.location.href = '/auth/login'
      }
    })

    // 在 settingsArea 之后插入按钮
    settingsArea.parentNode!.insertBefore(btn, settingsArea.nextSibling)
    console.log('[dsh-ui-auth] 退出按钮已注入到设置按钮下方')
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', tryInject)
  } else {
    tryInject()
  }
}
