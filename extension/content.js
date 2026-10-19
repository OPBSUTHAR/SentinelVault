// SentinelVault Auto-fill — content script.
// Fills username/email + password fields on the active page after the
// popup fetches the decrypted item from the user's own SentinelVault API.

function findVisible(selector) {
  return Array.from(document.querySelectorAll(selector)).find((el) => {
    const r = el.getBoundingClientRect()
    return r.width > 0 && r.height > 0 && !el.disabled && !el.readOnly
  })
}

function setValue(el, value) {
  if (!el) return false
  const proto = Object.getPrototypeOf(el)
  const desc = Object.getOwnPropertyDescriptor(proto, 'value')
  if (desc && desc.set) desc.set.call(el, value)
  else el.value = value
  el.dispatchEvent(new Event('input', { bubbles: true }))
  el.dispatchEvent(new Event('change', { bubbles: true }))
  return true
}

function fillForm({ username, password }) {
  const pwField =
    findVisible('input[type="password"]') ||
    findVisible('input[autocomplete="current-password"]') ||
    findVisible('input[name*="pass" i]')

  const userField =
    findVisible('input[autocomplete="username"]') ||
    findVisible('input[type="email"]') ||
    findVisible('input[name*="user" i]') ||
    findVisible('input[name*="email" i]') ||
    findVisible('input[name*="login" i]') ||
    findVisible('input[type="text"]')

  const okUser = username ? setValue(userField, username) : false
  const okPw = password ? setValue(pwField, password) : false
  return { filledUser: okUser, filledPassword: okPw }
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg && msg.type === 'SV_FILL') {
    try {
      sendResponse({ ok: true, ...fillForm(msg.item || {}) })
    } catch (e) {
      sendResponse({ ok: false, error: String(e) })
    }
    return true
  }
  if (msg && msg.type === 'SV_PING') {
    sendResponse({ ok: true, url: location.href })
    return true
  }
})
