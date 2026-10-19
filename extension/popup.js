// SentinelVault Auto-fill — popup logic.

const $ = (id) => document.getElementById(id)

let state = { apiBase: 'http://localhost:8000', token: '', user: null }

async function api(path, options = {}) {
  const res = await fetch(`${state.apiBase}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(state.token ? { Authorization: `Bearer ${state.token}` } : {}),
      ...(options.headers || {}),
    },
  })
  let data = null
  try {
    data = await res.json()
  } catch {
    /* no body */
  }
  if (!res.ok) throw new Error((data && data.detail) || `HTTP ${res.status}`)
  return data
}

async function save() {
  await chrome.storage.local.set(state)
}

async function restore() {
  const stored = await chrome.storage.local.get(['apiBase', 'token', 'user'])
  state = { ...state, ...stored }
  $('api').value = state.apiBase || 'http://localhost:8000'
  if (state.token) showVault()
}

function showVault() {
  $('login').style.display = 'none'
  $('vault').style.display = 'block'
  $('who').textContent = state.user ? `${state.user.display_name || state.user.email}` : 'unlocked'
  loadItems()
}

async function loadItems() {
  $('msg').textContent = ''
  $('err').textContent = ''
  try {
    const data = await api('/api/vault/items')
    const items = data.items || []
    const list = $('items')
    list.innerHTML = ''
    if (!items.length) {
      list.innerHTML = '<li class="muted">Vault is empty — add items in the SentinelVault dashboard.</li>'
      return
    }
    for (const item of items) {
      const li = document.createElement('li')
      li.innerHTML = `<b></b><div class="sub"></div>`
      li.querySelector('b').textContent = item.title
      li.querySelector('.sub').textContent = [item.username, item.url].filter(Boolean).join(' · ') || item.category
      const row = document.createElement('div')
      row.className = 'row'
      const fill = document.createElement('button')
      fill.textContent = 'Fill'
      fill.onclick = () => fillItem(item)
      const copy = document.createElement('button')
      copy.className = 'ghost'
      copy.textContent = 'Copy pw'
      copy.onclick = () => copyPassword(item)
      row.append(fill, copy)
      li.appendChild(row)
      list.appendChild(li)
    }
  } catch (e) {
    $('err').textContent = e.message
  }
}

async function fillItem(item) {
  try {
    const full = await api(`/api/vault/items/${item.id}`)
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true })
    if (!tab || !tab.id) throw new Error('No active tab')
    const res = await chrome.tabs.sendMessage(tab.id, {
      type: 'SV_FILL',
      item: {
        username: full.item.username || full.item.email || '',
        password: full.item.password || '',
      },
    })
    if (res && res.ok && (res.filledPassword || res.filledUser)) {
      $('msg').textContent = '✔ Filled on the current page'
    } else {
      $('msg').textContent = 'Could not find login fields on this page'
    }
  } catch (e) {
    $('msg').textContent = ''
    $('err').textContent = e.message
  }
}

async function copyPassword(item) {
  try {
    const full = await api(`/api/vault/items/${item.id}`)
    await navigator.clipboard.writeText(full.item.password || '')
    $('msg').textContent = '📋 Password copied'
  } catch (e) {
    $('err').textContent = e.message
  }
}

$('btnLogin').onclick = async () => {
  $('err').textContent = ''
  state.apiBase = ($('api').value || '').replace(/\/+$/, '') || 'http://localhost:8000'
  try {
    const data = await api('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email: $('email').value, password: $('password').value }),
    })
    state.token = data.token
    state.user = data.user
    $('password').value = ''
    await save()
    showVault()
  } catch (e) {
    $('err').textContent = e.message
  }
}

$('btnLock').onclick = async () => {
  try {
    await api('/api/auth/lock', { method: 'POST' })
  } catch {
    /* ignore */
  }
  state.token = ''
  state.user = null
  await save()
  $('vault').style.display = 'none'
  $('login').style.display = 'block'
}

$('btnReload').onclick = loadItems

restore()
