// =====================================================================
// Mailvelope (OpenPGP 浏览器扩展) 集成工具
// ---------------------------------------------------------------------
// CloudMail 不内建 OpenPGP 实现，读写加密邮件依赖浏览器外接插件
// Mailvelope（唯一支持任意自建 webmail 的扩展）。本工具封装：
//   1. 扩展可用性检测（window.mailvelope / 'mailvelope' 事件）
//   2. keyring 按邮箱账户获取/创建（identifier = 邮箱地址）
//   3. PGP ASCII-armor 提取（容忍 HTML 与 "> " 引用前缀）
//   4. 站点授权、安装引导辅助
// 扩展注入的 API 见 https://mailvelope.github.io/mailvelope
// =====================================================================

export const MAILVELOPE_STORES = {
  chrome: {
    name: 'Chrome Web Store',
    url: 'https://chrome.google.com/webstore/detail/mailvelope/kajibbejlbohfaggdiogboambcijhkke',
  },
  firefox: {
    name: 'Firefox Add-ons',
    url: 'https://addons.mozilla.org/firefox/addon/mailvelope/',
  },
}

// 判断扩展是否已注入（同步快查，用于低开销预判）
export function isMailvelope() {
  return typeof window !== 'undefined' && !!window.mailvelope
}

// 等待扩展注入的 window.mailvelope（页面脚本可能在扩展之前执行）。
// 超时返回 null：调用方按「未安装 / 未对本站点启用」引导用户。
export function waitMailvelope(timeout = 1500) {
  if (isMailvelope()) return Promise.resolve(window.mailvelope)
  if (!timeout) return Promise.resolve(null)
  return new Promise((resolve) => {
    let done = false
    const cleanup = () => {
      window.removeEventListener('mailvelope', onEvent)
      clearTimeout(timer)
    }
    const onEvent = () => {
      if (done) return
      done = true
      cleanup()
      resolve(window.mailvelope || null)
    }
    const timer = setTimeout(() => {
      if (done) return
      done = true
      cleanup()
      resolve(window.mailvelope || null)
    }, timeout)
    window.addEventListener('mailvelope', onEvent, { once: true })
  })
}

// 授权 Mailvelope 访问本站点（Mailvelope 官方授权流程，与官方 api-test 一致）
export function openMailvelopeAuthorize() {
  if (typeof document === 'undefined') return
  if (document.getElementById('mailvelope-authorize-frame')) return
  const frame = document.createElement('iframe')
  frame.id = 'mailvelope-authorize-frame'
  frame.style.display = 'none'
  frame.src = 'https://api.mailvelope.com/authorize-domain/?api=true'
  document.body.appendChild(frame)
}

// 获取（或按需创建）某邮箱账户的 keyring
export async function getOrCreateKeyring(mvel, identifier) {
  if (!mvel) throw new Error('MAILVELOPE_NOT_FOUND')
  const id = String(identifier || '').trim().toLowerCase()
  if (!id) throw new Error('EMPTY_KEYRING_IDENTIFIER')
  try {
    return await mvel.getKeyring(id)
  } catch (e) {
    if (e && (e.code === 'NO_KEYRING_FOR_ID' || /NO_KEYRING_FOR_ID/.test(String(e.message || '')))) {
      return await mvel.createKeyring(id)
    }
    throw e
  }
}

// 通过 keyring 打开 Mailvelope 密钥管理页
export async function openKeyringSettings(mvel, identifier) {
  const keyring = await getOrCreateKeyring(mvel, identifier)
  return keyring.openSettings()
}

// ---------- ASCII-armor 提取 ----------
const ARMOR_KIND = {
  'MESSAGE': 'message',
  'SIGNED MESSAGE': 'signed-message',
  'SIGNATURE': 'signature',
  'PUBLIC KEY BLOCK': 'pubkey',
  'PRIVATE KEY BLOCK': 'seckey',
}
const MAX_ARMOR_LINES = 50000

function unquote(line) {
  // 兼容 "> " / ">> " 引用前缀与 HTML 实体 &gt;（浏览器渲染前的源码形式）
  return line.replace(/^(?:&gt;|>)+ ?/, '')
}

// 单行 -> 候选 armor 行：剥掉引用前缀与行内 HTML 标签（<br>/<div> 等分行形式）
function armorClean(raw) {
  return unquote(String(raw).replace(/<[^>]*>/g, '')).trim()
}

export function armorKindOfLabel(label) {
  const key = String(label || '').trim().toUpperCase()
  return ARMOR_KIND[key] || null
}

// 从任意文本（邮件 HTML / 纯文本）中提取第一段完整 PGP armor 块。
// 容忍：行首 "> " 引用前缀；HTML 中 <pre>/<br> 之外的行间无标签的连续密文。
// 返回 { kind, armored }；找不到返回 null。
export function extractArmor(input) {
  if (!input) return null
  const lines = String(input).replace(/\r\n?/g, '\n').split('\n')
  const beginRe = /^-----BEGIN PGP (MESSAGE|SIGNED MESSAGE|SIGNATURE|PUBLIC KEY BLOCK|PRIVATE KEY BLOCK)-----\s*$/i
  const endRe = /^-----END PGP (MESSAGE|SIGNED MESSAGE|SIGNATURE|PUBLIC KEY BLOCK|PRIVATE KEY BLOCK)-----\s*$/i
  let start = -1
  for (let i = 0; i < lines.length && i < MAX_ARMOR_LINES; i++) {
    if (beginRe.test(armorClean(lines[i]))) { start = i; break }
  }
  if (start < 0) return null
  const beginClean = armorClean(lines[start])
  const m = beginClean.match(/^-----BEGIN PGP (.+)-----$/i)
  const kind = m ? armorKindOfLabel(m[1]) : null
  if (!kind) return null
  const body = [beginClean]
  let closed = false
  for (let i = start + 1; i < lines.length && i < MAX_ARMOR_LINES; i++) {
    const raw = lines[i]
    const clean = armorClean(raw)
    // 纯标签行（如 <br>/<div></div>）跳过；空行是 armor 头与正文的分隔，必须保留
    if (!clean && /<[^>]*>/.test(raw)) continue
    if (endRe.test(clean)) { closed = true; body.push(clean); break }
    body.push(clean)
  }
  if (!closed) return null
  while (body.length && !body[body.length - 1]) body.pop()
  // 至少 begin + 内容 + end 三段
  if (body.length < 3) return null
  return { kind, armored: body.join('\n') }
}

// armor 文本 -> HTML <pre>（用于写信时把密文放进正文 / 纯文本双份发出）
export function armorToHtml(armored, escapeHtml) {
  const esc = typeof escapeHtml === 'function' ? escapeHtml : (s) => s
  return `<pre style="font-family:Consolas,Menlo,Monaco,'Courier New',monospace;font-size:12px;line-height:1.45;white-space:pre-wrap;word-break:break-all;margin:0">${esc(armored)}</pre>`
}

// HTML -> 纯文本（切换 Mailvelope 编辑器时把 TinyMCE 内容带过去）
export function htmlToPlain(html) {
  if (!html) return ''
  let text = String(html).replace(/<br\s*\/?>|<\/p>|<\/div>|<\/li>|<\/tr>|<\/h[1-6]>|<\/blockquote>/gi, '\n')
  text = text.replace(/<[^>]*>/g, '')
  if (!text.trim() && typeof DOMParser !== 'undefined') {
    const doc = new DOMParser().parseFromString(String(html), 'text/html')
    text = doc.body ? doc.body.textContent || '' : ''
  }
  return text.replace(/\u00a0/g, ' ').replace(/\n{3,}/g, '\n\n').trim()
}

// 附件是否为 PGP 密文载体（.asc / .gpg / application/pgp-encrypted）
export function isPgpAttachment(att) {
  if (!att) return false
  const name = String(att.filename || '')
  if (/\.(asc|gpg|pgp)$/i.test(name)) return true
  const type = String(att.contentType || att.type || '')
  return /pgp|openpgp/i.test(type) || /^(?:encrypted|message)\.asc$/i.test(name)
}

// Mailvelope 常见错误码 -> 前端提示 key（读信/写信共用）
export function pgpErrorHint(code) {
  const map = {
    MAILVELOPE_NOT_FOUND: 'pgpErrExt',
    EMPTY_KEYRING_IDENTIFIER: 'pgpErrAccount',
    NO_KEYRING_FOR_ID: 'pgpErrKeyring',
    KEYRING_ALREADY_EXISTS: 'pgpErrKeyring',
    NO_KEY_FOR_ADDRESS: 'pgpErrNoKey',
    NO_KEY_FOUND: 'pgpErrNoKey',
    DECRYPT_ERROR: 'pgpErrDecrypt',
    ARMOR_PARSE_ERROR: 'pgpErrParse',
    PWD_DIALOG_CANCEL: 'pgpErrCancel',
    NOT_AUTHORIZED: 'pgpErrAuthorize',
    WRONG_ARMORED_TYPE: 'pgpErrType',
    INVALID_OPTIONS: 'pgpErrOpts',
  }
  const key = code ? map[String(code).toUpperCase()] : null
  return key || 'pgpErrGeneric'
}
