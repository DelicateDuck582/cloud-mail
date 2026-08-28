// CloudMail Reader — 页面脚本
// 安全说明：
//  - 本页面不接触 JWT token（token 只在 background.js 持有）。
//  - 邮件正文用 sandbox iframe（无 allow-scripts）渲染，脚本不会执行。
//  - 附件用后端签名的 att.url 直接下载（host permission 已声明，绕过 CORS，签名 15 分钟有效）。

const $ = (id) => document.getElementById(id);

let state = {
  accounts: [],
  currentAccountId: 0,
  list: [],
  lastEmailId: 0,
  hasMore: true,
  loading: false,
  token: null,
};

function showView(name) {
  $('login-view').classList.toggle('hidden', name !== 'login');
  $('main-view').classList.toggle('hidden', name !== 'main');
}

function setStatus(text) {
  $('status-text').textContent = text || '';
}

function esc(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function fmtTime(iso) {
  if (!iso) return '';
  const d = new Date(iso.includes('T') ? iso : iso.replace(' ', 'T') + 'Z');
  if (isNaN(d.getTime())) return iso;
  return d.toLocaleString();
}

function fmtSize(bytes) {
  if (!bytes && bytes !== 0) return '';
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

// ---------- 登录 ----------
async function init() {
  const r = await browser.runtime.sendMessage({ type: 'checkAuth' });
  if (r.ok) {
    await enterMain();
  } else {
    showView('login');
  }
}

$('login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = $('login-email').value.trim();
  const password = $('login-password').value;
  $('login-error').classList.add('hidden');
  $('login-btn').disabled = true;
  $('login-btn').textContent = '登录中…';
  const r = await browser.runtime.sendMessage({ type: 'login', email, password });
  $('login-btn').disabled = false;
  $('login-btn').textContent = '登录';
  if (r.ok) {
    await enterMain();
  } else {
    $('login-error').textContent = r.message || '登录失败';
    $('login-error').classList.remove('hidden');
  }
});

$('logout-btn').addEventListener('click', async () => {
  await browser.runtime.sendMessage({ type: 'logout' });
  state = { accounts: [], currentAccountId: 0, list: [], lastEmailId: 0, hasMore: true, loading: false, token: null };
  $('email-list').innerHTML = '';
  showView('login');
});

// ---------- 主界面 ----------
async function enterMain() {
  showView('main');
  await loadAccounts();
  await loadList(true);
}

async function loadAccounts() {
  const r = await browser.runtime.sendMessage({ type: 'accounts' });
  if (!r.ok) {
    if (r.authExpired) return handleAuthExpired();
    return setStatus(r.message || '获取账户失败');
  }
  state.accounts = r.data || [];
  const sel = $('account-select');
  sel.innerHTML = '';
  state.accounts.forEach((a) => {
    const opt = document.createElement('option');
    opt.value = a.accountId;
    opt.textContent = a.name && a.name !== a.email ? a.name + ' <' + a.email + '>' : a.email;
    sel.appendChild(opt);
  });
  if (sel.options.length) {
    state.currentAccountId = Number(sel.value);
  }
}

$('account-select').addEventListener('change', (e) => {
  state.currentAccountId = Number(e.target.value);
  loadList(true);
});

$('refresh-btn').addEventListener('click', () => loadList(true));

async function loadList(reset) {
  if (state.loading) return;
  state.loading = true;
  setStatus(reset ? '加载中…' : '加载更多…');
  if (reset) {
    state.list = [];
    state.lastEmailId = 0;
    state.hasMore = true;
  }
  const r = await browser.runtime.sendMessage({
    type: 'list',
    accountId: state.currentAccountId,
    emailId: state.lastEmailId,
    size: 30,
    mailType: 'receive',
  });
  state.loading = false;
  if (!r.ok) {
    if (r.authExpired) return handleAuthExpired();
    setStatus(r.message || '加载失败');
    return;
  }
  const data = r.data || {};
  const items = data.list || [];
  items.forEach((it) => state.list.push(it));
  if (items.length) {
    state.lastEmailId = items[items.length - 1].emailId;
  }
  state.hasMore = items.length >= 30;
  renderList();
  setStatus('');
}

function renderList() {
  const ul = $('email-list');
  ul.innerHTML = '';
  if (!state.list.length) {
    $('list-empty').classList.remove('hidden');
    $('load-more-btn').classList.add('hidden');
    return;
  }
  $('list-empty').classList.add('hidden');
  state.list.forEach((it) => {
    const li = document.createElement('li');
    li.className = 'email-item' + (it.unread ? ' unread' : '');
    li.innerHTML =
      '<div class="item-sender">' + esc(it.name || it.sendEmail || '') + '</div>' +
      '<div class="item-subject">' + esc(it.subject || '(无主题)') + '</div>' +
      '<div class="item-time">' + esc(fmtTime(it.createTime)) + '</div>';
    li.addEventListener('click', () => openDetail(it.emailId));
    ul.appendChild(li);
  });
  $('load-more-btn').classList.toggle('hidden', !state.hasMore);
}

$('load-more-btn').addEventListener('click', () => loadList(false));

// ---------- 详情 ----------
async function openDetail(emailId) {
  const r = await browser.runtime.sendMessage({ type: 'detail', emailId });
  if (!r.ok) {
    if (r.authExpired) return handleAuthExpired();
    setStatus(r.message || '加载邮件失败');
    return;
  }
  const mail = r.data;
  $('list-pane').classList.add('hidden');
  $('detail-pane').classList.remove('hidden');
  $('detail-subject').textContent = mail.subject || '(无主题)';
  $('detail-sender').textContent = (mail.name ? mail.name + ' ' : '') + '<' + (mail.sendEmail || '') + '>';
  $('detail-time').textContent = fmtTime(mail.createTime);

  // 正文：sandbox iframe（无 allow-scripts），脚本不会执行
  const frame = $('body-frame');
  const html = mail.content || '';
  frame.srcdoc = '<!DOCTYPE html><html><head><meta charset="utf-8"></head><body style="font-family:sans-serif;line-height:1.5;word-break:break-word;margin:0;padding:8px">' +
    html.replace(/<head[\s\S]*?<\/head>/gi, '') +
    '</body></html>';

  // 附件
  const attBox = $('detail-attachments');
  attBox.innerHTML = '';
  const atts = mail.attList || [];
  if (atts.length) {
    const title = document.createElement('div');
    title.className = 'att-title';
    title.textContent = '附件 (' + atts.length + ')';
    attBox.appendChild(title);
    atts.forEach((att) => {
      const row = document.createElement('div');
      row.className = 'att-row';
      const name = document.createElement('span');
      name.className = 'att-name';
      name.textContent = att.filename || '附件';
      const size = document.createElement('span');
      size.className = 'att-size';
      size.textContent = fmtSize(att.size);
      const dl = document.createElement('button');
      dl.textContent = '下载';
      dl.addEventListener('click', () => downloadAttachment(att));
      row.appendChild(name);
      row.appendChild(size);
      row.appendChild(dl);
      attBox.appendChild(row);
    });
  }
}

$('back-btn').addEventListener('click', () => {
  $('detail-pane').classList.add('hidden');
  $('list-pane').classList.remove('hidden');
});

// 附件下载：用签名的 att.url（cos.duckgame-play.top）→ 页面 fetch（host permission）→ blob → 保存
async function downloadAttachment(att) {
  if (!att || !att.url) return;
  try {
    const res = await fetch(att.url);
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = att.filename || 'attachment';
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 30000);
  } catch (e) {
    setStatus('附件下载失败：' + e.message);
  }
}

// ---------- 会话过期 ----------
function handleAuthExpired() {
  browser.storage.local.remove('token');
  state = { accounts: [], currentAccountId: 0, list: [], lastEmailId: 0, hasMore: true, loading: false, token: null };
  $('email-list').innerHTML = '';
  showView('login');
  $('login-error').textContent = '登录已过期，请重新登录';
  $('login-error').classList.remove('hidden');
}

init();

