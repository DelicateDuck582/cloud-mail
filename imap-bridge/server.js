#!/usr/bin/env node
/**
 * CloudMail → IMAP 桥（v0.1 只读收件箱）
 * - 监听 TLS 端口（默认 993），实现最小 IMAP 子集供 Thunderbird 读取收件箱
 * - 数据全部来自 CloudMail HTTP API（mail.duckgame-play.top）
 * - 零第三方依赖（Node >= 18，内置 node:net / node:tls / fetch）
 *
 * 环境变量：
 *   IMAP_PORT     默认 993
 *   IMAP_TLS_CERT / IMAP_TLS_KEY  证书路径（PEM）
 *   MAIL_BASE     默认 https://mail.duckgame-play.top
 *   FETCH_PAGE    列表每页条数，默认 50
 *   CACHE_TTL_MS  列表缓存时长，默认 30000
 */
'use strict';
const tls = require('node:tls');
const fs = require('node:fs');

const PORT = Number(process.env.IMAP_PORT || 993);
const MAIL_BASE = process.env.MAIL_BASE || 'https://mail.duckgame-play.top';
const FETCH_PAGE = Number(process.env.FETCH_PAGE || 50);
const CACHE_TTL_MS = Number(process.env.CACHE_TTL_MS || 30000);
const CRLF = '\r\n';

// ---------------- CloudMail API 客户端 ----------------
class CloudMail {
  constructor() { this.token = null; this.email = null; this.password = null; }

  async api(path, { method = 'GET', body, retry = true } = {}) {
    const headers = {};
    if (body) headers['Content-Type'] = 'application/json';
    if (this.token) headers['Authorization'] = this.token;
    const res = await fetch(MAIL_BASE + path, { method, headers, body: body ? JSON.stringify(body) : undefined });
    const json = await res.json().catch(() => ({}));
    if (json.code === 401 && retry) {
      await this.login(this.email, this.password);
      return this.api(path, { method, body, retry: false });
    }
    return json;
  }

  async login(email, password) {
    const r = await fetch(MAIL_BASE + '/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });
    const json = await r.json().catch(() => ({}));
    if (json.code !== 200 || !json.data || !json.data.token) {
      throw new Error('登录失败：' + (json.message || 'unknown'));
    }
    this.token = json.data.token;
    this.email = email;
    this.password = password;
  }

  async accounts() {
    const r = await this.api('/api/account/list?size=30');
    if (r.code !== 200) throw new Error('获取账户失败：' + (r.message || ''));
    return r.data || [];
  }

  async fetchEmails(accountId, cursor) {
    const qs = new URLSearchParams({ accountId: accountId || 0, emailId: cursor || 0, size: FETCH_PAGE, type: 0, full: 0, timeSort: 0 });
    const r = await this.api('/api/email/list?' + qs.toString());
    if (r.code !== 200) throw new Error('拉取列表失败：' + (r.message || ''));
    const list = r.data.list || [];
    return list;
  }

  async emailDetail(emailId) {
    const r = await this.api('/api/email/detail?emailId=' + encodeURIComponent(emailId));
    if (r.code !== 200) throw new Error('拉取详情失败：' + (r.message || ''));
    return r.data;
  }
}

// ---------------- IMAP 会话 ----------------
class Session {
  constructor(socket) {
    this.socket = socket;
    this.buf = '';
    this.authed = false;
    this.messages = [];      // [{emailId, subject, name, sendEmail, createTime, unread}]
    this.cacheTs = 0;
    this.lastLoadAttempt = 0;
    this._loading = null;
    this.loginFails = 0;
    this.uidValidity = 1;
  }

  send(line) { this.socket.write(line + CRLF); }
  writeRaw(data) { this.socket.write(data); }
  ok(tag, t) { this.send((tag || '*') + ' OK ' + t); }
  no(tag, t) { this.send((tag || '*') + ' NO ' + t); }
  bad(tag, t) { this.send((tag || '*') + ' BAD ' + t); }

  // 带「进行中去重 + 失败冷却」的收件箱加载，防止并发打爆/失败重试风暴
  loadInbox(accountId) {
    if (Date.now() - this.cacheTs < CACHE_TTL_MS && this.messages.length) return Promise.resolve();
    if (this._loading) return this._loading;
    if (!this.messages.length && Date.now() - this.lastLoadAttempt < 3000) return Promise.resolve();
    this.lastLoadAttempt = Date.now();
    this._loading = (async () => {
      try {
        const list = await withApiLimit(() => cloud.fetchEmails(accountId, 0));
        this.messages = list;
        this.cacheTs = Date.now();
        this.uidValidity = 1;
      } finally {
        this._loading = null;
      }
    })();
    return this._loading;
  }

  uidNext() {
    return this.messages.length ? Math.max(...this.messages.map(m => m.emailId)) + 1 : 1;
  }
}

const cloud = new CloudMail();
const sessions = new Map();

// ---------------- 性能/安全：详情缓存 + 并发上限 + 清洗 ----------------
const DETAIL_CACHE_MAX = 200;
const detailCache = new Map();           // emailId -> detail
let apiActive = 0;
const API_MAX_ACTIVE = 4;                // 对 CloudMail 的最大并发请求数

// 轻量并发限制：超过 4 个在途请求时轮询等待
async function withApiLimit(fn) {
  while (apiActive >= API_MAX_ACTIVE) await new Promise(r => setTimeout(r, 30));
  apiActive++;
  try { return await fn(); } finally { apiActive--; }
}

async function getDetail(uid) {
  if (detailCache.has(uid)) return detailCache.get(uid);
  const d = await withApiLimit(() => cloud.emailDetail(uid));
  if (detailCache.size >= DETAIL_CACHE_MAX) {
    const first = detailCache.keys().next().value;
    if (first !== undefined) detailCache.delete(first);
  }
  detailCache.set(uid, d);
  return d;
}

// 清洗可能破坏 IMAP 协议行的字符（防响应注入）
function cleanField(v) {
  return String(v || '').replace(/[\r\n]/g, '');
}


// ---------------- TLS 服务 ----------------
const server = tls.createServer({
  cert: fs.readFileSync(process.env.IMAP_TLS_CERT || '/etc/letsencrypt/live/imap.duckgame-play.top/fullchain.pem'),
  key: fs.readFileSync(process.env.IMAP_TLS_KEY || '/etc/letsencrypt/live/imap.duckgame-play.top/privkey.pem'),
}, (socket) => {
  const s = new Session(socket);
  sessions.set(socket, s);
  socket.on('close', () => sessions.delete(socket));
  socket.on('error', () => sessions.delete(socket));
  socket.on('data', (d) => onData(socket, s, d));
  socket.setNoDelay(true);
  s.send('* OK [CAPABILITY IMAP4rev1] CloudMail IMAP bridge ready');
});
server.on('tlsClientError', (e) => console.error('TLS error:', e.message));
server.listen(PORT, '0.0.0.0', () => console.log('CloudMail IMAP bridge listening on :' + PORT));

function onData(socket, s, data) {
  s.buf += data.toString('utf8');
  // 安全：单连接缓冲上限 64KB，防止超长无换行数据导致内存无限增长
  if (s.buf.length > 65536) {
    s.send('* BYE Excessive buffer, closing connection');
    socket.destroy();
    return;
  }
  let idx;
  while ((idx = s.buf.indexOf(CRLF)) !== -1) {
    const line = s.buf.slice(0, idx);
    s.buf = s.buf.slice(idx + 2);
    if (line.trim() === '') continue;
    if (line.length > 8192) { // 单行命令超长，丢弃并断开（防滥用）
      s.bad('*', 'command too long');
      socket.destroy();
      return;
    }
    try { handleLine(socket, s, line); } catch (e) { console.error(e); s.bad('*', 'internal error'); }
  }
}

function parseLine(line) {
  const m = line.match(/^(\S+)\s+(.*)$/);
  if (!m) return { tag: '*', cmd: '', rest: '' };
  const rest = m[2].trim();
  const cmd = rest.split(/\s+/)[0].toUpperCase();
  return { tag: m[1], cmd, rest: rest.slice(cmd.length).trim() };
}

function handleLine(socket, s, line) {
  const { tag, cmd, rest } = parseLine(line);

  switch (cmd) {
    case 'CAPABILITY':
      s.send('* CAPABILITY IMAP4rev1');
      s.ok(tag, 'CAPABILITY completed');
      break;

    case 'NOOP':
      s.ok(tag, 'NOOP completed');
      break;

    case 'LOGOUT':
      s.send('* BYE CloudMail IMAP bridge logging out');
      s.ok(tag, 'LOGOUT completed');
      socket.end();
      break;

    case 'LOGIN': {
      const m = rest.match(/^"?([^"\s]+)"?\s+"?([^"\s]+)"?$/);
      if (!m) return s.bad(tag, 'LOGIN failed');
      // 防爆破：单连接最多 5 次失败，超过即断开（避免把失败持续转发给 CloudMail 触发其 IP 锁定）
      if (s.loginFails >= 5) {
        s.send('* BYE Too many failed logins');
        socket.end();
        return;
      }
      cloud.login(cleanField(m[1]), m[2])
        .then(() => { s.authed = true; s.loginFails = 0; s.ok(tag, 'LOGIN completed'); })
        .catch((e) => { s.loginFails++; s.no(tag, 'LOGIN failed: ' + cleanField(e.message)); });
      break;
    }

    case 'LIST':
    case 'LSUB':
      if (!s.authed) return s.no(tag, 'not authenticated');
      s.send('* LIST (\\HasNoChildren) "/" "INBOX"');
      s.ok(tag, cmd + ' completed');
      break;

    case 'SELECT':
    case 'EXAMINE': {
      if (!s.authed) return s.no(tag, 'not authenticated');
      const mbox = (rest.match(/"([^"]+)"|\S+/) || [])[0] || '';
      if (mbox.replace(/^"|"$/g, '').toUpperCase() !== 'INBOX') return s.no(tag, 'mailbox not found');
      const accountId = 0;
      s.loadInbox(accountId).then(() => {
        const n = s.messages.length;
        s.send('* ' + n + ' EXISTS');
        s.send('* 0 RECENT');
        s.send('* FLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)');
        s.send('* OK [UIDVALIDITY ' + s.uidValidity + '] UIDs valid');
        s.send('* OK [UIDNEXT ' + s.uidNext() + '] Predicted next UID');
        s.ok(tag, cmd + ' completed');
      }).catch((e) => s.no(tag, e.message));
      break;
    }

    case 'STATUS': {
      if (!s.authed) return s.no(tag, 'not authenticated');
      s.loadInbox(0).then(() => {
        const n = s.messages.length;
        const un = s.messages.filter(m => m.unread).length;
        s.send('* STATUS INBOX (MESSAGES ' + n + ' RECENT 0 UNSEEN ' + un + ' UIDNEXT ' + s.uidNext() + ' UIDVALIDITY ' + s.uidValidity + ')');
        s.ok(tag, 'STATUS completed');
      }).catch((e) => s.no(tag, e.message));
      break;
    }

    case 'FETCH':
    case 'UID FETCH': {
      if (!s.authed) return s.no(tag, 'not authenticated');
      const m = rest.match(/^(\S+)\s+\(?([^)]*)\)?\s*$/);
      if (!m) return s.bad(tag, 'FETCH bad args');
      s.loadInbox(0).then(async () => {
        const seqs = expandSet(m[1], s.messages.length);
        for (const seq of seqs) {
          const msg = s.messages[seq - 1];
          if (msg) await emitFetch(s, seq, msg, m[2].toUpperCase());
        }
        s.ok(tag, cmd + ' completed');
      }).catch((e) => s.no(tag, e.message));
      break;
    }

    case 'UID SEARCH':
    case 'SEARCH': {
      if (!s.authed) return s.no(tag, 'not authenticated');
      s.loadInbox(0).then(() => {
        const c = rest.toUpperCase();
        let ids = s.messages.map(m => m.emailId);
        if (c.includes('UNSEEN') || c.includes('NEW')) ids = s.messages.filter(m => m.unread).map(m => m.emailId);
        else if (c.includes('SEEN')) ids = s.messages.filter(m => !m.unread).map(m => m.emailId);
        s.send('* SEARCH ' + ids.join(' '));
        s.ok(tag, cmd + ' completed');
      }).catch((e) => s.no(tag, e.message));
      break;
    }

    case 'STORE':
    case 'CLOSE':
    case 'EXPUNGE':
    case 'CHECK':
    case 'ID':
    case 'NAMESPACE':
    case 'UID':
    case 'STARTTLS':
      s.ok(tag, cmd + ' completed');
      break;

    default:
      s.ok(tag, cmd + ' completed');
  }
}


// ---------------- FETCH 数据组装 ----------------
async function emitFetch(s, seq, msg, items) {
  const uid = msg.emailId;
  const flags = msg.unread ? '(\\Unseen)' : '()';
  const subject = cleanField(msg.subject || '').replace(/\\/g, '\\\\').replace(/"/g, '\\"');
  const senderName = cleanField(msg.name || '').replace(/\\|"/g, '');
  const sendEmail = cleanField(msg.sendEmail || '');
  const from = senderName + ' <' + sendEmail + '>';
  const msgId = 'cloudmail-' + uid + '@duckgame-play.top';
  const date = msg.createTime ? msg.createTime.replace(' ', 'T') + 'Z' : new Date().toISOString();

  // 性能：只有请求正文（BODY[] / BODY[TEXT]）才调详情 API；HEADER 类请求不拉正文
  const wantsBody = /BODY(?:\.PEEK)?\[\]|BODY(?:\.PEEK)?\[TEXT\]/.test(items);
  let html = '';
  if (wantsBody) {
    try {
      const detail = await getDetail(uid); // 走 LRU 缓存 + 并发限制
      if (detail && detail.content) html = detail.content;
    } catch (e) { /* 详情失败仍返回头部 */ }
  }

  const header =
    'From: ' + from + CRLF +
    'To: undisclosed-recipients:;' + CRLF +
    'Subject: ' + subject + CRLF +
    'Date: ' + new Date(date).toUTCString() + CRLF +
    'Message-ID: <' + msgId + '>' + CRLF +
    'MIME-Version: 1.0' + CRLF +
    'Content-Type: text/html; charset=utf-8' + CRLF +
    'Content-Transfer-Encoding: base64' + CRLF + CRLF;
  const body = Buffer.from(html, 'utf8').toString('base64');

  const parts = [];
  if (items.includes('UID')) parts.push('UID ' + uid);
  if (items.includes('FLAGS')) parts.push('FLAGS ' + flags);
  if (items.includes('INTERNALDATE')) parts.push('INTERNALDATE "' + imapDateTime(date) + '"');
  if (items.includes('RFC822.SIZE')) parts.push('RFC822.SIZE ' + (header.length + body.length));
  if (items.includes('ENVELOPE')) parts.push('ENVELOPE ' + envelope(from, subject, date, msgId));

  let bodyData = null;
  if (/BODY(?:\.PEEK)?\[\]/.test(items)) bodyData = header + body;
  else if (/BODY(?:\.PEEK)?\[TEXT\]/.test(items)) bodyData = body;
  else if (/BODY(?:\.PEEK)?\[HEADER/.test(items)) bodyData = header;
  else if (/BODY(?:\.PEEK)?\[/.test(items)) bodyData = header;

  const base = '* ' + seq + ' FETCH (' + parts.join(' ');
  if (bodyData !== null) {
    // IMAP literal 格式：{N}\r\n + 恰好 N 字节 + )\r\n（用 writeRaw 保证字节数精确）
    s.send(base + 'BODY[] {' + bodyData.length + '}');
    s.writeRaw(bodyData);
    s.send(')');
  } else {
    s.send(base + ')');
  }
}


function expandSet(set, max) {
  const out = new Set();
  for (const part of set.split(',')) {
    let a, b;
    if (part.includes(':')) { [a, b] = part.split(':'); } else { a = b = part; }
    if (a === '*') a = max;
    if (b === '*') b = max;
    a = Number(a); b = Number(b);
    if (!isFinite(a) || !isFinite(b)) continue;
    // 安全：把 a/b 都钳制到 [1, max]，杜绝任何超大范围（正/反向）导致的 CPU 打满
    a = Math.max(1, Math.min(a, max));
    b = Math.max(1, Math.min(b, max));
    if (a <= b) { for (let i = a; i <= b; i++) out.add(i); }
    else { for (let i = a; i >= b; i--) out.add(i); }
  }
  return [...out].sort((x, y) => x - y);
}

function imapDateTime(iso) {
  const d = new Date(iso);
  if (isNaN(d.getTime())) return '01-Jan-1970 00:00:00 +0000';
  const days = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'];
  const months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
  return days[d.getUTCDay()] + ', ' + String(d.getUTCDate()).padStart(2,'0') + '-' + months[d.getUTCMonth()] + '-' + d.getUTCFullYear() +
    ' ' + String(d.getUTCHours()).padStart(2,'0') + ':' + String(d.getUTCMinutes()).padStart(2,'0') + ':' + String(d.getUTCSeconds()).padStart(2,'0') + ' +0000';
}

function envelope(from, subject, date, msgId) {
  const name = from.split(' <')[0] || '';
  const addr = (from.match(/<([^>]+)>/) || [,''])[1];
  const a = '("' + name.replace(/\\|"/g, '') + '" NIL "' + addr + '")';
  return '(' + a + ' NIL NIL NIL NIL NIL NIL "' + subject + '" NIL NIL NIL)';
}

