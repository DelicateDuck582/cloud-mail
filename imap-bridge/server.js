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
    this.uidValidity = 1;
  }

  send(line) { this.socket.write(line + CRLF); }
  ok(tag, t) { this.send((tag || '*') + ' OK ' + t); }
  no(tag, t) { this.send((tag || '*') + ' NO ' + t); }
  bad(tag, t) { this.send((tag || '*') + ' BAD ' + t); }

  async loadInbox(accountId) {
    if (Date.now() - this.cacheTs < CACHE_TTL_MS && this.messages.length) return;
    const list = await cloud.fetchEmails(accountId, 0);
    this.messages = list;
    this.cacheTs = Date.now();
    this.uidValidity = 1;
  }

  uidNext() {
    return this.messages.length ? Math.max(...this.messages.map(m => m.emailId)) + 1 : 1;
  }
}

const cloud = new CloudMail();
const sessions = new Map();

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
  let idx;
  while ((idx = s.buf.indexOf(CRLF)) !== -1) {
    const line = s.buf.slice(0, idx);
    s.buf = s.buf.slice(idx + 2);
    if (line.trim() === '') continue;
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
      cloud.login(m[1], m[2])
        .then(() => { s.authed = true; s.ok(tag, 'LOGIN completed'); })
        .catch((e) => s.no(tag, 'LOGIN failed: ' + e.message));
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
  const subject = (msg.subject || '').replace(/[\r\n]/g, ' ').replace(/\\/g, '\\\\').replace(/"/g, '\\"');
  const senderName = (msg.name || '').replace(/[\r\n\\"]/g, ' ');
  const from = senderName + ' <' + (msg.sendEmail || '') + '>';
  const msgId = 'cloudmail-' + uid + '@duckgame-play.top';
  const date = msg.createTime ? msg.createTime.replace(' ', 'T') + 'Z' : new Date().toISOString();

  // 正文（详情接口返回已签名图片 URL 的 HTML）
  let html = '';
  try {
    const detail = await cloud.emailDetail(uid);
    if (detail && detail.content) html = detail.content;
  } catch (e) { /* 详情失败仍返回头部 */ }

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
  if (items.includes('BODY[]') || items.includes('BODY.PEEK[]')) bodyData = header + body;
  else if (items.includes('BODY[HEADER]') || items.includes('BODY.PEEK[HEADER]')) bodyData = header;
  else if (items.includes('BODY[TEXT]') || items.includes('BODY.PEEK[TEXT]')) bodyData = body;
  else if (items.includes('BODY.PEEK[HEADER.FIELDS') || items.includes('BODY[HEADER.FIELDS')) bodyData = header;
  else if (items.includes('BODY[') || items.includes('BODY.PEEK[')) bodyData = header + body;

  let base = '* ' + seq + ' FETCH (' + parts.join(' ');
  if (bodyData !== null) {
    s.send(base + 'BODY[] {' + bodyData.length + '}');
    s.send(bodyData);
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
    if (a <= b) { for (let i = a; i <= b && i <= max; i++) out.add(i); }
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

