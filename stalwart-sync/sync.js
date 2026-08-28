#!/usr/bin/env node
/**
 * CloudMail → Stalwart 同步脚本 v2
 *
 * 功能：
 *  - 多账户：遍历 CloudMail 全部账户，按 STALWART_ACCOUNTS 映射投递到对应 Stalwart 邮箱
 *  - 已读回写：读取 Stalwart(JMAP) 的已读状态 → 回写 CloudMail（PUT /api/email/read）
 *  - 增量：状态文件记录已同步 accountId:emailId；轮询拉新邮件
 *  - 附件可选（ATTACHMENTS=1 时拉签名 URL 拼 MIME）
 *  - 零第三方依赖（Node >= 18）
 *
 * 环境变量：
 *   CLOUDMAIL_BASE       默认 https://mail.duckgame-play.top
 *   CLOUDMAIL_EMAIL      CloudMail 登录邮箱（必填）
 *   CLOUDMAIL_PASSWORD   CloudMail 密码（必填）
 *   STALWART_SMTP_HOST   默认 127.0.0.1
 *   STALWART_SMTP_PORT   默认 25
 *   STALWART_RCPT_TO     默认 Stalwart 目标邮箱（未配置 STALWART_ACCOUNTS 时所有账户用这个）
 *   STALWART_ACCOUNTS    可选 JSON：{"CloudMail账户邮箱":"Stalwart目标邮箱"}，多账户映射
 *   STALWART_JMAP_URL    可选，如 https://127.0.0.1:8080/jmap —— 设置后开启已读回写
 *   STALWART_USERNAME    Stalwart 邮箱账户（JMAP 认证，同雷鸟用的账号）
 *   STALWART_PASSWORD    Stalwart 邮箱密码
 *   STATE_FILE           默认 /var/lib/cloudmail-sync/state.json
 *   FETCH_PAGE           默认 50
 *   POLL_INTERVAL        默认 30000（毫秒）
 *   ATTACHMENTS          '1' 时同步附件
 */
'use strict';
const net = require('node:net');
const fs = require('node:fs');
const path = require('node:path');

function envBool(v) { return v === '1' || v === 'true'; }

const CFG = {
  base: process.env.CLOUDMAIL_BASE || 'https://mail.duckgame-play.top',
  email: process.env.CLOUDMAIL_EMAIL || '',
  password: process.env.CLOUDMAIL_PASSWORD || '',
  smtpHost: process.env.STALWART_SMTP_HOST || '127.0.0.1',
  smtpPort: Number(process.env.STALWART_SMTP_PORT || 25),
  defaultRcpt: process.env.STALWART_RCPT_TO || '',
  accountMap: (() => { try { return JSON.parse(process.env.STALWART_ACCOUNTS || '{}'); } catch (e) { return {}; } })(),
  jmapUrl: process.env.STALWART_JMAP_URL || '',
  jmapUser: process.env.STALWART_USERNAME || '',
  jmapPass: process.env.STALWART_PASSWORD || '',
  stateFile: process.env.STATE_FILE || '/var/lib/cloudmail-sync/state.json',
  page: Number(process.env.FETCH_PAGE || 50),
  interval: Number(process.env.POLL_INTERVAL || 30000),
  withAttachments: envBool(process.env.ATTACHMENTS),
};

if (!CFG.email || !CFG.password) {
  console.error('缺少必填环境变量：CLOUDMAIL_EMAIL / CLOUDMAIL_PASSWORD');
  process.exit(1);
}

// ---------------- CloudMail API ----------------
const cloud = {
  token: null,
  async login() {
    const r = await fetch(CFG.base + '/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: CFG.email, password: CFG.password }),
    });
    const j = await r.json().catch(() => ({}));
    if (j.code !== 200 || !j.data || !j.data.token) throw new Error('CloudMail 登录失败：' + (j.message || 'unknown'));
    this.token = j.data.token;
  },
  async api(p, { method = 'GET', body, retry = true } = {}) {
    const h = {};
    if (body) h['Content-Type'] = 'application/json';
    if (this.token) h['Authorization'] = this.token;
    const r = await fetch(CFG.base + p, { method, headers: h, body: body ? JSON.stringify(body) : undefined });
    const j = await r.json().catch(() => ({}));
    if (j.code === 401 && retry) { await this.login(); return this.api(p, { method, body, retry: false }); }
    return j;
  },
  // 多账户：用户全部邮箱账户
  async accounts() {
    const j = await this.api('/api/account/list?size=30');
    if (j.code !== 200) throw new Error('获取账户失败：' + (j.message || ''));
    return (j.data || []).filter(a => !a.isDel);
  },
  async list(accountId, cursor) {
    const qs = new URLSearchParams({ accountId: accountId || 0, emailId: cursor || 0, size: CFG.page, type: 0, full: 0, timeSort: 0 });
    const j = await this.api('/api/email/list?' + qs.toString());
    if (j.code !== 200) throw new Error('拉取列表失败：' + (j.message || ''));
    return j.data.list || [];
  },
  async detail(emailId) {
    const j = await this.api('/api/email/detail?emailId=' + encodeURIComponent(emailId));
    if (j.code !== 200) throw new Error('拉取详情失败：' + (j.message || ''));
    return j.data;
  },
  // 已读回写：批量标记已读
  async markRead(emailIds) {
    if (!emailIds.length) return;
    const j = await this.api('/api/email/read', { method: 'PUT', body: { emailIds } });
    if (j.code !== 200) throw new Error('标记已读失败：' + (j.message || ''));
  },
};

// ---------------- 状态文件（key = accountId:emailId） ----------------
function loadState() {
  try {
    const data = JSON.parse(fs.readFileSync(CFG.stateFile, 'utf8'));
    return new Set(Array.isArray(data.synced) ? data.synced : []);
  } catch (e) { return new Set(); }
}
function saveState(set) {
  const dir = path.dirname(CFG.stateFile);
  fs.mkdirSync(dir, { recursive: true });
  const tmp = CFG.stateFile + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify({ updatedAt: new Date().toISOString(), synced: [...set] }));
  fs.renameSync(tmp, CFG.stateFile);
}

// ---------------- MIME 重建 ----------------
function cleanHeaderField(v) {
  return String(v || '').replace(/[\r\n]/g, '').replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, '');
}
function b64(s) { return Buffer.from(String(s), 'utf8').toString('base64'); }
function b64buf(b) { return Buffer.from(b).toString('base64'); }
function rndBoundary() { return '----=_cloudmail_' + Math.random().toString(36).slice(2) + Date.now().toString(36); }

// Message-ID 固定为 cloudmail-<emailId>@duckgame-play.top，便于已读回写按 Message-ID 匹配
async function buildMime(detail, emailId, rcptTo) {
  const subject = cleanHeaderField(detail.subject);
  const fromName = cleanHeaderField(detail.name || '');
  const fromAddr = cleanHeaderField(detail.sendEmail) || CFG.email;
  const date = cleanHeaderField(detail.createTime);
  const msgId = 'cloudmail-' + emailId + '@duckgame-play.top';
  const plain = detail.text || '';
  const html = detail.content || '';
  const atts = (detail.attList || []).filter(a => a && a.url);

  const headers =
    'From: ' + (fromName ? fromName + ' <' + fromAddr + '>' : fromAddr) + '\r\n' +
    'To: ' + cleanHeaderField(rcptTo) + '\r\n' +
    'Subject: ' + subject + '\r\n' +
    'Date: ' + (date ? date : new Date().toUTCString()) + '\r\n' +
    'Message-ID: <' + msgId + '>' + '\r\n' +
    'MIME-Version: 1.0' + '\r\n';

  const boundaryAlt = rndBoundary();
  const altPart =
    'Content-Type: multipart/alternative; boundary="' + boundaryAlt + '"\r\n\r\n' +
    '--' + boundaryAlt + '\r\n' +
    'Content-Type: text/plain; charset=utf-8\r\n' +
    'Content-Transfer-Encoding: base64\r\n\r\n' + b64(plain) + '\r\n' +
    '--' + boundaryAlt + '\r\n' +
    'Content-Type: text/html; charset=utf-8\r\n' +
    'Content-Transfer-Encoding: base64\r\n\r\n' + b64(html) + '\r\n' +
    '--' + boundaryAlt + '--\r\n';

  let bodyPart = altPart;
  let contentType = 'multipart/alternative; boundary="' + boundaryAlt + '"';
  if (CFG.withAttachments && atts.length) {
    const boundaryMix = rndBoundary();
    let mix = '--' + boundaryMix + '\r\n' + altPart + '\r\n';
    for (const a of atts) {
      let bytes;
      try {
        const res = await fetch(a.url); // 签名 URL（COS 私有桶）
        if (!res.ok) throw new Error('HTTP ' + res.status);
        bytes = Buffer.from(await res.arrayBuffer());
      } catch (e) {
        console.warn('  附件拉取失败 ' + (a.filename || a.key) + '：' + e.message);
        continue;
      }
      mix += '--' + boundaryMix + '\r\n' +
        'Content-Type: ' + (a.mimeType || 'application/octet-stream') + '\r\n' +
        'Content-Disposition: attachment; filename="' + cleanHeaderField(a.filename || 'attachment').replace(/"/g, '\\"') + '"\r\n' +
        'Content-Transfer-Encoding: base64\r\n\r\n' + b64buf(bytes) + '\r\n';
    }
    mix += '--' + boundaryMix + '--\r\n';
    bodyPart = mix;
    contentType = 'multipart/mixed; boundary="' + boundaryMix + '"';
  }

  return headers + 'Content-Type: ' + contentType + '\r\n\r\n' + bodyPart;
}

// ---------------- 最小 SMTP 客户端（投递到 Stalwart 本机，rcpt 可指定） ----------------
function smtpSend(raw, rcptTo) {
  return new Promise((resolve, reject) => {
    const sock = net.connect(CFG.smtpPort, CFG.smtpHost);
    sock.setTimeout(15000);
    let buf = '';
    let step = 0;
    const fail = (e) => { sock.destroy(); reject(e); };
    sock.on('timeout', () => fail(new Error('SMTP 超时')));
    sock.on('error', fail);
    sock.on('data', (d) => {
      buf += d.toString('utf8');
      let idx;
      while ((idx = buf.indexOf('\r\n')) !== -1) {
        const line = buf.slice(0, idx); buf = buf.slice(idx + 2);
        const code = Number(line.slice(0, 3));
        if (step === 0) { if (code !== 220) return fail(new Error('SMTP banner ' + line)); step = 1; sock.write('EHLO localhost\r\n'); }
        else if (step === 1) { if (code === 250) { step = 2; sock.write('MAIL FROM:<' + CFG.email + '>\r\n'); } }
        else if (step === 2) { if (code !== 250) return fail(new Error('MAIL FROM ' + line)); step = 3; sock.write('RCPT TO:<' + rcptTo + '>\r\n'); }
        else if (step === 3) { if (code !== 250 && code !== 251) return fail(new Error('RCPT TO ' + line)); step = 4; sock.write('DATA\r\n'); }
        else if (step === 4) { if (code !== 354) return fail(new Error('DATA ' + line)); step = 5; sock.write(raw + '\r\n.\r\n'); }
        else if (step === 5) { if (code !== 250) return fail(new Error('DATA body ' + line)); step = 6; sock.write('QUIT\r\n'); }
        else if (step === 6) { sock.end(); resolve(); }
      }
    });
  });
}


// ---------------- JMAP 已读回写（读取 Stalwart 已读状态） ----------------
async function jmapFetch(path, method, body) {
  const auth = 'Basic ' + Buffer.from(CFG.jmapUser + ':' + CFG.jmapPass).toString('base64');
  const opts = { headers: { Authorization: auth, 'Content-Type': 'application/json' }, method };
  if (body) opts.body = JSON.stringify(body);
  const r = await fetch(CFG.jmapUrl + path, opts);
  if (!r.ok) throw new Error('JMAP HTTP ' + r.status);
  return r.json();
}

// 返回 { messageId: true(已读)/false(未读) }
async function jmapSeenMap() {
  const session = await jmapFetch('', 'GET');
  const accountId = session && session.primaryAccounts && session.primaryAccounts.mail;
  if (!accountId) throw new Error('JMAP 无 mail 账户');

  const mb = await jmapFetch('', 'POST', {
    using: ['urn:ietf:params:jmap:core', 'urn:ietf:params:jmap:mail'],
    methodCalls: [['Mailbox/query', { accountId, filter: { name: 'INBOX' } }, 'm1']],
  });
  const inboxId = ((mb.methodResponses || []).find(r => r[0] === 'Mailbox/query') || [null, {}])[1].ids?.[0];
  if (!inboxId) return {};

  const q = await jmapFetch('', 'POST', {
    using: ['urn:ietf:params:jmap:core', 'urn:ietf:params:jmap:mail'],
    methodCalls: [['Email/query', { accountId, filter: { inMailbox: inboxId }, limit: 500 }, 'q1']],
  });
  const ids = ((q.methodResponses || []).find(r => r[0] === 'Email/query') || [null, {}])[1].ids || [];

  const seen = {};
  for (let i = 0; i < ids.length; i += 100) {
    const g = await jmapFetch('', 'POST', {
      using: ['urn:ietf:params:jmap:core', 'urn:ietf:params:jmap:mail'],
      methodCalls: [['Email/get', { accountId, ids: ids.slice(i, i + 100), properties: ['messageId', 'keywords'] }, 'g1']],
    });
    for (const r of (g.methodResponses || [])) {
      if (r[0] === 'Email/get') {
        for (const e of (r[1].list || [])) {
          const mid = Array.isArray(e.messageId) ? e.messageId[0] : null;
          if (mid) seen[mid] = !!(e.keywords && e.keywords['$seen']);
        }
      }
    }
  }
  return seen;
}

async function readBack(accounts) {
  if (!CFG.jmapUrl || !CFG.jmapUser) return;
  const seenMap = await jmapSeenMap();
  for (const acc of accounts) {
    let cursor = 0, page = 0, marked = 0;
    while (page < 10) {
      const emails = await cloud.list(acc.accountId, cursor);
      if (!emails.length) break;
      const toMark = [];
      for (const m of emails) {
        if (m.unread && seenMap['cloudmail-' + m.emailId + '@duckgame-play.top'] === true) toMark.push(m.emailId);
      }
      if (toMark.length) {
        await cloud.markRead(toMark);
        marked += toMark.length;
      }
      const last = emails[emails.length - 1].emailId;
      if (emails.length >= CFG.page && last && last !== cursor) { cursor = last; page++; } else break;
    }
    if (marked) console.log('[' + new Date().toISOString() + '] 已读回写 ' + acc.email + '：' + marked + ' 封');
  }
}

// ---------------- 主同步循环（多账户） ----------------
async function syncAccount(acc, rcpt, synced) {
  let cursor = 0, page = 0, added = 0;
  while (true) {
    const emails = await cloud.list(acc.accountId, cursor);
    if (!emails.length) break;
    for (const m of emails) {
      const key = acc.accountId + ':' + m.emailId;
      if (synced.has(key)) continue;
      try {
        const detail = await cloud.detail(m.emailId);
        const raw = await buildMime(detail, m.emailId, rcpt);
        await smtpSend(raw, rcpt);
        synced.add(key); added++;
        console.log('  [' + acc.email + '] 同步 ' + m.emailId + '：' + (m.subject || '').slice(0, 50));
      } catch (e) {
        console.error('  邮件 ' + m.emailId + ' 失败：' + e.message); // 下一轮重试
      }
    }
    const last = emails[emails.length - 1].emailId;
    if (emails.length >= CFG.page && last && last !== cursor) { cursor = last; page++; } else break;
    if (page > 50) break;
  }
  if (added) console.log('[' + new Date().toISOString() + '] ' + acc.email + ' 新增 ' + added + ' 封');
}

async function syncOnce() {
  const synced = loadState();
  const accounts = await cloud.accounts();
  if (!accounts.length) { console.warn('CloudMail 无可用账户'); return; }
  for (const acc of accounts) {
    const rcpt = CFG.accountMap[acc.email] || CFG.defaultRcpt;
    if (!rcpt) { console.warn('账户 ' + acc.email + ' 无目标 Stalwart 邮箱（STALWART_RCPT_TO/STALWART_ACCOUNTS），跳过'); continue; }
    await syncAccount(acc, rcpt, synced);
  }
  saveState(synced);
  if (CFG.jmapUrl && CFG.jmapUser) {
    try { await readBack(accounts); } catch (e) { console.warn('已读回写跳过（' + e.message + '）'); }
  }
}

async function main() {
  console.log('CloudMail→Stalwart 同步 v2 启动，轮询 ' + (CFG.interval / 1000) + 's'
    + (CFG.jmapUrl && CFG.jmapUser ? '，已读回写开启' : ''));
  while (true) {
    try {
      await cloud.login();
      await syncOnce();
    } catch (e) {
      console.error('[' + new Date().toISOString() + '] 同步异常：', e.message);
    }
    await new Promise((r) => setTimeout(r, CFG.interval));
  }
}

main().catch((e) => { console.error('致命错误：', e); process.exit(1); });

