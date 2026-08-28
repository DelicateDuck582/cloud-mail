#!/usr/bin/env node
/**
 * CloudMail → Stalwart 同步脚本（只读收件箱镜像，v1）
 *
 * 流程：拉 CloudMail 收件箱（HTTP API）→ 重建 MIME → 投递到 Stalwart 本机 SMTP
 *       → Stalwart 落库，雷鸟走标准 IMAP 读取（协议由 Stalwart 兜底，零自定义 bug）。
 * 增量：状态文件记录已同步 emailId；轮询拉取新邮件。
 * 零第三方依赖（Node >= 18：内置 fetch / node:net / node:fs）。
 *
 * 环境变量：
 *   CLOUDMAIL_BASE      默认 https://mail.duckgame-play.top
 *   CLOUDMAIL_EMAIL     CloudMail 登录邮箱（必填）
 *   CLOUDMAIL_PASSWORD  CloudMail 密码（必填）
 *   STALWART_SMTP_HOST  默认 127.0.0.1
 *   STALWART_SMTP_PORT  默认 25（Stalwart 本地投递端口）
 *   STALWART_RCPT_TO    Stalwart 目标邮箱（必填，例如 cloudmail@local.domain）
 *   STATE_FILE          默认 /var/lib/cloudmail-sync/state.json
 *   FETCH_PAGE          默认 50
 *   POLL_INTERVAL       默认 30000（毫秒）
 *   ATTACHMENTS         '1' 时同步附件（默认关，附件仍在 CloudMail 网页查看）
 */
'use strict';
const net = require('node:net');
const fs = require('node:fs');
const path = require('node:path');

const CFG = {
  base: process.env.CLOUDMAIL_BASE || 'https://mail.duckgame-play.top',
  email: process.env.CLOUDMAIL_EMAIL || '',
  password: process.env.CLOUDMAIL_PASSWORD || '',
  smtpHost: process.env.STALWART_SMTP_HOST || '127.0.0.1',
  smtpPort: Number(process.env.STALWART_SMTP_PORT || 25),
  rcptTo: process.env.STALWART_RCPT_TO || '',
  stateFile: process.env.STATE_FILE || '/var/lib/cloudmail-sync/state.json',
  page: Number(process.env.FETCH_PAGE || 50),
  interval: Number(process.env.POLL_INTERVAL || 30000),
  withAttachments: process.env.ATTACHMENTS === '1',
};

if (!CFG.email || !CFG.password || !CFG.rcptTo) {
  console.error('缺少必填环境变量：CLOUDMAIL_EMAIL / CLOUDMAIL_PASSWORD / STALWART_RCPT_TO');
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
    if (j.code !== 200 || !j.data || !j.data.token) throw new Error('登录失败：' + (j.message || 'unknown'));
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
  async list(cursor) {
    const qs = new URLSearchParams({ accountId: 0, emailId: cursor || 0, size: CFG.page, type: 0, full: 0, timeSort: 0 });
    const j = await this.api('/api/email/list?' + qs.toString());
    if (j.code !== 200) throw new Error('拉取列表失败：' + (j.message || ''));
    return j.data.list || [];
  },
  async detail(emailId) {
    const j = await this.api('/api/email/detail?emailId=' + encodeURIComponent(emailId));
    if (j.code !== 200) throw new Error('拉取详情失败：' + (j.message || ''));
    return j.data;
  },
};

// ---------------- 状态文件（已同步 emailId） ----------------
function loadState() {
  try {
    const raw = fs.readFileSync(CFG.stateFile, 'utf8');
    const data = JSON.parse(raw);
    return new Set(Array.isArray(data.synced) ? data.synced : []);
  } catch (e) { return new Set(); }
}
function saveState(set) {
  const dir = path.dirname(CFG.stateFile);
  fs.mkdirSync(dir, { recursive: true });
  const tmp = CFG.stateFile + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify({ updatedAt: new Date().toISOString(), synced: [...set] }));
  fs.renameSync(tmp, CFG.stateFile); // 原子替换，防进程中断损坏
}

// ---------------- MIME 重建 ----------------
function cleanHeaderField(v) {
  return String(v || '').replace(/[\r\n]/g, '').replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, '');
}
function b64(s) { return Buffer.from(String(s), 'utf8').toString('base64'); }
function b64buf(b) { return Buffer.from(b).toString('base64'); }
function rndBoundary() { return '----=_cloudmail_' + Math.random().toString(36).slice(2) + Date.now().toString(36); }

async function buildMime(detail, emailId) {
  const subject = cleanHeaderField(detail.subject);
  const fromName = cleanHeaderField(detail.name || '');
  const fromAddr = cleanHeaderField(detail.sendEmail) || CFG.email;
  const date = cleanHeaderField(detail.createTime);
  const msgId = cleanHeaderField(detail.messageId) || ('cloudmail-' + emailId + '@duckgame-play.top');
  const plain = detail.text || '';
  const html = detail.content || '';
  const atts = (detail.attList || []).filter(a => a && a.url);

  const headers =
    'From: ' + (fromName ? fromName + ' <' + fromAddr + '>' : fromAddr) + '\r\n' +
    'To: ' + cleanHeaderField(CFG.rcptTo) + '\r\n' +
    'Subject: ' + subject + '\r\n' +
    'Date: ' + (date ? date : new Date().toUTCString()) + '\r\n' +
    'Message-ID: <' + msgId + '>' + '\r\n' +
    'MIME-Version: 1.0' + '\r\n';

  // 正文部分（alternative: plain + html）
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

  // 附件（可选）
  let bodyPart = altPart;
  let contentType = 'multipart/alternative; boundary="' + boundaryAlt + '"';
  if (CFG.withAttachments && atts.length) {
    const boundaryMix = rndBoundary();
    let mix = '--' + boundaryMix + '\r\n' + altPart + '\r\n';
    for (const a of atts) {
      let bytes;
      try {
        const res = await fetch(a.url); // 签名 URL（COS 私有桶，15 分钟有效）
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

// ---------------- 最小 SMTP 客户端（投递到 Stalwart 本机） ----------------
function smtpSend(raw) {
  return new Promise((resolve, reject) => {
    const sock = net.connect(CFG.smtpPort, CFG.smtpHost);
    sock.setTimeout(15000);
    let buf = '';
    let step = 0;
    let hello = null;
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
        else if (step === 1) { if (code === 250) { step = 2; sock.write('MAIL FROM:<' + (CFG.email) + '>\r\n'); } }
        else if (step === 2) { if (code !== 250) return fail(new Error('MAIL FROM ' + line)); step = 3; sock.write('RCPT TO:<' + CFG.rcptTo + '>\r\n'); }
        else if (step === 3) { if (code !== 250 && code !== 251) return fail(new Error('RCPT TO ' + line)); step = 4; sock.write('DATA\r\n'); }
        else if (step === 4) { if (code !== 354) return fail(new Error('DATA ' + line)); step = 5; sock.write(raw + '\r\n.\r\n'); }
        else if (step === 5) { if (code !== 250) return fail(new Error('DATA body ' + line)); step = 6; sock.write('QUIT\r\n'); }
        else if (step === 6) { sock.end(); resolve(); }
      }
    });
  });
}


// ---------------- 主同步循环 ----------------
async function syncOnce() {
  const synced = loadState();
  let cursor = 0;
  let totalNew = 0;
  let page = 0;

  while (true) {
    let emails;
    try {
      emails = await cloud.list(cursor);
    } catch (e) {
      console.error('[' + new Date().toISOString() + '] 拉取列表失败：', e.message);
      return; // 失败重试留给下一轮（避免打爆 API）
    }
    if (!emails.length) break;

    for (const m of emails) {
      if (synced.has(m.emailId)) continue;
      try {
        const detail = await cloud.detail(m.emailId);
        const raw = await buildMime(detail, m.emailId);
        await smtpSend(raw);
        synced.add(m.emailId);
        totalNew++;
        console.log('  同步 ' + m.emailId + '：' + (m.subject || '').slice(0, 60));
      } catch (e) {
        console.error('  邮件 ' + m.emailId + ' 失败：' + e.message);
        // 单封失败不中断：下一轮再试（state 未记录该 id）
      }
    }

    // 分页：本页已满则用最后一条 emailId 作为下一页游标
    const lastId = emails[emails.length - 1].emailId;
    if (emails.length >= CFG.page && lastId && lastId !== cursor) { cursor = lastId; page++; }
    else break;
    if (page > 50) break; // 保险：单轮最多 50 页
  }

  saveState(synced);
  if (totalNew) console.log('[' + new Date().toISOString() + '] 本轮新增 ' + totalNew + ' 封');
  return totalNew;
}

async function main() {
  console.log('CloudMail→Stalwart 同步启动，轮询间隔 ' + (CFG.interval / 1000) + 's');
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

