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
  // 无 25 方案：阿里云/VPS 默认封 25，本机投递改用 2525（Stalwart 监听 127.0.0.1:2525 明文 SMTP）。
  // 仅回环投递不涉及出站，纯明文即可（不可被外部窃听）。
  smtpPort: Number(process.env.STALWART_SMTP_PORT || 2525),
  defaultRcpt: process.env.STALWART_RCPT_TO || '',
  accountMap: (() => { try { return JSON.parse(process.env.STALWART_ACCOUNTS || '{}'); } catch (e) { return {}; } })(),
  jmapUrl: process.env.STALWART_JMAP_URL || '',
  jmapUser: process.env.STALWART_USERNAME || '',
  jmapPass: process.env.STALWART_PASSWORD || '',
  stateFile: process.env.STATE_FILE || '/var/lib/cloudmail-sync/state.json',
  page: Number(process.env.FETCH_PAGE || 50),
  interval: Number(process.env.POLL_INTERVAL || 30000),
  withAttachments: envBool(process.env.ATTACHMENTS),
  // 反向同步（需 STALWART_JMAP_URL 已配置）：
  syncDelete: envBool(process.env.SYNC_DELETE === undefined ? '1' : process.env.SYNC_DELETE), // 雷鸟删除 → CloudMail 垃圾桶
  syncSent: envBool(process.env.SYNC_SENT === undefined ? '1' : process.env.SYNC_SENT),       // 雷鸟发信 → CloudMail 已发送
  sentMailbox: (process.env.STALWART_SENT_MAILBOX || 'Sent').trim(),                          // Stalwart 已发送邮箱名
  syncSentHistory: envBool(process.env.SYNC_SENT_HISTORY),                                     // 首次启用时是否追溯历史已发送（默认否）
  // 发信同步落库方式：
  //   import（默认，方案 A/B）：Stalwart/第三方已投递，仅镜像记录（/api/email/import-sent，不投递）
  //   send（方案 C）：Stalwart 只收集（哑 SMTP），真正投递走 CloudMail Resend（/api/email/send，HTTPS 不走 25）
  sentMode: ((process.env.SYNC_SENT_MODE || 'import').trim().toLowerCase() === 'send') ? 'send' : 'import',
  // 下行投递方式：
  //   jmap（默认）：JMAP Email/import 到"按收件人划分的文件夹"（聚合 5 号 + 文件夹区分，支持垃圾桶/恢复）
  //   smtp（兼容）：SMTP 2525 投递到 INBOX 混流（旧方式，无文件夹区分）
  delivery: ((process.env.SYNC_DELIVERY || 'jmap').trim().toLowerCase() === 'smtp') ? 'smtp' : 'jmap',
  // 文件夹映射（可选）：{"CloudMail账户邮箱":"Stalwart文件夹名"}，未配置时默认用账户邮箱地址作文件夹名
  folderMap: (() => { try { return JSON.parse(process.env.STALWART_FOLDERS || '{}'); } catch (e) { return {}; } })(),
};

if (!CFG.email || !CFG.password) {
  console.error('缺少必填环境变量：CLOUDMAIL_EMAIL / CLOUDMAIL_PASSWORD');
  process.exit(1);
}

// 性能：状态最多保留最新 STATE_MAX 条（旧 emailId 不会再出现在最新列表，可安全裁剪）
const STATE_MAX = Number(process.env.STATE_MAX || 10000);
// 附件上限：单文件 / 整封，超限跳过（防内存撑爆与 COS 流量）
const ATTACH_MAX_MB = Number(process.env.ATTACH_MAX_MB || 10);
const ATTACH_TOTAL_MAX_MB = Number(process.env.ATTACH_TOTAL_MAX_MB || 25);

// ---------------- 安全守卫 ----------------
const LOOPBACK = new Set(['127.0.0.1', 'localhost', '::1']);
if (CFG.smtpHost && !LOOPBACK.has(CFG.smtpHost)) {
  // SMTP 目标非回环：邮件内容（含正文/主题）会发到该主机，仅建议本地 Stalwart
  console.warn('[安全] STALWART_SMTP_HOST 非回环地址，请确认目标可信（仅建议 127.0.0.1 本地 Stalwart）');
}
// 无 25 端口环境提醒：若仍在使用 25，多半无法投递（云厂商封 25）；建议 Stalwart 监听 2525
if (CFG.smtpPort === 25) {
  console.warn('[提示] STALWART_SMTP_PORT=25：云厂商通常封禁 25，若投递失败请改用 2525（无 25 方案）');
}
if (CFG.jmapUrl) {
  try {
    const u = new URL(CFG.jmapUrl);
    if (u.protocol === 'http:' && !LOOPBACK.has(u.hostname)) {
      console.error('[安全] STALWART_JMAP_URL 使用明文 http 且非本地回环，密码会明文外发，已拒绝启动');
      process.exit(1);
    }
  } catch (e) {
    console.error('STALWART_JMAP_URL 非法：' + CFG.jmapUrl);
    process.exit(1);
  }
}

// HTTP 统一超时（Node fetch 默认无超时，防止网络卡死整轮）
const HTTP_TIMEOUT_MS = Number(process.env.HTTP_TIMEOUT_MS || 20000);
function fetchT(url, opts) { return fetch(url, Object.assign({}, opts, { signal: AbortSignal.timeout(HTTP_TIMEOUT_MS) })); }
// 严格清洗邮箱地址，防 SMTP 命令注入（rcpt 来自 CloudMail 账户名，不可信）
function cleanRcpt(v) { return String(v || '').replace(/[^A-Za-z0-9._@\-]/g, ''); }



// ---------------- CloudMail API ----------------
const cloud = {
  token: null,
  async login() {
    const r = await fetchT(CFG.base + '/api/login', {
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
    const r = await fetchT(CFG.base + p, { method, headers: h, body: body ? JSON.stringify(body) : undefined });
    const j = await r.json().catch(() => ({}));
    if (j.code === 401 && retry) { await this.login(); return this.api(p, { method, body, retry: false }); }
    return j;
  },
  // 多账户：用户全部邮箱账户
  async accounts() {
    const j = await this.api('/api/account/list?size=50');
    if (j.code !== 200) throw new Error('获取账户失败：' + (j.message || ''));
    return (j.data || []).filter(a => !a.isDel);
  },
  async list(accountId, cursor) {
    // allReceive=0 强制按 accountId 过滤：若账户设了「接收所有邮件」，
    // 不显式传 0 会导致拉取到全部账户邮件 → 多号模式下重复投递
    const qs = new URLSearchParams({ accountId: accountId || 0, emailId: cursor || 0, size: CFG.page, type: 0, full: 0, timeSort: 0, allReceive: 0 });
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
  // 删除同步：移入 CloudMail 垃圾桶（软删除）
  async delete(emailIds) {
    if (!emailIds.length) return;
    const j = await this.api('/api/email/delete?emailIds=' + emailIds.join(','), { method: 'DELETE' });
    if (j.code !== 200) throw new Error('删除失败：' + (j.message || ''));
  },
  // 恢复同步：从 CloudMail 垃圾桶恢复
  async restore(emailIds) {
    if (!emailIds.length) return;
    const j = await this.api('/api/email/restore', { method: 'POST', body: { emailIds } });
    if (j.code !== 200) throw new Error('恢复失败：' + (j.message || ''));
  },
  // 发信同步：导入已发送记录（不触发 Resend 投递）
  async importSent(body) {
    const j = await this.api('/api/email/import-sent', { method: 'POST', body });
    if (j.code !== 200) throw new Error('导入已发送失败：' + (j.message || ''));
    return j.data;
  },
  // 发信同步（方案 C）：真正投递走 CloudMail Resend（HTTPS，不走 25）
  async send(body) {
    const j = await this.api('/api/email/send', { method: 'POST', body });
    if (j.code !== 200) throw new Error('Resend 投递失败：' + (j.message || ''));
    return j.data;
  },
};

// ---------------- 状态文件 ----------------
// 结构：
//   synced:          Set<"accountId:emailId">      已下行同步（防重复投递）
//   stalwartMap:     Map<stalwartEmailId, key>     已登记 Stalwart 邮件 ↔ CloudMail 映射（删除检测用）
//   sentDone:        Set<stalwartEmailId>          已导入/已发送的 Stalwart Sent 邮件
//   sentQueryState:  JMAP Email/queryChanges 的增量游标
//   sentFail:        Map<stalwartEmailId, count>   发信同步失败重试计数（≥3 放弃，防确定性失败刷屏）
function emptyState() {
  return { synced: new Set(), stalwartMap: new Map(), sentDone: new Set(), sentQueryState: '', sentFail: new Map() };
}
function pruneState(st) {
  if (st.synced.size > STATE_MAX) {
    // 保留 emailId 最大的（最新）STATE_MAX 条
    const arr = [...st.synced].sort((a, b) => Number(b.slice(b.lastIndexOf(':') + 1)) - Number(a.slice(a.lastIndexOf(':') + 1)));
    st.synced = new Set(arr.slice(0, STATE_MAX));
  }
  if (st.stalwartMap.size > STATE_MAX) {
    const arr = [...st.stalwartMap.entries()]
      .sort((a, b) => Number(b[1].slice(b[1].lastIndexOf(':') + 1)) - Number(a[1].slice(a[1].lastIndexOf(':') + 1)));
    st.stalwartMap = new Map(arr.slice(0, STATE_MAX));
  }
  if (st.sentDone.size > STATE_MAX) {
    st.sentDone = new Set([...st.sentDone].slice(-STATE_MAX));
  }
  if (st.sentFail.size > 100) {
    st.sentFail = new Map([...st.sentFail].slice(-100));
  }
}
function loadState() {
  try {
    const data = JSON.parse(fs.readFileSync(CFG.stateFile, 'utf8'));
    return {
      synced: new Set(Array.isArray(data.synced) ? data.synced : []),
      stalwartMap: new Map(Object.entries(data.stalwartMap || {})),
      sentDone: new Set(Array.isArray(data.sentDone) ? data.sentDone : []),
      sentQueryState: typeof data.sentQueryState === 'string' ? data.sentQueryState : '',
      sentFail: new Map(Object.entries(data.sentFail || {})),
    };
  } catch (e) { return emptyState(); }
}
function saveState(st) {
  pruneState(st); // 先裁剪再落盘，控制文件大小与写盘开销
  const dir = path.dirname(CFG.stateFile);
  fs.mkdirSync(dir, { recursive: true });
  const tmp = CFG.stateFile + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify({
    updatedAt: new Date().toISOString(),
    synced: [...st.synced],
    stalwartMap: Object.fromEntries(st.stalwartMap),
    sentDone: [...st.sentDone],
    sentQueryState: st.sentQueryState,
    sentFail: Object.fromEntries(st.sentFail),
  }));
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
    let totalBytes = 0;
    const MAX_SINGLE = ATTACH_MAX_MB * 1024 * 1024;
    const MAX_TOTAL = ATTACH_TOTAL_MAX_MB * 1024 * 1024;
    for (const a of atts) {
      if (a.size && a.size > MAX_SINGLE) { console.warn('  附件超单文件上限跳过：' + (a.filename || a.key)); continue; }
      if (totalBytes >= MAX_TOTAL) { console.warn('  附件总量超限，剩余跳过'); break; }
      let bytes;
      try {
        const res = await fetchT(a.url); // 签名 URL（COS 私有桶）
        if (!res.ok) throw new Error('HTTP ' + res.status);
        bytes = Buffer.from(await res.arrayBuffer());
      } catch (e) {
        console.warn('  附件拉取失败 ' + (a.filename || a.key) + '：' + e.message);
        continue;
      }
      totalBytes += bytes.length;
      if (totalBytes > MAX_TOTAL) { console.warn('  附件总量超限，剩余跳过'); break; }
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
        else if (step === 1) { if (code === 250) { step = 2; sock.write('MAIL FROM:<' + cleanRcpt(CFG.email) + '>\r\n'); } }
        else if (step === 2) { if (code !== 250) return fail(new Error('MAIL FROM ' + line)); step = 3; sock.write('RCPT TO:<' + cleanRcpt(rcptTo) + '>\r\n'); }
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
  const r = await fetchT(CFG.jmapUrl + path, opts);
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

// ---------------- JMAP 反向同步（删除回写 / 发信导入） ----------------
const jmap = {
  accountId: null,
  mailboxIds: {}, // name -> id（进程内缓存）
  async session() {
    if (!this.accountId) {
      const session = await jmapFetch('', 'GET');
      this.accountId = session && session.primaryAccounts && session.primaryAccounts.mail;
      if (!this.accountId) throw new Error('JMAP 无 mail 账户');
    }
    return this.accountId;
  },
  // 通用调用：methodCalls = [[name, args, tag]]，返回 { 方法名: [响应,...] }
  async call(methodCalls) {
    const accountId = await this.session();
    const r = await jmapFetch('', 'POST', {
      using: ['urn:ietf:params:jmap:core', 'urn:ietf:params:jmap:mail'],
      methodCalls: methodCalls.map(([name, args, tag]) => [name, Object.assign({}, args, { accountId }), tag || 'm']),
    });
    const resp = {};
    for (const [name, data] of (r.methodResponses || [])) {
      if (!resp[name]) resp[name] = [];
      resp[name].push(data);
    }
    return resp;
  },
  async mailboxId(name) {
    if (this.mailboxIds[name] !== undefined) return this.mailboxIds[name];
    const r = await this.call([['Mailbox/query', { filter: { name }, limit: 10 }, 'mb']]);
    const ids = (r['Mailbox/query'] && r['Mailbox/query'][0] && r['Mailbox/query'][0].ids) || [];
    this.mailboxIds[name] = ids[0] || null;
    return this.mailboxIds[name];
  },
  // 当前收件箱全部邮件 ID（分页，上限 10000 防失控）
  async inboxIds() {
    const inboxId = await this.mailboxId('INBOX');
    if (!inboxId) return new Set();
    return this.mailboxEmailIds(inboxId);
  },
  // 指定文件夹全部邮件 ID（分页，上限 10000）
  async mailboxEmailIds(folderId) {
    const ids = new Set();
    for (let pos = 0; pos < 10000 && ids.size >= pos; pos = ids.size) {
      const r = await this.call([['Email/query', { filter: { inMailbox: folderId }, limit: 500, position: pos }, 'q']]);
      const list = ((r['Email/query'] && r['Email/query'][0]) ? r['Email/query'][0].ids : []) || [];
      if (!list.length) break;
      for (const id of list) ids.add(id);
      if (list.length < 500) break;
      if (ids.size >= 10000) break;
    }
    return ids;
  },
  // 确保文件夹存在（查询 → 不存在则创建），进程内缓存
  async ensureMailbox(name) {
    if (this.mailboxIds[name] !== undefined) return this.mailboxIds[name];
    let id = await this.mailboxId(name);
    if (!id) {
      const r = await this.call([['Mailbox/set', { create: { m0: { name } } }, 'ms']]);
      const created = ((r['Mailbox/set'] && r['Mailbox/set'][0]) ? r['Mailbox/set'][0].created : {}) || {};
      id = (created.m0 && created.m0.id) || null;
      if (!id) throw new Error('创建文件夹失败：' + name);
    }
    this.mailboxIds[name] = id;
    return id;
  },
  // 上传 raw MIME（RFC 8621 /upload）→ blobId
  async upload(raw) {
    const accountId = await this.session();
    const auth = 'Basic ' + Buffer.from(CFG.jmapUser + ':' + CFG.jmapPass).toString('base64');
    const url = CFG.jmapUrl.replace(/\/+$/, '') + '/upload/' + encodeURIComponent(accountId);
    const r = await fetchT(url, {
      method: 'POST',
      headers: { Authorization: auth, 'Content-Type': 'message/rfc822' },
      body: raw,
    });
    if (!r.ok) throw new Error('JMAP upload HTTP ' + r.status);
    const j = await r.json().catch(() => ({}));
    if (!j.blobId) throw new Error('JMAP upload 无 blobId');
    return j.blobId;
  },
  // Email/import 到指定文件夹，返回创建的 Stalwart email id
  async importEmail(raw, folderId, { seen = false, receivedAt = null } = {}) {
    const blobId = await this.upload(raw);
    const r = await this.call([['Email/import', {
      emails: {
        i0: {
          blobId,
          mailboxIds: { [folderId]: true },
          keywords: seen ? { '$seen': true } : {},
          receivedAt: receivedAt || null,
        },
      },
    }, 'imp']]);
    const created = ((r['Email/import'] && r['Email/import'][0]) ? r['Email/import'][0].created : {}) || {};
    const entry = created && created.i0;
    if (!entry || entry.type !== 'created' || !entry.id) throw new Error('JMAP Email/import 失败');
    return entry.id;
  },
};

// 按固定 Message-ID 查询 Stalwart 邮件 ID（返回 id 或 null，不修改状态）
async function queryStalwartId(key) {
  const emailId = key.slice(key.lastIndexOf(':') + 1);
  const mid = 'cloudmail-' + emailId + '@duckgame-play.top';
  const r = await jmap.call([['Email/query', { filter: { messageId: mid }, limit: 1 }, 'q']]);
  return ((r['Email/query'] && r['Email/query'][0]) ? r['Email/query'][0].ids : [])[0] || null;
}

// CloudMail 账户 → Stalwart 文件夹名（默认用账户邮箱地址，可用 STALWART_FOLDERS 覆盖）
function folderFor(acc) {
  return CFG.folderMap[acc.email] || acc.email;
}

// 删除同步（jmap 模式）：邮件移出"各号文件夹"（删除/移入垃圾桶/归档）→ CloudMail 垃圾桶
async function syncDeletes(st, folderIds) {
  if (!CFG.syncDelete || !st.stalwartMap.size || !folderIds.length) return;
  const activeIds = new Set();
  for (const fid of folderIds) {
    const ids = await jmap.mailboxEmailIds(fid);
    for (const id of ids) activeIds.add(id);
    if (activeIds.size >= 10000) break;
  }
  if (!activeIds.size) return; // 查询失败/空文件夹保护
  const toDelete = [];
  for (const [sid, key] of st.stalwartMap) {
    if (!activeIds.has(sid)) toDelete.push({ sid, key });
  }
  for (const { sid, key } of toDelete) {
    const emailId = key.slice(key.lastIndexOf(':') + 1);
    try {
      await cloud.delete([Number(emailId)]);
      st.stalwartMap.delete(sid);
      st.synced.delete(key); // 释放：若 CloudMail 端恢复，将重新镜像
      console.log('[' + new Date().toISOString() + '] 删除同步：' + key);
    } catch (e) {
      console.error('  删除 ' + key + ' 失败：' + e.message); // 下轮重试
    }
  }
}

// 恢复同步（垃圾桶/文件夹恢复 → CloudMail restore）：各号文件夹中"未登记"的 cloudmail-* 邮件，
// 说明其 CloudMail 端曾被移入垃圾桶（stalwartMap 已释放）→ 调 restore + 重新登记
async function syncRestores(st, folderIds) {
  if (!CFG.syncDelete || !folderIds.length) return;
  for (const fid of folderIds) {
    const ids = [...await jmap.mailboxEmailIds(fid)].filter(id => !st.stalwartMap.has(id));
    if (!ids.length) continue;
    for (let i = 0; i < ids.length; i += 100) {
      const batch = ids.slice(i, i + 100);
      const r = await jmap.call([['Email/get', { ids: batch, properties: ['messageId'] }, 'g']]);
      const list = ((r['Email/get'] && r['Email/get'][0]) ? r['Email/get'][0].list : []) || [];
      for (const e of list) {
        const mid = Array.isArray(e.messageId) ? e.messageId[0] : null;
        if (!mid || !mid.startsWith('cloudmail-')) continue; // 非镜像邮件（草稿/转发等）跳过
        const m = /^cloudmail-(\d+)@/.exec(mid);
        if (!m) continue;
        const emailId = Number(m[1]);
        const key = findKeyByEmailId(st, emailId);
        try {
          await cloud.restore([emailId]);
          // 登记防重复 restore（key 可能已释放；用 'r:' 虚拟 key，删除同步只取 emailId 部分）
          st.stalwartMap.set(e.id, key || ('r:' + emailId));
          console.log('[' + new Date().toISOString() + '] 恢复同步：' + mid);
        } catch (err) {
          console.error('  恢复 ' + mid + ' 失败：' + err.message);
        }
      }
    }
  }
}

// 从 stalwartMap 值（accountId:emailId）反查 key
function findKeyByEmailId(st, emailId) {
  for (const key of st.stalwartMap.values()) {
    if (Number(key.slice(key.lastIndexOf(':') + 1)) === emailId) return key;
  }
  return null;
}

function formatCloudTime(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return String(iso).slice(0, 19);
  const p = (n) => String(n).padStart(2, '0');
  return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate())
    + ' ' + p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
}

async function jmapDownload(accountId, blobId, name) {
  const base = CFG.jmapUrl.replace(/\/+$/, '');
  const url = base + '/download/' + encodeURIComponent(accountId) + '/' + encodeURIComponent(blobId) + '/' + encodeURIComponent(name);
  const auth = 'Basic ' + Buffer.from(CFG.jmapUser + ':' + CFG.jmapPass).toString('base64');
  const r = await fetchT(url, { headers: { Authorization: auth } });
  if (!r.ok) throw new Error('JMAP 下载 HTTP ' + r.status);
  return Buffer.from(await r.arrayBuffer());
}

async function importSentEmails(st, ids, accountByEmail) {
  for (let i = 0; i < ids.length; i += 50) {
    const batch = ids.slice(i, i + 50);
    const r = await jmap.call([['Email/get', {
      ids: batch,
      properties: ['messageId', 'from', 'to', 'cc', 'subject', 'textBody', 'htmlBody', 'attachments', 'date'],
    }, 'g']]);
    const list = ((r['Email/get'] && r['Email/get'][0]) ? r['Email/get'][0].list : []) || [];
    for (const e of list) {
      try {
        const from = Array.isArray(e.from) ? e.from[0] : null;
        if (!from || !from.email) { st.sentDone.add(e.id); console.warn('  已发送无发件人，跳过：' + e.id); continue; }
        const acc = accountByEmail.get(from.email);
        if (!acc) { st.sentDone.add(e.id); console.warn('  发件人 ' + from.email + ' 不是 CloudMail 账户，跳过导入'); continue; }
        const textBody = (e.textBody || []).find(b => b.type === 'text/plain');
        const htmlBody = (e.htmlBody || []).find(b => b.type === 'text/html');
        const attachments = [];
        let total = 0;
        const MAX_SINGLE = ATTACH_MAX_MB * 1024 * 1024;
        const MAX_TOTAL = ATTACH_TOTAL_MAX_MB * 1024 * 1024;
        for (const a of (e.attachments || [])) {
          if (a.disposition === 'inline' || !a.blobId) continue; // 内嵌图跳过（v1）
          if (a.size && a.size > MAX_SINGLE) { console.warn('  附件超上限跳过：' + (a.name || a.blobId)); continue; }
          if (total >= MAX_TOTAL) break;
          try {
            const buf = await jmapDownload(await jmap.session(), a.blobId, a.name);
            total += buf.length;
            if (total > MAX_TOTAL) break;
            attachments.push({ filename: a.name || 'attachment', mimeType: a.type || 'application/octet-stream', content: buf.toString('base64') });
          } catch (err) { console.warn('  附件下载失败 ' + (a.name || a.blobId) + '：' + err.message); }
        }
        // send 模式（方案 C）：CloudMail /api/email/send 限制附件 ≤10，超限截断
        const deliverAtts = CFG.sentMode === 'send' && attachments.length > 10
          ? (() => { console.warn('  [方案C] 附件 >10，CloudMail send 限制，仅投递前 10 个（共 ' + attachments.length + '）'); return attachments.slice(0, 10); })()
          : attachments;
        const body = {
          accountId: acc.accountId,
          sendEmail: from.email,
          name: from.name || acc.name || '',
          receiveEmail: (e.to || []).map(t => t.email).filter(Boolean),
          cc: (e.cc || []).map(t => t.email).filter(Boolean),
          subject: e.subject || '',
          text: textBody ? textBody.value : '',
          content: htmlBody ? htmlBody.value : '',
          messageId: Array.isArray(e.messageId) ? e.messageId[0] : null,
          createTime: formatCloudTime(e.date),
          attachments: deliverAtts,
        };
        const deliver = CFG.sentMode === 'send' ? cloud.send : cloud.importSent;
        await deliver(body);
        st.sentDone.add(e.id);
        st.sentFail.delete(e.id);
        console.log('[' + new Date().toISOString() + '] 发信同步' + (CFG.sentMode === 'send' ? '[Resend投递]' : '[镜像]') + '：' + (e.subject || '').slice(0, 50) + ' ← ' + from.email);
      } catch (err) {
        // 失败重试计数：连续 3 轮失败（多为确定性错误：附件超限/权限/账户不存在）→ 放弃防刷屏
        const cnt = (st.sentFail.get(e.id) || 0) + 1;
        st.sentFail.set(e.id, cnt);
        if (cnt >= 3) {
          st.sentDone.add(e.id);
          st.sentFail.delete(e.id);
          console.warn('  发信同步放弃 ' + (e.id || '') + '（连续失败 ' + cnt + ' 轮）：' + err.message);
        } else {
          console.warn('  发信同步失败 ' + (e.id || '') + '（第 ' + cnt + ' 轮，下轮重试）：' + err.message);
        }
      }
    }
  }
}

// 发信同步：Stalwart 已发送邮箱新增邮件 → 导入 CloudMail 已发送（不重复投递）
async function syncSent(st, accounts) {
  if (!CFG.syncSent) return;
  const sentId = await jmap.mailboxId(CFG.sentMailbox);
  if (!sentId) { console.warn('未找到 Stalwart 邮箱「' + CFG.sentMailbox + '」，发信同步跳过'); return; }
  const accountByEmail = new Map();
  for (const a of accounts) accountByEmail.set(a.email, a);

  // 首次启用：建立基线。默认不追溯历史（SYNC_SENT_HISTORY=1 才导入）
  if (!st.sentQueryState) {
    const q = await jmap.call([['Email/query', { filter: { inMailbox: sentId }, limit: 500 }, 'q']]);
    const res = q['Email/query'] && q['Email/query'][0];
    st.sentQueryState = (res && res.queryState) || '';
    for (const id of (res && res.ids) || []) st.sentDone.add(id);
    if (!CFG.syncSentHistory) {
      console.log('[' + new Date().toISOString() + '] 发信同步基线建立（历史 ' + st.sentDone.size + ' 条不追溯）');
      return;
    }
    await importSentEmails(st, [...st.sentDone], accountByEmail);
    return;
  }

  let qs = st.sentQueryState;
  for (let round = 0; round < 5; round++) {
    const r = await jmap.call([['Email/queryChanges', { filter: { inMailbox: sentId }, sinceQueryState: qs }, 'c']]);
    const res = r['Email/queryChanges'] && r['Email/queryChanges'][0];
    if (!res) break;
    qs = res.newQueryState || qs;
    const addedIds = (res.added || []).map(a => a.id).filter(id => !st.sentDone.has(id));
    if (addedIds.length) await importSentEmails(st, addedIds, accountByEmail);
    if (!res.hasMoreChanges) break;
  }
  st.sentQueryState = qs;
}

// ---------------- 主同步循环（多账户） ----------------
async function syncAccount(acc, rcpt, folderId, st) {
  let cursor = 0, page = 0, added = 0, fails = 0;
  const useJmap = CFG.delivery === 'jmap';
  try {
    while (true) {
      let emails;
      try { emails = await cloud.list(acc.accountId, cursor); }
      catch (e) { console.error('  列表失败（进度已保留，下轮重试）：' + e.message); break; }
      if (!emails.length) break;
      for (const m of emails) {
        const key = acc.accountId + ':' + m.emailId;
        if (st.synced.has(key)) continue;
        try {
          const detail = await cloud.detail(m.emailId);
          const raw = await buildMime(detail, m.emailId, useJmap ? acc.email : rcpt);
          let sid = null;
          if (useJmap) {
            // 幂等投递：先查 Stalwart 是否已有该 Message-ID（如垃圾桶恢复后），有则跳过 import
            const existing = await queryStalwartId(key);
            if (existing) {
              st.stalwartMap.set(existing, key);
            } else {
              sid = await jmap.importEmail(raw, folderId, { seen: !m.unread });
              st.stalwartMap.set(sid, key);
            }
          } else {
            await smtpSend(raw, rcpt);
            // SMTP 模式：通过固定 Message-ID 反查登记（供删除同步匹配）
            if (CFG.syncDelete && CFG.jmapUrl && CFG.jmapUser) {
              try { sid = await queryStalwartId(key); } catch (e) { /* 登记失败不阻塞 */ }
              if (sid) st.stalwartMap.set(sid, key);
            }
          }
          st.synced.add(key); added++;
          fails = 0;
          console.log('  [' + acc.email + '] 同步 ' + m.emailId + '：' + (m.subject || '').slice(0, 50));
        } catch (e) {
          fails++;
          console.error('  邮件 ' + m.emailId + ' 失败：' + e.message); // 下一轮重试
          // 连续 3 次失败（如 Stalwart 停机）→ 熔断本账户，避免每封都等超时
          if (fails >= 3) { console.error('  连续失败，暂停本账户本轮（下轮重试）'); break; }
        }
      }
      if (fails >= 3) break;
      const last = emails[emails.length - 1].emailId;
      if (emails.length >= CFG.page && last && last !== cursor) { cursor = last; page++; } else break;
      if (page > 50) break;
    }
  } finally {
    saveState(st); // 每账户同步完就落盘，防中途失败丢进度导致重复投递
  }
  if (added) console.log('[' + new Date().toISOString() + '] ' + acc.email + ' 新增 ' + added + ' 封');
}

async function syncOnce() {
  const st = loadState();
  const accounts = await cloud.accounts();
  if (!accounts.length) { console.warn('CloudMail 无可用账户'); return; }
  const useJmap = CFG.delivery === 'jmap';
  const folderIds = [];
  for (const acc of accounts) {
    const rcpt = cleanRcpt(CFG.accountMap[acc.email] || CFG.defaultRcpt);
    if (!useJmap && !rcpt) {
      // 仅 smtp 模式需要目标 Stalwart 邮箱；jmap 模式按账户邮箱创建文件夹投递
      console.warn('账户 ' + acc.email + ' 无目标 Stalwart 邮箱（STALWART_RCPT_TO/STALWART_ACCOUNTS），跳过');
      continue;
    }
    let folderId = null;
    if (useJmap) {
      try { folderId = await jmap.ensureMailbox(folderFor(acc)); }
      catch (e) { console.warn('  文件夹准备失败：' + e.message); }
      if (!folderId) continue; // jmap 模式必须能拿到文件夹
    }
    if (folderId) folderIds.push(folderId);
    try { await syncAccount(acc, rcpt, folderId, st); }
    catch (e) { console.error('  账户 ' + acc.email + ' 同步异常：' + e.message); saveState(st); }
  }
  if (CFG.jmapUrl && CFG.jmapUser) {
    if (CFG.syncDelete) {
      if (useJmap && folderIds.length) {
        try { await syncDeletes(st, folderIds); } catch (e) { console.warn('删除同步跳过（' + e.message + '）'); }
        try { await syncRestores(st, folderIds); } catch (e) { console.warn('恢复同步跳过（' + e.message + '）'); }
      } else {
        try { await syncDeletes(st); } catch (e) { console.warn('删除同步跳过（' + e.message + '）'); }
      }
    }
    if (CFG.syncSent) {
      try { await syncSent(st, accounts); } catch (e) { console.warn('发信同步跳过（' + e.message + '）'); }
    }
    try { await readBack(accounts); } catch (e) { console.warn('已读回写跳过（' + e.message + '）'); }
    saveState(st); // 持久化 sentQueryState / stalwartMap 变更
  }
}

async function main() {
  const jmapOn = !!(CFG.jmapUrl && CFG.jmapUser);
  const features = [];
  if (jmapOn) {
    if (CFG.syncDelete) features.push('删除回写');
    if (CFG.syncSent) features.push('发信导入');
    features.push('已读回写');
  }
  console.log('CloudMail→Stalwart 同步 v4 启动，轮询 ' + (CFG.interval / 1000) + 's'
    + (CFG.delivery === 'jmap' ? '，投递 JMAP 文件夹' : '，投递 ' + CFG.smtpHost + ':' + CFG.smtpPort)
    + (features.length ? '，反向同步：' + features.join('/') : '（未配置 JMAP，仅下行）')
    + (CFG.withAttachments ? '，附件开启' : ''));
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

