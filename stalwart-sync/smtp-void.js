#!/usr/bin/env node
/**
 * 哑 SMTP 收集器（方案 C：发信走 CloudMail Resend API）
 *
 * 作用：Stalwart 的 outbound relay 指向本机该端口。收到邮件后应答「投递成功」并**丢弃内容**，
 *       Stalwart 认为已投递（邮件从出站队列移除），副本保留在 Stalwart Sent。
 *       真正的投递由同步脚本调用 CloudMail POST /api/email/send（Resend，HTTPS 不走 25）完成。
 *
 * 安全：
 *  - 仅允许监听回环地址（127.0.0.1/localhost/::1），防变成开放 SMTP 中继
 *  - 每连接数据上限 SMTP_VOID_MAX_MB（默认 30MB），超出即断开
 *  - 无数据超时 SMTP_VOID_IDLE_MS（默认 60s）自动断开
 *  - 内容不落盘、不记录正文，仅打印 from/rcpt/字节数
 *
 * 环境变量：
 *   SMTP_VOID_HOST      默认 127.0.0.1
 *   SMTP_VOID_PORT      默认 2526
 *   SMTP_VOID_MAX_MB    默认 30
 *   SMTP_VOID_IDLE_MS   默认 60000
 */
'use strict';
const net = require('node:net');

const HOST = process.env.SMTP_VOID_HOST || '127.0.0.1';
const PORT = Number(process.env.SMTP_VOID_PORT || 2526);
const MAX_BYTES = (Number(process.env.SMTP_VOID_MAX_MB || 30) || 30) * 1024 * 1024;
const IDLE_MS = Number(process.env.SMTP_VOID_IDLE_MS || 60000);

const LOOPBACK = new Set(['127.0.0.1', 'localhost', '::1']);
if (!LOOPBACK.has(HOST)) {
  console.error('[安全] smtp-void 仅允许监听回环地址，防变成开放 SMTP 中继，已拒绝启动');
  process.exit(1);
}


const server = net.createServer((sock) => {
  sock.setTimeout(IDLE_MS);
  sock.on('timeout', () => sock.destroy());
  sock.on('error', () => { /* 客户端断开，忽略 */ });

  let recv = Buffer.alloc(0);   // 行模式缓冲（非 DATA 阶段）
  let dataBuf = Buffer.alloc(0); // DATA 阶段累积（Buffer，二进制安全）
  let inData = false;
  let lastFrom = '';
  let lastRcpt = '';

  const respond = (code, text) => sock.write(code + (text ? ' ' + text : '') + '\r\n');
  const dump = (label) => console.log('[' + new Date().toISOString() + '] smtp-void ' + label + ' from=' + lastFrom + ' rcpt=' + lastRcpt);
  // 优雅关闭：先 FIN flush 响应，50ms 后强制断开，防半开连接死锁（客户端仍继续发送时）
  const hardClose = () => { sock.end(); setTimeout(() => sock.destroy(), 50); };

  sock.write('220 smtp-void ESMTP ready\r\n');

  // DATA 终止符：`\r\n.\r\n`（正文行首 '.' 会被 SMTP dot-stuffing，故该序列只可能是终止符）
  const DOT_TERM = Buffer.from('\r\n.\r\n');

  // 行模式：逐行处理命令
  function handleLines() {
    let idx;
    while ((idx = recv.indexOf(10)) !== -1) { // 0x0A
      const line = recv.slice(0, idx).toString('utf8').replace(/\r$/, '');
      recv = recv.slice(idx + 1);
      const cmd = line.toUpperCase();

      if (cmd.startsWith('EHLO') || cmd.startsWith('HELO')) {
        respond(250, 'localhost');
      } else if (cmd.startsWith('MAIL FROM')) {
        lastFrom = line.slice(line.indexOf(':') + 1).trim();
        respond(250, 'OK');
      } else if (cmd.startsWith('RCPT TO')) {
        lastRcpt = line.slice(line.indexOf(':') + 1).trim();
        respond(250, 'OK');
      } else if (cmd.startsWith('DATA')) {
        inData = true;
        respond(354, 'End data with <CR><LF>.<CR><LF>');
        // 同一 TCP 段里 DATA 后的剩余字节是邮件内容（pipeline），并入 dataBuf 并立即检查终止
        if (recv.length) { dataBuf = Buffer.concat([dataBuf, recv]); recv = Buffer.alloc(0); }
        checkDataDone();
        return;
      } else if (cmd.startsWith('RSET')) {
        lastFrom = ''; lastRcpt = '';
        respond(250, 'OK');
      } else if (cmd.startsWith('STARTTLS')) {
        respond(502, 'Command not implemented');
      } else if (cmd.startsWith('NOOP')) {
        respond(250, 'OK');
      } else if (cmd.startsWith('QUIT')) {
        respond(221, 'Bye');
        sock.end();
        return;
      } else {
        respond(500, 'Unknown command');
      }
    }
    if (recv.length > 4096) { respond(552, 'Line too long'); return hardClose(); }
  }

  // DATA 阶段：检查是否已收到终止符；是则丢弃内容、回 250、剩余字节回行模式
  function checkDataDone() {
    const idx = dataBuf.indexOf(DOT_TERM);
    if (idx === -1) return;
    const rest = dataBuf.slice(idx + DOT_TERM.length);
    dump('收件并丢弃（bytes=' + idx + '）');
    dataBuf = Buffer.alloc(0);
    inData = false;
    respond(250, 'OK: queued as void');
    // 终止符后的剩余字节（如 pipeline 的 QUIT）交回行模式
    if (rest.length) {
      recv = Buffer.concat([recv, rest]);
      if (recv.indexOf(10) !== -1) handleLines();
    }
  }

  sock.on('data', (chunk) => {
    if (inData) {
      dataBuf = Buffer.concat([dataBuf, chunk]);
      if (dataBuf.length > MAX_BYTES) { respond(552, 'Message too large'); return hardClose(); }
      checkDataDone();
      return;
    }
    recv = Buffer.concat([recv, chunk]);
    handleLines();
  });
});

server.on('error', (e) => { console.error('smtp-void 错误：', e.message); process.exit(1); });
server.listen(PORT, HOST, () => console.log('[smtp-void] 监听 ' + HOST + ':' + PORT + '（丢弃最大 ' + (MAX_BYTES / 1024 / 1024) + 'MB）'));
