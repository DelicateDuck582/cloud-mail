// smtp-void.js 临时自测：模拟 Stalwart relay 的 SMTP 会话（原始客户端）
const { spawn } = require('child_process');
const net = require('net');

const HOST = '127.0.0.1', PORT = 25261;
const child = spawn('node', ['smtp-void.js'], { env: { ...process.env, SMTP_VOID_PORT: String(PORT), SMTP_VOID_MAX_MB: '1' } });
child.stdout.on('data', d => console.log('[smtp-void]', d.toString().trim()));

let pass = 0, fail = 0;
const ok = (c, n) => { if (c) { pass++; console.log('  OK ' + n); } else { fail++; console.log('  FAIL ' + n); } };
const ready = new Promise((res) => child.stdout.on('data', (d) => { if (d.toString().includes('监听')) res(); }));

// 逐步发送 steps，收到 [235]xx 响应后自动发下一个；返回收到的回复数组
function session(steps) {
  return new Promise((resolve) => {
    const sock = net.connect(PORT, HOST);
    let buf = '', replies = [], i = 0;
    sock.on('data', (d) => {
      buf += d.toString('utf8');
      let idx;
      while ((idx = buf.indexOf('\r\n')) !== -1) {
        const line = buf.slice(0, idx); buf = buf.slice(idx + 2);
        replies.push(line);
        if (/^[235]\d\d/.test(line) && i < steps.length) { sock.write(steps[i++]); }
      }
    });
    sock.on('close', () => resolve(replies));
    sock.on('error', (e) => { console.log('  [client-socket-error] ' + e.message + ' replies=' + replies.length); });
    sock.write(steps[i++]);
  });
}

setTimeout(async () => {
  await ready; // 等 smtp-void 完成监听
  // 会话 1：正常投递 → 丢弃成功
  const s1 = ['EHLO localhost\r\n', 'MAIL FROM:<a@b.c>\r\n', 'RCPT TO:<d@e.f>\r\n', 'DATA\r\n', 'Subject: t\r\n\r\nbody\r\n.\r\n', 'QUIT\r\n'];
  const r1 = await session(s1);
  ok(r1[5] === '250 OK: queued as void' && r1[6] === '221 Bye', 'DATA 收完 250 + QUIT 221（丢弃成功）');

  // 会话 2：STARTTLS 拒绝
  const r2 = await session(['EHLO localhost\r\n', 'STARTTLS\r\n', 'QUIT\r\n']);
  ok(r2[2] === '502 Command not implemented', 'STARTTLS 502（Stalwart relay 应配 no-encryption）');

  // 会话 3：超 1MB 回 552 并断开
  const big = 'X'.repeat(1100 * 1024);
  const r3 = await session(['EHLO localhost\r\n', 'MAIL FROM:<a@b.c>\r\n', 'RCPT TO:<d@e.f>\r\n', 'DATA\r\n',
    'Subject: big\r\n\r\n' + big + '\r\n.\r\n']);
  ok(r3[5] === '552 Message too large', '超 1MB 断开前回 552');

  console.log('\n结果：' + pass + ' 通过，' + fail + ' 失败');
  child.kill();
  process.exit(fail ? 1 : 0);
}, 800);

// 守卫：非回环监听应拒绝启动
const guard = spawn('node', ['smtp-void.js'], { env: { ...process.env, SMTP_VOID_HOST: '0.0.0.0' } });
let guardExit = null;
guard.on('exit', (c) => { guardExit = c; });
setTimeout(() => {
  if (guardExit === 1) { console.log('  OK 非回环监听被拒绝启动（exit 1）'); }
  else { console.log('  FAIL 非回环守卫失效'); fail++; }
  guard.kill();
}, 1500);


