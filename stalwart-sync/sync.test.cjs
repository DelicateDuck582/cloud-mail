// sync.js 回归测试（stub JMAP/CloudMail，不联网）。运行：node sync.test.cjs
process.env.CLOUDMAIL_EMAIL = 't@example.com';
process.env.CLOUDMAIL_PASSWORD = 'x';
process.env.STATE_FILE = require('path').join(__dirname, '_test_state.json');
const fs = require('fs');
const path = require('path');
let src = fs.readFileSync(__dirname + '/sync.js', 'utf8');
src = src.replace(/^#!.*\n/, '');
src = src.replace(/main\(\)\.catch[\s\S]*$/, '');
const fn = new Function('require', src + '\nreturn { pruneState, cleanRcpt, buildMime, formatCloudTime, syncDeletes, syncRestores, syncSent, queryStalwartId, jmap, cloud, loadState, saveState, emptyState, STATE_MAX, CFG, folderFor };');
const api = fn(require);
let pass = 0, fail = 0;
const ok = (c, n) => { if (c) { pass++; console.log('  OK ' + n); } else { fail++; console.log('  FAIL ' + n); } };

(async () => {
  console.log('1) formatCloudTime');
  ok(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(api.formatCloudTime('2026-08-28T10:20:30Z')), 'ISO->CloudMail 时间格式');
  ok(api.formatCloudTime('') === '', '空输入');

  console.log('2) 状态 round-trip');
  const st = api.emptyState();
  st.synced.add('1:100'); st.stalwartMap.set('S1', '1:100'); st.sentDone.add('A'); st.sentQueryState = 'QS9';
  api.saveState(st);
  const st2 = api.loadState();
  ok(st2.synced.has('1:100') && st2.stalwartMap.get('S1') === '1:100' && st2.sentDone.has('A') && st2.sentQueryState === 'QS9', '全字段恢复');

  console.log('3) pruneState');
  const big = api.emptyState();
  for (let i = 0; i < 12000; i++) { big.synced.add('1:' + i); big.stalwartMap.set('S' + i, '1:' + i); big.sentDone.add('S' + i); }
  api.pruneState(big);
  ok(big.synced.size <= api.STATE_MAX && big.stalwartMap.size <= api.STATE_MAX && big.sentDone.size <= api.STATE_MAX, '裁剪到上限内');
  ok(big.synced.has('1:11999') && big.stalwartMap.get('S11999') === '1:11999', '保留最新');

  console.log('4) syncDeletes');
  const stD = api.emptyState();
  stD.stalwartMap.set('SA', '1:100'); stD.stalwartMap.set('SB', '1:99'); stD.synced.add('1:99');
  let delCalls = [];
  api.jmap.mailboxEmailIds = async () => new Set(['SA']);
  api.cloud.delete = async (ids) => { delCalls.push(ids); return 0; };
  await api.syncDeletes(stD, ['F1']);
  ok(delCalls.length === 1 && delCalls[0][0] === 99, '仅删移出文件夹的 1:99');
  ok(!stD.stalwartMap.has('SB') && stD.stalwartMap.has('SA'), '映射清理');
  ok(!stD.synced.has('1:99'), 'synced 释放');

  console.log('5) syncDeletes 失败重试');
  const stF = api.emptyState();
  stF.stalwartMap.set('SC', '1:50');
  api.jmap.mailboxEmailIds = async () => new Set([]);
  api.cloud.delete = async () => { throw new Error('x'); };
  await api.syncDeletes(stF, ['F1']);
  ok(stF.stalwartMap.has('SC'), '失败保留映射');

  console.log('6) queryStalwartId（幂等投递检查）');
  const stR = api.emptyState();
  api.jmap.call = async (calls) => calls[0][0] === 'Email/query' ? { 'Email/query': [{ ids: ['SX'] }] } : {};
  const qid = await api.queryStalwartId('1:42');
  ok(qid === 'SX', 'Message-ID 反查返回 id');

  console.log('7) syncSent 基线（不追溯）');
  const stB = api.emptyState();
  api.jmap.mailboxId = async () => 'SENT-ID';
  let importCalls = 0;
  api.jmap.call = async (calls) => calls[0][0] === 'Email/query' ? { 'Email/query': [{ ids: ['a', 'b'], queryState: 'QS1' }] } : {};
  api.cloud.importSent = async () => { importCalls++; return {}; };
  await api.syncSent(stB, [{ accountId: 1, email: 'u@duckgame-play.top' }]);
  ok(stB.sentDone.size === 2 && stB.sentQueryState === 'QS1', '基线记录');
  ok(importCalls === 0, '不追溯历史');

  console.log('8) syncSent 增量导入');
  const stI = api.emptyState();
  stI.sentQueryState = 'QS0'; stI.sentDone.add('a');
  api.jmap.mailboxId = async () => 'SENT-ID';
  api.jmap.call = async (calls) => {
    const n = calls[0][0];
    if (n === 'Email/queryChanges') return { 'Email/queryChanges': [{ newQueryState: 'QS1', added: [{ id: 'b' }], hasMoreChanges: false }] };
    if (n === 'Email/get') return { 'Email/get': [{ list: [{ id: 'b', from: [{ name: '小明', email: 'u@duckgame-play.top' }], to: [{ email: 'x@y.com' }], cc: [], subject: '你好', textBody: [{ type: 'text/plain', value: '正文' }], htmlBody: [{ type: 'text/html', value: '<p>正文</p>' }], messageId: ['mid-1'], date: '2026-08-28T10:20:30Z', attachments: [] }] }] };
    return {};
  };
  let body = null;
  api.cloud.importSent = async (b) => { body = b; return {}; };
  await api.syncSent(stI, [{ accountId: 1, email: 'u@duckgame-play.top' }]);
  ok(body && body.accountId === 1 && body.receiveEmail[0] === 'x@y.com' && body.subject === '你好', '导入参数');
  ok(body && body.text === '正文' && body.content === '<p>正文</p>' && body.messageId === 'mid-1', '正文/Message-ID');
  ok(stI.sentDone.has('b') && stI.sentQueryState === 'QS1', '增量推进');

  console.log('9) syncSent 非 CloudMail 发件人');
  const stX = api.emptyState();
  stX.sentQueryState = 'QS0';
  api.jmap.mailboxId = async () => 'SENT-ID';
  api.jmap.call = async (calls) => {
    const n = calls[0][0];
    if (n === 'Email/queryChanges') return { 'Email/queryChanges': [{ newQueryState: 'QS1', added: [{ id: 'c' }], hasMoreChanges: false }] };
    if (n === 'Email/get') return { 'Email/get': [{ list: [{ id: 'c', from: [{ email: 'stranger@evil.com' }], to: [], subject: 's', textBody: [], htmlBody: [], attachments: [] }] }] };
    return {};
  };
  let skip = 0;
  api.cloud.importSent = async () => { skip++; return {}; };
  await api.syncSent(stX, [{ accountId: 1, email: 'u@duckgame-play.top' }]);
  ok(skip === 0 && stX.sentDone.has('c'), '跳过且标记完成（防刷）');

  console.log('10) 发信同步 send 模式（方案 C）');
  const stS = api.emptyState();
  stS.sentQueryState = 'QS0';
  api.CFG.sentMode = 'send';
  api.jmap.mailboxId = async () => 'SENT-ID';
  api.jmap.call = async (calls) => {
    const n = calls[0][0];
    if (n === 'Email/queryChanges') return { 'Email/queryChanges': [{ newQueryState: 'QS1', added: [{ id: 's1' }], hasMoreChanges: false }] };
    if (n === 'Email/get') return { 'Email/get': [{ list: [{ id: 's1', from: [{ email: 'u@duckgame-play.top' }], to: [{ email: 'x@y.com' }], cc: [], subject: 'hi', textBody: [{ type: 'text/plain', value: 't' }], htmlBody: [], messageId: ['m1'], date: '2026-08-28T10:20:30Z', attachments: [] }] }] };
    return {};
  };
  let sendCalls = 0, importCalls2 = 0;
  api.cloud.send = async () => { sendCalls++; return {}; };
  api.cloud.importSent = async () => { importCalls2++; return {}; };
  await api.syncSent(stS, [{ accountId: 1, email: 'u@duckgame-play.top' }]);
  ok(sendCalls === 1 && importCalls2 === 0, 'send 模式调 /api/email/send（不走 import-sent）');
  ok(stS.sentDone.has('s1'), 'send 成功后标记完成');

  console.log('11) send 失败重试 3 轮放弃');
  const stRetry = api.emptyState();
  stRetry.sentQueryState = 'QS0';
  api.jmap.mailboxId = async () => 'SENT-ID';
  let failN = 0;
  api.jmap.call = async (calls) => {
    const n = calls[0][0];
    if (n === 'Email/queryChanges') return { 'Email/queryChanges': [{ newQueryState: 'QS' + (failN + 1), added: [{ id: 'f1' }], hasMoreChanges: false }] };
    if (n === 'Email/get') return { 'Email/get': [{ list: [{ id: 'f1', from: [{ email: 'u@duckgame-play.top' }], to: [{ email: 'x@y.com' }], cc: [], subject: 's', textBody: [], htmlBody: [], attachments: [] }] }] };
    return {};
  };
  api.cloud.send = async () => { failN++; throw new Error('模拟失败'); };
  for (let round = 0; round < 3; round++) { stRetry.sentQueryState = 'QS' + round; await api.syncSent(stRetry, [{ accountId: 1, email: 'u@duckgame-play.top' }]); }
  ok(failN === 3 && stRetry.sentDone.has('f1'), '连续失败 3 轮后放弃并标记完成');
  ok(!stRetry.sentFail.has('f1'), '放弃后清除失败计数');

  console.log('12) syncRestores 垃圾桶恢复');
  const stR2 = api.emptyState();
  stR2.stalwartMap.set('EXIST', '1:100'); // 已登记 → 不处理
  console.log('[dbg] stR2.stalwartMap.size=' + stR2.stalwartMap.size + ' has EXIST=' + stR2.stalwartMap.has('EXIST'));
  let restoreCalls = [];
  api.jmap.mailboxEmailIds = async () => new Set(['R1', 'EXIST']);
  api.jmap.call = async (calls) => {
    const n = calls[0][0];
    if (n === 'Email/get') {
      const reqIds = (calls[0][1].ids || []);
      const all = [
        { id: 'R1', messageId: ['cloudmail-42@duckgame-play.top'] },
        { id: 'EXIST', messageId: ['cloudmail-100@duckgame-play.top'] },
        { id: 'D1', messageId: ['<native-mid@stalwart>'] },
      ];
      return { 'Email/get': [{ list: all.filter(x => reqIds.includes(x.id)) }] };
    }
    return {};
  };
  api.cloud.restore = async (ids) => { restoreCalls.push(ids); return 0; };
  await api.syncRestores(stR2, ['F1']);
  ok(restoreCalls.length === 1 && restoreCalls[0][0] === 42, '仅恢复未登记的 cloudmail-42（已有/非镜像跳过）');
  ok(stR2.stalwartMap.has('R1'), '恢复后登记防重复');

  console.log('13) jmap.importEmail（JMAP 文件夹投递核心）');
  api.jmap.session = async () => 'ACCT';
  api.jmap.upload = async (raw) => { ok(Buffer.isBuffer(raw) || typeof raw === 'string', 'upload 收到 raw MIME'); return 'BLOB1'; };
  let importArgs = null;
  const origCall = api.jmap.call;
  api.jmap.call = async (calls) => {
    const n = calls[0][0];
    if (n === 'Email/import') { importArgs = calls[0][1]; return { 'Email/import': [{ created: { i0: { type: 'created', id: 'NEWID' } } }] }; }
    return origCall(calls);
  };
  const newId = await api.jmap.importEmail('RAW', 'FOLDERX', { seen: true });
  ok(newId === 'NEWID', 'import 返回创建 id');
  ok(importArgs && importArgs.emails.i0.blobId === 'BLOB1' && importArgs.emails.i0.mailboxIds.FOLDERX === true, 'blob 与文件夹正确');
  ok(importArgs && importArgs.emails.i0.keywords['$seen'] === true, '已读关键词正确');

  console.log('14) folderFor 文件夹映射');
  ok(api.folderFor({ email: 'contact@ciallo.sale' }) === 'contact@ciallo.sale', '默认用账户邮箱作文件夹名');
  api.CFG.folderMap = { 'contact@ciallo.sale': '联系邮箱' };
  ok(api.folderFor({ email: 'contact@ciallo.sale' }) === '联系邮箱', 'STALWART_FOLDERS 覆盖');

  try { fs.unlinkSync(path.join(__dirname, '_test_state.json')); } catch (e) {}
  console.log('\n结果：' + pass + ' 通过，' + fail + ' 失败');
  process.exit(fail ? 1 : 0);
})();
