// CloudMail Reader — 设置页：触发 URL / Token
const $ = (id) => document.getElementById(id);

async function load() {
  const cfg = await browser.storage.local.get(['triggerUrl', 'triggerToken']);
  $('url').value = cfg.triggerUrl || 'https://sync.duckgame-play.top/trigger';
  $('token').value = cfg.triggerToken || '';
}

$('save').addEventListener('click', async () => {
  await browser.storage.local.set({
    triggerUrl: $('url').value.trim(),
    triggerToken: $('token').value.trim(),
  });
  $('status').textContent = '已保存 ✓';
  setTimeout(() => ($('status').textContent = ''), 1500);
});

load();
