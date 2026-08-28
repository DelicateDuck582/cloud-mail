// CloudMail Reader — 后台脚本
// 职责：持有 JWT token、调 CloudMail HTTP API、把数据返回给页面。
// token 只存在 browser.storage.local，页面脚本通过 browser.runtime.sendMessage 间接获取数据，
// 页面自身永远拿不到 token（防插件页面 XSS 窃取）。

const DEFAULT_BASE = 'https://mail.duckgame-play.top';
const LIST_SIZE = 30;
// 邮件类型：与后端 emailConst.type 对应（0=收件 1=发件）
const TYPE_MAP = { receive: 0, send: 1 };

async function getToken() {
  const { token } = await browser.storage.local.get('token');
  return token || null;
}

// 统一 API 调用：带 Authorization 头；返回后端业务 JSON（{code,message,data}）
async function apiCall(path, { method = 'GET', body } = {}) {
  const token = await getToken();
  const headers = {};
  if (body) headers['Content-Type'] = 'application/json';
  if (token) headers['Authorization'] = token;
  const res = await fetch(DEFAULT_BASE + path, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  const json = await res.json().catch(() => ({}));
  return json; // { code, message, data }
}

browser.runtime.onMessage.addListener(async (msg) => {
  try {
    switch (msg.type) {
      case 'login': {
        const r = await apiCall('/api/login', {
          method: 'POST',
          body: { email: msg.email, password: msg.password },
        });
        if (r.code === 200 && r.data && r.data.token) {
          await browser.storage.local.set({ token: r.data.token });
          return { ok: true, token: r.data.token };
        }
        return { ok: false, message: r.message || '登录失败' };
      }

      case 'logout': {
        const token = await getToken();
        if (token) {
          try { await apiCall('/api/logout', { method: 'DELETE' }); } catch (e) { /* 忽略服务端失败 */ }
        }
        await browser.storage.local.remove('token');
        return { ok: true };
      }

      case 'checkAuth': {
        const token = await getToken();
        return { ok: !!token };
      }

      case 'accounts': {
        const r = await apiCall('/api/account/list?size=30');
        if (r.code === 401) return { ok: false, authExpired: true };
        return { ok: r.code === 200, data: r.data, message: r.message };
      }

      case 'list': {
        const typeNum = TYPE_MAP[msg.mailType] !== undefined ? TYPE_MAP[msg.mailType] : 0;
        const qs = new URLSearchParams({
          accountId: msg.accountId || 0,
          emailId: msg.emailId || 0,
          size: msg.size || LIST_SIZE,
          type: typeNum,
          full: 0,
          timeSort: 0,
        }).toString();
        const r = await apiCall('/api/email/list?' + qs);
        if (r.code === 401) return { ok: false, authExpired: true };
        return { ok: r.code === 200, data: r.data, message: r.message };
      }

      case 'detail': {
        const r = await apiCall('/api/email/detail?emailId=' + encodeURIComponent(msg.emailId));
        if (r.code === 401) return { ok: false, authExpired: true };
        return { ok: r.code === 200, data: r.data, message: r.message };
      }

      default:
        return { ok: false, message: 'unknown message type' };
    }
  } catch (e) {
    console.error('CloudMail Reader background error:', e);
    return { ok: false, message: '网络错误：无法访问 ' + DEFAULT_BASE };
  }
});
