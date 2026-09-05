# COS Worker 通信 / 安全 / 性能审计报告（browse-alist）

> 分支：`browse-alist`（HEAD `db375ca`，doc/cos-proxy-worker.js = `6385075`）
> 审计日期：2026-09-05
> 审计对象：`doc/cos-proxy-worker.js`（cos-exchange，`cos.<域名>`）
> 对照基准：mail-worker 侧取 `attachment-manager`（`3770547`，含 v3.3.0 整合）
> 范围：通信一致性、安全、性能三项；**不改部署行为前不修改代码，先出报告**

---

## 0. 架构回顾（审计上下文）

```
mail-vue ──(settings.r2Domain = cos.<域名>)──▶ cos-exchange Worker
                                                 │  1) /attachments/* 强制 HMAC 验签
                                                 │  2) 验签后 Cache API 按 path 缓存
                                                 │  3) 回源私有 COS（S3 V4 签名，只读子账号）
                                                 ▼
                                              私有 COS 桶
```

mail-worker 签发侧（attachment-manager `sign-utils.js`）：
- `sign = hex(HMAC-SHA256(secret, "/<key>:<expires>"))`，key 形如 `attachments/<32hex>.<ext>`
- URL = `r2Domain + "/" + key + "?expires=&sign="`（key 原样拼入，未 encode）

cos-worker 验签侧（本文件 `verifySignature`）：
- `pathname = decodeURIComponent(url.pathname)`（浏览器编码后的 pathname 解码还原 key）
- `expected = hex(HMAC-SHA256(secret, "<pathname>:<expires>"))`
- 二者等价：`/<key>` == `/attachments/xxx` == decode 后 pathname ✅（已实测 4/4 通过，含中文/空格/%）

---

## 1. 通信审计

### 1.1 结论：两侧签名协议一致（未发现通信缺陷）

| 项 | mail-worker 签发 | cos-worker 验签 | 一致 |
|---|---|---|---|
| 算法 | HMAC-SHA256 hex | HMAC-SHA256 hex | ✅ |
| message | `/${key}:${expires}` | `${decode(pathname)}:${expires}` | ✅ 等价 |
| 密钥 | `ATT_SIGN_SECRET`（trim） | `ATT_SIGN_SECRET`（trim） | ✅ 需两侧同值 |
| 时间 | `ATT_SIGN_TTL` 默认 900 | `ATT_SIGN_MAX_TTL` 默认 3600 | ✅ 900<3600 |
| 比较 | `timingSafeEqual` | `timingSafeEqual` | ✅ |
| 大小写 | sign 小写 hex | `.toLowerCase()` | ✅ |

- 附件 key 实际为 `attachments/<32位 hex>.<ext>`（SHA-256 前 16 字节 hex），key 本身无用户可控路径段；
  ext 来自用户文件名后缀，**可能含中文/空格/%** → 通信已通过 decode/encode 处理（实测通过）。
- 签名有效期双保险：前端签发 ≤ATT_SIGN_TTL；worker 侧 ≤ATT_SIGN_MAX_TTL 拒绝超长，非法值兜底 3600。
- **无绕过**：验签先于缓存查找、先于回源。Referer/Sec-Fetch 作为签名之外的二道防线，对 `isSignedOk` 放宽（签名本身就是凭证），对 `/static/` 不放松。
- KV 回退路径（mail-worker 直读 `/attachments`）与 COS 路径共用同一验签逻辑，通信一致。

### 1.2 运维注意（非代码缺陷）

1. **TTL 两侧需同步**：若把 mail-worker `ATT_SIGN_TTL` 调大（如 7200），必须同步调 cos-worker
   `ATT_SIGN_MAX_TTL` ≥7200，否则合法长签名会被 worker 拒绝 → 附件在 1 小时后 403。
   建议部署清单固定两值配对（如 900 / 3600 或 3600/7200）。
2. **密钥轮换窗口**：改 `ATT_SIGN_SECRET` 时旧附件 URL 立即失效，需选择低峰期，并清空
   cos-worker 的 Cache API（若无需保留旧缓存）。

---

## 2. 安全审计

### 2.1 整体评估：安全设计良好，未发现可被利用的高危/中危漏洞

已有防护（逐条确认）：
- ✅ 路径白名单：只代理 `/attachments/`、`/static/`、`/browse`
- ✅ 方法白名单：GET/HEAD only（登录 POST 特判）
- ✅ `/attachments/` HMAC 验签前置，防伪造/重放（有效期 + 短 TTL）
- ✅ 双层访问控制（Referer 域名 + Sec-Fetch-Site/Dest）
- ✅ Cache-Control `private`（禁 CF 边缘缓存绕过验签/密码门控）
- ✅ CORS 白名单只放行邮件域；响应剥离 `x-cos-request-id`
- ✅ `/browse` 密码 cookie：HMAC-SHA256 指纹（非明文）+ HttpOnly + Secure + SameSite=Lax
  + 恒定时间比较 + 指纹缓存
- ✅ 登录：可选 Turnstile + 同 IP 5 次/10 分钟锁定 + 1s 延迟 + 失败 Map 定期清理
- ✅ 限流：list 40/分、file 120/分（per-IP，内存实现有上限清理）
- ✅ key 路径穿越拦截（绝对路径 / 反斜杠 / `../`）
- ✅ 错误脱敏：列表失败只回 error 字段；COS 域名/签名中间值只在服务端日志
- ✅ COS 健康探测 30s 缓存，防放大
- ✅ 前端 XSS：esc() 全量转义 + `<script>` 内 `\uXXXX`、HTML 实体
- ✅ HEAD/Range 不写缓存（防污染同 path 的 GET 缓存）

### 2.2 观察项 / 建议（按优先级）

**[低] A. `/static/` 无签名 + 7 天缓存**
- `/static/`（登录背景等）仅靠 Referer/Sec-Fetch，命中后缓存 7 天。
  若某 static 资源被误删/更换，最长 7 天才失效。静态资源通常不变，风险可接受。
- 建议：若将来允许用户上传背景，需要把 /static/ 也纳入签名或白名单管理。

**[低] B. 附件响应未强制 `Content-Disposition`**
- cos-worker 透传 COS 响应头。COS 存储时未设 ContentDisposition 的附件，浏览器可能
  直接内联打开（如 HTML/SVG）——COS 桶只读子账号 + 私有 + 签名，实际仅收件人可访问；
  mail 正文又有 XSS 清洗。残留风险很小。
- 建议：COS 上传时统一 `Content-Disposition: attachment`（除内嵌图 image/* 外），
  或 cos-worker 对非 image Content-Type 追加 attachment。

**[低] C. `rateLimited` 用 `x-forwarded-for` 兜底**
- `clientIP` 优先 `CF-Connecting-IP`（可信），无 CF 头才用 XFF（可伪造）。
  生产全走 CF，风险极低。与 attachment-manager 侧待办 #3 相同。

**[低] D. COS 健康探测在未登录页也执行**
- `/browse` 未登录访问会触发 `probeCosHealth`（30s 缓存 1 次），无放大。
  未配置 BROWSE_PASS 时先探测再弹登录页，浪费 1 次探测但无害。

**[低] E. 附件列表接口不暴露 key 的 URL 编码差异**
- signContent 用正则 `attachments/[^"'<>?]+` 抓 key，若文件名含 `"` `<` `>` `?`
  不会被签 → 内嵌图不显示。实际 key 是 hex+ext，ext 理论可含这些字符（少见）。
  低风险；如需彻底可让后端存 key 时把 ext 白名单化。

### 2.3 未发现

- 未发现验签旁路（缓存绕过签名检查）
- 未发现 COS 密钥/桶名泄露到客户端
- 未发现存储型 XSS 直达（页面模板全转义）
- 未发现登录绕过 / cookie 伪造（指纹密钥独立于密码）

---

## 3. 性能审计

### 3.1 缓存设计

| 路径 | 缓存 | TTL | 说明 |
|---|---|---|---|
| `/attachments/*` GET 200 | Cache API 按 path | 7 天 | 附件 key=内容哈希，命中后不再回源 COS |
| `/static/*` GET 200 | Cache API 按 path | 7 天 | 同上 |
| HEAD / 206 / Range / 非200 | 不写缓存 | — | 防污染 GET 缓存 |
| `/browse/api/file` GET 200 | Cache API 按 path | 7 天 | 缩略图/重复下载降源 |
| 视频/音频 Range | 直连回源 | — | Cache API 不支持 206，交给 COS |

**性能良好**：验签→缓存→回源三级，正常邮件附件打开走 Cache 命中（0 COS 回源），
同文件 7 天内只回源一次。Cache-Control private 禁边缘缓存，不绕过验签。

### 3.2 CPU/IO 热点

- 每个附件请求做 1 次 HMAC（importKey+sign）+ timingSafeEqual，开销可忽略。
- 每次回源（miss）做 1 次 S3 V4 签名（4 次 HMAC importKey）。miss 是少数。
- XML 列表解析为逐条 regex，目录大时 O(n)，受 max-keys=200 限制，可控。
- 限流 Map 超 5000 全清（防内存），登录失败 Map 定期 GC（>1万清理）。

### 3.3 建议（低优先）

1. **S3 V4 签名可加 100~300ms 退避重试**（browseFetchFile 已有 600ms 重试；
   附件主流程没有重试）。COS 偶发 429/5xx 时附件直接失败。→ 低成本高收益。
2. **缓存键可规范化**：当前 cacheKey 用 `url.origin+url.pathname`（原始编码形式）。
   同 key 若以不同编码到达（极少），会多存一份。无安全影响，仅轻微冗余。
3. **HMAC key import 可复用**：每次 importKey(secret) 相同，可在模块级缓存
   `crypto.subtle.importKey` 结果（secret 不变时）。当前每请求 importKey，
   实测开销小，属可选微优化。

---

## 4. 验证记录

| 项 | 结果 |
|---|---|
| node --check（语法） | ✅ |
| 通信一致性实测（普通/中文/空格/% key） | ✅ 4/4 |
| 未跟踪敏感文件扫描（doc/） | ✅ 无真实密钥 |
| 工作区状态 | 干净 |

## 6. 已实施修复（本次审计落地，2026-09-05）

对 `doc/cos-proxy-worker.js`（browse-alist）主流程的三处加固，均通过语法检查与 11/11 回归测试：

| # | 修复 | 位置 | 说明 |
|---|---|---|---|
| F1 | 附件/静态回源**加 10s 超时 + 429/5xx 重试一次（600ms 退避）** | fetch 回源 | 与 /browse 下载路径一致；此前 COS 抖动附件直接 5xx |
| F2 | 响应剥离 `x-cos-hash-crc64ecma` + 加 `X-Content-Type-Options: nosniff` | 响应头 | 与 browseFetchFile 对齐；防 MIME 嗅探 |
| F3 | 非 200 不缓存；**206/3xx 透传、4xx/5xx 脱敏**（不透传 COS XML，防桶名泄露） | 非 200 分支 | 404→404 'Not Found'、5xx→502 'Upstream Error'、429 保留 |

> ⚠️ `doc/cos-proxy-worker.js` 是**构建产物**，部署用文件在仓库外 `web开发\cos-proxy-worker.js`。
> 以上修复如需上线，需同步到部署文件（直接替换或经 `_parts` 构建源重出）。
> 验证记录：`node --check` ✅；回归 11/11 ✅；附件路径不涉及 Range（mail-vue 用 `<a download>`），206 透传为将来预留。


## 7. 遗留待办（未在本轮实施）

- [ ] P2：COS 上传 Content-Disposition 规范化（attachment vs inline）——mail-worker 侧（attachment-manager）
- [ ] P3：TTL 两侧配对写进部署文档（ATT_SIGN_TTL ≤ ATT_SIGN_MAX_TTL）
- [ ] P4：（可选）HMAC key import 模块级缓存 / cacheKey 规范化


