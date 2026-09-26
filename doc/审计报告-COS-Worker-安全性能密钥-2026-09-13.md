# COS Worker 安全 / 性能 / 密钥审计报告（2026-09-13）

> 审计对象：`doc/cos-proxy-worker.js`（cos-exchange Worker，域名 `cos.duckgame-play.top`）
> 审计版本：SHA256 `974D7CDFD93F9F3E075F88BE6B4402A5AFC206E6F111FAE04C159822879F1026`（192031 字节 / gzip 56007 字节）
> 分支与提交：`browse-alist` `1f701b6`（本报告随该提交归档）；同步副本 `attachment-manager` `92c914c`
> 审计方式：**可执行审计**——在 Node 内真实执行 Worker 代码（mock COS 回源 / KV / Cache API / IP 头），
> 而非仅阅读源码；安全断言 + 性能实测 + 密钥 canary 扫描 + 静态上界检查
> （首轮 61 项；**2026-09-13 晚复审扩展至 88 项**，新增续期面与 mail 契约两组，见 §8；
> **2026-09-18 修复两条信息级发现 + CLI 部署，见 §9；2026-09-25 容量策略改造，矩阵扩至 124 项，见 §10；
> 2026-09-25 限速与节流（可读 429 + 客户端排队）扩至 149 项，见 §11**）
> 审计脚本（仓库外，`web开发\`）：`_audit-security.mjs`、`_audit-perf.mjs`、`_audit.mjs`（既有密钥扫描）
> 不在本次范围：`mail-worker`（CloudMail 主体）的登录/发信/JWT 逻辑；本 Worker 只负责附件验签与 COS 回源

---

## 0. 审计结论（对应需要确认的三点）

| # | 待确认项 | 结论 | 关键依据（实测） |
|---|---|---|---|
| 1 | **mail 主体通信无安全问题** | ✅ 成立 | 附件签名与 mail-worker 侧口径一致（`hex(HMAC-SHA256(secret, "<path>:<expires>"))`、解码后验签、TTL 上限 86400/默认 3600）；**无签名 / 伪造 / 过期 / 跨 key / 超长有效期**全部 403，且**一次都没触发 COS 回源**；验签在缓存查找之前，缓存命中不能绕过 |
| 2 | **COS 无盗刷流量风险** | ✅ 成立（附条件，见 R1/R2） | 未签名/伪造请求回源 **0 次**；合法签名首次 **1 次**、Cache API 命中后 **0 次**（7 天）；`/static/` 有 per-IP 限流（第 121 次 429）；无开放代理（仅 `/attachments/`、`/static/` 两个前缀，其余 403）；`/temp` 全部走 KV，**不碰 COS** |
| 3 | **无「无权访问 / 越权访问」数据安全问题** | ✅ 成立 | 未登录拿不到任何列表/文件（fail-closed，`/browse/api/list` 只回登录页）；伪造会话、KV 中不存在/格式非法的会话、退出后复用的会话全被拒；`key` 穿越（`../`、绝对路径、`\`）400、编码式穿越不产生目录上溯（COS 请求路径无 `../`）；`/temp` 未登录上传/删除被拒且 **KV 写入 0 次**；`/static/` 属"公开前缀"策略（R3） |

未发现：可绕过签名读取 `attachments/*` 的路径、可利用的响应头注入/XSS、密钥或桶名外泄到任何响应、开放重定向、SSRF（回源地址只来自 `S3_ENDPOINT` 环境变量）。

---

## 1. 审计范围与方法

| 维度 | 方法 | 规模 |
|---|---|---|
| 安全 | 攻击矩阵，逐项断言 HTTP 状态 + 是否回源 + 响应内容 | 61 项断言（A~G 七组），全部通过 |
| 密钥 | 向 env 注入 canary 值（8 个密钥 + 假桶名 + 假 region），跑遍页面/API/错误路径，扫描响应体与全部响应头 | 23 个响应 × 11 个 canary，零命中 |
| 密钥（静态） | 项目自带 `_audit.mjs`：已知泄露值（`b7f29a1d` 等）+ 通用 `secret/password=` 模式 | 1 处既有误报（见 §3 F8） |
| 性能 | 体积/gzip、单请求密码学耗时、每请求 COS 回源次数、页面体积、内存与循环上界、正则回溯、冷启动 | 5 组实测 |
| 覆盖不到的 | Cloudflare 边缘缓存、真实 KV 最终一致性延迟、真实 COS 边界行为 | 以代码路径推理判定并标注 |

**攻击矩阵分组**：A 入口与路径白名单（10）｜B 附件签名/防盗刷/缓存（17）｜C `/static/` 双层校验与限流（5）｜
D `/browse` 鉴权+会话+2FA+CSRF（22 + 1 INFO）｜E `/temp` 鉴权与越权（8）｜F 跨前缀越权与错误信息（7）｜G 密钥 canary 全量扫描（3）。

---

## 2. 关键证据（实测输出摘录）

```
A 非白名单路径 403（/etc/passwd, /attachments(无斜杠), /attachmentsx/1, /tmp/x, /browse2, /api/init）
  → 且 COS 回源 0 次（不是开放代理）           POST /attachments → 405
B 无签名 403 + 回源0 ｜ 伪造 403 + 回源0 ｜ 过期 403 + 回源0 ｜ expires>MAX_TTL 403
  合法签名 200 + 回源1 ｜ 缓存已填后无签名仍 403（回源0）｜ A 的签名访问 B → 403
  中文/空格 key 编码后 200 ｜ 畸形 %zz → 403（不 500）｜ HEAD 不污染 GET 缓存
C 无 Referer 403 + 回源0 ｜ Referer+Sec-Fetch 合法 200 ｜ cross-site 403 ｜ 第 121 次 429
D 未登录 /browse/api/list 只回登录页（无 folders/files 字段）｜ 伪造会话 → 登录页
  大写 UUID 会话（即便存在于 KV）→ 登录页 ｜ 合法会话 → 主界面 + JSON
  KV 读取异常时登录 503（fail-closed，不降级为仅密码）｜ 2FA 无码/错码 401、正确码 302
  Set-Cookie: browse_sess=<随机 UUID>; HttpOnly; Secure; SameSite=Lax; Max-Age=604800
  跨站 Origin 的 POST → 403 ｜ 退出后同会话立即失效
E 未登录 /temp 只回登录页 ｜ 未登录上传/删除被拒且 KV 写入 0 ｜ 5 次失败后 429
F /static/../attachments/… → 403（仍需签名）｜ %2e%2e 被 URL 规范化 → /static/ 无 Referer 403
  列表错误回包 {"error":"list failed 403"}（无桶域名/StringToSign）
## 3. 发现清单（F1–F10）

| # | 级别 | 发现 | 状态 |
|---|---|---|---|
| F1 | 中 | 附件 **HEAD 预检被改写成 404** | ✅ 本次已修（`1f701b6`） |
| F2 | 低 | 列表错误回包**泄露 COS 原始 XML**（可能含 `<Resource>` 桶域名） | ✅ 本次已修（`1f701b6`） |
| F3 | 中（可用性） | 登录页 **2FA 输入框门控条件错误**（只绑 `TEMP_KV` 时会把用户锁死） | ✅ 本次已修（`1f701b6`） |
| F4 | 低 | `auth:totp` 存在但结构非法时**判为未绑定 → fail-open** | 建议修（R4） |
| F5 | 低 | 内存限流/锁定 Map 在阈值处**整体清空**，分布式来源可冲掉计数 | 建议加固（R5） |
| F6 | 提示 | `/static/` 前缀为公开策略（Referer/Sec-Fetch 可伪造） | 策略约束（R3） |
| F7 | 提示 | 会话未绑定 IP（KV 里存了 `ip` 但未校验） | 可接受 |
| F8 | 提示 | `_audit.mjs` 唯一告警为既有误报（`otpauth` URI 的 `?secret=` 拼接） | 无需处理 |
| F9 | 低 | `/browse/api/list` 对"扩展名不可识别"的文件会额外触发 ≤24 次 COS 头读（嗅探） | 可接受（R6） |
| F10 | 提示 | `/temp` 未登录即可从提示页看出是否配置了 `TEMP_PASS`/KV | 可接受（便于运维排障） |

### F1（中，已修）附件 HEAD 预检被改写成 404
- 现象：`HEAD /attachments/<key>?expires=…&sign=…`（签名合法）→ **404 "Not Found"**；同一 URL 用 GET → 200。
- 根因：成功响应只对 `status===200 && method==='GET'` 走缓存分支，其余一律落入"非 200 脱敏"分支，
  末尾 `upstream >= 500 ? 502 : 404` 把 200 的 HEAD 映射成 404。
- 影响：下载管理器/邮件客户端/预览器的 HEAD 预检误判"文件不存在"（不涉及数据泄露）。
- 修复：在缓存分支后新增 HEAD 200 透传分支（返回 `null` body + 原响应头）。

### F2（低，已修）列表错误回包泄露 COS 细节
- 现象：COS 返回非 2xx 时，`error` 字段被拼上 COS 响应体前 300 字符；`Myqcloud` 的
  `AccessDenied/NoSuchBucket` 等 XML 含 `<Resource>桶域名</Resource>`；文案还固定写
  `(SignatureDoesNotMatch)`，对非签名错误有误导。
- 影响：已登录（知道 `/browse` 密码）者可读到桶域名等部署细节。
- 修复：客户端只收到 `list failed <status>`；COS 响应体片段移入 `cosBody`，与
  `ourSTS/cosSTS/sentUrl` 一起仅进服务端日志（`console.error`）。

### F3（中，已修）登录页 2FA 输入框门控
- 现象：`browseLoginHtml` 用 `env.BROWSE_KV` 判断是否渲染验证码输入框，而 `authStore(env) = BROWSE_KV || TEMP_KV`。
  只绑定 `TEMP_KV` 时（文档中允许的配置），2FA 密钥存在 `TEMP_KV` → 服务端登录要求动态码，
  但页面不显示输入框 → **用户永久登不进去**。
- 修复：改用 `authStore(env)`（页面源码 `_parts/02_login.txt`，经构建器产出）。

### F4（低，建议修）`auth:totp` 结构非法时 fail-open
- 实测（INFO 行）：把 `auth:totp` 写成合法 JSON 但缺 `secret` 字段 → 登录**未要求动态码即放行**（302）。
- 说明：该值只由本 Worker 写入（`{secret, at}`），正常运维不会出现；仅在 KV 数据被手工改坏/版本迁移不兼容时触发。
- 建议：`getTotp` 增加显式结构校验——值存在但 `secret` 非 16–64 位 Base32 时，视作"配置损坏"，
  登录路径返回 503（fail-closed）而不是当作未绑定（详见 R4）。

### F5（低，建议加固）内存限流可被"冲掉"
- `rateLimited` 在 `rateMap.size > 5000` 时 **clear 全表**；`loginFailMap` 在 >1 万/2 万时清理或清空。
- 影响：具备大量出口 IP 的攻击者可周期性把计数器清空，使限流/登录锁定短暂失效（单 IP 仍受限）。
- 建议：换成带 TTL 的分片计数、或直接叠 Cloudflare Rate Limiting / WAF 规则做硬限（R5）。

---

## 4. 性能实测

| 指标 | 结果 | 说明 |
|---|---|---|
| 体积 | **192031 字节**（gzip 56007 / 54.7 KiB），3764 行 | 部署文件与仓库副本字节一致；Workers 脚本上限余量充足 |
| 附件验签 CPU | **0.044–0.045 ms/op** | `verifySignature`（`importKey`+`sign`+恒定时间比较），每请求 1 次 |
| 单次 HMAC | 0.036 ms/op | S3 V4 回源签名 ≈ 4 次 HMAC + 1 次 SHA256，**仅缓存未命中时**执行 |
| COS 回源（附件） | 未命中 **1 次** / 命中 **0 次** / 未签名 **0 次** | Cache API 按 path 缓存 7 天，验签先于缓存 |
| COS 回源（其它） | `/browse` 首页 1 次（30 秒内二次 **0**，探针缓存）；`list` 1 次/页；`file` 1 次；`/static/` 1 次 | 无 N+1 |
| COS 回源（临时网盘） | `list`/`upload` **0 次**（纯 KV） | 临时文件不落 COS，不产生 COS 流量 |
| 页面体积 | `/browse` 登录 5.5 KB（gzip 2.5）、主界面 59.4 KB（16.6）；`/temp` 登录 5.2 KB（2.4）、主界面 34.2 KB（10.8） | 含内联 CSS/JS，无外部资源请求 |
| 内存上界 | `sessionCache` >500 清空、`sniffCache` >5000 半清、`rateMap` >5000 清空、`loginFailMap` 1 万/2 万、前端任务/日志 200 | 长会话不无界增长 |
| 循环上界 | `tempList` ≤10 页 ×1000；嗅探 ≤24 项、并发 4；`per_page` ≤200；`prefix` ≤1024、`token` ≤2048 | 用户可控参数全部截断/封顶 |
| 正则 | 4 处 `[\s\S]*?` 跨行匹配（解析 ≤200 条 COS XML） | 输入受 `max-keys` 限制，无灾难性回溯面 |
| 冷启动 | 模块作用域 `await` **0**、`setInterval` **0** | 仅常量与 Map 初始化，无启动期 I/O |

---

## 5. 残余风险与建议（R1–R6）

| # | 项 | 级别 | 建议 |
|---|---|---|---|
| R1 | 内存限流为"尽力而为" | 中 | 在 CF 控制台对 `cos.<域名>` 加 **Rate Limiting 规则**（如 `/attachments/*` 300 次/分/IP、`/browse/login` 10 次/分/IP），把 R5 的绕过面兜住 |
| R2 | `/static/` 前缀无签名 | 中 | 该前缀按设计公开（Referer/Sec-Fetch 可伪造，仅靠 per-IP 限流）。**切勿把私有文件放进 `static/`**；若必须放，改用 `/attachments/`（走签名） |
| R3 | 同上（策略口径） | 提示 | `/static/` 已加 per-IP 限流 120 次/分，且被 Cache API 缓存（内容不变不重复回源），流量面可控 |
| R4 | `auth:totp` 结构非法 → fail-open（F4） | 低 | 建议在 `getTotp` 增加"值存在但结构非法 → 抛错"的分支，使登录路径 503 而非静默降级 |
| R5 | 限流 Map 清空策略（F5） | 低 | 改为分片 + TTL 清理，或依赖 R1 的边缘限流 |
| R6 | 嗅探放大（F9） | 低 | 已有 7 天结果缓存 + 单次 ≤24 项 + 并发 4 + 列表限流 40 次/分；如目录内大量无扩展名文件，可把上限调小或改为前端按需触发 |

**运维建议（非代码）**
- 确认 `cos-exchange` 绑定的 KV 命名空间**独立**于 mail-worker 的 KV（本 Worker 会读写 `tmp/*`、`sess:*`、`auth:totp`；虽只按精确 key/前缀操作，但混用不利隔离）。
- `ATT_SIGN_SECRET` 两侧一致；`ATT_SIGN_MAX_TTL`（cos）≥ `ATT_SIGN_TTL`（mail，默认 900）。
- 签名密钥轮换时旧附件 URL 立即失效，需在低峰期执行。

---

## 6. 复现方式

```powershell
# 1) 安全审计（当前 149 项攻击矩阵 A–K 十一组；mock COS/KV/Cache，不触网）
cd "E:\DEVE 开发\web开发"
node _audit-security.mjs "cloud-mail-fork\doc\cos-proxy-worker.js"
#   → 期望：PASS=149  FAIL=0 ；"ALL SECURITY CHECKS PASSED"
#     （历史基线：§0–§7 为 61 项，§8 为 88 项，§9 为 90 项，§10 为 124 项，§11 起为 149 项）

# 2) 性能审计（体积/CPU/回源次数/页面体积/上界）
node _audit-perf.mjs "cloud-mail-fork\doc\cos-proxy-worker.js"

# 3) 密钥扫描（项目既有脚本，需先在被测文件所在目录运行）
#    把 doc/cos-proxy-worker.js 复制为临时目录下的 cos-proxy-worker.js 后：
node _audit.mjs
```

脚本说明：`_audit-security.mjs` 会把被测文件复制成 `.mjs` 再 `import`（仓库内为 ESM 语法的 `.js`）；
mock 的 COS 回源会把每次请求计数并记录 URL，因此"回源次数""COS 请求路径"可断言。
`_audit-security.mjs` 中 `INFO F4` 行为"信息级发现"，不影响退出码。

---

## 7. 与既有审计的关系

| 报告 | 日期 | 侧重点 | 结果 |
|---|---|---|---|
| `doc/审计报告-COS-Worker-通信安全性能-2026-09-05.md` | 2026-09-05 | 与 mail-worker 的**签名口径一致性**（StringToSign/密钥/TTL/比较方式）+ 主流程加固（超时重试、脱敏、nosniff） | 3 处加固已落地 |
| **本报告** | 2026-09-13 | **可执行攻击矩阵**（入口/签名/缓存/鉴权/越权/CSRF/密钥 canary）+ 性能实测 | 61/61 通过；修 F1/F2/F3；列 F4–F10 与 R1–R6 |

两次结论一致：**未发现可绕过签名读取附件、未发现无鉴权读取 COS、未发现密钥外泄**；
本次新增的结论点是"缓存命中不绕过验签""HEAD 不污染缓存""编码式穿越不产生目录上溯""/temp 完全不产生 COS 流量"均已被实测覆盖。

---

## 8. 复审（2026-09-13 晚）：新增「文件续期」后的安全/越权复审

> 触发：`/temp` 新增 `POST /temp/api/renew`（文件续期）+ 上传任务面板
> 被测版本：`browse-alist` `d9cd744` 的 `doc/cos-proxy-worker.js`（blob `9fdf1e2f…`，197560 字节）
> 结论：**88 项断言（A–I 九组）全部通过**，另 1 条信息级发现（无安全影响）

| 组 | 覆盖 | 断言数 | 结果 |
|---|---|---|---|
| A | 入口 / 根跳转 / favicon / 路径白名单 / 方法限制 | 10 | ✅ |
| B | 附件签名（无签名·伪造·过期·超长 TTL·跨 key·编码一致性·缓存绕过·HEAD） | 14 | ✅ |
| C | `/static/` Referer/Sec-Fetch 双层校验 + per-IP 限流 | 5 | ✅ |
| D | `/browse` 鉴权 / 会话伪造 / 2FA fail-closed / CSRF / 退出 | 15 | ✅ |
| E | `/temp` 未登录上传删除 / 锁定 / CSRF / 未配置提示 | 7 | ✅ |
| F | 跨前缀越权与错误信息脱敏 | 7 | ✅ |
| G | 密钥 canary 全量扫描（23 响应 × 11 canary，含响应头） | 3 | ✅ |
| **H** | **新增：`/temp` 续期面 + KV 命名空间隔离（越权 / 刷流量）** | **20** | ✅ |
| **I** | **新增：mail 后端通信契约（算法 / 路径绑定 / TTL 边界）** | **7** | ✅ |

### 8.1 H 组：续期面与 KV 越权（20 项）

- 未登录续期 → 返回**登录页**（fail-closed，不是 JSON）；带 `Origin: https://evil.example` 的续期 POST → **403**（CSRF 纵深防御）
- **越权尝试全部被拒且"零副作用"**（同时用 KV stub 记录 put/delete 调用）：
  | 尝试的 key | 结果 | KV 副作用 |
  |---|---|---|
  | `auth:totp`（2FA 密钥） | 400 | put 0 / delete 0 |
  | `sess:<uuid>`（登录会话） | 400 | put 0 / delete 0 |
  | `tmp/../auth:totp` | 400 | put 0 / delete 0 |
  | `tmp/x`（不存在） | 404（**不会创建/复活**） | put 0 / delete 0 |
- `POST /temp/api/delete` 同样**删不掉** `auth:totp` / `sess:*`（400 且 delete 0 次）→ 无法借临时网盘接口绕过 2FA 或踢会话
- 缺 `key` 字段 → 400；`GET /temp/api/renew` 不执行任何动作
- 上传**忽略客户端提交的 `key` 字段**（服务端自生成 `tmp/<id>`；断言 `tmp/hack-attempt` 未被写入 KV）
- 续期响应**只含元数据**（响应体不含文件内容字节 `opqrs`）；续期后**文件内容逐字节不变**（下载读回比对）；`expireAt` 确实延后
- **整个 `/temp` 流程（上传 → 续期 → 下载 → 删除）触发 0 次 COS 回源**（回源计数断言）⇒ 临时网盘不产生 COS 流量，无盗刷面

### 8.2 I 组：与 mail 后端的通信契约（7 项）

按 mail-worker `sign-utils.signKeys` 的**真实算法**（`key` 含 `attachments/` 前缀、`message = "/" + key + ":" + expires`、`ATT_SIGN_TTL` 默认 900s）生成 URL 并打到代理：

| 用例 | 期望 | 实测 |
|---|---|---|
| mail 默认 TTL（900s）签名 | 200 | ✅ 200（两端契约一致） |
| `expires - now = 3600`（= cos 侧 `ATT_SIGN_MAX_TTL`） | 200 | ✅ 200 |
| `expires - now = 3601` | 403 | ✅ 403（TTL 配对生效） |
| 篡改 `expires` 但沿用原 `sign` | 403 | ✅ 403（expires 参与签名） |
| 换成 `/attachments/other.png` 用同一签名 | 403 | ✅ 403（签名绑定完整路径） |
| 中文/空格 key（mail 侧原始 key 签名 ↔ 代理侧解码后验签） | 200 | ✅ 200 |
| 少写 `/attachments/` 前缀 | 403 | ✅ 403（前缀是签名的一部分） |

→ 结论：**与 mail 后端的 API 通信没有问题**（算法/消息格式/前缀/编码/TTL 上限两端一致，越界即拒）。

### 8.3 信息级发现（无安全影响，已记录）

| # | 观察 | 说明与建议 |
|---|---|---|
| I1 | `TEMP_KEY_RE` 带 `i` 标志，`TMP/x` 能通过格式校验 | 键名仍按**原样**查 KV（KV 大小写敏感）→ 取不到 → 404，无法借此访问其它键；若要与 KV 语义严格一致可去掉 `i` 标志（纯整洁性） |
| I2 | POST-only 端点（`/temp/api/upload`、`/api/delete`、`/api/renew`）的 GET 请求返回 **404** 而非 405 | 不执行任何动作、不返回数据；仅 HTTP 语义不够精确，可按需补 405 |

### 8.4 与前次审计（§0–§7）的关系

前次的 F1–F10、R1–R6 仍有效；本次复审在**不改动业务逻辑**的前提下把矩阵扩到续期面与 mail 契约，
结论未变：**未发现可绕过签名读取附件、未发现无鉴权/越权访问 COS 或 KV 其它命名空间、未发现密钥外泄、未发现可放大 COS 回源的新路径**（续期只读写 `tmp/*`，`/temp` 全流程 0 次 COS 回源）。

---

## 9. 修复与上线部署（2026-09-18）

> 触发：维护者要求「修掉 §8.3 的两条信息级发现 + 用 wrangler CLI 上传 CF」。
> 被测/部署版本：`doc/cos-proxy-worker.js`，**198230 字节**（+670），
> sha256 `E53CBBDE0976925CFD4268B027785EECA3DA52DFBCB62CA517D1B418D66E969D`（仓库副本与部署文件逐字节一致）。
> 结论：**矩阵扩为 90 项（A–I 九组）全部通过（FAIL=0）**；两条信息级发现已修复，并在**生产环境用真实密码实测生效**。

### 9.1 代码修复（仅 2 处，未触碰签名/鉴权/COS 回源/mail 契约）

| # | 位置 | 修改 | 效果 |
|---|---|---|---|
| I1 | `TEMP_KEY_RE`（worker.js:642） | `/^tmp\/[a-z0-9-]+$/i` → **去掉 `i` 标志** | `TMP/x` 等大小写变体在校验阶段即判非法 → **400**（原先 404）；与 KV 大小写敏感语义严格一致 |
| I2 | `handleTemp`（worker.js:937–943） | 新增 POST-only 端点方法门控：`/temp/api/upload`、`/temp/api/delete`、`/temp/api/renew` 上非 POST → **405 + `Allow: POST`** | GET/HEAD 不再落到 404；门控放在**密码门控之后**，未登录访问仍先见登录页，不额外暴露接口面 |

### 9.2 复测（本地 mock，90 项）

```powershell
cd "E:\DEVE 开发\web开发"
node _audit-security.mjs "cloud-mail-fork\doc\cos-proxy-worker.js"   # PASS=90 FAIL=0 → ALL SECURITY CHECKS PASSED
node _audit-perf.mjs     "cloud-mail-fork\doc\cos-proxy-worker.js"   # 体积/CPU/回源/页面体积/上界 无回归
```

| 组 | A–G | H（续期面 + KV 越权） | I（mail 契约） | 合计 |
|---|---|---|---|---|
| 断言数 | 61 | 20 | 7 → **9** | **90** |

- H 组：原「`GET /temp/api/renew` 不执行动作（404/405 均可）」这 1 条，替换为 **3 条**明确断言（登录后 `GET /temp/api/{renew,upload,delete}` → 405 且含 `Allow: POST`）；`TMP/x` 的期望值由 404 改为 400。
- 其余组断言不变，全部通过；G 组密钥 canary（23 响应 × 11 canary）仍为 0 命中。

### 9.3 CLI 部署（wrangler，新增可复现配置）

新增 `doc/cos-exchange.wrangler.toml`（与"面板粘贴代码"等价，但可复现、可回滚）：

```powershell
cd mail-worker
npx wrangler deploy -c ../doc/cos-exchange.wrangler.toml
```

| 配置 | 值 | 为什么 |
|---|---|---|
| `compatibility_date` | `"2026-08-10"` | 先用 `wrangler versions view` 读出线上现值，保持一致，避免运行时语义漂移 |
| **`keep_vars`** | `true` | **必须**：CLI 部署默认会**删除所有明文变量**。线上有 `ATT_SIGN_MAX_TTL="3600"`、`BROWSE_ALLOW_COUNTRY="CN,JP"`、`REGION="ap-osaka"`、`TEMP_PASS` —— 漏掉会直接打断 `/browse`（COS 探活失败→503）与 `/temp`（未配置密码→提示页） |
| Secrets | 不声明 | Secrets 不会被部署删除：`ATT_SIGN_SECRET`、`AWS_ACCESS_KEY_ID`、`AWS_SECRET_ACCESS_KEY`、`BROWSE_PASS`、`S3_ENDPOINT`、`TURNSTILE_SITEKEY`、`TURNSTILE_SECRET` |
| `[[kv_namespaces]]` | `BROWSE_KV=086c531c…`、`TEMP_KV=f527c223…` | 必须与线上一致，否则 `/browse` 2FA 会话与 `/temp` 临时网盘失效 |
| `routes` | 不声明 | 已有自定义域（`cos.<域名>`）保持原样 |
| **`preview_urls`** | `false` | **CLI 首次部署默认会为版本生成公网预览 URL**（实测 `https://ade8635f-cos-exchange.<账号>.workers.dev/` 可访问）；关闭后新旧预览 URL 均 **404** |

部署输出：`Total Upload: 167.81 KiB / gzip: 44.10 KiB`、`Worker Startup Time: 1–2 ms`；
版本 `ade8635f-3961-48dc-9c66-6ee624e43506`（首推，带预览 URL）→ **`9c10d23c-58e5-4ec0-9d00-88d173c517c4`（最终，`preview_urls=false`）**。

> 网络：`api.cloudflare.com` **直连可用**（`curl` 实测有响应、`wrangler versions view` 正常），本次部署无需代理；
> 本地 10808 代理（`-x socks5h://127.0.0.1:10808`）仅用于验证"外网可达性"（workers.dev / 预览 URL）。

### 9.4 部署后核对（关键：变量/密钥/绑定未丢）

`npx wrangler versions view 9c10d23c… --name cos-exchange` 复核：

- `Compatibility Date: 2026-08-10`（未变）
- **7 个 Secret** 全在；**2 个 KV 绑定** ID 未变；**4 个环境变量**（`ATT_SIGN_MAX_TTL` / `BROWSE_ALLOW_COUNTRY` / `REGION` / `TEMP_PASS`）值与部署前一致

线上烟测（部署前基线与部署后同一 URL 集合对比）：

| 请求 | 部署前 | 部署后 |
|---|---|---|
| `GET /` | 302 → `mail.duckgame-play.top` | 302（同） |
| `GET /browse` | 200 / 6901 B | 200 / 6901 B |
| `GET /temp` | 200 / 6186 B | 200 / 6186 B |
| `GET /attachments/test.png`（无签名） | 403 / body 9 B | 403 / body 9 B（哈希一致） |
| `GET /temp/api/renew`（未登录） | 200（登录页） | 200（登录页，符合设计） |
| `GET /favicon.ico` | 204 | 204 |

页面体量一致；正文差异**仅为 CF 自身注入的** `window.__CF$cv$params={r:'<ray>',t:'<ts>'}`（每请求变化）⇒ Worker 输出未变、绑定/变量接线等价。

### 9.5 生产环境 E2E（真实密码 + 真实 KV，走自定义域）

| 步骤 | 期望 | 实测 |
|---|---|---|
| `POST /temp/login`（正确密码，带同源 `Origin`） | 302 + `Set-Cookie` | ✅ 302 |
| `POST /temp/api/upload`（`file=`20B 文本） | 200 + `file.key` | ✅ `tmp/mu733i2k-9484dc9c061705dc` |
| `POST /temp/api/renew`（key=该文件） | 200，`added=604800`、`expireAt` 延后 | ✅ |
| **`GET /temp/api/renew`（已登录）** | **405 + `Allow: POST`**（I2 修复实证） | ✅ 405 / `Allow: POST` |
| **`POST /temp/api/renew`，key=`TMP/x`** | **400**（I1 修复实证） | ✅ 400 |
| `GET /temp/api/file?key=…&dl=1` | 内容逐字节一致 | ✅ 一致（20 B） |
| `POST /temp/api/delete`（key=该文件） | 200 `{"ok":true}` | ✅ |
| `GET /temp/api/list` | 已无该 key | ✅（测试文件已清理，生产 KV 未留垃圾） |

### 9.6 遗留建议（与本次修复无关，未改动）

1. **`workers.dev` 路由仍公网可达**（走代理实测 `https://cos-exchange.<账号>.workers.dev/browse` = **200**）。其门控与自定义域相同（附件需签名、`/browse`/`/temp` 需密码、国家白名单 `CN,JP`），但属**多余入口**：可在 CF 面板 Workers → cos-exchange → Settings → Domains & Routes 停用，或在 `wrangler.toml` 加 `workers_dev = false`（会移除该入口，请先确认无依赖）。
2. **`TEMP_PASS` 是明文变量**（`wrangler versions view` 可读出，也会出现在面板/版本记录里），建议改为 **Secret（加密）** 类型，减少明文暴露面。
3. 前次审计的 R1–R6 / F4–F10（尤其 R1/F5：CF 边缘 Rate Limiting）仍然适用。

> 归因：本次仅改 2 处（正则标志 + 405 门控），F4–F10、R1–R6 状态不变；矩阵合计 90 项，`FAIL=0`。

---

## 10. 容量策略改造（2026-09-25）：单文件/数量不设限 → 只限 KV 总占用

> 触发：维护者要求「`/temp` 不限制单文件大小与数量，改为限制总存储空间（1 GB 免费 KV，留足余量）」。
> 被测/部署版本：`doc/cos-proxy-worker.js`，**211671 字节**（+13441）、gzip 62146（+6191），
> sha256 `674903477385A55FAED2D93FBADC655BFD04E9327CA3D62DF429F902FB5A66C2`、blob `fd9ae47f…`
> （构建链 `_parts/*.txt` → `_build-pages.mjs` → `_build-browse.mjs`，两次构建逐字节一致）。
> 结论：**矩阵扩为 124 项（A–J 十组）全部通过（FAIL=0）**；性能审计无回归；A–I 组断言未改动、全部保持通过。

### 10.1 策略与参数（对照）

| 项 | 变更前 | 变更后 |
|---|---|---|
| 单文件上限 | `TEMP_MAX_MB`（默认 20，≤24） | 仅 KV **平台硬上限** 25 MiB；`TEMP_FILE_MAX_MB`（默认 24，**只能调小**）——不是业务策略 |
| 文件数量 | `TEMP_MAX_FILES`（默认 100，≤1000），超限 400 | **取消**（KV 键数本身不设限，数量由总量自然约束） |
| 总容量 | 无 | `TEMP_TOTAL_MB` 默认 **800 MiB**，可调 1~900，超限 **507** |
| 记账 | 无 | KV 账本 `tmp.__usage` `{bytes,n,at}` + `list()` 校准 |
| 上传解析 | 直接 `request.formData()`（超大 body 无界读入） | 有 `Content-Length` 先拒；无 CL 走 `tempLimitedBody()`（**内存有界**） |

> 官方额度（KV limits，2026-04 版）：免费 **1 GB 存储/账号**、命名空间 1 GB、**单值 25 MiB**、键数不限、
> 读 10 万/天、写（不同键）1000/天、**同一键 1 写/秒**、list 1000/天。
> 800 MiB 上限即留 ~224 MiB 给 `sess:`/`auth:` 等键、键名与 metadata 计费、以及删除/过期清理的滞后。

### 10.2 实现要点（KV 无原子自增 → 「账本 + 校准」两层）

- **账本键 `tmp.__usage`**：不在 `tmp/` 前缀内（`list({prefix:'tmp/'})` 看不到），也不匹配 `TEMP_KEY_RE`
  → 用户接口**读不到也删不掉**（J 组实测：删除 400、下载 404、列表不出现键名）。
- **上传**：① 有 `Content-Length` 时按体积先拒（>单文件上限 → 413），再按「体积下界 = CL − multipart 余量」
  做总量预检（超 → 无 CL 时先强制全量校准再判，避免误拒）；② 解析后按**精确体积** `f.size` 再判一次总量；
  ③ 落盘后按绝对值记账。预检刻意用下界，保证「正好装满剩余容量」的文件被接受（有专门断言）。
- **记账按绝对值写**（`used = 已用量 + 本次`）：并发丢增量只会让账本**偏小**、不会偏大 —— 偏小可由校准自愈，
  偏大会误拒上传（设计上宁可偏小）。
- **校准**：`list({prefix:'tmp/'})` 直接读 `metadata.size` 汇总（不读文件内容、不回源 COS、免费额度只算 1 次 list）。
  触发场景：账本缺失/过期、预检命中上限、列表接口顺带纠偏（60s 节流防写放大）。
- **容错**：账本写失败（如「同键 1 写/秒」限流、KV 抖动）只 `console.warn`，**不影响上传成功**；下次校准兜底。
- **删除**：先 `list({prefix: key})` 取 `metadata.size` 释放账本，再 `delete`；响应回传 `used`/`total` 供前端即时更新。
- **无 Content-Length 的流式/chunked 客户端**：不拒绝（兼容），而是用 `tempLimitedBody()` 包一层再 `formData()`，
  累计读到 `单文件上限 + 8 KiB` 即中断 → **413**，内存有界（不再把任意大的 body 读进 128 MiB 的 isolate）。
  > 注：本站页面的 XHR 上传始终带 `Content-Length`（走第 ① 条快路径）；此分支为兼容其它客户端。
  > 该分支在 Node mock 中天然可测（undici 对 FormData/流式 body 不暴露 `Content-Length`），故 J 组有 3 条断言覆盖。

### 10.3 前端（`/temp` 页面）

- 顶栏提示条：`文件到期自动删除（保存 7 天） · 单文件上限 24 MB（KV 平台硬上限） · 已用 12.00M / 800.00M（余 788.00M） · 存储：TEMP_KV`。
- 队列按文件大小**预占**空间（同批多文件不会各自基于同一份「剩余空间」重复超额），失败/取消/网络错误/超时自动归还；
  剩余空间不足时本地直接跳过并在任务面板写明原因（不白传）；服务端 507/413 的文案（含已用/上限字节数）显示在任务面板。
- 页面配置下发 `tempTotalMb` / `tempFileMaxMb` / `tempUsedBytes`（旧的 `tempMaxMb` / `tempMaxFiles` 已移除）；
  列表接口回传 `used` / `total` / `count` / `fileMaxMb` / `totalMb` 供前端即时校准。

### 10.4 复测（124 项）

```powershell
cd "E:\DEVE 开发\web开发"
node _audit-security.mjs "cloud-mail-fork\doc\cos-proxy-worker.js"   # PASS=124  FAIL=0
node _audit-perf.mjs     "cloud-mail-fork\doc\cos-proxy-worker.js"   # 体积/CPU/回源/页面体积/上界 无回归
```

新增 **J 组 34 项**（容量策略）：

| 断言组 | 覆盖 | 数 |
|---|---|---|
| 默认与夹取 | 默认 800 MiB / 单文件 24 MiB；`garbage`→800、`9999`→900、`TEMP_FILE_MAX_MB=999`→24、可调小到 1 MiB（1.2 MiB 文件 413） | 5 |
| 配额强制 | 配额内 200 + `used` 正确 + 账本一致；超配额 **507** + 未落盘 + `used/total` 回传；删除归还（账本归零）；归还后可再传；**正好装满剩余容量的文件被接受** | 8 |
| 数量 | **120 个文件连续上传全 200**（旧版第 101 个即 400）；账本按绝对量累计（120×100 字节） | 2 |
| 无 CL 流式 | 合法 multipart（无 CL）仍 200；非 multipart → 400；2 MiB 流（上限 1 MiB）→ **413** 且未落盘 | 3 |
| 账本防护 | 删除接口碰不到 `tmp.__usage`（400 且未删）；下载 404；列表不泄露键名 | 3 |
| 页面同步 | 下发新字段、移除旧字段、「已用/余量」文案、「平台硬上限」措辞 | 4 |
| 容错与自愈 | 账本写失败仍 200 且占用正确；账本缺失时按 `list()` 重建（历史 3000 + 本次 500 = 3500，全程仅 1 次 get） | 4 |
| 其他 | 列表无 `maxFiles`；账本键不在 `tmp/` 前缀（不出现在文件列表）；整个容量流程 **0 次 COS 回源** | 5 |

性能实测（`_audit-perf.mjs`）：211671 字节 / gzip 62146；`/browse` 主界面 59436 字节、`/temp` 主界面 39501 字节；
回源次数（附件 1/0、`/browse` 1、`/temp` **0**）、Map/循环上界、模块作用域 await=0 均无变化。

### 10.5 风险与边界（如实记录）

1. **KV 最终一致 + 无原子自增**：并发上传可能同时通过预检，理论上短时超过 800 MiB。缓解：
   ① 上限本身留 ~224 MiB 余量；② 接近上限（≥90%）时列表纠偏阈值收紧到 64 KiB；
   ③ 预检命中上限时**强制全量校准**（宁可多 1 次 list，也不误拒）；④ 账本按绝对值记、偏小可自愈、偏大不会发生。
2. **免费额度**：每次上传 2 次写（文件键 + 账本键，不同键 → 计入「不同键 1000 写/天」）；账本键受「同键 1 写/秒」
   限制（写失败已容错）；`list()` 校准计入 1000 次/天。个人日常使用远低于额度。
3. **单文件 25 MiB 是平台硬上限**（KV 单值），Worker 侧无法绕过；更大文件需改 R2/COS
   （`TEMP_STORAGE=cos` 仍是预留位，接口已按此预留）。
4. §9.6 的两条建议（停用 `workers.dev` 入口、`TEMP_PASS` 改 Secret）依然适用。

> 归因：本次只改 `/temp` 的容量计量与上传解析路径；附件签名、`/browse`、mail 契约、各限流阈值均未触碰，
> A–I 组断言保持不变、全部通过，矩阵合计 **124 项 PASS / 0 FAIL**。

---

## 11. 限速与节流改造（2026-09-25）：把「点太快」变成可读提示 + 客户端主动排队

> 触发：维护者反馈「点得太快会被限流」，要求：**解决问题**（限流给出可读原因与等待秒数）、**限制调用速率**、
> 并让客户端**慢一点**（排队节流）。
> 被测/部署版本：`doc/cos-proxy-worker.js`，**219818 字节**、gzip 65240，
> sha256 `7D2BC8BA01DFAD3BDCDAE55017695695CEFB807EC4A411CFB3721BFA247EB112`、blob `55806708…`。
> 结论：**矩阵扩为 149 项（A–K 十一组）全部通过（FAIL=0）**；性能审计无回归；A–J 组断言未改动。

### 11.1 问题与修法

| 问题 | 原因 | 修法 |
|---|---|---|
| 被限流只看到 `Too Many Requests` / 前端显示 `HTTP 429`，不知道要等多久 | 429 是英文纯文本；`Retry-After` 一律写 60（比真实剩余时间更久 → 客户端白等） | 新增统一 `rateLimitResp()`：**API 路径回 JSON** `{error, retryAfter}`，文案为「操作太快了，请慢一点：上传过于频繁，请在 N 秒后重试（每 IP 每分钟最多 X 次）」；**页面/表单路径回同样可读的中文纯文本**；`Retry-After` 改用固定窗口的**真实剩余秒数**（`rateLimitCheck()` 计算） |
| 小文件连点/批量上传很快撞 429（等满 60 秒反而更慢） | 前端队列「串行但无间隔」，服务端 20 次/分 → 第 21 次就 429 | 服务端把节流参数下发到页面（`tempUploadPerMin` / `tempUploadGapMs`，默认 20 次/分 → 间隔 3.3 秒）；前端 `pumpTasks()` 按间隔放行，任务面板显示「限速等待 Ns」并在日志写明原因；429 时取 `JSON.retryAfter` 与 `Retry-After` 的较大值精确退避（上限 120 秒） |
| 连点上传按钮导致重复入队 | 同一文件可被重复选入队列 | 前端按 `name|size|lastModified` **去重**（仍在排队/上传中的同名同大小文件跳过并记日志） |
| 缺少 `/temp` 整体护栏 | 只有单接口限流 | 新增每 IP 护栏：`/temp` 页面 60 次/分、`/temp/api/*` 合计 90 次/分（都在密码门控之前 → 未登录同样受限） |

### 11.2 限速清单（每 IP，固定窗口 60 秒）

| 端点 | 上限 | 可调参数 |
|---|---|---|
| `/temp` 页面 GET/HEAD | 60 | `TEMP_PAGE_PER_MIN` |
| `/temp/api/*` 合计 | 90 | `TEMP_API_PER_MIN` |
| `/temp/api/upload` | **20**（前端按此自动节流） | `TEMP_UPLOAD_PER_MIN` |
| `/temp/api/list` / `file` / `renew` / `delete` | 60 / 120 / 30 / 60 | — |
| `/temp/login`、`/browse/login` | 失败 5 次/10 分钟锁定（429 + `Retry-After: 600`，中文提示） | — |
| `/browse/api/list` / `file`、2FA 校验/绑定/关闭 | 40 / 120 / 20 / 10 / 10 | — |
| `/static/*` | 120 | — |

### 11.3 复测（149 项）

```powershell
node _audit-security.mjs "cloud-mail-fork\doc\cos-proxy-worker.js"   # PASS=149  FAIL=0
node _audit-perf.mjs     "cloud-mail-fork\doc\cos-proxy-worker.js"   # 无回归（219818 字节 / gzip 65240）
```

新增 **K 组 15 项**：

| # | 断言 | 实测 |
|---|---|---|
| 1 | 上传超限（限 2 次/分，第 3 次）→ 429 | 200,200,**429** |
| 2 | 429 为 JSON、含「请慢一点」与 `retryAfter(1~60)` | `{"error":"操作太快了，请慢一点：上传过于频繁，请在 60 秒后重试（每 IP 每分钟最多 2 次）","retryAfter":60}` |
| 3 | `Retry-After` 头与 JSON 的 `retryAfter` 一致 | header=60 |
| 4 | 被限流请求 **不写任何 KV**（限流在读 body/落盘之前） | 仅 2 个 `tmp/<id>` |
| 5 | 限流按 IP 生效（其他 IP 不受影响） | 200 |
| 6 | `/temp` 页面与 `/temp/api` 各自独立限流 | 页面 200 |
| 7 | `/temp/api/*` 合计限流（限 5，第 6 次） | **429** JSON（含「接口调用」） |
| 8 | 页面限流（限 2，第 3 次）→ 429 可读中文 | 200,200,**429** |
| 9 | 页面 429 为纯文本 + 带 `Retry-After` | `text/plain; RA=60` |
| 10 | 429 不含内部细节（无 `__usage`、无 canary） | ✅ |
| 11 | 接口下发 `uploadPerMin` / `uploadGapMs`（12 次/分 → 5500 ms） | ✅ |
| 12 | 页面配置含 `tempUploadPerMin` / `tempUploadGapMs` | ✅ |
| 13 | 页面含节流实现（`UPLOAD_GAP_MS` + 限速等待 + 重复去重） | ✅ |
| 14 | 页面 429 退避读取 JSON `retryAfter` | ✅ |
| 15 | 默认 20 次/分、间隔 ≈3300 ms | ✅ |

性能：219818 字节（+8147）/ gzip 65240（+3094）；`/temp` 主界面约 40 KB；回源次数、Map/循环上界、冷启动无变化。

### 11.4 边界（如实记录）

1. 限流是**单 isolate 内存计数器**（沿用原有实现）：多 isolate/多 PoP 下同一 IP 的实际上限会略宽松；
   要严格配额应在 CF 面板加 **Rate Limiting 规则**（§7 的 R1/F5 建议依然有效）。
2. 客户端节流只约束**本站页面**；第三方脚本仍靠服务端 429（现在会收到可读 JSON + 精确等待秒数）。
3. 想更快的上传：调大 `TEMP_UPLOAD_PER_MIN`（前端间隔自动跟着变小）；注意 KV 免费档写额度
   （每次上传 2 次写，1000 写/天）与「同键 1 写/秒」。
4. `Retry-After` 是固定窗口的剩余时间（1~60 秒），客户端退避上限 120 秒；`/temp/login` 锁定时长 10 分钟。

> 归因：本次只动限速响应与前端队列节流，未触碰签名/鉴权/COS 回源/KV 容量语义；A–J 组断言保持不变全部通过。

### 11.5 部署与生产 E2E（2026-09-25）

**部署（wrangler CLI，经本机代理）**

```powershell
cd mail-worker
$env:HTTPS_PROXY='http://127.0.0.1:10808'   # 10808 为混合代理（SOCKS5 + HTTP CONNECT 同端口）
$env:HTTP_PROXY=$env:HTTPS_PROXY
npx wrangler deploy -c ../doc/cos-exchange.wrangler.toml
```
- 输出：`Total Upload: 184.34 KiB / gzip: 48.67 KiB`、`Worker Startup Time: 3 ms`、`Uploaded cos-exchange (3.77 sec)`
- 版本：**`a4b96b80-a263-41cc-920a-9ba282d55892`**（上一版 `9c10d23c…`）
- wrangler 自带提示 `▲ [WARNING] Proxy environment variables detected. We'll use your proxy for fetch requests.` ⇒ CLI 原生支持代理 env，
  无需额外 `NODE_USE_ENV_PROXY`（注意：Node/undici **不支持** `socks5://` 形式的 env 代理，必须写成 `http://127.0.0.1:10808`）
- 部署后核对（`wrangler versions view`）：`compatibility_date=2026-08-10` 未变、
  **7 个 Secret**（`ATT_SIGN_SECRET`/`AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`/`BROWSE_PASS`/`S3_ENDPOINT`/`TURNSTILE_SECRET`/`TURNSTILE_SITEKEY`）、
  **4 个明文变量**（`ATT_SIGN_MAX_TTL`/`BROWSE_ALLOW_COUNTRY`/`REGION`/`TEMP_PASS`）、
  **2 个 KV**（`BROWSE_KV=086c531c…`/`TEMP_KV=f527c223…`）全部保留
- 版本预览 URL 实测 **404**（`preview_urls=false` 生效）；`workers.dev` 常驻路由仍 200（§9.6 建议依旧）

**生产 E2E（`web开发\_prod-e2e-temp.mjs`，真实域名 `cos.duckgame-play.top`）—— 全部 PASS**

| 步骤 | 结果 |
|---|---|
| 未登录 `/temp` | 200 / 6186 B（登录页） |
| 已登录 `/temp` | 200 / **43503 B**，含 `tempUploadPerMin`/`tempUploadGapMs`/`UPLOAD_GAP_MS`/「已用·余量」文案 |
| 正常上传（带 `Content-Length`） | 200，`used` = 占用 + 2048 |
| **流式上传（无 Content-Length，chunked）** | **200** ⇒ `tempLimitedBody()` 分支在真实 Workers 运行时可用（受限 body 解析成立） |
| `/temp/api/list` | `used`/`total=838860800`/`uploadPerMin=20`/`uploadGapMs=3301` |
| 连续上传触发限速 | 前 20 次 200，**第 21 次 429**：`{"error":"操作太快了，请慢一点：上传过于频繁，请在 32 秒后重试（每 IP 每分钟最多 20 次）","retryAfter":32}`，`Retry-After: 32` 与 JSON 一致（32 秒=固定窗口真实剩余时间，非写死的 60） |
| 清理 | 本次创建的 21 个键全部删除，`used` 回落 3072 字节（生产账本原有 20 个文件 / ≈50.6 MB 占用，与列表一致） |
| 其它端点烟测 | `/` 302、`/browse` 200（6901 B）、`/temp` 200（6186 B）、未签名 `/attachments/test.png` 403、favicon 204 —— 与部署前一致 |

> 说明：内存限流计数器在真实环境**确实生效**（同 isolate 内一次突发即触发）；多 isolate 下额度会更宽松（§11.4-1）。

---

## 12. 在线查看（`/temp`）与只读网盘筛选修复（2026-09-25）

> 触发：① `/temp` 增加查看功能（文本/图片；**视频必须用户点击才播放**）；
> ② 只读网盘筛选器点「视频/音频…」应只显示这类文件，若无则提示「这个目录下没有这类文件，返回「全部」查看」。
> 被测/部署版本：`doc/cos-proxy-worker.js`，**241947 字节**、gzip 70559，
> sha256 `554AC0F08CA822FF761CA4420667DA1CFCA48BAB81FE27A2E54E93CC42D09A29`、blob `0b362358…`。
> 结论：**矩阵扩为 165 项（A–L 十二组）全部通过（FAIL=0）**；性能审计无回归。

### 12.1 `/temp` 在线查看（新增）

| 能力 | 实现 |
|---|---|
| 图片 | `<img>` 走 `/temp/api/file`（inline）；`.svg` 因服务端安全策略强制 `attachment` → 提示下载（防存储型 XSS） |
| 文本 | `fetch(url, { headers: { Range: 'bytes=0-262143' } })` 只取前 **256 KB**，用 `textContent` 注入 `<pre>`（不解析 HTML）；超出提示下载 |
| 音频/视频 | `<video/audio controls preload="none">`，**不设自动播放属性** → 必须用户点击播放（也不预取字节，省流量）；`playsinline` 适配移动端 |
| PDF | `<iframe>`（服务端 `application/pdf` 走 inline）+ 新窗口/下载兜底 |
| 其它类型 | 明确提示「暂不支持在线查看，请下载」 |
| 关闭 | 关闭按钮 / 点遮罩 / Esc；关闭时 `pause()` + `removeAttribute('src')` + `load()` 释放媒体、`AbortController` 中断文本请求（与只读网盘同款，避免后台继续下载） |

**服务端配套：`/temp/api/file` 增加 Range 支持**（`Accept-Ranges: bytes`）——视频/音频可拖动进度，文本按需只取前 256 KB：

| 请求 | 行为（10 字节样本 `ABCDEFGHIJ`） |
|---|---|
| 无 Range | 200 全量 + `Accept-Ranges: bytes` |
| `bytes=0-3` | **206** + `Content-Range: bytes 0-3/10` + `Content-Length: 4`（只回前 4 字节） |
| `bytes=5-` | 206，`bytes 5-9/10`（5 字节） |
| `bytes=-3` | 206（后缀范围），`bytes 7-9/10`（末 3 字节） |
| `bytes=0-9999` | 206，末端自动截断为 `0-9/10` |
| `bytes=99-` | **416** + `Content-Range: bytes */10` |
| 非 bytes 单位 / 非法范围 | 忽略 → 200 全量（不报错） |
| 未登录 / 非法 key | 仍分别回登录页 / 404（**Range 不改变鉴权与 key 校验**） |

> 只读网盘的详情预览同步改为**点击才播放**（`<video controls autoplay>` → `controls playsinline preload="none"`），
> 构建产物中已无 `autoplay` 字样（L 组有断言守住）。

### 12.2 只读网盘筛选修复

**问题**：`applyFilter()` 只过滤**当前页**已加载的条目（COS 按 continuation-token 分页、不支持按类型过滤），
文件多时点「视频」几乎必然空列表，且分不清「本页没有」与「整个目录没有」。

**修法**（`_parts/07_js1.txt` / `08_js2.txt` / `08_js3.txt` / `10_js5.txt`）：

- 新增 **整目录扫描** `scanFilter()`：按 token 顺序翻完该目录**全部页**，命中项累积到 `fscan.items`；
  每页间隔 600 ms（≤100 次/分，低于服务端上限），遇 429 按 `Retry-After` 退避后继续（不丢结果）。
- 命中结果用 **本地数字分页**（`renderFilterPager`，与最近/收藏一致，含每页条数与跳页）；排序/每页条数切换即时生效（无需重扫）。
- 顶部提示条：`筛选「视频」：命中 12 个 · 已扫描 3 页（186 个文件）`；达扫描上限（30 页）追加「结果可能不全」。
- **无命中**时按需求提示并可一键恢复：
  `这个目录下没有「视频」文件，返回「全部」查看`（+ 按钮「返回「全部」」，同时清空搜索词）；
  仅搜索无命中时：`这个目录下没有匹配「xxx」的文件，返回「全部」查看`。
- 搜索框改为 **350 ms 防抖**（避免每次按键都重扫整目录）；切换目录（`go`/`up`）作废扫描缓存。
- 服务端配套：`/browse/api/list` 限速 **40 → 120 次/分**（整目录筛选/搜索需顺序翻页；仍是 per-IP 固定窗口）。

### 12.3 复测（165 项）

```powershell
node _audit-security.mjs "cloud-mail-fork\doc\cos-proxy-worker.js"   # PASS=165  FAIL=0
node _audit-perf.mjs     "cloud-mail-fork\doc\cos-proxy-worker.js"   # 无回归（241947 字节 / gzip 70559）
```

新增 **L 组 16 项**：Range 全量/单段/后缀/末端截断/**416 起点越界**/非法范围忽略（6 条，逐字节核对 `Content-Range`/`Content-Length`）、
Range 不改变鉴权（未登录回登录页）、带 Range 的非法 key 仍 404、
源码断言：预览实现存在、**产物中无 `autoplay`** 且媒体 `preload='none'`、文本取前 256 KB、关闭释放媒体、
筛选实现（`scanFilter`/`renderFiltered`/`renderFilterPager`）、无匹配提示文案与「返回「全部」」按钮、列表限速 120。

性能：241947 字节（+22129）/ gzip 70559（+5319）；`/browse` 主界面 70701 字节（+11265）、`/temp` 主界面约 45 KB；
回源次数（附件 1/0、`/browse` 1、`/temp` 0）、Map/循环上界、冷启动均无变化。

### 12.4 边界（如实记录）

1. **整目录扫描有上限**：最多 30 页（30×`perPage` 条，默认 1800 条），达上限会提示「结果可能不全」；
   超大目录（数千文件）建议先用搜索词缩小范围。
2. 扫描期间会占用 `/browse/api/list` 额度（每页 1 次、间隔 600 ms）；服务端限速 120 次/分，遇 429 自动按 `Retry-After` 退避继续。
3. 筛选/搜索只在**当前目录**内（与「搜索当前目录」的既有语义一致），不递归子目录。
4. `/temp` 单文件仍受 25 MiB 平台上限；文本预览只显示前 256 KB（大文本请下载）。
5. Range 会读到整份 KV 值再切片（KV 无部分读接口），因此**不会**降低 KV 读放大，只减少回给浏览器的字节。

5. Range 会读到整份 KV 值再切片（KV 无部分读接口），因此**不会**降低 KV 读放大，只减少回给浏览器的字节。
6. **CF 边缘会压缩文本类响应**：`text/plain` 的 200 响应被压成 `content-encoding: br`，此时边缘会**省略 `Accept-Ranges` 与 `Content-Length`**
   （实测；不可压缩类型如 `application/octet-stream` 正常带 `Accept-Ranges: bytes`）。**不影响 Range**：带 `Range` 的请求一律回
   206 + `Accept-Ranges` + `Content-Range`（实测逐字节正确），浏览器/播放器仍可拖动进度。

### 12.5 部署与生产 E2E（2026-09-25）

**部署**：`npx wrangler deploy -c ../doc/cos-exchange.wrangler.toml`（经 `HTTPS_PROXY=http://127.0.0.1:10808`）
→ `Total Upload: 205.40 KiB / gzip: 53.57 KiB`、Worker Startup 1 ms、版本 **`23163fe6-b7a6-47c2-843b-b36480a4529f`**；
核对：`compatibility_date=2026-08-10` 未变、**7 Secret + 4 明文变量 + 2 KV 全保留**
（注：`versions view` 的 `resources.script.etag` **不是**文件 sha256，故字节一致性以"仓库副本 = 构建产物 = 部署入参文件"三者哈希相等来保证，
行为一致性由下面的生产 E2E 验证）。

**生产 E2E（`web开发\_prod-e2e-view.mjs`）—— 16/16 全 PASS**

| 检查 | 结果 |
|---|---|
| 已登录 `/temp` | 200 / **51513 B**，含 `openPreview`/`pvTypeOf`/`pvRelease` |
| **无自动播放** | 页面不含 `autoplay`，媒体 `preload='none'` ✔（视频须点击） |
| 文本预览 | 页面按 `bytes=0-262143` 只取前 256 KB ✔ |
| `Range: bytes=0-9` | **206** + `Content-Range: bytes 0-9/1024`，仅回 10 字节 ✔ |
| `Range: bytes=-16` / `bytes=512-` | 206（`1008-1023/1024` / `512-1023/1024`）✔ |
| `Range: bytes=99999-` | **416** + `Content-Range: bytes */1024` ✔ |
| 非法范围（`items=0-1`） | 忽略 → 200 全量 ✔ |
| 未登录带 Range | 回登录页、无内容（鉴权不受影响）✔ |
| 不可压缩类型 200 | `Accept-Ranges: bytes` + `Content-Length: 1024` ✔ |
| 清理 | 两个测试文件删除成功，`used` 精确回落 ✔ |

> 只读网盘的筛选修复属前端行为，已在 L 组用源码断言守住（`scanFilter`/`renderFiltered`/`renderFilterPager`、无匹配文案、重置按钮、
> 列表限速 120），生产页面同源（同一构建产物部署），故无需浏览器自动化即可保证一致性。

---

## 13. 缺陷修复：`/temp` 查看器打不开 PNG（2026-09-25）

> 现象：临时网盘里明明是 `.png`，点「查看」却提示「该类型暂不支持在线查看」。
> 修复版本：**246504 字节**、gzip 72270，sha256 `B6745496E84750D5FCEFDD4929BE9A202D68897565016EC6BFBA1A2C72CF4815`；
> 部署版本 **`6a9ffa77-da15-4377-8985-114dec35466d`**。
> 结论：**矩阵 170 项（A–L）全部通过（FAIL=0）**；性能无回归；生产 E2E 全部通过。

### 13.1 根因

**客户端类型判定用错了字段**：`/temp/api/list` 返回的 `type` 是 **MIME 字符串**（`image/png`），
而预览函数 `pvTypeOf()` 在比较**简写类型**：

```js
if(o.type==='img'){return 'img';}   // 实际 o.type === "image/png" → 恒为 false
```

→ `.png/.jpg` 一路落到 `return 'none'` → 显示「该类型暂不支持在线查看」。
（列表图标是按**扩展名**算的，所以图标正常、只有查看器坏 —— 这也是最初误判的原因。）

**服务端侧同类问题（顺带修掉）**：客户端若把类型写成 `application/octet-stream`（curl/脚本/部分客户端如此），
服务端会按「非内联类型」下发 `Content-Disposition: attachment` + `nosniff` → 浏览器同样不会把它当图片渲染
（已复现：同一 PNG 声明 octet-stream 时返回 `attachment`）。

### 13.2 修法

| 侧 | 修改 |
|---|---|
| 客户端 | `pvTypeOf()` 改为 **扩展名为主 + MIME 兜底**：`IMG/VID/AUD` 扩展名命中，或 MIME 以 `image/`/`video/`/`audio/` 开头 → 对应类型；`pdf`、`text/*`、`application/json` 同理；SVG（含 MIME 含 svg）仍只提示下载 |
| 客户端 | 预览失败改为 `pvFail()`：给出原因 + **可点击的「在新窗口打开」** + 提示下载；图片容器改 `justify-content:flex-start` + `margin:auto`，避免大图被 flex 居中裁掉顶部且无法滚动 |
| 服务端 | 新增 `TEMP_EXT_MIME` 扩展名白名单 + `tempDisplayType(storedType, name)`：存储类型为空/过泛（`octet-stream`）时按扩展名兜底；被误标成 `text/plain` 但扩展名更具体（如 `.png`）时纠正。**绝不映射到 `text/html` / `image/svg+xml` / `application/xhtml+xml`**；`.html/.svg` 只映射成 `text/plain`（配 `nosniff`，作为文本查看、不可执行） |
| 服务端 | `/temp/api/file` 与 `/temp/api/list` 统一走 `tempDisplayType`（列表 `type` 与下载响应一致，前端据此判定预览能力） |

### 13.3 复测（170 项）

新增 5 项（L 组）：

| 断言 | 实测 |
|---|---|
| `octet-stream` 上传的 png → **image/png + inline** | `ct=image/png cd=inline` ✔ |
| `.html/.svg` 兜底**只映射为 text/plain** + nosniff（不产生可执行类型） | `ct=text/plain nosniff=nosniff` ✔ |
| 存储类型为 `text/html` → **强制 attachment** | `cd=attachment` ✔ |
| 列表 `type` 与下载响应一致 | `image/png` ✔ |
| 前端判定按扩展名/MIME + `pvFail` 存在 | ✔ |

性能：246504 字节（+4557）/ gzip 72270（+1711）；`/temp` 主界面 52151 字节；回源次数与上界无变化。

### 13.4 部署与生产验证

- `npx wrangler deploy -c ../doc/cos-exchange.wrangler.toml`（经 `HTTPS_PROXY=http://127.0.0.1:10808`）
  → 版本 **`6a9ffa77-da15-4377-8985-114dec35466d`**；核对 `兼容日期=2026-08-10`、**7 Secret + 4 变量 + 2 KV** 全保留。
- **`_prod-e2e-png.mjs`（6/6 PASS）**：页面已含扩展名/MIME 判定与 `pvFail`；
  **现有 3.9 MB PNG 真实取回 = 200 + `image/png` + `inline` + 字节完整（3919817/3919817，PNG 签名 137,80,78,71）**；
  上传声明 `octet-stream` 的 png → 响应 `image/png` + `inline`（修复前为 `attachment`）；测试文件已清理。
- **`_prod-e2e-view.mjs`（16/16 PASS）**：预览 / Range / 鉴权全部复测无回归（页面 53093 字节）。

> 经验记录：跨端字段语义必须写清（`type` 是 MIME 还是简写分类）——这次就是「列表给 MIME、前端按简写比较」导致的
> 「图标正常但查看器坏」。凡是客户端按类型分支的地方，都应以扩展名/MIME 双依据判定。






