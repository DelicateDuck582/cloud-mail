# COS Worker 安全 / 性能 / 密钥审计报告（2026-09-13）

> 审计对象：`doc/cos-proxy-worker.js`（cos-exchange Worker，域名 `cos.duckgame-play.top`）
> 审计版本：SHA256 `974D7CDFD93F9F3E075F88BE6B4402A5AFC206E6F111FAE04C159822879F1026`（192031 字节 / gzip 56007 字节）
> 分支与提交：`browse-alist` `1f701b6`（本报告随该提交归档）；同步副本 `attachment-manager` `92c914c`
> 审计方式：**可执行审计**——在 Node 内真实执行 Worker 代码（mock COS 回源 / KV / Cache API / IP 头），
> 而非仅阅读源码；安全断言 + 性能实测 + 密钥 canary 扫描 + 静态上界检查
> （首轮 61 项；**2026-09-13 晚复审扩展至 88 项**，新增续期面与 mail 契约两组，见 §8）
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
# 1) 安全审计（当前 90 项攻击矩阵 A–I 九组；mock COS/KV/Cache，不触网）
cd "E:\DEVE 开发\web开发"
node _audit-security.mjs "cloud-mail-fork\doc\cos-proxy-worker.js"
#   → 期望：PASS=90  FAIL=0 ；"ALL SECURITY CHECKS PASSED"
#     （历史基线：§0–§7 为 61 项，§8 为 88 项，§9 起为 90 项）

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


