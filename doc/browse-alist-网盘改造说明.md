# browse-alist 分支说明 —— COS 网盘 Alist 风格改造

> 分支：`browse-alist`（从 `attachment-manager` 分叉）
> 用途：给维护者 / 后续对话提供本分支的完整上下文。
> 状态：本地 + 已推送 origin/browse-alist，**不合并 main、不贡献上游**。

---

## 0. 一句话概况

把 cos-exchange Worker（`cos.duckgame-play.top`）的 `/browse` 个人只读网盘重做为
**Alist 风格 UI（手机优先适配）**，并做了一轮安全/逻辑/性能加固。核心架构
「COS 前置代理 Worker —— 短期签名（防伪造）+ Cache API 按文件缓存」**逐字节未变**。

设计规格对照本地 alist-web 源码（`E:\数据迁移\开发\alist-web`，SolidJS + HopeUI）。

该 Worker 同时承载 **`/temp` 临时网盘**（独立密码 + KV 存储 + 上传任务面板），见 §2.1。

---

## 1. 改动清单（相对 attachment-manager）

| 文件 | 改动 |
|---|---|
| `doc/cos-proxy-worker.js` | **唯一改动的部署文件**（仓库内副本；部署用文件在仓库外 `web开发\cos-proxy-worker.js`，两者始终同步） |
| `doc/browse-alist-网盘改造说明.md` | 本说明文档 |
| `doc/审计报告-COS-Worker-安全性能密钥-2026-09-13.md` | 可执行审计报告（61 项攻击矩阵 + 性能实测 + 密钥 canary 扫描） |

> `mail-worker/`、`mail-vue/`、`main`、`attachment-manager` **均未改动**。

---

## 2. UI 功能（Alist 风格，对照 alist-web 源码）

- **配色/布局**：主色 `#1890ff`、页面背景 `#f7f8fa`、hover `rgba(132,133,141,.18)`、
  内容容器 `min(99%, 980px)`、Alist 字体栈（`-apple-system,BlinkMacSystemFont,"Segoe UI",...`）。
- **文件列表白卡片**：`rounded 12px + 阴影`；默认列表视图（Alist `global_default_layout=list`）。
- **列表三列**：名称 35% / 大小 30% / 修改时间 25%（右对齐，移动端隐藏修改时间列），表头点击排序。
- **网格卡片**：`minmax(110px,1fr)`、悬停 `scale(1.05)` + hover 底色、主色单色 SVG 图标、名称单行居中省略。
- **大小/时间格式**：同 Alist `getFileSize`（`1.02K`/`1.00M`/`2.00G`，两小数）；`YYYY-MM-DD HH:MM:SS`。
- **顶栏**：搜索 pill（`Ctrl+K` 快捷键）、网格/列表切换、深色模式、**返回邮件**（✉️ → `mail.duckgame-play.top`）、**退出**。
- **侧栏**：首页 / 最近 / 收藏（存 localStorage，每页 100 条）；移动端为抽屉式（汉堡菜单 + 遮罩）。
- **面包屑路径条**：首页 / 文件夹 / …，可点击任意层级，超出横向滚动。
- **交互**：点图片 → 全屏灯箱（左右切换 / 触摸滑动 / 键盘方向键）；点其他文件 → 详情弹层
  （移动端底部抽屉 / 桌面居中卡片），内嵌预览视频/音频/PDF/文本 + **下载** + **收藏**。
- **分页器（对齐 alist-web Paginator）**：文件列表与最近/收藏均在翻页部位显示
  「每页条数选择（30/60/100）+ 页码导航」。文件列表用 COS continuation-token 顺序翻页
  （已访问页可点页码回翻、上一页/下一页）；最近/收藏本地数据有总数，数字分页
  （首页/当前附近/末页 + 省略号）。`/browse/api/list` 通过 `per_page` 控制每页条数
  （默认 60，上限 200）。
- **视频**：`Range` 流式透传（秒开、可拖动 seek，按段下载）；关闭弹层时自动暂停并释放媒体。
- **缩略图**：IntersectionObserver 懒加载 + **并发限流（最多同时 4 个请求）**，避免打满限流。
- **其它**：429 自动重试；深色模式记忆本地偏好；默认搜索/排序/筛选状态本地持久化。

### 2.1 `/temp` 临时网盘（独立入口）

| 项 | 说明 |
|---|---|
| 鉴权 | 独立密码 `TEMP_PASS`（普通密码登录，无 2FA）+ `SameSite=Lax` HttpOnly cookie；未配置密码或未绑 KV 时显示「未启用」配置提示页 |
| 存储 | KV（`TEMP_KV`，未绑定时回退 `BROWSE_KV`）：键 `tmp/<id>`，metadata `{name,type,size,at}`，到期由 `expirationTtl` 自动删除 |
| 接口 | `GET /temp`、`POST /temp/login`、`GET /temp/logout`、`GET /temp/api/list`、`POST /temp/api/upload`（multipart 字段 `file`）、`GET /temp/api/file?key=&dl=1`、`POST /temp/api/delete`（字段 `key`）、`POST /temp/api/renew`（字段 `key`，**续期**） |
| 容量 | **只限总量**（2026-09-25 起）：`TEMP_TOTAL_MB`（默认 800 MiB，可调 1~900）；单文件大小与文件数量**不再设业务上限**。单文件仅剩 KV 平台硬上限 25 MiB（`TEMP_FILE_MAX_MB` 默认 24，只能调小）；TTL `TEMP_TTL`（默认 7 天）；并发上传串行 |
| 占用统计 | 服务端账本 `tmp.__usage`（`{bytes,n,at}`，不在 `tmp/` 前缀内 → 用户接口读不到也删不掉）+ `list()` 全量校准：上传/删除按绝对值记账、接近上限时强制扫描、列表接口顺带纠偏（60s 节流）；顶栏提示条显示「已用 X / Y（余 Z）」 |
| 容量拒绝 | 总容量不足 → **507**（回传 `used`/`total`，前端也会本地预检并跳过，不白传）；单文件超平台上限 → **413**；无 `Content-Length` 的流式上传走「受限 body」（读到上限即截断 → 413），内存有界 |
| 限速 | 每 IP 固定窗口 60 秒：页面 60 次/分（`TEMP_PAGE_PER_MIN`）、`/temp/api/*` 合计 90 次/分（`TEMP_API_PER_MIN`）、上传 20 次/分（`TEMP_UPLOAD_PER_MIN`）、列表 60 / 下载 120 / 续期 30 / 删除 60；登录失败 5 次/10 分钟锁定。**429 一律可读**：API 回 `{error, retryAfter}`，页面回中文纯文本 + `Retry-After`（真实剩余秒数） |
| 上传节流 | 前端按服务端下发的 `tempUploadGapMs`（默认 20 次/分 → 3.3 秒/个）排队放行，任务面板显示「限速等待 Ns」并写日志；同名同大小文件在队列中自动去重（防连点）；429 时按 `retryAfter` 精确退避（≤120 秒） |
| 上传体验 | **右下角悬浮「上传任务」小按钮（仿 Alist）**：角标显示进行中任务数；面板含每个文件的进度条/百分比/实时速度/状态与**上传日志**（时间戳，上限 200 行）；失败可重试、上传中可取消、一键清除已完成。上传用 `XMLHttpRequest` 取真实进度 |
| 列表一致性 | KV `list()` 最终一致（数秒内查不到新 key）→ 上传成功即**乐观并入本地列表**并落 `localStorage`（上限 50 条 / 120s），刷新后仍可见；批次结束在 2.5/7/16/32s 自动校准，服务端确认后清理本地 pending；删除用 tombstone 防「回魂」 |
| 限流 | `Retry-After` 优先的退避重试（上限 90s），面板显示「等待重试 Ns」倒计时 |
| 类型安全 | 上传的 `Content-Type` 经 `tempSafeType()` 清洗（剥控制字符 + 限长 + 形态校验，非法回退 `application/octet-stream`），写入、列表回显、下载头三处一致；`image/svg+xml` 仍强制 `attachment` 防存储型 XSS |
| 文件续期 | 每行「续期」按钮（↻，与下载/删除同款样式，请求中禁用）：每次从**当前到期时间**再延长一个保存期限（`TEMP_TTL`，默认 7 天）；总保留上限 30 天（`TEMP_KEEP_MAX=2592000`），达上限时提示"未再延长"。实现：KV 无 touch/延期接口 → 服务端 `getWithMetadata` 读回原值 + 以新的 `expirationTtl` 重写（metadata 原样保留），当前到期时间由 `list({prefix:key})` 的 `expiration` 得到；限流 30 次/分 |

**容量策略（2026-09-25 调整，取代「单文件上限 + 数量上限」）**

- 需求：单文件大小与数量不设业务上限，改为限制**命名空间总占用**——CF 免费 KV 额度 1 GB，默认只用 800 MiB
  （`TEMP_TOTAL_MB`），余量（~224 MiB）留给 `sess:`/`auth:` 等其它键、键名与 metadata 计费、以及过期/删除清理的滞后。
- 唯一保留的单文件限制是**平台硬上限**：KV 单值最大 25 MiB（`TEMP_FILE_MAX_MB` 默认 24，只能调小）。
  官方额度（KV limits）：免费 1 GB 存储/账号、单值 25 MiB、键数不限、读 10 万/天、写（不同键）1000/天、
  **同一键 1 写/秒**、list 1000/天。
- 账本：KV 无原子自增 → `tmp.__usage`（`{bytes,n,at}`）+ `list({prefix:'tmp/'})` 校准（自带 `metadata.size`，
  不读文件内容、不回源 COS）。上传/删除按**绝对值**记账（并发丢增量只会偏小，不会偏大 → 不会误拒）；
  接近上限时强制全量校准；列表接口用同一份 list 结果顺带纠偏（60s 节流防写放大）；账本写失败（同键 1 写/秒等）
  只记日志，不影响上传成功；账本缺失/过期时按 list 重建。
- 响应码：总容量不足 **507**（回传 `used`/`total`）、单文件超平台上限 **413**；预检用「体积下界」比较，
  不会因 multipart 开销把「正好装满」的文件误拒。无 `Content-Length` 的流式客户端走 `tempLimitedBody()`
  （读到上限即中断 → 413），内存有界。
- 前端：顶栏提示条显示「已用 / 总量 / 余量」；队列按文件大小**预占**空间（失败/取消归还），
  空间不足直接跳过不白传；页面配置下发 `tempTotalMb`/`tempFileMaxMb`/`tempUsedBytes`。
- 实测：`_audit-security.mjs` **J 组 34 项**（默认值与夹取、507/413、删除归还、120 连传、无 CL 流式、
  账本越权、页面同步、账本不可写容错、重建扫描、0 回源），矩阵合计 **124 项 PASS / 0 FAIL**。

---

## 3. 接口（与改造前完全一致，新增 1 个退出接口）

| 接口 | 方法 | 说明 |
|---|---|---|
| `/browse` | GET | 密码门控，已登录返回主界面，未登录返回登录页 |
| `/browse/login` | POST | 字段 `p`（密码）+ `cf-turnstile-response`（可选），成功 302 + Set-Cookie 7 天 |
| `/browse/logout` | GET | **新增**。服务端 Set-Cookie 删除 HttpOnly cookie 后 302 回 `/browse` |
| `/browse/api/list?prefix=&token=&per_page=` | GET | ListObjectsV2 列目录，`per_page` 控制每页条数（30/60/100，默认 60，上限 200 → `max-keys`） |
| `/browse/api/file?key=` | GET/HEAD | 经 Worker 回源 COS（S3 签名），支持 `Range` 头（视频/音频流式） |

---

## 4. 环境变量（与交接文档 §6 完全一致，未新增）

| 变量 | 说明 | 必填 |
|---|---|---|
| `ATT_SIGN_SECRET` | 附件签名密钥（与 mail-worker 一致） | ✅ |
| `S3_ENDPOINT` | COS 桶默认访问域名（`https://<BUCKET>.cos.<REGION>.myqcloud.com`）。⚠️ **真实桶地址/密钥属于敏感配置，不要提交到公开仓库**，只在 CF 环境变量里配置 | ✅ |
| `REGION` | COS 桶所在地域（如 `ap-guangzhou`，按桶实际所在地配置） | ✅ |
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` | COS **只读子账号**（权限仅 GetObject + GetBucket，与上传子账号隔离）。⚠️ **SecretId/SecretKey 绝不可出现在任何文档** | ✅ |
| `BROWSE_PASS` | 网盘访问密码。⚠️ **绝不可提交到公开仓库** | ✅ |
| `ATT_SIGN_MAX_TTL` | 可选，默认 3600（非法值自动回退默认） | 否 |
| `BROWSE_ALLOW_COUNTRY` | 可选，如 `CN` | 否 |
| `TURNSTILE_SITEKEY` / `TURNSTILE_SECRET` | 可选，登录人机验证 | 否 |

> ⚠️ `cos-exchange` 需绑定 KV：`/browse` 的 2FA 密钥与登录会话用 `BROWSE_KV`，`/temp` 临时网盘文件用 `TEMP_KV`（只绑一个时两者共用该命名空间，按前缀隔离）。未绑定时 2FA 不可用、`/temp` 显示未启用提示。完整环境变量清单见 `doc/cos-proxy-worker.js` 顶部注释（`TEMP_*` / `TOTP_*` / `SESSION_TTL` / `ATT_SIGN_*`）。
> 本文档面向公开 fork 仓库：除公网域名（`cos./mail.duckgame-play.top`）外，所有真实配置值
> （桶地址、SecretId/SecretKey、密码、Turnstile Secret）一律用占位符，真实值只存在于 CF 环境变量。
> 含完整敏感值的交接文档在仓库外（`web开发\交接文档-CloudMail-COS现状.md`），标注禁止外发、禁止提交 GitHub。

---

## 5. 安全模型（含本次加固）

| 入口 | 鉴权 | 时效 | 防刷 |
|---|---|---|---|
| `/attachments/*`（附件） | HMAC-SHA256 签名，**验签先于缓存** | 默认 15 分钟（ATT_SIGN_MAX_TTL 兜底） | 路径白名单 + 缓存降本 |
| `/static/*`（背景） | Referer + Sec-Fetch 双层校验 | — | 路径白名单 |
| `/browse/*`（网盘） | 密码 cookie（**HMAC-SHA256 指纹**，64 位 hex，不可碰撞/不可逆） | cookie 7 天 | 登录锁定 + 限流 + 国家白名单 |
| COS 直连 | 私有桶 + 只读子账号 | — | 密钥最小化 |

**本次安全加固明细：**
1. **cookie 指纹 FNV-1a(32 位可碰撞) → HMAC-SHA256(64 位 hex)**：不可碰撞、不可反推密码
   （密钥为独立常量 `cos-browse-cookie-fp-v2`；指纹缓存避免重复 importKey）。
2. **退出登录改服务端 `/browse/logout`**：HttpOnly cookie 前端 JS 删不掉，必须服务端 Set-Cookie 清除。
3. **`ATT_SIGN_MAX_TTL` 非法值兜底**：此前 `Number("abc")→NaN` 会让 TTL 上限检查失效（超长签名放行），现回退默认 3600。
4. **`/browse/api/file` HEAD 空 body 不写缓存**：避免污染同 key 的 GET 缓存；Range(206) 同样不写。
5. **登录失败 Map 定期清理**：防攻击者用海量 IP 撑爆内存（超 1 万条清理过期项）。
6. **根路径防自杀式重定向**：代码误部署到 mail 域名时返回 200 而非 302 死循环。
7. **移除「复制链接」按钮**：不暴露文件路径结构；链接本身无鉴权信息（无 token/签名），无 cookie 打不开。
8. **前端 XSS 防护**：所有动态内容经 `esc()` 转义；`<script>` 内字符串用 `\uXXXX`、文本用 HTML 实体。

**测试脚本**（仓库外 `web开发\`）：`_test-syntax` / `_test-browse` / `_test-attachments` /
`_test-ttl` / `_test-range` / `_test-redirect` / `_test-hmac` / `_test-logout` / `_audit`（密钥扫描）。

---

## 6. 部署步骤（cos-exchange）

1. 部署 `web开发\cos-proxy-worker.js`（**211671 字节 / gzip 62146**，以文件为准；仓库内副本 `doc/cos-proxy-worker.js` 与其逐字节一致）。
   - **推荐 CLI（可复现、可回滚）**：`cd mail-worker; npx wrangler deploy -c ../doc/cos-exchange.wrangler.toml`
     （务必确认 `keep_vars = true`，否则会删掉面板上的明文变量，见审计报告 §9.3）
   - 或面板全量粘贴 `doc/cos-proxy-worker.js`（等价，但会覆盖面板版本记录）
2. 确认 §4 环境变量均在（`BROWSE_PASS` 等）。
3. 部署后验证：
   - `https://cos.duckgame-play.top/browse` → Alist 风格登录页
   - 登录 → 主界面（列表视图 + 侧栏 + 搜索 Ctrl+K + ✉️ 返回邮件）
   - 播放视频 → 秒开、可拖动；关闭弹层声音停止
   - 退出按钮 → 真正回到登录页
4. ⚠️ HMAC 指纹升级后，**所有已登录用户需重新登录一次**（预期行为）。

---

## 7. 本地构建与开发（重要）

`cos-proxy-worker.js` 是**构建产物**，不要直接改它（会被覆盖）。改页面请改源码再构建：

```
web开发\_parts\（12 个分块，含中文原文）
   │  _build-pages.mjs（按序拼接）
   ▼
_browse-pages.new.js（页面源码，含中文）
   │  _build-browse.mjs（合并 + 非 ASCII 转义 + 统一 CRLF）
   ▼
cos-proxy-worker.js（部署产物）
```

**构建命令：**
```bash
cd "e:\DEVE 开发\web开发"
node _build-pages.mjs
node _build-browse.mjs   # 默认输出 cos-proxy-worker.built.js
node --check cos-proxy-worker.built.js
# 确认无误后覆盖：
Copy-Item cos-proxy-worker.built.js cos-proxy-worker.js -Force
Copy-Item cos-proxy-worker.built.js "cloud-mail-fork\doc\cos-proxy-worker.js" -Force
```

**手写 `_parts\` 块的硬性规则：**
1. 中文/emoji 照常写，构建器自动转换：`<script>` 内 → `\uXXXX`，其余 → HTML 实体，保证 served 页面纯 ASCII。
2. 模板内**不要**出现反引号 `` ` `` 与 `${`（除页面已声明的插值如 `${tsWidget}`）。
3. 内联 JS 里**不要**写反斜杠正则（如 `\d`）；需要转义的用 `\uXXXX` 由构建器处理。

---

## 8. 已修复问题记录（按 commit）

| Commit | 内容 |
|---|---|
| `73b4f88` | feat: Alist 风格 UI 初版（架构/接口不变） |
| `8d1f8a8` | refine: 对照 alist-web 源码精确对齐设计（主色/容器/列表三列/单色 SVG 图标/文件卡片） |
| `f5e61d1` | docs: 补充设计规格 |
| `5180c87` | fix: TTL 非法值兜底、/browse HEAD 污染缓存、登录 Map 清理、缩略图并发限流 |
| `2de902d` | fix: 根路径防自杀式重定向 |
| `f921089` | feat: 视频 Range 流式、关闭弹层暂停媒体、每页 100 条 |
| `8dc6040` | feat: 移除复制链接按钮 |
| `8297727` | fix: 退出改服务端 /browse/logout、退出图标缺字形换 SVG |
| `aa30ea2` | feat: cookie 指纹 FNV-1a → HMAC-SHA256 |
| `a45b7b3` | feat: 顶栏「返回邮件」按钮 |
| `49cdf53` | feat: `/browse` 与 `/temp` 页脚版权行「© 2026 DelicateDuck582」（无下划线/非蓝色超链接 → fork 仓库；`target=_blank` + `rel=noopener noreferrer`） |
| `de8f581` | feat: `/temp` **上传任务面板（仿 Alist）**——悬浮按钮+角标、进度条/速度/状态、上传日志、失败重试/取消/清除；修复「上传后列表不刷新」（KV `list()` 最终一致 → 乐观插入 + `localStorage` 持久化 + 2.5/7/16/32s 校准）；429 尊重 `Retry-After`；服务器端新增 `tempSafeType()` 清洗 Content-Type（防 CRLF 注入/500 与 KV metadata 超限） |
| `1f701b6` | **审计修复**（详见 `doc/审计报告-COS-Worker-安全性能密钥-2026-09-13.md`）：① 附件 **HEAD 预检 404**（成功 HEAD 落入"非 200"分支被映射为 404）→ 新增 HEAD 200 透传；② 列表错误回包**不再泄露 COS 原始 XML/桶域名**（只回 `list failed <status>`，细节仅进服务端日志）；③ 登录页 **2FA 输入框门控改 `authStore(env)`**（只绑 `TEMP_KV` 时不再把用户锁死） |
| `1e8ced9` | docs: 新增审计报告（安全/性能/密钥），说明文档同步 |
| `d9cd744` | feat: `/temp` **文件续期按钮**（每行 ↻，每次从当前到期时间 +7 天，总上限 30 天）：新增 `POST /temp/api/renew`（读回原值 + 新 `expirationTtl` 重写、metadata 保留、限流 30/分、key 校验 400、不存在 404）；前端点击后本地到期时间即时更新并提示（达上限不虚报天数） |

---

## 9. 已知限制 / 后续可做

- **视频/音频不走 Worker Cache**：Cache API 不支持 206/Range 且大文件不适合，视频直连 COS 回源（私有桶下行流量费）。
  若需进一步降流量，可考虑 R2 或 CF 边缘缓存（注意勿绕过 /browse 密码门控）。
- **COS 列表无总数**：`ListObjectsV2` 不返回总条数/总页数，所以文件列表分页器只能
  「已访问页 + 上一页/下一页」顺序翻页，无法像本地页那样一次显示全部页码并任意跳转。
  若目录量大且需要任意跳页，需引入 R2/COS 索引服务（超出当前单 Worker 范围）。
- **单一共享密码**：所有登录者看到同一桶全部文件，无用户级权限体系。
- **文件路径结构**会出现在 `key=` 参数中（下载/预览必需），已通过移除复制链接降低暴露面。
- 后续可选项：文件级签名链接（像附件那样）、R2 视频缓存、多用户体系。

---

## CLI 部署（wrangler，2026-09-18 起）

`/browse`、`/temp` 与附件代理同属 **cos-exchange** Worker；除"面板粘贴代码"外，现支持 CLI 部署（可复现、可回滚）：

```powershell
cd mail-worker
npx wrangler deploy -c ../doc/cos-exchange.wrangler.toml
```

配置要点（完整注释见 `doc/cos-exchange.wrangler.toml`，实测记录见审计报告 §9.3）：

| 项 | 值 | 为什么 |
|---|---|---|
| `main` | `cos-proxy-worker.js`（同目录） | 部署的就是仓库里这份文件；改完先 `node --check` |
| `compatibility_date` | `"2026-08-10"` | 与线上现版本一致（读自 `wrangler versions view`），避免运行时语义漂移 |
| **`keep_vars`** | `true` | **必须**：CLI 部署默认删除所有明文变量（`REGION`/`TEMP_PASS`/`ATT_SIGN_MAX_TTL`/`BROWSE_ALLOW_COUNTRY`）→ 会直接打断 `/browse`（COS 探活失败）与 `/temp`（未配置密码） |
| `[[kv_namespaces]]` | `BROWSE_KV`、`TEMP_KV` | 必须与线上 ID 一致，否则 2FA 会话与临时网盘全部失效 |
| `routes` | 不声明 | 已有自定义域保持原样 |
| `preview_urls` | `false` | CLI 默认会为版本生成**公网**预览 URL（实测可访问），关掉减少暴露面 |

部署后核对：

```powershell
cd mail-worker
npx wrangler deployments status --name cos-exchange
npx wrangler versions view <Version ID> --name cos-exchange   # 期望：7 个 Secret + 2 个 KV + 4 个环境变量
```

> 若清单里少了 `REGION` / `TEMP_PASS` 等变量，说明 `keep_vars` 未生效：需在面板补回（值不要写进仓库）。
