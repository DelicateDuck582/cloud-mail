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

---

## 1. 改动清单（相对 attachment-manager）

| 文件 | 改动 |
|---|---|
| `doc/cos-proxy-worker.js` | **唯一改动的部署文件**（仓库内副本；部署用文件在仓库外 `web开发\cos-proxy-worker.js`，两者始终同步） |
| `doc/browse-alist-网盘改造说明.md` | 本说明文档 |

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
| `S3_ENDPOINT` | `https://cloudmail-1304899838.cos.ap-osaka.myqcloud.com` | ✅ |
| `REGION` | `ap-osaka` | ✅ |
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` | `cos-worker-readonly` 只读子账号（GetObject + GetBucket） | ✅ |
| `BROWSE_PASS` | 网盘访问密码 | ✅ |
| `ATT_SIGN_MAX_TTL` | 可选，默认 3600（非法值自动回退默认） | 否 |
| `BROWSE_ALLOW_COUNTRY` | 可选，如 `CN` | 否 |
| `TURNSTILE_SITEKEY` / `TURNSTILE_SECRET` | 可选，登录人机验证 | 否 |

> ⚠️ `cos-exchange` **不需要 KV 绑定**（代码无 `env.kv`）。KV 是 mail-worker 用的。

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

1. 用 `web开发\cos-proxy-worker.js`（**83168 字节附近**，以文件为准）全量替换 Worker `cos-exchange` 的代码。
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
