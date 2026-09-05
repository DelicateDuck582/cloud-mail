# COS-exchange / mail-worker 环境变量配置核对（2026-09-05）

> 依据：Cloudflare 面板实际配置 + 代码（mail-worker=attachment-manager 3770547；cos=doc/cos-proxy-worker.js）
> 目标：核对配置与代码要求是否一致，标出风险项

---

## 1. cos-exchange（cos.<域名>）

| 变量 | 你的值 | 类型 | 代码要求 | 核对 |
|---|---|---|---|---|
| `ATT_SIGN_SECRET` | 加密 | 密钥 | 与 mail-worker 同值 | ✅（需人工确两侧一致） |
| `ATT_SIGN_MAX_TTL` | `3600` | 文本 | 数字；非法回退 3600 | ✅ |
| `AWS_ACCESS_KEY_ID` | 加密 | 密钥 | COS 只读子账号 | ✅ |
| `AWS_SECRET_ACCESS_KEY` | 加密 | 密钥 | 同上 | ✅ |
| `BROWSE_ALLOW_COUNTRY` | `CN,JP` | 文本 | 逗号分隔地区码 | ✅（注意：除 CN/JP 外**全部拒绝**） |
| `BROWSE_PASS` | 加密 | 密钥 | 必填 | ✅ |
| `REGION` | `ap-osaka` | 文本 | S3 签名 region | ⚠️ 见下 |
| `S3_ENDPOINT` | 加密 | 密钥 | 桶访问域名 | ✅（需以 `https://` 开头） |
| `TURNSTILE_SECRET` | 加密 | 密钥 | 可选 | ✅ |
| `TURNSTILE_SITEKEY` | 加密 | 密钥 | 可选 | ⚠️ 见下 |

### ⚠️ cos-exchange 两个注意点

1. **`TURNSTILE_SITEKEY` 用「密钥」类型**：sitekey 是**公开值**（会直接出现在登录页 HTML 的 `data-sitekey` 与前端脚本里），
   放「密钥」类型不影响读取，但属于类型误用——它最终必然暴露给浏览器，设为 secret 无保密收益。
   建议改「文本」类型，便于排障；`TURNSTILE_SECRET` 保持「密钥」正确。
   （不影响当前功能，仅运维建议。）

2. **`REGION=ap-osaka` + `S3_ENDPOINT`（日本桶）**：
   - 与代码无冲突；S3 V4 签名 `Credential=…/ap-osaka/s3/…`，只要 S3_ENDPOINT 是同一 ap-osaka 桶即可。
   - ⚠️ `BROWSE_ALLOW_COUNTRY=CN,JP` 是**访问者 IP 国家白名单**，与桶地域无关，配置本身正确；
     但需注意：你在日本访问会过，但若用其它地区代理/服务器测试会被 403——排障时容易误判。

3. **COS 健康探测**：探测走 `browseList`（需 `GetBucket` 权限）。若只读子账号策略缺 `GetBucket`，
   `/browse` 首页会 503「COS对象存储错误」，与列表权限相关，建议确认策略含 `GetObject + GetBucket`。

---

## 2. mail-worker（mail.<域名>）

| 变量 | 你的值 | 类型 | 代码要求 | 核对 |
|---|---|---|---|---|
| `admin` | `admin@moeq.moe` | 文本 | 管理员邮箱 | ✅ 内部超管域（§2.2），登录不查 domain |
| `ATT_SIGN_SECRET` | 加密 | 密钥 | 与 cos-exchange 同值 | ✅ 需两侧一致 |
| `ATT_SIGN_TTL` | `900` | 文本 | 60~86400，默认 900 | ✅ |
| `domain` | `["duckgame-play.top","delicateduck.xyz","ciallo…` | JSON | 数组 | ✅ 不含 moeq.moe（内部域，§2.2） |
| `INIT_SECRET` | 加密 | 密钥 | 必填（/init） | ✅ |
| `jwt_secret` | 加密 | 密钥 | 签名密钥 | ✅ |
| `RESEND_SIGNING_SECRET` | 加密 | 密钥 | Resend webhook 验签 | ✅ |

### 2.2 ✅ 澄清：`moeq.moe` 是内部超管域（设计如此，非配置缺失）

维护者确认：`admin@moeq.moe` 是**内部管理员邮箱（超级管理员）**，
`moeq.moe` **刻意不加入** `domain` 用户白名单。

代码事实（已逐行确认，与该设计自洽）：
- **注册**（`login-service.js` L86）：强制 `c.env.domain.includes(邮箱域)` → `moeq.moe` 用户无法自助注册；
- **新增账户**（`account-service.js` L38）：同样校验 → 普通用户无法把 moeq.moe 加入自己的可用账号；
- **OAuth 绑定**（`oauth-service.js` bindUser → `loginService.register`）：同样受 domain 校验拦截；
- **登录**（`login-service.js` L224+）：**不校验 domain**，DB 中已有该用户即可登录。

设计效果：
- 超管账号 `admin@moeq.moe` **登录不受影响**（登录不查 domain）；
- 普通用户**无法注册/绑定** `@moeq.moe` 域 → 该域被"锁定"为内部域，只能通过超管手动创建账号使用；
- 超管权限判定为 `user.email === c.env.admin`（硬编码邮箱比较），与 domain 列表无关。

**→ 原先标"高"的 #1 项撤销：这是正确配置，非缺陷。**
注意：`admin@moeq.moe` 账号本身需已存在于 DB（由部署者经开放注册/手动 SQL 建立一次），此后 domain 无需包含 moeq.moe。

### ⚠️ mail-worker 补充

1. `domain` 里出现 `ciallo…`（如 ciallo.sale）与 `delicateduck.xyz`：与 thunderbird/stalwart 文档中
   收件域一致（contact/service/pgp/noreply@ciallo.sale、admin@delicateduck.xyz），属预期。
2. 超管判定按 `user.email === c.env.admin` 硬编码比较（见 §2.2），与 domain 列表无关。
3. `ATT_SIGN_TTL=900` + cos 侧 `ATT_SIGN_MAX_TTL=3600`：**配对正确**（900<3600），无超长签名被拒风险。

---

## 3. 安全提示汇总

| # | 项 | 级别 | 说明 |
|---|---|---|---|
| 1 | ~~`admin@moeq.moe` 域不在白名单~~ | ~~高~~ | ✅ **撤销**：moeq.moe 为内部超管域，设计如此（见 §2.2） |
| 2 | `ATT_SIGN_SECRET` 两侧一致性 | 高 | 面板两侧均「加密」无法目检；可用同一随机串重新 set 两侧 |
| 3 | `TURNSTILE_SITEKEY` 应为文本类型 | 低 | 改文本（值本就公开） |
| 4 | COS 只读子账号需 `GetObject+GetBucket` | 中 | 确认策略，否则 /browse 503 |
| 5 | `BROWSE_ALLOW_COUNTRY=CN,JP` | 低 | 排障时注意非中/日 IP 一律 403 |
| 6 | `domain` 数组完整值 | 低 | 截图截断处已确认包含 ciallo/delicateduck 等收件域即可 |

> 无凭证探测已在 2026-08-29 做过（行为正常）；本次为配置↔代码静态核对。
