<p align="center">
    <img src="doc/demo/logo.png" width="80px" />
    <h1 align="center">Cloud Mail</h1>
    <p align="center">基于 Cloudflare 的简约响应式邮箱服务，支持邮件发送、附件收发 🎉</p> 
    <p align="center">
        简体中文 | <a href="/README-en.md" style="margin-left: 5px">English </a>
    </p>
    <p align="center">
        <a href="https://github.com/maillab/cloud-mail/tree/main?tab=MIT-1-ov-file" target="_blank" >
            <img src="https://img.shields.io/badge/license-MIT-green" />
        </a>    
        <a href="https://github.com/maillab/cloud-mail/releases" target="_blank" >
            <img src="https://img.shields.io/github/v/release/maillab/cloud-mail" alt="releases" />
        </a>  
        <a href="https://github.com/maillab/cloud-mail/issues" >
            <img src="https://img.shields.io/github/issues/maillab/cloud-mail" alt="issues" />
        </a>  
        <a href="https://github.com/maillab/cloud-mail/stargazers" target="_blank">
            <img src="https://img.shields.io/github/stars/maillab/cloud-mail" alt="stargazers" />
        </a>  
        <a href="https://github.com/maillab/cloud-mail/forks" target="_blank" >
            <img src="https://img.shields.io/github/forks/maillab/cloud-mail" alt="forks" />
        </a>
    </p>
    <p align="center">
        <a href="https://trendshift.io/repositories/20459" target="_blank" >
            <img src="https://trendshift.io/api/badge/repositories/20459" alt="trendshift" >
        </a>
    </p>
</p>

## 项目简介

只需要一个域名，就可以创建多个不同的邮箱，类似各大邮箱平台，本项目支持署到 Cloudflare Workers ，降低服务器成本，搭建自己的邮箱服务

## 项目展示

- [在线演示](https://skymail.ink)<br>
- [部署文档](https://doc.skymail.ink)<br>

| ![](/doc/demo/demo1.png) | ![](/doc/demo/demo2.png) |
|-----------------------|-----------------------|
| ![](/doc/demo/demo3.png) | ![](/doc/demo/demo4.png) |

## 功能介绍

- **💰 低成本使用**： 可部署到 Cloudflare Workers 降低服务器成本
- **💻 响应式设计**：响应式布局自动适配PC和大部分手机端浏览器
- **📧 邮件发送**：集成Resend发送邮件，支持群发，内嵌图片和附件发送，发送状态查看
- **🛡️ 管理员功能**：可以对用户，邮件进行管理，RABC权限控制对功能及使用资源限制
- **📦 附件收发**：支持收发附件，使用R2对象存储保存和下载文件
- **🔔 邮件推送**：接收邮件后可以转发到TG机器人或其他服务商邮箱
- **📡 开放API**：支持使用API批量生成用户，多条件查询邮件
- **🔢 验证码识别**：使用Workers AI，自动识别邮件验证码
- **📈 数据可视化**：使用ECharts对系统数据详情，用户邮件增长可视化显示
- **🎨 个性化设置**：可以自定义网站标题，登录背景，透明度
- **🤖 人机验证**：集成Turnstile人机验证，防止人机批量注册
- **📜 更多功能**：正在开发中...

## 本项目新增功能（Fork 增强）

#### **这是由AI编写的增强功能。本人只是小白，按照自己的想法与实际用到的功能让AI编写的**

本仓库在 upstream 基础上增加了以下自定义功能：

- **🔐 附件签名防伪造**：COS/S3 私有桶存储，附件访问使用后端签发的短期 HMAC 签名（默认 15 分钟有效）+ Referer/Sec-Fetch 双层校验，防止盗链与伪造访问；直读代理 Worker（cos-exchange）验签通过后用 Cache API 按文件缓存（附件 key 为内容哈希，缓存 7 天，文件不变即最多每 7 天回源一次）。改造说明见 [doc/签名防伪造改造说明.md](doc/签名防伪造改造说明.md)，代理 Worker 代码见 [doc/cos-proxy-worker.js](doc/cos-proxy-worker.js)
- **📁 附件管理器**：独立的附件管理页面
  
  - 「全部 / 垃圾桶」双选项卡
  - **按文件（内容哈希）分组展示**，可展开二级表格查看每个用户的引用明细，支持单用户操作（定位邮件 / 删除 / 恢复）
  - 类型自动识别显示（`附件-图片` / `附件-Word文档` / `附件-PDF` / `附件-压缩包` 等，按扩展名）
  - 工具栏操作按钮常驻（预览 / 下载 / 删除 / 恢复 / 彻底删除），未选择附件时给出提示
  - 管理员可按用户筛选，显示所属用户与权限组
  - 点击文件名可直接预览（移动端友好）
  - 响应式布局，表格在容器内滚动不溢出
- **🗑️ 邮件与附件垃圾桶机制**：删除 = 移入垃圾桶（软删除，原文件不受影响），记录删除时间，7 天后系统自动彻底清理；删除附件会连带邮件一起进垃圾桶，恢复附件也会连带恢复邮件；邮件删除同样进垃圾桶并支持恢复；**仅超级管理员可彻底删除**
- **📊 COS 使用量统计**：附件管理页展示附件占用 / COS 实际存储 / 已用 / 总量 / 剩余，可配置总容量（GB）与 S3 到期时间（过期红色提醒）
- **👥 权限组（安全组）**：被授予 `all-email:query` 权限的角色可查看全部用户的邮件与附件，可管理（软删 / 恢复）任意附件，但**不能彻底删除垃圾桶**（该操作仅限超级管理员）
- **✍️ HTML 签名**：个人设置中配置 HTML 个性签名（如 QQ 邮箱签名卡），新建邮件时自动插入编辑器
- **📏 附件大小限制**：发送时附件超过 28MB 前端直接提示超限（适配 Resend 整封邮件 40MB、base64 后的实际上限）
- **🛡️ 安全加固**：
  - 修复默认角色被误授 `all-email:query`（全站邮件/附件查看）权限的问题
  - 附件直读端点（`/api/oss`、`/attachments`）强制 HMAC 签名校验，防止绕过签名防伪系统
  - 无权限的删除 / 恢复操作明确返回 403（不再静默成功）
  - 邮件删除 / 恢复接口纳入权限中间件与归属校验
  - COS 用量遍历增加页数上限，错误响应不泄露内部信息
  - 附件直读代理 Worker（cos-exchange）修复含空格 / Unicode 文件名的签名校验，并对已签名请求放宽 Referer / Sec-Fetch 校验（兼容邮件客户端）
  - **邮件内容 XSS 防护**：邮件 HTML 在入库时用白名单清洗（linkedom）：移除 `script` / `iframe` / `object` / `embed` / `svg` / `math` / 表单控件、所有 `on*` 事件属性、`javascript:` / `vbscript:` / `data:text/html` 等危险 URL 与危险 CSS；前端渲染（ShadowHtml 详情、回复/转发注入、TG 预览页、签名预览）再做一次同规则清洗兜底旧数据
- **📋 安全审计记录（2026-08-18 第三轮）**：
  - **🔴 高危（已修复）**：Resend Webhook Svix 验签解析 bug —— 原实现 `sigHeader.split(' ').includes(sigB64)` 把 `"v1,<签名>"` 整体与裸签名比较，配置 `RESEND_SIGNING_SECRET` 后**所有 webhook 均 401**（送达/退信/已读回执等状态更新全部失效）；已修复为解析 `v1,` 前缀 + `.some()` 支持多签名 token（密钥轮换）+ **恒定时间比较**（`timingSafeEqual`，防时序侧信道）
  - **📧 已读回执（新功能）**：webhook 支持 `email.opened` / `email.clicked` → 邮件状态标记「已读」（`OPENED=9`），前端已发送列表新增「已读 👁」图标；**未处理事件**（`email.received` / `email.sent` 等）直接忽略、不再误改状态；**状态只升不降**（已读 9 之后迟到的 delivered 2 不会回退覆盖）
  - **✅ 复核确认安全**：CORS 白名单、`/init` 独立 INIT_SECRET + per-IP 限流、`/oss` + `/attachments` 附件直读 HMAC 签名、TG 预览 token 7 天 TTL + `Cache-Control: no-store`、public token 24h TTL 仅超管签发、登录防爆破（5 次/10 分钟 + 延迟）、`crypto.getRandomValues` 密码学随机、注册/加号 Turnstile + per-IP 验证记录、入站邮件 25MB/20 附件上限、发信前附件数量限制、发信限额/账号归属/域名权限校验、SQL 全参数化（drizzle / `prepare().bind()`）、全局错误脱敏、邮件 XSS 入库清洗 + 前端渲染兜底
  - **⚠️ 部署要求**：**必须在 Cloudflare 环境变量配置 `RESEND_SIGNING_SECRET`**（= Resend Webhooks 的 Signing secret），否则 webhook 未验签、邮件状态可被伪造；**所有密钥类环境变量不要写入 `wrangler.toml` / 不要提交到 git**（本地开发用 `wrangler-dev.toml`，已被 gitignore）
  - **☁️ COS 专项审计（2026-08-18）**：附件直读三层防护复核通过（COS 私有桶 + HMAC 短期签名 + 代理 Worker 路径白名单）；修复**中风险**：`/attachments/*` 与 `/browse/api/file` 响应原带 `Cache-Control: public, max-age=604800`，会让 Cloudflare 边缘 HTTP 缓存按完整 URL（含 query）缓存 → 签名过期后 7 天内旧 URL 仍可**直接命中边缘缓存，绕过 Worker 验签 / 网盘密码**。已改为 `private`（仅浏览器缓存、禁用共享缓存），内部 Cache API 7 天缓存不受影响；另给 mail-worker `/oss/*` 直读加 **per-IP 限流（120 次/分）**，防已登录用户反复拉取自己附件刷 COS 下行流量。⚠️ 部署注意：COS 桶必须保持**私有读写**；`ATT_SIGN_SECRET` / `BROWSE_PASS` 不得泄露；旧版 `cos-browser-worker`（files.* 子域名）若未下线，请确认已设置 `BROWSE_PASS`
- **📬 邮件镜像（Thunderbird / IMAP 客户端）**：`stalwart-sync/` 同步脚本把 CloudMail 收件箱镜像到自托管 **Stalwart Mail Server**，雷鸟 / 手机邮件客户端用标准 IMAP/SMTP 收发：
  - **多账户文件夹聚合**：每个 CloudMail 邮箱账户对应一个 IMAP 文件夹（JMAP Email/import 投递），支持 Sent / Trash
  - **双向同步**：已读回写、删除回写 + 垃圾桶恢复、发信镜像（方案 C：经 CloudMail Resend API 投递，不依赖出站 25 端口）
  - **按需同步**：默认由雷鸟打开 / 切换文件夹时经 HTTP 触发服务即时同步，仅保留低频兜底轮询——大幅降低 Cloudflare Worker 调用（适合免费额度）
  - **附件可选镜像**：`ATTACHMENTS=1` 时同步附件到本地 Stalwart（雷鸟直接查看 / 下载，无需 web 端）
  - **健壮性**：状态文件幂等（防重复投递）、失败熔断与指数退避重试、原子写、SIGTERM 优雅保存 state（防中断重复导入）；触发服务仅回环 + token 校验；MIME boundary 使用密码学随机
  - **📌 2026-08-29 更新**：
    - **内嵌图 cid 嵌入**：同步时把正文中的 COS 图片下载并嵌入 MIME（`multipart/related` + `Content-ID`），镜像邮件自包含——手机/雷鸟**无需插件、无需 CloudMail 账户、无需联网签名**即可显示内嵌图
    - **中文主题乱码修复**：邮件头非 ASCII 字段（Subject/发件人名字）按 **RFC 2047**（`=?UTF-8?B?…?=`）编码，解决手机客户端中文主题乱码
    - **KV/R2 附件 403 修复**：COS 故障回退 KV 时附件 URL 产生 `attachments/attachments/` 双前缀导致签名验签 403——`sign-utils` 按存储类型去除重复前缀（`mail-worker`）
    - **网络抗波动**：CloudMail API 指数退避重试（600ms→12s），覆盖 VPS→CF 间歇性网络波动
    - **魔数嗅探（MIME 识别）**：内嵌图/附件下载后读文件头魔数判断真实类型（JPEG/PNG/GIF/WebP/BMP），解决 COS 存储 Content-Type 为 `octet-stream` 且 key 无扩展名（如 `<hash>.58D8796A00000000`）导致客户端无法渲染的问题——Web 端靠浏览器内容嗅探能显示，雷鸟/手机必须靠正确的 MIME part
    - **内嵌图排版修复**：邮件 HTML 注入内联样式（对齐 CloudMail 原始排版：body 字体/颜色、`p{margin:0}`、h1-4、a、table 响应式），雷鸟/手机不执行 JS / Shadow DOM 也能获得与 Web 端一致的排版
    - **附件图片 MIME 优先**：附件下载时图片魔数绝对优先（覆盖 COS/attList 错误的 octet-stream），非图片保持原类型
  - 详见 [`stalwart-sync/README.md`](stalwart-sync/README.md)（含完整环境变量说明）；部署与凭据说明见本地部署文档（**不含在仓库中**）
- **🔒 安全审计（2026-08-29）**：CloudMail ↔ Stalwart 镜像链路全流程安全复核通过
  - **CloudMail 用户数据**：邮件详情 / 删除 / 恢复 / 已读均按 `userId` 归属校验（越权 403）；SQL 全参数化；邮件 XSS 入库清洗 + 前端渲染兜底；登录防爆破
  - **COS 附件安全**：COS 私有桶 + HMAC 短期签名（15min）+ 代理 Worker 路径白名单 + per-IP 限流 + `Cache-Control: private`（防边缘缓存绕过验签）——无权访问 / 越权访问 / 盗刷流量均受防护
  - **sync.js**：凭据仅存环境变量（权限 600）、JMAP/SMTP 强制回环、SMTP/邮件头注入防护、MIME boundary 密码学随机（防邮件头走私）、触发服务仅回环 + token 校验、状态文件原子写
  - **源码密钥检查**：git 历史 / 工作区无真实密钥（JWT / 签名密钥 / 密码 / token 均为占位符或环境变量）；含部署凭据说明的文档已从 git 移出跟踪
  - **语法检查**：`sync.js` / `smtp-void.js` / 雷鸟插件脚本 `node --check` 全部通过
  - **性能**：按需触发（雷鸟打开时同步）+ 低频兜底 + 指数退避重试 + 失败熔断——Worker 调用量大幅下降
  - 完整报告见 `stalwart-sync/安全审计报告-2026-08-29.md`


## 技术栈

- **平台**：[Cloudflare Workers](https://developers.cloudflare.com/workers/)
- **Web框架**：[Hono](https://hono.dev/)
- **ORM：**[Drizzle](https://orm.drizzle.team/)
- **前端框架**：[Vue3](https://vuejs.org/)
- **UI框架**：[Element Plus](https://element-plus.org/)
- **邮件推送：** [Resend](https://resend.com/)
- **缓存**：[Cloudflare KV](https://developers.cloudflare.com/kv/)
- **数据库**：[Cloudflare D1](https://developers.cloudflare.com/d1/)
- **文件存储**：[Cloudflare R2](https://developers.cloudflare.com/r2/)

## 目录结构

```
cloud-mail
├── mail-worker				    # worker后端项目
│   ├── src                  
│   │   ├── api	 			    # api接口层			
│   │   ├── const  			    # 项目常量
│   │   ├── dao                 # 数据访问层
│   │   ├── email			    # 邮件处理接收
│   │   ├── entity			    # 数据库实体
│   │   ├── error			    # 自定义异常
│   │   ├── hono			    # web框架配置、拦截器、全局异常等
│   │   ├── i18n			    # 语言国际化
│   │   ├── init			    # 数据库缓存初始化
│   │   ├── model			    # 响应体数据封装
│   │   ├── security			# 身份权限认证
│   │   ├── service			    # 业务服务层
│   │   ├── template			# 消息模板
│   │   ├── utils			    # 工具类
│   │   └── index.js			# 入口文件
│   ├── pageckge.json			# 项目依赖
│   └── wrangler.toml			# 项目配置
│
├── mail-vue				    # vue前端项目
│   ├── src
│   │   ├── axios 			    # axios配置
│   │   ├── components			# 自定义组件
│   │   ├── echarts			    # echarts组件导入
│   │   ├── i18n			    # 语言国际化
│   │   ├── init			    # 入站初始化
│   │   ├── layout			    # 主体布局组件
│   │   ├── perm			    # 权限认证
│   │   ├── request			    # api接口
│   │   ├── router			    # 路由配置
│   │   ├── store			    # 全局状态管理
│   │   ├── utils			    # 工具类
│   │   ├── views			    # 页面组件
│   │   ├── app.vue			    # 入口组件
│   │   ├── main.js			    # 入口js
│   │   └── style.css			# 全局css
│   ├── package.json			# 项目依赖
└── └── env.release				# 项目配置
```

## 赞助（支持它一下吧maillab/cloud-mail）

<a href="https://doc.skymail.ink/support.html" >
<img width="170px" src="./doc/images/support.png" alt="">
</a>

## 许可证

本项目采用 [MIT](LICENSE) 许可证

## 交流

[Telegram](https://t.me/cloud_mail_tg)


