<p align="center">
    <img src="doc/demo/logo.png" width="80px" />
    <h1 align="center">Cloud Mail</h1>
    <p align="center">A simple, responsive email service designed to run on Cloudflare Workers 🎉</p> 
    <p align="center">
       <a href="/README.md" style="margin-left: 5px">简体中文</a> | English 
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

## Description

With only one domain, you can create multiple different email addresses, similar to major email platforms. This project can be deployed on Cloudflare Workers to reduce server costs and build your own email service.

## Project Showcase

- [Live Demo](https://skymail.ink)<br>
- [Deployment Guide](https://doc.skymail.ink/en/)<br>

| ![](/doc/demo/demo1.png) | ![](/doc/demo/demo2.png) |
|--------------------------|--------------------------|
| ![](/doc/demo/demo3.png) | ![](/doc/demo/demo4.png) |

## Features

- **💰 Low-Cost Usage**: No server required — deploy to Cloudflare Workers to reduce costs.
- **💻 Responsive Design**: Automatically adapts to both desktop and most mobile browsers.
- **📧 Email Sending**: Integrated with Resend, supporting bulk email sending and attachments.
- **🛡️ Admin Features**: Admin controls for user and email management with RBAC-based access control.
- **📦 Attachment Support**: Send and receive attachments, stored and downloaded via R2 object storage.
- **🔔 Email Push**: Forward received emails to Telegram bots or other email providers.
- **📡 Open API**: Supports batch user creation via API and multi-condition email queries
- **🔢 Verification Code Recognition**: Auto-detect codes via Workers AI
- **📈 Data Visualization**: Use ECharts to visualize system data, including user email growth.
- **🎨 Personalization**: Customize website title, login background, and transparency.
- **🤖 CAPTCHA**: Integrated with Turnstile CAPTCHA to prevent automated registration.
- **📜 More Features**: Under development...

## New Features (Fork Enhancements)

### This is an enhancement written by AI. I'm just a beginner, and I had AI write it based on my own ideas and the features I actually use.

This fork adds the following custom features on top of the upstream:

- **🔐 Attachment Signature Anti-Forgery**: Attachments are stored in a private COS/S3 bucket and served through short-lived HMAC-signed URLs (15 min by default) with Referer/Sec-Fetch validation, preventing hotlinking and forgery; Cloudflare edge caching reduces origin traffic.
- **📁 Attachment Manager**: A dedicated attachment management page:
  
  - "All / Trash" tabs
  - Auto-detected type labels (`Attachment-Image` / `Attachment-Word` / `Attachment-PDF` / `Attachment-Archive` / `Attachment-oc` etc., by extension)
  - Select and act: preview / download / locate email / delete / restore
  - Admins can filter by user and see the owner's email and role group
  - Click the filename to preview directly (mobile-friendly)
  - Responsive layout; table scrolls inside its container
- **🗑️ Trash Mechanism**: Deleting moves attachments to trash (soft delete, original files untouched); the system auto-purges after 7 days; users can restore their own attachments; **only the super admin can permanently delete**.
- **👥 Role Group (Security Group)**: Roles granted `all-email:query` can view all users' emails and attachments and manage (soft-delete / restore) any attachment, but **cannot permanently delete from trash** (super admin only).
- **✍️ HTML Signature**: Configure an HTML signature (e.g., QQ Mail style card) in personal settings; it is auto-inserted when composing a new email.
- **📏 Attachment Size Limit**: The frontend warns when an attachment exceeds 28MB (adapted to Resend's 40MB post-base64 total limit).

## Tech Stack

- **Platform**: [Cloudflare Workers](https://developers.cloudflare.com/workers/)
- **Web Framework**: [Hono](https://hono.dev/)
- **ORM**: [Drizzle](https://orm.drizzle.team/)
- **Frontend Framework**: [Vue3](https://vuejs.org/)
- **UI Framework**: [Element Plus](https://element-plus.org/)
- **Email Service**: [Resend](https://resend.com/)
- **Cache**: [Cloudflare KV](https://developers.cloudflare.com/kv/)
- **Database**: [Cloudflare D1](https://developers.cloudflare.com/d1/)
- **File Storage**: [Cloudflare R2](https://developers.cloudflare.com/r2/)

## Project Structure

```
cloud-mail
├── mail-worker				    # Backend worker project
│   ├── src                  
│   │   ├── api	 			    # API layer
│   │   ├── const  			    # Project constants
│   │   ├── dao                 # Data access layer
│   │   ├── email			    # Email processing and handling
│   │   ├── entity			    # Database entities
│   │   ├── error			    # Custom exceptions
│   │   ├── hono			    # Web framework, middleware, error handling
│   │   ├── i18n			    # Internationalization
│   │   ├── init			    # Database and cache initialization
│   │   ├── model			    # Response data models
│   │   ├── security			# Authentication and authorization
│   │   ├── service			    # Business logic layer
│   │   ├── template			# Message templates
│   │   ├── utils			    # Utility functions
│   │   └── index.js			# Entry point
│   ├── package.json			# Project dependencies
│   └── wrangler.toml			# Project configuration
│
├─ mail-vue				        # Frontend Vue project
│   ├── src
│   │   ├── axios 			    # Axios configuration
│   │   ├── components			# Custom components
│   │   ├── echarts			    # ECharts integration
│   │   ├── i18n			    # Internationalization
│   │   ├── init			    # Startup initialization
│   │   ├── layout			    # Main layout components
│   │   ├── perm			    # Permissions and access control
│   │   ├── request			    # API request layer
│   │   ├── router			    # Router configuration
│   │   ├── store			    # Global state management
│   │   ├── utils			    # Utility functions
│   │   ├── views			    # Page components
│   │   ├── app.vue			    # Root component
│   │   ├── main.js			    # Entry JS file
│   │   └── style.css			# Global styles
│   ├── package.json			# Project dependencies
└── └── env.release				# Environment configuration
```

## Sponsor（Give him some support maillab/cloud-mail）

<a href="https://doc.skymail.ink/support.html">
<img width="170px" src="./doc/images/support.png" alt="">
</a>

## License

This project is licensed under the [MIT](LICENSE) license.

## Communication

[Telegram](https://t.me/cloud_mail_tg)
