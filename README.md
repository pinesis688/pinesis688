# 🔐 SecureFx 加密工具箱

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/11955/badge)](https://www.bestpractices.dev/projects/11955)
[![Security](https://img.shields.io/badge/Security-Client%20Side-green.svg)](https://github.com)
[![Web Crypto API](https://img.shields.io/badge/API-Web%20Crypto-blue.svg)](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)

一款功能完善的浏览器端加密工具箱，所有加密操作均在本地完成，数据不经过任何服务器。支持 AES-GCM/CBC 对称加密、RSA/ECC 非对称加密、ECDSA 数字签名、SHA-2/SHA-3 哈希计算、古典密码等功能。

## ✨ 功能特性

### 🔒 核心加密功能

| 功能模块 | 描述 | 算法支持 |
|---------|------|----------|
| 📁 **文件加密** | 大文件分块加密，支持进度显示 | AES-256-GCM / AES-256-CBC + HMAC |
| 📝 **文本加密** | 文本字符串加密 | AES-256-GCM / AES-256-CBC |
| 🔑 **RSA 加密** | 非对称加密，适合小数据 | RSA-OAEP (2048/4096 bit) |
| 🔐 **ECC 加密** | 椭圆曲线加密，效率更高 | ECDSA P-256 + AES-GCM (ECIES) |

### ✍️ 数字签名

| 功能 | 描述 |
|------|------|
| 📜 **文本签名** | 对文本内容进行签名验证 |
| 📄 **文件签名** | 生成独立的 `.sig` 签名文件 |
| 🔄 **签名+加密** | 加密同时签名，一站式操作 |
| 🛡️ **篡改检测** | 自动检测数据是否被篡改 |

### 🔧 密钥派生函数 (KDF)

| 算法 | 特点 | 推荐场景 |
|------|------|----------|
| 💎 **Argon2id** | 抗 GPU/ASIC 攻击，内存硬函数 | 高安全需求（推荐） |
| 🔐 **Scrypt** | 内存硬函数，广泛支持 | 兼容性要求 |

### #️⃣ 哈希算法

| 算法 | 输出长度 | 说明 |
|------|----------|------|
| SHA-256 | 32 字节 | ✅ 推荐使用 |
| SHA-384 | 48 字节 | 🔒 高安全需求 |
| SHA-512 | 64 字节 | 🔒 高安全需求 |
| SHA3-256 | 32 字节 | 🆕 NIST 新标准 |
| SHA3-512 | 64 字节 | 🆕 NIST 新标准 |
| MD5 | 16 字节 | ⚠️ 不推荐，仅用于兼容 |

### 🎭 古典密码

| 密码 | 说明 |
|------|------|
| 📋 维吉尼亚密码 | 多表替换密码 |
| 🚧 栅栏密码 | 换位密码 |
| 🥓 培根密码 | 二进制编码 |
| 🔀 埃特巴什码 | 字母表反转 |
| 🔢 仿射密码 | 数学加密 |
| 🏛️ 凯撒密码 | 位移加密 |
| 🔁 ROT13 | 字母偏移13位 |

### 🎨 趣味编码

| 编码 | 说明 |
|------|------|
| Base32 | 📚 RFC 4648 编码 |
| Base58 | ₿ 比特币风格编码 |
| 摩尔斯电码 | 📟 经典电报编码 |
| 表情编码 | 😊 文本转表情符号 |
| 猪圈密码 | 🐷 图形替换密码 |
| 二进制/十六进制 | 💻 进制转换 |

### 🔑 密码工具

- 🎲 **密码生成器** - 可配置长度、字符集
- 💪 **密码强度评估** - zxcvbn 算法
- ⏱️ **破解时间估算** - 离线攻击场景
- 🧪 **随机性测试** - NIST SP 800-22 标准

## 🛡️ 安全特性

### 🌐 端到端安全

- ✅ 所有加密操作在浏览器本地完成
- ✅ 数据不经过任何服务器
- ✅ 无需网络连接即可使用
- ✅ 开源代码，可审计

### 🔍 安全审计

内置 28 项自检测试，覆盖所有核心功能。

### ⚠️ 安全警告

本工具无法防御：
- 🦠 恶意软件、键盘记录器
- 💻 系统级攻击、内存 dump
- 🔓 浏览器恶意扩展

禁止用于：国家秘密、金融核心数据、等保三级以上数据、任何法律禁止的场景。

## 🚀 快速开始

直接打开 `index.html` 即可使用，无需安装。

或访问在线版本：[https://securefx.vercel.app](https://securefx.vercel.app)

## 💻 浏览器兼容性

| 浏览器 | 最低版本 |
|--------|----------|
| 🌐 Chrome | 60+ |
| 🦊 Firefox | 60+ |
| 🧭 Safari | 14+ |
| 🪟 Edge | 79+ |

## 📜 许可证

MIT License

## 👥 贡献者

- 111 (💡 灵感来源)
- pinesis
- Trae CN

## 🏆 徽章

本项目遵循 [OpenSSF 最佳实践](https://www.bestpractices.dev/)，已获得 🥇 Gold 级别徽章。
