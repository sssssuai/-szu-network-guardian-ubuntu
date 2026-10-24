# SZU Network Guardian — Ubuntu 安全版 2

针对教学／办公区、有线网络、无代理场景的本地适配版本。
已知目标环境：Ubuntu 22.04.3 LTS、x86_64、有图形桌面。
基于 [Georgeupup/szu-network-guardian](https://github.com/Georgeupup/szu-network-guardian)
上游提交 `44554ac5396abd977b3563f64ae3dc633d5cd988`。

本次改动：

- 校验学校认证服务器的 HTTPS 证书、有效期和域名。
- 直连物理网卡时保留域名、SNI 与 Host；不把关闭 TLS 校验作为兼容办法。
- 禁止认证请求自动重定向；只允许向 `https://net.szu.edu.cn` 认证。
- 默认不保存密码，运行时输入；明确选择后才在本机加密保存。
- 禁用宿舍区明文 HTTP 认证及自动回退，安全校验失败时停止监控。
- 请求异常和服务器错误文本不直接写入日志，密码及认证参数做脱敏。
- 提供图形界面、无桌面监控和用户级 systemd 服务；服务需明确保存密码。

使用方法见 [Ubuntu 安装说明](README-UBUNTU.md)。
安全边界和已验证的内容见 [SECURITY.md](SECURITY.md)。

本版本基于上游进行独立的 Ubuntu 适配，未合并到上游；尚未在 Ubuntu 或真实校园网中端到端验证。
本机测试包含真实回环 HTTPS 连接；Ubuntu 文件权限相关测试需在 Linux 上执行。
上游 Windows 构建文件保留作参考，本次交付以 Ubuntu 源码运行方式为主。

已知限制与待修复事项见 [KNOWN_ISSUES.md](KNOWN_ISSUES.md)，包括终端关闭后窗口退出的反馈。

原项目 MIT 许可证保留在 [LICENSE](LICENSE)。SRun 协议移植的归属和许可说明
见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
