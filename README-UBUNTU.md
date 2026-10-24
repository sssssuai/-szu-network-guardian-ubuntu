# Ubuntu 安全版 2 使用说明

版本：`2.0.0-ubuntu-security`。
目标环境：Ubuntu 22.04.3 LTS、x86_64、有图形桌面、有线网络，教学／办公区，无代理。
本版仅支持教学／办公区，已禁用宿舍区明文 HTTP 认证和自动区域回退。
学校认证算法保留上游 SRun 实现；传输和密码保存策略已加固。

## 1. 安装桌面版

先退出旧版程序。解压新压缩包，打开包含 `main.py` 和 `install-ubuntu.sh` 的文件夹，
在文件夹空白处右键选择“在终端打开”。以下命令每次只执行一条。
安装依赖前，先在浏览器登录学校官网完成校园网认证，确保 apt / pip 能联网。

```bash
bash install-ubuntu.sh --desktop
```

sudo 提示时输入 Ubuntu 登录用户密码；稍后程序中输入的才是校园网密码。
脚本在项目目录创建 `.venv`。它固定使用 `/usr/bin/python3`，并安装与系统 Python
匹配的 venv / Tkinter，不受终端 `(base)` 环境中 Conda Python 3.12.7 的优先路径影响。
不会卸载 Conda，也不修改网卡或路由。后续始终使用 `.venv/bin/python`。

如果提示已有 `.venv` 不匹配，请将它改名备份后重试；新解压目录通常没有此问题。
不要复制旧目录的 `.venv` 到新版本。项目移到最终位置后再启用自启动。

## 2. 先验证学校 HTTPS 连接

本次检查不需要账号密码：

```bash
.venv/bin/python main.py --check-security
```

看到“TLS 证书和域名校验通过”后再继续。证书不受信任、过期或域名不匹配时，
程序阻止认证，不提供忽略证书错误或回退 HTTP 的开关。
校验失败时请核对系统日期时间，并提供脱敏错误信息；不要安装来源不明的证书。
校验通过只说明该次 TLS 连接通过校验，不代表电脑或整个网络已经过安全审计。

如自动网卡识别失败：

```bash
ip -br -4 addr
```

找到校园网网卡名后，可临时指定，例如：

```bash
.venv/bin/python main.py --check-security --interface enp3s0
```

将 enp3s0 换成实际网卡名。无代理环境下也可用 `--no-direct` 检查系统 DNS 和路由，
证书校验仍然开启。直连绑定源 IPv4，不保证绕过 TUN 策略路由。

## 3. 打开图形界面

```bash
.venv/bin/python main.py
```

输入校园网账号、密码，设置间隔（建议 3 分钟），点击“开始守护”。
默认不勾选“记住密码”：密码用于本次运行，不写入配置文件；再次启动需重新输入。
最小化后继续运行，关闭窗口退出。Linux 默认不启用托盘，以避免托盘后端兼容问题。

需要自动启动监控时，必须明确勾选“记住密码”，再勾选“登录桌面后自动启动”。
密码在本机加密保存。密钥与密文位于同一用户目录，能访问两者的程序或管理员仍可解密；
这不是针对已入侵电脑的保护。详细限制见 [SECURITY.md](SECURITY.md)。

## 4. 旧版密码与升级

旧版本曾隐式保存的密码不会在安全版中自动使用，需要重新明确选择是否保存。
旧配置的文件内容在首次修改前仍保留在磁盘上。
如果希望清除旧密码，请先关闭旧版窗口；曾安装后台服务时先停止：

```bash
systemctl --user stop szu-network-guardian
```

然后从新版本目录运行：

```bash
.venv/bin/python main.py --forget-password
```

该操作移除当前配置中的密码密文及相邻密钥文件。正在运行的旧进程、备份、快照、
磁盘残留不会因此自动清除。曾启用桌面自启动时，在新版重新设置启动项；
曾安装后台服务时，按下节重新安装并重启，确保指向新版目录。

## 命令行与服务器

服务器依赖安装使用 `bash install-ubuntu.sh`，无需 Tkinter、Pillow 或 pystray。
配置账号和检测选项，默认不保存密码：

```bash
.venv/bin/python main.py --configure --zone office --interval 3
```

检测并按需认证一次，会在终端询问密码（输入不显示）：

```bash
.venv/bin/python main.py --once
```

持续监控至按 Ctrl+C 停止：

```bash
.venv/bin/python main.py --headless
```

希望无人值守时，明确选择加密保存：

```bash
.venv/bin/python main.py --configure --zone office --interval 3 --save-password
```

保存前会询问校园网密码。无需通过命令行参数、环境变量或聊天发送密码。
`--ask-password` 可用于本次重新输入；非交互环境且没有已保存密码时程序拒绝启动。
终端不能关闭输入回显时，也会取消密码输入。

安装用户 systemd 服务前，关闭其他守护实例并验证 `--once` 成功：

```bash
.venv/bin/python main.py --install-service
```

```bash
systemctl --user restart szu-network-guardian
```

```bash
systemctl --user status szu-network-guardian
```

```bash
journalctl --user -u szu-network-guardian -n 50 --no-pager
```

只有明确保存密码时才允许安装服务。配置错误或安全校验失败退出码为 2，
生成的服务不会反复重启该类失败。需要修正问题后手动启动。
普通临时网络故障仍会按检测间隔重试。需要未登录时随开机运行，可在目标 Ubuntu 执行：

```bash
sudo loginctl enable-linger "$USER"
```

删除服务使用 `.venv/bin/python main.py --remove-service`。
桌面和后台服务同时运行会被文件锁阻止。程序只负责校园网认证，网卡需由 Ubuntu 自动连接。

## 配置与诊断

- 默认目录：`~/.config/szu-network-guardian/`；支持 `XDG_CONFIG_HOME` 与
  `SZU_GUARDIAN_DATA_DIR`，自启动项记录当前配置目录和虚拟环境绝对路径。
- `config.json` 保存账号及选项；仅明确选择保存密码时写入密码密文。
  Linux 使用 Fernet 和 `config.key`，Windows 保留 DPAPI。
- Linux 配置目录权限为 700；配置文件及密钥权限为 600，所有者必须为当前用户。
  配置和密钥的符号链接、过于宽松的权限会被拒绝。
- `logs/` 保存最近 7 天日志。日志不直接输出服务器错误原文或含认证参数的异常 URL。
- `--diagnose` 显示网卡 IPv4 与 DNS，不需要账号密码。
- `--once` 返回码：0 联网正常／重连成功；1 网络或认证失败；2 配置或安全错误。
- 不要向聊天提供密码、配置文件或密钥。反馈时提供 `--check-security`、`--diagnose`
  或 `--once` 的脱敏输出即可。

## 测试范围

```bash
.venv/bin/python -m unittest discover -s tests -v
```

本机 Windows 测试结果：60 项中 58 项通过，2 项 Linux 权限测试跳过。
真实本地 HTTPS 测试覆盖可信证书连接、错误域名、不受信任和过期证书阻断，
以及错误证书下不发送 HTTP 数据；其他测试覆盖 SRun 协议、重定向阻断、密码保存
策略、日志、网卡发现、服务及监控退出行为。
学校认证服务器兼容性、Ubuntu 图形桌面、Linux 权限和实际校园网登录尚未端到端实测。
提供了 Ubuntu 22.04 / 24.04 和 Windows 的 CI 工作流，但未在远端运行。
