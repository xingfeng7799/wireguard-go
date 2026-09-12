# [WireGuard](https://www.wireguard.com/) 的 Go 实现

这是 WireGuard 的 Go 语言实现。

## 使用方法

大多数使用 Linux 内核版 WireGuard 的用户习惯通过 `ip link add wg0 type wireguard` 创建接口。使用 wireguard-go 时，只需运行：

```shell
wireguard-go wg0
```

该命令会创建接口，然后转入后台运行。可以使用常规命令 `ip link del wg0` 删除接口。如果系统不支持直接删除接口，也可以删除控制套接字：

```shell
rm -f /var/run/wireguard/wg0.sock
```

控制套接字被删除后，wireguard-go 将自动退出。

如需让 wireguard-go 保持前台运行，请添加 `-f` 或 `--foreground`：

```shell
wireguard-go -f wg0
```

接口运行后，可以使用 [`wg(8)`](https://git.zx2c4.com/wireguard-tools/about/src/man/wg.8) 配置接口，也可以使用常规的 `ip(8)` 和 `ifconfig(8)` 命令。

如需输出更详细的日志，可以设置环境变量：

```shell
LOG_LEVEL=debug
```

### 配置文件客户端模式

在 macOS 和 Windows 上，wireguard-go 可以直接解析并运行 WireGuard 配置文件，不需要 `wg-quick`。

macOS：

```shell
sudo wireguard-go -c /path/to/wg.conf
```

Windows 需要在以管理员身份运行的命令提示符或 PowerShell 中执行：

```powershell
wireguard-go.exe -c C:\path\to\wg.conf
```

该模式会保持前台运行。按 `Ctrl+C` 可以停止隧道，并恢复程序修改过的 DNS、路由、地址和 MTU。

启动前可以执行只读配置检查，不需要管理员权限，也不会创建 TUN、修改路由或覆盖 DNS：

```shell
wireguard-go --check /path/to/wg.conf
```

Windows：

```powershell
wireguard-go.exe --check C:\path\to\wg.conf
```

检查会验证配置语法和密钥、解析 Endpoint，并输出接口地址、peer 数量、IPv4/IPv6 全隧道状态、DNS 覆盖状态和 Endpoint 自动刷新周期。如果 `AllowedIPs` 包含默认路由，或配置会覆盖系统 DNS，还会提示与代理软件、其他 TUN/VPN 及 Fake-IP DNS 发生冲突的风险。配置文件包含服务商 API 参数时，检查过程会实际调用相应 API，但不会修改本机网络。

`[Interface]` 支持以下字段：

- `PrivateKey`
- `ListenPort`
- `Address`
- `DNS`
- `MTU`

`[Peer]` 支持以下字段：

- `PublicKey`
- `PresharedKey`
- `Endpoint`
- `AllowedIPs`
- `PersistentKeepalive`

为了避免产生不明确的行为，客户端模式会拒绝 Hook 命令、`Table` 和 `SaveConfig`，不会静默忽略这些配置。

配置文件包含 WireGuard 私钥，应当只允许文件所有者读取。例如在 macOS 上执行：

```shell
chmod 600 wg.conf
```

Windows 客户端模式使用系统自带的 Windows PowerShell 网络管理命令，因此需要管理员权限。发布包中的 `wintun.dll` 必须和 `wireguard-go.exe` 放在同一个目录。

### 代理共存与高级路由

当 `AllowedIPs` 包含 `0.0.0.0/0` 或 `::/0` 时，WireGuard 会接管对应地址族的全部流量。代理软件的远端服务器也可能被送入 WireGuard，代理自己的 TUN 路由或 Fake-IP DNS 还可能与 WireGuard 冲突。可以通过全局 `[Routing]` 配置段让代理服务器、本地网络或其他目标绕过 WireGuard：

```ini
[Peer]
AllowedIPs = 0.0.0.0/0, ::/0

[Routing]
Mode = split
ExcludeIPs = 192.168.0.0/16, 203.0.113.20/32
ExcludeDomains = proxy.example.com, api.example.com
RefreshInterval = 60
```

 配置示例：

  [Peer]
  AllowedIPs = 0.0.0.0/0, ::/0

  [Routing]
  Mode = split
  ExcludeIPs = 192.168.0.0/16, 203.0.113.20/32
  ExcludeDomains = proxy.example.com, api.example.com
  RefreshInterval = 60



支持的字段：

- `Mode = full|split`
  - `full` 表示 `AllowedIPs` 中必须至少包含一个 IPv4 或 IPv6 默认路由。
  - `split` 可以配合普通的非默认 `AllowedIPs` 使用；也可以在全隧道配置中配合 `ExcludeIPs` 或 `ExcludeDomains`，表示“除排除目标外全部进入 WireGuard”。
  - 未填写时，程序根据 `AllowedIPs` 自动判断。
- `ExcludeIPs`：需要走原网络出口的 IPv4/IPv6 地址或网段，支持逗号分隔和重复配置。
    - 支持 IPv4、IPv6、单个地址和网段
    - 让目标通过原网络出口访问
- `ExcludeDomains`：需要走原网络出口的域名，支持逗号分隔和重复配置。启动时解析该域名返回的全部 IPv4/IPv6 地址，并为每个地址建立主机路由。
    - 启动时解析全部 IPv4/IPv6
    - 自动添加直连主机路由
- `RefreshInterval`：重新解析 `ExcludeDomains` 的周期，单位为秒，默认为 `60`，最大为 `86400`，设置为 `0` 可关闭刷新。
  - 域名地址默认每 60 秒刷新
- 地址改变时先添加新路由，再删除旧路由
- DNS 失败时保留上一次有效地址
- 与 WireGuard Endpoint 保护路由共享状态，避免误删
- 自动保存启动前的 IPv4/IPv6 出口
- 只删除程序自己创建的路由
- 退出时自动恢复
- --check 会输出分流模式和最终解析地址
- 支持重复配置自动去重

客户端会在添加 WireGuard 路由前记录原来的 IPv4/IPv6 网络出口，并先添加排除路由。域名解析结果发生变化时，先保护新地址，再移除不再使用的旧地址；刷新失败时继续保留上一次成功的结果。程序只删除自己创建的路由，退出时自动清理。

如果代理服务器使用域名，推荐同时配置 `ExcludeDomains`，不要只把当前解析到的 IP 写进 `ExcludeIPs`。如果代理软件依赖 Fake-IP 或自己的加密 DNS，还应考虑删除 WireGuard 配置中的 `DNS`，避免客户端覆盖代理的 DNS 设置。

可先运行以下命令确认最终解析地址和分流模式：

```shell
wireguard-go --check wg.conf
```

### Endpoint 配置

Endpoint 支持标准 WireGuard 格式，包括 IPv4、带方括号的 IPv6，以及指定端口的域名：

```ini
Endpoint = 192.0.2.10:51820
Endpoint = [2001:db8::10]:51820
Endpoint = vpn.example.com:51820
```

同时支持不显式填写端口的 IP4P 域名：

```ini
Endpoint = ip4p.example.com
```

在普通 IP4P 模式下，客户端按照以下顺序解析：

1. 查询域名的 TXT 记录。
2. 将 TXT 内容进行 Base64 解码。
3. 尝试将解码结果解析为 `IPv4:端口` 或 `[IPv6]:端口`。
4. 如果没有有效 TXT 记录，继续查找 `2001:0000:...:端口:IPv4` 格式的 IP4P 编码 AAAA 记录。

TXT 内容示例：

```text
203.0.113.9:51820
[2001:db8::9]:51820
```

可以使用以下命令生成 Base64 内容：

```shell
printf '%s' '203.0.113.9:51820' | base64
printf '%s' '[2001:db8::9]:51820' | base64
```

未启用 API 模式时，带显式端口的 Endpoint 保持原有 WireGuard 解析行为。通过 IP4P TXT、编码 AAAA 或服务商 API 得到的 Endpoint 默认每 60 秒重新查询一次；如果 IP 或端口发生变化，客户端会动态更新运行中的 WireGuard peer，不需要重启进程。查询失败时继续使用上一次成功的 Endpoint，并在下一个周期重试。

启动时会输出 Endpoint 解析模式、使用的 DNS 服务商、原始域名，以及最终解析得到的 IP 和端口。如需同时查看 WireGuard 设备的详细调试日志，可以设置 `LOG_LEVEL=debug`。

### DNS 服务商 API 模式

如果希望绕过本机 DNS、直接通过 DNS 服务商 API 读取 TXT 记录，可以在配置文件中增加全局 `[IP4P]` 配置段。

目前支持以下服务商：

- `cloudflare`
- `tencent`：腾讯云 DNSPod
- `alibaba`：阿里云 DNS

#### Cloudflare

```ini
[Peer]
Endpoint = ip4p.example.com

[IP4P]
Mode = api
Provider = cloudflare
APIKey = your-api-token
ZoneID = your-zone-id
```

Cloudflare API Token 至少需要目标 Zone 的 DNS 读取权限。

#### 腾讯云 DNSPod

```ini
[Peer]
Endpoint = ip4p.example.com

[IP4P]
Mode = api
Provider = tencent
APIKey = your-secret-id
APISecret = your-secret-key
```

其中 `APIKey` 对应腾讯云 `SecretId`，`APISecret` 对应 `SecretKey`。

#### 阿里云 DNS

```ini
[Peer]
Endpoint = ip4p.example.com

[IP4P]
Mode = api
Provider = alibaba
APIKey = your-access-key-id
APISecret = your-access-key-secret
```

其中 `APIKey` 对应阿里云 AccessKey ID，`APISecret` 对应 AccessKey Secret。

配置了 `Provider` 后，可以省略 `Mode = api`，程序会自动进入 API 模式：

```ini
[IP4P]
Provider = cloudflare
APIKey = your-api-token
ZoneID = your-zone-id
```

API 模式规则：

- 域名类型的 Endpoint 只通过配置的服务商 HTTPS API 查询。
- TXT 记录中的地址和端口会覆盖 Endpoint 中原来填写的地址和端口。
- 启动时 API 请求失败、认证失败或返回无效记录时，程序会直接报错退出；运行期间刷新失败则继续使用上一次成功的 Endpoint。
- API 模式不会回退到系统 DNS TXT 或 IP4P AAAA 查询。
- 字面量 IPv4 和 IPv6 Endpoint 不受 API 模式影响。

如果希望明确使用系统 DNS 查询，可以配置：

```ini
[IP4P]
Mode = lookup_text
```

`lookup_text` 模式不能同时配置 `Provider`、`APIKey`、`APISecret` 或 `ZoneID`。

可以通过 `[IP4P]` 中的 `RefreshInterval` 调整自动刷新周期，单位为秒，最大为 86400。设置为 `0` 可关闭自动刷新：

```ini
[IP4P]
Mode = lookup_text
RefreshInterval = 60
```

Endpoint 变化时，程序会输出旧值、新值和解析方式。对于全流量隧道，客户端会先为新 Endpoint 建立绕过隧道的主机路由，再切换 peer，最后移除不再使用的旧主机路由。服务商 API 或 DNS 查询暂时失败不会断开当前连接。

配置文件同时包含 WireGuard 私钥和 DNS 服务商 API 凭据，请严格限制文件读取权限，不要将真实密钥提交到公开仓库。

## 支持平台

### Linux

wireguard-go 可以在 Linux 上运行。不过，通常更建议使用 Linux 内核提供的 WireGuard 模块，因为它的性能更高，并且与操作系统集成得更好。安装方式请参阅 [WireGuard 官方安装页面](https://www.wireguard.com/install/)。

### macOS

wireguard-go 在 macOS 上使用 `utun` 驱动。目前不支持 sticky socket；受 Darwin 平台限制，也不支持 fwmark。

`utun` 接口不能使用任意名称。可以指定 `utun[0-9]+`，也可以使用 `utun` 让内核自动选择接口编号。如果使用 `utun`，并设置了 `WG_TUN_NAME_FILE` 环境变量，内核实际分配的接口名称会写入该变量指定的文件。

### Windows

wireguard-go 可以在 Windows 上运行。原项目通常建议使用功能更完整的 [WireGuard for Windows](https://git.zx2c4.com/wireguard-windows/about/)；本分支另外提供了可直接读取配置文件的 `-c` 客户端模式。

Windows 版本依赖 `wintun.dll`。GitHub Release 的 Windows ZIP 包已经包含与 AMD64 或 ARM64 架构对应的 DLL，请不要只复制 EXE 文件。

### FreeBSD

wireguard-go 可以在 FreeBSD 上运行。目前不支持 sticky socket，fwmark 会映射为 `SO_USER_COOKIE`。

### OpenBSD

wireguard-go 可以在 OpenBSD 上运行。目前不支持 sticky socket，fwmark 会映射为 `SO_RTABLE`。

TUN 接口不能使用任意名称。可以指定 `tun[0-9]+`，也可以使用 `tun` 让程序自动选择接口编号。如果使用 `tun`，并设置了 `WG_TUN_NAME_FILE` 环境变量，程序实际选择的接口名称会写入该变量指定的文件。

## 构建

构建项目需要安装较新版本的 [Go](https://go.dev/)。

```shell
git clone https://git.zx2c4.com/wireguard-go
cd wireguard-go
make
```

也可以直接使用 Go 构建：

```shell
go build -o wireguard-go .
```

## 许可证

本项目使用 MIT 许可证，完整条款请参阅 [LICENSE](LICENSE)。

Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
