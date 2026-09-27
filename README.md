# CF-Workers-OpenVPN-TCP

基于 Cloudflare Workers 的 **VLESS → WebSocket → OpenVPN TCP Client → OpenVPN Data Channel → 手工 IPv4/TCP → 目标** 出站代理实验项目。

它不再是简单的 `WebSocket → connect() → 目标` 字节转发，也不是旧的 SSTP/PPP 路径。Worker 在受限边缘运行时内：

1. 解析 `.ovpn` 配置（`remote`、`<ca>`、`<tls-auth>`、`cipher`、`auth`……）；
2. 用 Workers `connect()` 建立到 OpenVPN 服务端的 TCP 连接；
3. 完成 OpenVPN 控制信道：`HARD_RESET_CLIENT_V2` → TLS 1.2 握手 → `key_method 2`（密钥交换 + 用户名/密码）→ `PUSH_REQUEST` → `PUSH_REPLY`；
4. 派生出数据信道密钥块，按 `P_DATA_V1`/`P_DATA_V2` 收发加密数据包（AES-GCM 或 AES-CBC + HMAC）；
5. 拿到虚拟 IPv4 地址后，在 Worker 内手工构造 IPv4/TCP 包，做 `SYN / SYN+ACK / ACK / PSH` 双向中继，再通过 VLESS/WebSocket 送回客户端。

> 这是协议研究与学习代码，用于验证在**没有完整系统网络栈、没有 TUN/TAP、没有原生 VPN 客户端**的 Workers 环境中，能否重建一条可用的虚拟通信路径。实际代理体验不保证稳定。

## 协议路径

```text
客户端
  VLESS over WebSocket
    ↓
Cloudflare Worker
  OpenVPN TCP Client (控制信道 + 数据信道)
    ↓
OpenVPN / SoftEther Server (VPN Gate)
  虚拟 IPv4 链路
  手工 IPv4/TCP
    ↓
目标 TCP 服务
```

## 功能特性

- **VLESS over WebSocket** 入口（保留原项目逻辑）。
- **`.ovpn` 解析**：`remote` / `<ca>` / `<tls-auth>` + `key-direction` / `cipher` / `data-ciphers` / `auth`；跳过证书（`<cert>/<key>`）与 TAP / UDP 不支持项。
- **OpenVPN 控制信道**：
  - `P_CONTROL_HARD_RESET_CLIENT_V2` / `SERVER_V2`、`P_CONTROL_V1`、`P_ACK_V1`；
  - 可靠性通道（reliable-id、ACK、重传）；
  - `tls-auth`（HMAC 前向/反向包，key-direction 0/1）；
  - `key_method 2`（client/server 非对称 key_source：客户端发送 `pre_master + random1 + random2`，服务端只回 `random1 + random2`）。
- **TLS 1.2**（纯 Web Crypto）：ECDHE / AES-GCM / SHA256，支持 `extended master secret`，证书链验证（配置 CA + 链式回退）。
- **客户端证书认证**：解析 `<cert>/<key>` 并在服务端请求时发送 `Certificate` + `CertificateVerify`（RSA PKCS#1 v1.5 / SHA-256），支持需要客户端证书的节点（如 `opengw.net` 提供方）。
- **数据信道**：
  - `AES-256/128-GCM`（`P_DATA_V2`，`peer-id`）；
  - `AES-256/128-CBC + HMAC-SHA1/256`（`P_DATA_V1`）；
  - OpenVPN 数据密钥扩展（`OpenVPN master secret` / `OpenVPN key expansion`，TLS 1.0 PRF：MD5⊕SHA1）。
- **虚拟 IPv4 地址**：解析 `PUSH_REPLY` 的 `ifconfig`。
- **用户态 IPv4/TCP**：`createTcp()` 构造 IPv4/TCP 头、计算校验和、维护序号/Acknowledgement、MSS 分段，双向中继。
- **目标地址解析**：IPv4 直用，域名走 Cloudflare DoH。
- **诊断端点 `/ovpn-test`**：POST JSON / multipart / 原始配置，或 GET 查询参数；返回 `{ok, virtualIp, response}`。

## 服务端来源

默认用 VPN Gate 公共 Relay 列表（筑波大学志愿者项目）：

- VPN Gate 官网：<https://www.vpngate.net/>
- 公共服务器列表：<https://www.vpngate.net/en/volunteer_servers.aspx?number=0>

节点质量、可用性、出口位置随列表实时变化。默认账号为 VPN Gate 公共账号 `vpn / vpn`。

## 文件结构

| 文件 | 说明 |
| --- | --- |
| [`src/worker.js`](./src/worker.js) | Worker 入口：`import { connect } from 'cloudflare:sockets'` 并 `route()`。 |
| [`src/handler.js`](./src/handler.js) | 路由：VLESS/WS 入口 + `/ovpn-test`；维护 `OPENVPN_OVPN` 配置。 |
| [`src/vless.js`](./src/vless.js) | VLESS 请求头解析。 |
| [`src/dns.js`](./src/dns.js) | Cloudflare DoH 解析。 |
| [`src/tcp.js`](./src/tcp.js) | 用户态 IPv4/TCP（`createTcp`）。 |
| [`src/openvpn/`](./src/openvpn) | OpenVPN 协议栈：`config` / `packet` / `control` / `crypto` / `tls` / `x509` / `data` / `client`。 |
| [`build.js`](./build.js) | 无依赖 ESM 打包器：把 `src/` 打成单文件 `_worker.js`。 |
| [`test/`](./test) | 单元、mock 服务端、handler、真实 VPN Gate 测试脚本。`test/configs/sample0.ovpn` 为一个示例配置。 |
| [`LICENSE`](./LICENSE) | GPL-3.0（沿用原项目）。 |

## 构建

```bash
node build.js        # 产出单文件 _worker.js（无依赖）
node --check _worker.js
```

将 `_worker.js` 部署到 Cloudflare Workers 即可。在 Worker 环境变量或绑定中提供 `OPENVPN_OVPN`（`.ovpn` 全文），或用 `_setOpenVpnConfig()` 运行时设置。

## 测试

```bash
node test/run.js     # unit + mock(GCM/CBC) + handler
```

- `test/unit.js`：MD5/HMAC/AES/keyExpansion 等原语。
- `test/mocktest.js AES-128-GCM|AES-128-CBC`：本地 mock OpenVPN 服务端，完整 TLS + 数据信道 + HTTP 回环。
- `test/handler-test.js`：`/ovpn-test` 端到端。
- `test/vpngate.js <file.ovpn> <ip> <port>`：连接真实 VPN Gate 节点（默认走 `127.0.0.1:10808` 代理，`OVPN_PROXY=0` 可关闭）。
- `test/nodecheck.js <host> <port> [--debug]`：对任意节点做「连接 + 出口 IP」诊断。
- `test/egress.js`：连真实节点并请求 `api.ipify.org` 验证出口 IP。

## 已验证

在真实 VPN Gate OpenVPN TCP 节点上（含 SoftEther Academic 集群 `public-vpn-*.opengw.net` 的 `219.100.37.x:443` 与 opengw.net 需客户端证书的节点）：

- HARD_RESET / TLS 1.2（`TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`）握手成功；
- `key_method 2`（`vpn/vpn` 认证）通过；
- 服务端要求客户端证书时，自动发送 `<cert>/<key>` 并完成 `CertificateVerify`；
- `PUSH_REPLY` 获得虚拟 IPv4（`10.2xx.x.x`）；
- 数据信道解密成功（AES-128-CBC），识别并忽略 OpenVPN keepalive ping；
- 用户态 TCP 建立 `SYN/SYN+ACK`，经隧道发出 HTTP 请求；
- 出口 IP 确认为对应节点地址（如美国节点 `73.131.220.236`、日本节点 `219.100.37.x`）。

## 已知限制

- 当前服务端若强制 **AES-256-GCM-SHA384** 控制信道记录保护，与本实现存在互操作边界（已回退到 AES-128-GCM 优先套件）；多数 VPN Gate 节点可用。
- **只支持 TCP**：OpenVPN over TCP；UDP 不在当前主线内，也只转发 TCP 目标。
- 客户端证书仅支持 RSA 私钥（PKCS#1 / PKCS#8）；ECDSA 客户端证书暂未实现。
- `tls-auth` 支持 `key-direction 0/1`；无 `key-direction` 时按双向 `keys[0]` 处理。
- 证书链验证采用「配置 CA → 链式回退」，宁可拒绝不可信链也不接受伪造。
- 长连接、大流量受 Workers 限制影响。
- 认证、参数和路径需按实际服务端调整。

## 参考

- 开源协议：[GPL-3.0](./LICENSE)（衍生自 ToiCF/CF-Workers-SoftEther，协议沿用）。
- 原项目：<https://github.com/ToiCF/CF-Workers-SoftEther>
- SoftEther VPN：<https://www.softether.org/> · GitHub <https://github.com/SoftEtherVPN/SoftEtherVPN>
- OpenVPN 文档 / 源码（本地 `_ref/` 为参考材料，未纳入本仓库）。
- VPN Gate：<https://www.vpngate.net/>
