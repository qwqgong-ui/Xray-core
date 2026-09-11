# 通用混合 QUIC 与多跳转发（Generic Hybrid QUIC）

[返回功能目录](../features.md)

每个 UDP 目标使用一条普通代理流建立会话并承载 QUIC 握手，同时尝试让后续短包头 QUIC 数据通过客户端到终端 Xray 的 raw UDP 路径传输。可靠流保留用于回退，并决定会话生命周期。

## 配置入口

客户端需要支持本分支的 HQS1 协议；mihomo 节点显式设置 `hybrid-quic: true`。服务端在顶层配置：

```json
{
  "hybridQUIC": {
    "listen": "0.0.0.0:443",
    "advertise": "YOUR_PUBLIC_IP:443"
  }
}
```

这是添加到既有配置中的片段，需替换公网地址，并保留普通入站与出站配置。`listen` 必须是 IP:443，`advertise` 必须是可达的公网 IP:443。使用 HY2 的同一 UDP socket 时，可设置 `shareHysteria: true`，监听地址须完全对应。

## 多跳与回退

流以 `hybrid-quic.invalid:443` 为保留目标，在其中传递真实目标。按真实 UDP 目标选路后，仅对列入 `forwardOutbounds` 的出站继续转发整条流；终端通过 `trustedForwardInbounds` 信任上一跳携带的原始客户端地址，最多八跳。配置方式见[完整专题](../hybrid-quic.md)。

raw 仅面向公网 UDP 443 目标。客户端应保持隧道源 IP 与 raw 源 IP 一致；不满足绑定条件时继续走流。握手、Retry 等非短包头数据始终走可靠流。HQS1 与旧 HQV3 不兼容，需升级两端。

配套客户端探测无响应、raw 错误或激活后长时间没有回复时，永久关闭本流的 raw 路径；不会在同一流上自动重注册。可靠流关闭时清理目标连接与绑定。具体计时、CID 条件和帧格式见专题。

## 实现入口

- [dispatcher 配置、路由与多跳处理](../../app/dispatcher/hybrid.go)
- [终端 raw 中继](../../common/hybrid/server.go)、[协议帧](../../common/hybrid/wire.go)
- [HY2 socket 共享](../../common/hybrid/shared.go)、[配置解析](../../infra/conf/xray.go)

本页依据当前实现说明能力，不将历史 HQV3 测试数据视为当前 HQS1 多跳部署验证。
