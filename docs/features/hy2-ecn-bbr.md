# QUIC BBR 的 ECN 反馈控制（ECN-Aware BBR）

[返回功能目录](../features.md)

在现有 BBR 上接入经过 QUIC 校验的 ACK_ECN 增量，使发送控制可以结合显式拥塞信号，而不仅依赖吞吐、RTT 和丢包。

## 使用方式

在支持 QUIC 参数的 streamSettings 中，使用既有 BBR 配置。例如将以下片段并入 streamSettings：

```json
{
  "finalmask": {
    "quicParams": {
      "congestion": "bbr",
      "bbrProfile": "standard"
    }
  }
}
```

ECN 状态机没有单独的启用字段。HY2 和 XHTTP 的 QUIC 路径使用同一套 BBR 实现时均受影响，不能理解为只修改了 HY2 协议。必须按[构建说明](build-and-patches.md)应用 quic-go 依赖补丁。

## 状态与边界

有效反馈中没有 CE 标记时允许快速增长；首次 CE 冻结当前速率与窗口；连续 CE 结合比例与 EWMA 逐步回缩。实现保留安全丢包和 RTT 排队保护，路径迁移时衰减路径模型并重新处理 ECN 状态。

ECN 不可用或校验失败时回退至原有带宽、RTT 与 loss 控制。它不要求网络一定支持 ECN，也不能据此保证消除拥塞或丢包。

## Linux 内核定时发送

HY2 入站和出站在安装 BBR 后请求 quic-go 的 FQ EDT 后端：
`SO_TXTIME(CLOCK_MONOTONIC)` 配置 socket 时钟，每数据报携带独立
`SCM_TXTIME`。共享 UDP socket 不设置某个连接的全局速率，各 QUIC 连接
独立根据有效 BBR pacing rate 排程。依赖补丁为
`patches/quic-go/0006-linux-fq-edt-pacing.patch`。

预约提前量不超过 1 ms，每连接最多保留 32 个未到时刻的预约。内核模式不使用
GSO 大批次，握手、ACK-only、PTO、PMTU 探测保持既有发送。保留 QUIC 原有
入队时间记账，因此 RTT 包含受限的内核排队时间，并非网卡实发时间戳。

Linux（不含 Android）之外及不支持 TXTIME/OOB 的 socket 自动保留用户态
pacing/GSO；非 BBR 控制器亦不启用。协议与现有节点兼容。此功能不修改 qdisc，
出口需已有 FQ；不能保证消除 FQ 限额或路径拥塞造成的丢包。

依赖测试 `TestKernelPacing*` 覆盖时间域转换、共享 socket 控制消息、预约边界、
延迟发送线程与回退。`TestKernelPacingFQIntegration` 读取
`QUIC_KERNEL_PACING_PEER` 指向 UDP echo 接收器，在真实 FQ 环境验证到达间隔。

## 实现与验证入口

- [BBR 状态机](../../transport/internet/hysteria/congestion/bbr/ecn_bbr.go)、[BBR 集成](../../transport/internet/hysteria/congestion/bbr/bbr_sender.go)
- [ECN 回归测试](../../transport/internet/hysteria/congestion/bbr/ecn_bbr_test.go)
- [ACK_ECN 依赖补丁](../../patches/quic-go/0001-hy2-expose-validated-ack-ecn-deltas.patch)
