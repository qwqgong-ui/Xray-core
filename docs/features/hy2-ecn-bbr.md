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

`0007-hy2-bbr-fq-coordination.patch` 完成 BBR、QUIC 反馈与 EDT 调度的联动：

- 就绪时只绕过软件 pacing 预算，仍执行拥塞窗口、放大保护、PTO 和包数量限制。
- 软件与 EDT 使用同一有效速率，移除原来的 64 KiB/s 下限，使低速路径和 ECN 排空可以实际降速。
- 速率变化按上一包大小重算后续间隔；发送线程反馈预约进度，数据积压只限制继续打包数据，ACK/PTO 的发送机会保留。
- 纯 ACK 不消耗 EDT 预约，并保留后续数据的发送机会；BBR 的小窗口配合 `min(25 ms, max(1 ms, RTT/4))` 的 ACK 等待预算。ACK 定时从首个待确认包起算，不被后续包推迟。
- QUIC 无数据可打包时才通知 BBR 应用受限，避免 pacing 或小窗口导致带宽模型误判；控制器替换同步当前 MTU，迁移时重置 MTU、排程与 ACK 抽样状态。
- BBR 的发送前/后在途字节语义、纯丢包恢复、ECN 与 DRAIN/PROBE_RTT/恢复的优先级，以及速率和 BDP 算术均有回归覆盖。

预约提前量不超过 1 ms，每连接最多记录 32 个未来预约，发送线程待处理数据量
按提前量和包间隔进一步限制。内核模式不使用 GSO 大批次，握手、ACK-only、
PTO、PMTU 探测保持既有发送。保留 QUIC 原有入队时间记账，因此 RTT 仍包含
内核排队和发送线程延迟，并非网卡实发时间戳。

Linux（不含 Android）上还会按实际远端、UDP 端口、源地址/接口、socket mark、
网络命名空间进行只读路由与 qdisc 检查。要求出口 root 为启用 pacing 的 `fq`，
或 `mq` 的全部发送队列均为此类 `fq`；未知路由、混合队列与不支持 TXTIME/OOB
的 socket 保留用户态 pacing/GSO。路径变化立即重新检查，路由/qdisc/socket
选项变化最多缓存 5 秒；任意 BPF、nftables 或 TC redirect 后的最终出口仍不能
仅由该查询保证。程序不修改 qdisc。

socket 设置非零 DSCP 且支持 ECN 时也保守回退，因为现有 ECN 控制消息会
覆盖 socket 的 traffic class，此时不能直接用原 DSCP 证明本次发送的出口。

最小 RTT 小于 2 ms 时保留用户态 pacing/GSO，避免 EDT 的提前量及逐包发送
开销影响本地路径。Linux 之外、Android、非 BBR 控制器以及掩码未暴露 OOB 的
socket 也保留原后端。明确的 TXTIME 不兼容写错误或内核时钟读取失败会按
预约时刻使用普通发送并回退。
`QUIC_GO_DISABLE_KERNEL_PACING=1` 可强制保留用户态后端；
`Conn.KernelPacingEnabled()` 提供安全的状态读取，QUIC debug 日志记录 FQ 路径检查。
协议与现有节点兼容，不能保证消除 qdisc 限额、网络拥塞或 HY2 应用 UDP 队列满
造成的丢包。

依赖测试 `TestKernelPacing*` 覆盖时间域转换、共享 socket 控制消息、预约边界、
延迟发送线程与回退。`TestKernelPacingFQIntegration` 读取
`QUIC_KERNEL_PACING_PEER` 指向 UDP echo 接收器，在真实 FQ 环境验证到达间隔。

执行 `bash scripts/test-hy2-bbr-fq.sh` 可自动应用补丁、检测本机 CPU、构建测试
程序，并在临时网络命名空间中验证 FQ 时间间隔、HY2 认证、PMTU、共享服务端
socket 的双客户端双向传输、短 RTT 回退和非 FQ 回退。测试中可给接收批次增加
5 ms 处理延迟以覆盖 EDT 后端，这属于控制反馈测试，不代表 WAN 吞吐基准。
若运行内核缺少 veth，脚本改用隔离 loopback 并明确报告；退出时清理命名空间。

本次本机验证使用 `GOAMD64=v3`：HY2 与 quic-go/ACK handler 完整测试、相关 race
检查通过。隔离 loopback FQ 两路 10 包的接收跨度约为 18/27 ms；双客户端各
4,200,000 字节上行及等量下行校验通过，qdisc 统计无丢包。veth、独立 CPU
基准和长期公平性仍需在对应环境测量；真实 WAN 的短时对比如下。

## 2026-10-10 Mihomo 与日本生产服务器实测

使用原有 HY2/UDP 443 端口，依次运行原生产二进制 `6e8cec40-edt` 和
`hy2-bbr-fq-coordinated`，客户端使用同一版本 Mihomo、认证和 TLS/ECH 配置。
测试源仅监听服务器 `127.0.0.1:28080`，用临时 routing 与 freedom `finalRules`
放行；仅添加 routing 无法覆盖 freedom 的 HY2 私网保护。测试后已恢复原配置。
`scripts/hy2-wan-ab.py` 提供测试源、私有配置准备和重复负载，准备的配置权限为
600，单流下载 16 MiB、上传 8 MiB、四路各下载 4 MiB，每轮另做 12 次 1 KiB 请求。
吞吐包含请求和 curl 进程开销，均校验完整字节数及 HTTP 成功状态。

首轮直接连接的下载中位数为 60.3→473.4 Mbps，反向切换复测则为
275.9→492.1 Mbps，说明连接或时段波动明显，不能将首轮差距全部归因于修复。
为进一步控制路径变化，在本机使用同一个带 routing mark 的 UDP socket
转发 Mihomo 流量，保留每包 ECN traffic class，切换服务器二进制期间保持 socket。
服务器 access 日志确认两版最后 112 个测试请求来自同一个公网 IP/UDP 端口。
这个额外中转用于控制连接变量，其开销同时存在于下列两组数据中。

固定 UDP 出口后三轮中位数：

| 项目 | 修复前 | 修复后 | 变化 |
| --- | ---: | ---: | ---: |
| 单流下载 | 369.5 Mbps | 453.6 Mbps | +22.8% |
| 上传 | 198.6 Mbps | 216.5 Mbps | +9.0% |
| 四流并发下载 | 391.1 Mbps | 591.4 Mbps | +51.2% |
| 小请求首字节 | 74.25 ms | 74.55 ms | 接近 |

[原始逐轮指标与环境摘要](../benchmarks/hy2-bbr-fq-2026-10-10.json)保留 24 项负载结果。
服务器实际出口为 ens5 上的 `mq` 加两路开启 pacing 的 `fq`，horizon 为 10 秒。
修复版 QUIC 日志报告实际 HY2 客户端路径 `ready=true`；测试前后两路 qdisc
累计 dropped 均为 0，本机中转的接收溢出计数也为 0。观察到了 ECT(0)，未观察到
CE，因此此处不能作为真实 WAN 上 CE 回缩效果的证据。CPU 计数包含整个生产
`xray.service` 的其他流量及统计请求间隔，负载较短，不能据此声称 CPU 开销降低。
这些结果用于此次部署判断，不能证明长期公平性或其他网络的收益。

生产服务器 Xeon Platinum 8259CL 已确认支持所需 AVX-512 指令，部署产物使用
`GOAMD64=v4`，命名为 `xray-after-linux-amd64-v4`。最终 `/usr/local/bin/xray`
为修复版，SHA-256 是
`7546db3d4cc023ab507f457f2987810742900f06fdd93444c7d3dbb352dd6396`。
原配置 SHA-256
`6ea91b8928c1d3e91681d78a2ce83c3ccb3f0bb412cbaf94e55330a12b39796e`
已逐字节恢复，服务 active，恢复后 HY2 新连接及本机现有 Mihomo 公网访问均返回
HTTP 204。临时调试配置、服务器测试源和本机测试服务已清理；保留原二进制备份
`/usr/local/bin/xray.pre-hy2-fq-01a12406`，其校验值见原始指标文件。本机现有
Mihomo 服务未重启，当前配置保留。

## 实现与验证入口

- [BBR 状态机](../../transport/internet/hysteria/congestion/bbr/ecn_bbr.go)、[BBR 集成](../../transport/internet/hysteria/congestion/bbr/bbr_sender.go)
- [ECN 回归测试](../../transport/internet/hysteria/congestion/bbr/ecn_bbr_test.go)
- [ACK_ECN 依赖补丁](../../patches/quic-go/0001-hy2-expose-validated-ack-ecn-deltas.patch)
