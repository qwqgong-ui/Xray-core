# 激进 BBR 窗口与快速 PMTU 探测（Aggressive BBR / PMTU）

[返回功能目录](../features.md)

增加 aggressive 档位的拥塞窗口增益，并缩短确认到 1400 字节之前的 QUIC MTU 探测间隔。这是两项不同层面的调整。

## aggressive 窗口

使用 `streamSettings.finalmask.quicParams.bbrProfile: "aggressive"` 选择该档位，并确保实际拥塞控制为 BBR。当前配置中 `highCwndGain` 从上游的 2.25 调整为 2.5，`congestionWindowGainConstant` 从 2.5 调整为 3.0。

standard 和 conservative 的档位参数未随此修改一同放大。更大的窗口可能增加在途数据与排队，不代表对所有网络都更快。

## PMTU 探测

quic-go 的 MTU 探测下界尚未确认到 1400 字节时，探测间隔采用两倍平滑 RTT；达到该下界后恢复原有间隔。仍遵守“已有探测在途”与“探测完成”等条件，不把路径 MTU 强行设为 1400。

这项依赖补丁不受 aggressive 档位控制；凡使用该已打补丁 quic-go 探测器且启用 PMTU 探测的路径都可能受影响。关闭 PMTU discovery 后不会因本补丁重新启用。

## 实现与验证入口

- [BBR 档位参数](../../transport/internet/hysteria/congestion/bbr/bbr_sender.go)
- [BBR 测试](../../transport/internet/hysteria/congestion/bbr/bbr_sender_test.go)
- [PMTU 补丁及其内嵌测试](../../patches/quic-go/0002-hy2-fast-pmtu-below-1400.patch)
