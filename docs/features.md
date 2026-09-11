# Xray SingleUser 下游修改索引

本文按 2026-09-11 的 `SingleUser` 源码整理，基于合并提交 `5239854c`，
对比已合入的上游 `XTLS/Xray-core main`（`52a412d9`，v26.9.9）。
目录只介绍相对该上游基线仍保留的定制功能。上游带来的 udpHop、
freedom 解析流程调整、Go 1.27 等变化不作为本分支原创功能列出。

文档按用途、启用条件、限制及源码入口组织；没有用户开关的内部优化会明确说明。
已有 [Hybrid QUIC 专题](hybrid-quic.md)和 [Cloudflare ECH 专题](cloudflare-ech-dns.md)
继续保留，供协议和历史验证细节参考。

## DNS 与代理协作

- [代理隧道内的服务端 DNS（Tunnel DNS）](features/tunnel-dns.md)
- [地址与 HTTPS 共享缓存（Domain DNS Bundle）](features/domain-dns-bundle.md)
- [Cloudflare ECH 元数据补充（Cloudflare ECH Supplementation）](features/cloudflare-ech.md)
- [通用混合 QUIC 与多跳转发（Generic Hybrid QUIC）](features/hybrid-quic.md)

## 数据传输与内存开销

- [XHTTP 浏览器下行心跳（Browser Downlink Heartbeat）](features/xhttp-heartbeat.md)
- [XHTTP 下行批量写入与缓冲复用（Downlink Batching）](features/xhttp-downlink.md)
- [XHTTP 上行已就绪数据批处理（Ready MultiBuffer Uplink）](features/xhttp-uplink.md)
- [VLESS 加密层保留批次（Encrypted MultiBuffer Writes）](features/vless-multibuffer.md)
- [Linux freedom TCP 零拷贝写入（MSG_ZEROCOPY）](features/freedom-zerocopy.md)

## QUIC 拥塞控制与构建

- [QUIC BBR 的 ECN 反馈控制（ECN-Aware BBR）](features/hy2-ecn-bbr.md)
- [激进 BBR 窗口与快速 PMTU 探测（Aggressive BBR / PMTU）](features/quic-window-pmtu.md)
- [构建、依赖补丁与发布（Build and Dependency Patches）](features/build-and-patches.md)

## 源码、补丁与验证范围

Xray 自身修改已经合入源码；`patches/xray/` 不是正常构建时需要重新应用的补丁。
外部 quic-go 依赖仍由 [apply-dependency-patches.sh](../patches/apply-dependency-patches.sh)
处理，构建和测试必须使用其输出的 GOFLAGS。

本次整理进行了源码对照和文档链接检查，没有重新跑性能基准、公网流量或部署验证。
合并阶段执行过的定向测试不代表所有协议、所有平台或整条代理链均已验证。
各页的测试链接用于说明可检查的行为，不承诺固定性能收益。
