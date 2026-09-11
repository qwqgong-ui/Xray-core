# XHTTP 下行批量写入与缓冲复用（Downlink Batching）

[返回功能目录](../features.md)

把连续的小块下行写入适度合并，减少 HTTP ResponseWriter 的细碎调用，同时保留已经到达的 MultiBuffer 批次。

## 生效范围

VLESS 入站解析出普通 TCP 请求且目标端口为 443 后，向支持此能力的底层连接启用聚合。目前实现位于 XHTTP 服务端。其他目标端口、UDP 或不支持该接口的传输不会因此自动开启聚合。

无需新增配置开关。判断依据是请求命令与端口，不检测目标内容是否真的为 HTTPS。

## 缓冲策略

- 16 KiB 是软目标，不是强制切片尺寸；单次大写入可以直接发送。
- 小写入在达到目标或约 1 ms 定时 flush 时发出；实际调度可能更晚。
- 跨越剩余容量的批次按一次应用写入发送，不把窗口永久扩大。
- 预热八个 16 KiB 缓冲供连接共用，每条连接按需借用，不预先为每条连接分配八块。
- MultiBuffer 优先利用第一块缓冲的可用尾部拼接，无法容纳时才分配连续缓冲。

HTTP/2 DATA 帧的最终边界由 Go HTTP 实现决定，不能将应用侧 16 KiB 目标等同于线上帧大小。收益取决于写入分布，本文不承诺固定吞吐提升。

## 实现与验证入口

- [启用判断](../../proxy/vless/inbound/inbound.go)、[传输能力接口](../../proxy/proxy.go)
- [缓冲、flush 与池](../../transport/internet/splithttp/hub.go)
- [聚合回归测试](../../transport/internet/splithttp/downlink_aggregation_test.go)
- [MultiBuffer 基准](../../transport/internet/splithttp/downlink_multibuffer_bench_test.go)、[缓冲池基准](../../transport/internet/splithttp/downlink_prealloc_bench_test.go)
