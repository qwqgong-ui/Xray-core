# UDP 中继批量收发（UDP Relay Batching）

[返回功能目录](../features.md)

把 UDP 中继里"每个包一次"的开销摊到一批包上：freedom 一次系统调用取走已排队的多个数据报，读取时不再清零缓冲；Hybrid QUIC 的 raw 中继按批交接数据报，下行把同尺寸的一串包合成一次 UDP GSO 发送。

## 生效范围

没有配置开关，自动生效。

- **freedom 批量读取**：出站是普通 UDP 套接字时，等到第一个数据报后，用一次 recvmmsg 取走此刻已排队的全部数据报，最多 16 个。每个数据报照常经过 finalRules、来源地址处理和流量计数；被规则拦下的数据报，其缓冲留给下一次读取。经其他包装的连接仍逐个读取。
- **读取不清零**：`Resize`/`Extend` 会把新增空间清零，原来每读一个 UDP 数据报都要先清空整块 8 KiB 缓冲。freedom 与 HY2 两侧的 UDP 读取现在直接写入池化缓冲，再用 `ExtendFilled` 只把收到的字节计入内容，缓冲末尾正好落在数据报结尾。
- **raw 下行**：终端把目标一次交来的数据报整批处理，绑定状态每批只查一次。批首连续的短包头包一起走 raw：尺寸相同、最后一个可以更短的一串，以一次带 `UDP_SEGMENT` 的 sendmsg 发出，最多 64 个、65000 字节。套接字不支持 GSO，或内核拒绝某一串时逐个发送；内核因网卡缺少 TX 校验和卸载返回 EIO 后，本进程停用 GSO。
- **raw 上行**：客户端的 raw 包只复制一次，进入池化缓冲；写入协程把已排队的包一次交给出站。

包的内容、顺序和目的地址都不变，raw 与可靠流之间的切换规则也不变。目标发来的空数据报会被跳过：它不是 QUIC 包，若放到可靠流上会被读成 raw 停止信号。

GSO 让一串包在网卡上背靠背发出。原来逐包 sendto 的间隔也只有几微秒，远低于 [UDP 乱序](hy2-udp-reorder.md) 中出现乱序的约 100 µs，所以发包节奏基本不变。

## 实测

2026-09-21，东京 t3.micro（2 vCPU）终端，本机经 mihomo（`hybrid-quic: true`）4 条并发 HTTP/3 下载，约 105 MB/s、9.3 万包/秒，下行全部走 raw：

| | 修改前 | 修改后 | 修改后并关闭 busy_poll |
| --- | --- | --- | --- |
| xray CPU（单核 %） | 115 | 87 | 55（98 MB/s） |
| 其中用户态 | 49 | 20 | 20 |
| 每 100 MB/s 的 xray CPU | 112 | 84 | 58 |
| 每秒系统调用 | 约 20 万 | 约 7 万 | — |

修改后平均每次 GSO 发送约 7 个包。`net.core.busy_poll`/`busy_read` 为 50 时，省下的时间会被 epoll 的忙轮询空转占去，内核态不降；两者设为 0 后，内核态从约 67% 降到约 36%。锁不是瓶颈：修改前 Mutex 慢路径为 0，运行时锁约占 0.4% 核。

## 实现与验证入口

- [freedom 批量读取](../../proxy/freedom/freedom.go)、[读取回归测试](../../proxy/freedom/packet_reader_test.go)
- [`ExtendFilled`](../../common/buf/buffer.go)、[HY2 UDP 读取](../../proxy/hysteria/client.go)
- [raw 批量发送](../../common/hybrid/raw.go)、[Linux GSO](../../common/hybrid/raw_linux.go)、[raw 下行](../../common/hybrid/server.go)、[目标适配](../../app/dispatcher/hybrid.go)
- [GSO 与批次测试](../../common/hybrid/raw_test.go)、[目标适配测试](../../app/dispatcher/hybrid_target_test.go)
