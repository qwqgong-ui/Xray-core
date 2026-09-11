# XHTTP 上行已就绪数据批处理（Ready MultiBuffer Uplink）

[返回功能目录](../features.md)

通过一个读取生产者预读上行，将已经到达的数据作为 MultiBuffer 向后传递，减少逐个小 buffer 穿过代理链的开销。

## 行为

XHTTP 服务端在把连接交给入站协议之前启动 ready reader。每次读取先等待第一份结果，再取走队列中已经就绪的数据，最多八个 buffer；不会为了凑满八块等待未来流量。

关闭连接时停止交付并释放排队缓冲，底层阻塞读取仍需由连接所有者关闭底层 reader 来解除。没有额外用户配置项。

## 与其他优化的关系

本功能负责形成批次；[VLESS 加密 MultiBuffer](vless-multibuffer.md)让批次穿过加密包装；[freedom 零拷贝](freedom-zerocopy.md)在满足 Linux socket 条件时进一步减少写入拷贝。它们具有不同的触发条件，并非启用其中一项就保证整条链路都走零拷贝。

## 实现与验证入口

- [ReadyReader](../../common/buf/ready_reader.go)、[XHTTP 连接](../../transport/internet/splithttp/connection.go)
- [公共读写包装](../../common/buf/io.go)
- [ReadyReader 测试](../../common/buf/ready_reader_test.go)、[上行测试](../../transport/internet/splithttp/uplink_multibuffer_test.go)
