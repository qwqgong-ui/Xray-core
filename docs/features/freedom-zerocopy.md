# Linux freedom TCP 零拷贝写入（MSG_ZEROCOPY）

[返回功能目录](../features.md)

freedom 的普通 TCP 写入路径可在 socket 已开启 SO_ZEROCOPY 时，使用 Linux MSG_ZEROCOPY 发送较大的 MultiBuffer 批次。

## 启用条件

通过既有的 `streamSettings.sockopt.customSockopt` 对目标 Linux TCP socket 设置 SO_ZEROCOPY。具体字段由[customSockopt 配置解析](../../infra/conf/transport_sockopt.go)定义；该 writer 只检查 socket 选项，不会自行开启它。

同时需要底层暴露可用的 syscall connection，且当前批次至少为 16 KiB、有效分片不超过 1024 个。启用 freedom 的 FragmentWriter 时不使用这个普通 TCP writer。

## 回退与资源管理

未开启 socket 选项、非 Linux、不支持的包装连接或小批次使用原有 writer。零拷贝发送在任何字节尚未发出时失败可回退；已部分发送时报告错误，避免把已发送的数据重复写出。

缓冲需等内核完成通知后才能释放，并保持写入计数；“调用了 MSG_ZEROCOPY”不代表内核对每次发送都实际免除了复制，也不表示 TLS、HTTP 等上层没有拷贝。

## 实现与验证入口

- [Linux writer](../../common/buf/zerocopy_writer_linux.go)、[其他平台回退](../../common/buf/zerocopy_writer_stub.go)
- [freedom 接入](../../proxy/freedom/freedom.go)
- [writer 测试](../../common/buf/zerocopy_writer_linux_test.go)
