# VLESS 加密层保留批次（Encrypted MultiBuffer Writes）

[返回功能目录](../features.md)

为 VLESS 的 CommonConn 加密包装实现 MultiBuffer 写入，避免已有批次在包装层被拆成每个 buffer 一次的标量 Write。

## 行为与兼容性

适用于实际经过该加密包装的连接，自动生效，不增加加密算法、协议字段或配置开关。单 buffer 使用直接路径；多个 buffer 能放入第一块的剩余空间时原地合并，否则按 `buf.Size` 组织加密记录。

记录写入仍使用原有加密过程，并处理原来的 padding / reshape 路径；本功能不是对所有 VLESS 流量统一加密，也不是改变握手协议。

## 实现与验证入口

- [CommonConn.WriteMultiBuffer](../../proxy/vless/encryption/common.go)
- [加密读写回归测试](../../proxy/vless/encryption/common_test.go)
- [公共 writer 适配](../../common/buf/io.go)
