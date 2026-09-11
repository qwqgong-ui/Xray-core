# XHTTP 浏览器下行心跳（Browser Downlink Heartbeat）

[返回功能目录](../features.md)

为支持此扩展的客户端提供显式的数据帧和心跳帧，让长时间没有业务数据的 XHTTP 下行仍能周期性发送字节。

## 如何启用

客户端在带 session 的下行请求中发送：

```text
X-AndroidCyaml-XHTTP-Framing: v1
```

服务端接受时回显该响应头。无此请求头的连接保持普通下行；没有 session 的 stream-one 不启用这套 framing。无需新增服务端 JSON 字段。

## 格式与限制

每帧为一字节类型、四字节大端 payload 长度及 payload。类型 0 为业务数据，类型 1 为心跳；服务端每 30 秒尝试发出零 payload 心跳。发送心跳前先 flush 已缓冲的业务数据，避免打乱顺序。

客户端必须解析帧并剥离心跳，不能把 framing 字节直接交给目标应用。此修改不能保证绕过所有中间代理的超时策略。

## 实现与验证入口

- [请求协商、帧写入与心跳循环](../../transport/internet/splithttp/hub.go)
- [帧测试](../../transport/internet/splithttp/downlink_frame_test.go)
- [历史源码补丁](../../patches/xray/0001-xhttp-browser-downlink-heartbeat.patch)，正常构建不再重复应用
