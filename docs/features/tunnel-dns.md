# 代理隧道内的服务端 DNS（Tunnel DNS）

[返回功能目录](../features.md)

让客户端通过已经选定的代理节点，查询该 Xray 实例看到的 A、AAAA、SVCB 和 HTTPS 记录。HTTPS/SVCB 中的 ECH、ALPN 等信息不会被压缩成单纯的 IP 列表。

## 使用方式

客户端将目标设为 `server-dns.invalid:53`，通过普通代理连接发送 DNS 报文。服务端在 dispatcher 内直接处理，不需要额外监听 DNS 端口，也没有独立的启用开关。客户端必须保留这个目标域名，不能提前在本地解析成 IP。

- TCP：两字节大端长度前缀加 DNS 消息，一条连接可连续查询。
- UDP：每个数据报携带一条 DNS 消息。
- 仅接受单个 IN 类问题；支持 A、AAAA、SVCB、HTTPS，其他类型返回 REFUSED。
- 目标匹配要求小写的精确域名 `server-dns.invalid`、端口 53，以及 TCP 或 UDP。

## 解析行为与限制

记录查询复用本实例 DNS 的服务器选择、域名规则、顺序和回退。DoH、TCP、QUIC 使用各自的传输；配置为普通 UDP 的 DNS 服务器在此记录查询路径使用 TCP，因此该服务器还需要允许 TCP DNS。没有记录查询能力的服务器会被跳过。

记录查询通常有 5 秒期限，并隔离用户连接的 splice 上下文。它不会自动查到多跳代理链最后一台服务器的 DNS：哪个实例截获这个保留目标，就由哪个实例回答。客户端应按实际目标选择查询节点。

HTTPS 查询还会尝试[域名 bundle](domain-dns-bundle.md)；普通查询在 bundle 失败时可退回记录查询。

## 实现与验证入口

- [保留目标与报文处理](../../app/dispatcher/tunnel_dns.go)
- [记录查询](../../app/dns/record.go)及[传输适配](../../app/dns/record_transport.go)
- [隧道 DNS 测试](../../app/dispatcher/tunnel_dns_test.go)、[记录测试](../../app/dns/record_test.go)
