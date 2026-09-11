# 地址与 HTTPS 共享缓存（Domain DNS Bundle）

[返回功能目录](../features.md)

把域名的真实地址与 HTTPS 服务记录作为同一份有期限的结果交给客户端，并让后续出站连接复用这些地址，减少客户端获取的服务信息与服务端实际拨号地址不一致的情况。

## 使用方式

支持此扩展的客户端向 `server-dns.invalid:53` 发起 HTTPS 查询，并附带 EDNS 私有选项 `65001`，内容为单字节 `0x01`。响应的 Answer 保存服务记录，Additional 保存 A/AAAA，附带相同的选项确认支持。

普通 HTTPS 查询也会尝试生成 bundle，但不会向响应添加 bundle 的地址部分或确认选项。显式 bundle 请求失败会返回 SERVFAIL，不会伪装成成功的普通记录响应。客户端对旧服务器的兼容与回退由客户端实现。

## 缓存和出站复用

地址经过本实例的 `LookupIP`，包含 hosts、查询策略、预期 IP 过滤及 fallback；HTTPS 经记录查询取得。两部分完成后才发布共享结果。

- 缓存最多 1024 项，属于进程内缓存，不落盘。
- TTL 取地址、服务记录以及实际参与结果的 CNAME/ECH 数据的最短有效期；读取时返回剩余 TTL。
- 零 TTL 或没有可赋予有效 TTL 的 HTTPS 结果不建立长期 bundle 缓存。
- 出站 DNS 查询可复用未过期地址；某地址族没有可用结果时仍交给正常解析判断。
- freedom 的 AsIs 路径只读取已有缓存，不因这次读取启动新查询；命中后仍执行 `finalRules`。
- 使用 `sockopt.dialerProxy` 时，freedom 不在这里把域名替换成缓存 IP；显式 `sockopt.domainStrategy` 仍交给上游解析流程处理。

## 实现与验证入口

- [bundle 生成及缓存](../../app/dns/domain.go)、[DNS 入口](../../app/dns/dns.go)
- [缓存读取接口](../../transport/internet/dialer.go)、[freedom 复用](../../proxy/freedom/freedom.go)
- [缓存与 TTL 测试](../../app/dns/domain_test.go)、[合并后的 freedom 回归测试](../../proxy/freedom/domain_cache_test.go)
