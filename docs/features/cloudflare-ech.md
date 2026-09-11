# Cloudflare ECH 元数据补充（Cloudflare ECH Supplementation）

[返回功能目录](../features.md)

当隧道 DNS 查询返回的真实地址全部位于源码保存的 Cloudflare 代理网段内，而且 HTTPS 记录缺少 ECH 时，尝试补充 ECH 元数据。它改变 DNS 应答，不修改转发中的 TLS 握手。

## 生效条件

没有额外配置开关，随[域名 bundle](domain-dns-bundle.md)及隧道 HTTPS 查询生效。ECH 配置从 `cloudflare-ech.com` 的 HTTPS 记录取得，经过本实例配置的 DNS，而不是写死一把密钥。

网段表是源码中的静态快照；其记录的核对日期为 2026-09-08，本次文档整理没有重新核对公网网段。混合供应商地址、空地址、无效地址，以及已有 ECH 的记录不会被强行改写。

## 行为与限制

保留已有 ALPN、端口等参数；没有 HTTPS 服务记录时，可以生成最小的 `HTTPS 1 . ech=...`。AliasMode、其他服务目标、异常记录或负响应等情况保留原结果。

密钥缓存按源 TTL 过期，共享并发刷新；失败保留原应答并冷却 30 秒。获取源记录的期限为 2 秒，同时受 bundle 总期限约束。修改过的 HTTPS RRset 对应签名会被移除，不声称合成结果具有 DNSSEC 认证。

命中网段只是适用性判断，不保证每个站点接受 ECH；客户端仍需支持 ECH 并正常处理拒绝。详细协议行为及历史验证记录见[原有专题](../cloudflare-ech-dns.md)。

## 实现与验证入口

- [ECH 补充实现](../../app/dns/cloudflare_ech.go)
- [适用性、缓存和异常处理测试](../../app/dns/cloudflare_ech_test.go)
