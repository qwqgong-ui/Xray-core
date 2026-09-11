# 构建、依赖补丁与发布（Build and Dependency Patches）

[返回功能目录](../features.md)

SingleUser 的 Xray 自身修改已经合入 Go 源码。正常构建需要额外应用的，是外部 quic-go module 的补丁。

## 补丁边界

| 位置 | 用途 |
| --- | --- |
| `patches/xray/` | 已合入源码的历史补丁系列，供维护和补丁工作流使用；不要在当前源码上重复应用 |
| `patches/quic-go/0001-*.patch` | 给 BBR 暴露经过校验的 ACK_ECN 增量及相关状态 |
| `patches/quic-go/0002-*.patch` | 1400 字节以下更快的 PMTU 探测 |
| `patches/apply-dependency-patches.sh` | 复制锁定依赖、校验并应用补丁，生成独立 modfile 与 GOFLAGS，不改根目录 go.mod |

补丁脚本生成的 `.xray-patched-deps.*` 是构建辅助目录。GOFLAGS 中的 modfile 路径相对仓库根目录，因此加载后应留在仓库根目录执行 Go 命令。

## Linux AMD64 本地构建

先检查**目标机器** CPU；满足 AVX-512F、BW、CD、DQ、VL 的目标使用 v4，否则按本仓库约定使用 v3。v3 本身也要求对应指令集，不适合任意旧 x86-64 CPU；只有明确需要兼容旧设备时才另做 v1 构建。

以下命令在仓库根目录执行，假定已确认目标支持 v4：

```bash
patch_env=$(mktemp)
sh patches/apply-dependency-patches.sh "$PWD" "$patch_env"
. "$patch_env"
export GOFLAGS
export GOAMD64=v4
CGO_ENABLED=0 go build -o xray -trimpath -buildvcs=false ./main
```

目标只支持 v3 时，将 GOAMD64 改为 v3。Go 版本以 [go.mod](../../go.mod) 为准；当前 Go 1.27 是已合并的上游要求，不单列为下游功能。测试前也应执行补丁脚本并导出其 GOFLAGS。

## 工作流范围

[发布工作流](../../.github/workflows/release.yml)的 Linux AMD64 发布项使用 v4，并以 `linux-amd64-v4` 标识；本地为特定目标编译的 v3 不能当作 v4 产物分发。

[上游同步工作流](../../.github/workflows/sync-upstream.yml)定义每六小时同步仓库的 main 基线，不会自动把这些提交合入 SingleUser。这里只描述仓库内工作流定义，不保证远端计划任务当前已启用或最近执行成功。

[补丁测试工作流](../../.github/workflows/test-patches.yml)面向历史补丁系列在干净基线上的应用检查；[普通测试工作流](../../.github/workflows/test.yml)也加载依赖补丁。历史补丁应用成功与当前源码行为测试属于不同证据。
