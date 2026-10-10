#!/usr/bin/env bash
set -euo pipefail

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"
test_root=$(mktemp -d "$repo_root/.git/hy2-bbr-fq-test.XXXXXX")
client_ns="xray-hy2-fq-c-$$"
server_ns="xray-hy2-fq-s-$$"
client_dev="xhfc$$"
server_dev="xhfs$$"
server_pid=
client_ns_created=0
server_ns_created=0
link_created=0
runtime_server_ns="$server_ns"
peer_ip=10.203.0.2

cleanup() {
    if [[ -n "$server_pid" ]]; then kill "$server_pid" 2>/dev/null || true; wait "$server_pid" 2>/dev/null || true; fi
    if [[ "$client_ns_created" == 1 ]]; then sudo -n ip netns del "$client_ns" 2>/dev/null || true; fi
    if [[ "$server_ns_created" == 1 ]]; then sudo -n ip netns del "$server_ns" 2>/dev/null || true; fi
    if [[ "$link_created" == 1 ]]; then
        sudo -n ip link del "$client_dev" 2>/dev/null || true
        sudo -n ip link del "$server_dev" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# Test binaries execute on this CPU, rather than a production release target.
cpu_info=$(LC_ALL=C lscpu)
GOAMD64=v4
for flag in avx512f avx512bw avx512cd avx512dq avx512vl; do
    if [[ " $cpu_info " != *" $flag "* ]]; then GOAMD64=v3; fi
done
export GOAMD64
sh patches/apply-dependency-patches.sh "$PWD" "$test_root/patch.env"
source "$test_root/patch.env"
export GOFLAGS
go test -mod=mod -c -o "$test_root/quic.test" github.com/apernet/quic-go
sh patches/apply-dependency-patches.sh "$PWD" "$test_root/patch.env"
source "$test_root/patch.env"
go test -c -o "$test_root/hy2.test" ./transport/internet/hysteria

sudo -n ip netns add "$client_ns"
client_ns_created=1
sudo -n ip netns add "$server_ns"
server_ns_created=1
if sudo -n ip link add "$client_dev" type veth peer name "$server_dev"; then
    link_created=1
    sudo -n ip link set "$client_dev" netns "$client_ns"
    sudo -n ip link set "$server_dev" netns "$server_ns"
    sudo -n ip -n "$client_ns" link set "$client_dev" name fq0
    sudo -n ip -n "$server_ns" link set "$server_dev" name fq0
    sudo -n ip -n "$client_ns" addr add 10.203.0.1/30 dev fq0
    sudo -n ip -n "$server_ns" addr add 10.203.0.2/30 dev fq0
    test_dev=fq0
else
    # Kernel module mismatch must not turn into host environment repair.
    # Loopback still traverses the installed fq qdisc inside this namespace.
    runtime_server_ns="$client_ns"
    peer_ip=127.203.0.2
    test_dev=lo
    printf 'veth unavailable; testing isolated loopback fq\n'
fi
test_namespaces=("$client_ns")
if [[ "$runtime_server_ns" != "$client_ns" ]]; then test_namespaces+=("$runtime_server_ns"); fi
for ns in "${test_namespaces[@]}"; do
    sudo -n ip -n "$ns" link set lo up
    sudo -n ip -n "$ns" link set "$test_dev" up
    sudo -n ip netns exec "$ns" tc qdisc replace dev "$test_dev" root fq
done

sudo -n ip netns exec "$runtime_server_ns" python3 -u -c '
import select, socket, struct, time
sockets = []
for port in (34567, 34568):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", port))
    sockets.append(s)
for _ in range(20):
    ready, _, _ = select.select(sockets, [], [], 10)
    if not ready: raise TimeoutError("fq echo receiver")
    data, addr = ready[0].recvfrom(65536)
    ready[0].sendto(data[:1] + struct.pack("!Q", time.monotonic_ns()), addr)
' &
server_pid=$!
sleep 0.2
sudo -n ip netns exec "$client_ns" env QUIC_KERNEL_PACING_PEER="$peer_ip" QUIC_KERNEL_PACING_EXPECT_FQ=1 "$test_root/quic.test" -test.run 'TestKernelPacing(FQIntegration|FQPathDetection)$' -test.v -test.timeout 15s
wait "$server_pid"
server_pid=

run_hy2() {
    local expected=$1 disabled=$2 delay=${3:-0}
    sudo -n ip netns exec "$runtime_server_ns" env XRAY_HY2_FQ_ROLE=server XRAY_HY2_FQ_ADDR="$peer_ip:34569" XRAY_HY2_FQ_DELAY_MS="$delay" QUIC_KERNEL_PACING_EXPECT_FQ="$expected" QUIC_GO_DISABLE_KERNEL_PACING="$disabled" QUIC_GO_LOG_LEVEL="${QUIC_GO_LOG_LEVEL:-}" HYSTERIA_BBR_DEBUG="${HYSTERIA_BBR_DEBUG:-}" "$test_root/hy2.test" -test.run '^TestBBRFQEndToEnd$' -test.v -test.timeout 35s &
    server_pid=$!
    sleep 0.2
    sudo -n ip netns exec "$client_ns" env XRAY_HY2_FQ_ROLE=client XRAY_HY2_FQ_ADDR="$peer_ip:34569" QUIC_KERNEL_PACING_EXPECT_FQ="$expected" QUIC_GO_DISABLE_KERNEL_PACING="$disabled" QUIC_GO_LOG_LEVEL="${QUIC_GO_LOG_LEVEL:-}" HYSTERIA_BBR_DEBUG="${HYSTERIA_BBR_DEBUG:-}" "$test_root/hy2.test" -test.run '^TestBBRFQEndToEnd$' -test.v -test.timeout 35s
    wait "$server_pid"
    server_pid=
}

run_hy2 0 1 5
run_hy2 1 0 5
run_hy2 0 0 0
for ns in "${test_namespaces[@]}"; do sudo -n ip netns exec "$ns" tc -s qdisc show dev "$test_dev"; done
for ns in "${test_namespaces[@]}"; do sudo -n ip netns exec "$ns" tc qdisc del dev "$test_dev" root; done
sudo -n ip netns exec "$client_ns" env QUIC_KERNEL_PACING_PEER="$peer_ip" QUIC_KERNEL_PACING_EXPECT_FQ=0 "$test_root/quic.test" -test.run '^TestKernelPacingFQPathDetection$' -test.v -test.timeout 10s
run_hy2 0 0
