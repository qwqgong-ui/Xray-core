# Ready DATAGRAM batching

The apernet/quic-go dependency patch coalesces up to four already queued
DATAGRAM frames into one QUIC packet, with no timer or wait for future data.
Extra DATAGRAMs use space left after the existing first DATAGRAM, ACK,
retransmission and STREAM scheduling. Messages that do not fit remain queued.

Each application datagram retains a separate length-bearing RFC 9221 frame.
No Hysteria2 envelope or handshake changes are needed. An unmodified peer can
receive the packets; either endpoint can be upgraded independently. This
change is in the shared QUIC packer and applies to its DATAGRAM users.

Serialization preserves DATAGRAM queue order. Batch queue removal passes
wakeups to blocked senders while capacity remains. ACK-only packets and
unreliable, non-retransmitted DATAGRAM semantics are unchanged.

A lost packet can lose up to four datagrams together. Sparse traffic may not
benefit. The bound limits loss grouping and does not guarantee a production
PPS reduction.

## Validation

```sh
sh patches/apply-dependency-patches.sh "$PWD" /tmp/xray-datagram.env
set -a
. /tmp/xray-datagram.env
set +a
CGO_ENABLED=1 go test -race github.com/apernet/quic-go -run 'Test(Datagram|Pack)' -count=1
```

The patch includes regression tests for ready-only packing, queue wakeups,
message boundaries and order, MTU remainder, and ACK/STREAM/retransmission
priority. Localhost interop with Mihomo's pinned MetaCubeX dependency passed
QUIC v1/v2 with both sides patched and with either side unmodified. Both sides
verified 256 datagrams of 32/64/128/256 bytes per case. Packet-sent tracing
counted 64 data packets for a patched sender versus 256 for an unmodified
sender in this queued-burst test. This is not a production PPS or latency test.

Full-binary HY2/SOCKS5 UDP echo tests on localhost passed with both the new
Mihomo and the previously installed Mihomo talking to the new Xray. Each
completed 128 round trips using 32 through 4000 byte payloads, exercising HY2
fragmentation and reassembly as well. Production services were not replaced.

## Production rollback comparison (2026-09-27)

The saved pre-batching Mihomo/Xray binaries and the new binaries each ran a
60-second Pion WebRTC echo workload through HY2: 3000 unordered,
zero-retransmission DataChannel messages plus 3000 synthetic Opus RTP packets.
Both runs kept ICE, DTLS and SCTP connected.

| Measurement | Saved binaries | Batching binaries |
|---|---:|---:|
| DataChannel round trips | 3000/3000 | 2999/3000 |
| RTP round trips | 2999/3000 | 3000/3000 |
| RTT median / P95 | 70.55 / 72.56 ms | 67.68 / 70.88 ms |
| HY2 uplink packets | 18605 | 12231 |
| HY2 downlink packets | 21202 | 15691 |

Counts cover only the dedicated test connection, including setup, ACKs and
control traffic, over approximately 62.9 seconds. Neither capture had UDP
payloads above 1472 bytes or kernel capture drops. Total packet count fell
29.9%, from 39807 to 27922. This short public-network comparison found no
obvious connection or latency regression, but cannot guarantee zero loss or
long-term behavior. The saved server was a13779b-dirty; the new server used
SingleUser 2bc25f8, so the comparison includes that base revision change.
The new binaries were restored, with configuration hashes unchanged.
