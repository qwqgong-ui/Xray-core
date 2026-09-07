# Hybrid QUIC over proxy streams

Hybrid QUIC uses one ordinary, domain-preserving proxy stream per UDP target.
The stream opens `hybrid-quic.invalid:443`, carries the real destination and QUIC
handshake, remains available for fallback, and owns the flow's lifetime. Raw
UDP carries unchanged short-header QUIC packets to the terminal Xray. It does
not add a flow identifier or a packet header.

This replaces HQV3. Upgrade both ends; the old HY2 datagram registration protocol
is removed. In mihomo, enable `hybrid-quic: true` on a proxy node explicitly.
It is disabled by default. Raw acceleration is limited to public targets on UDP
443; other traffic uses the selected node's ordinary capabilities.

## Terminal Xray

Add this top-level configuration alongside ordinary inbounds and outbounds:

```json
{
  "hybridQUIC": {
    "listen": "0.0.0.0:443",
    "advertise": "YOUR_PUBLIC_IP:443"
  }
}
```

`listen` and `advertise` must be literal IP addresses on port 443. `advertise`
must be the reachable address of this exact terminal server, including any NAT
mapping. A wildcard listen address cannot be advertised. IPv4 and IPv6 work;
a terminal advertises one raw endpoint. The target IP is resolved by this Xray's
DNS, independently of the raw endpoint's address family.

If HY2 already owns UDP 443 on this instance, set `shareHysteria: true` and make
`listen` match that HY2 inbound's bind address exactly. Hybrid then reuses that
socket before its UDP mask, with no second listener. Every unclaimed packet
continues to the HY2 stack, including connection migration. If a matching shared
listener is absent, the stream works without raw acceleration. A standalone
listener fails startup on a bind conflict instead of silently changing ports.

## mihomo -> first Xray -> terminal Xray

The first Xray reads the real UDP destination and applies its existing routing
rules once. It forwards the entire reliable stream only when the chosen outbound
tag appears in `forwardOutbounds`. All other selected outbounds terminate hybrid
locally and forward ordinary UDP; local termination requires a raw listener
configuration, even if raw subsequently proves unavailable.

First Xray, top-level additions:

```json
{
  "hybridQUIC": {
    "forwardOutbounds": ["next-xray"]
  },
  "routing": {
    "rules": [
      {
        "type": "field",
        "domain": ["domain:example.com"],
        "network": "udp",
        "outboundTag": "next-xray"
      }
    ]
  }
}
```

Configure the ordinary `next-xray` outbound to reach the terminal using VLESS,
VMess, Trojan, Shadowsocks, SOCKS, HTTP CONNECT or HY2. The next server must
implement this hybrid protocol. The selected outbound receives the reserved
marker directly; the marker is never submitted to routing again. A freedom,
blackhole or IP-tunnel outbound cannot be a hybrid forwarding outbound.

Terminal Xray, top-level additions:

```json
{
  "hybridQUIC": {
    "listen": "0.0.0.0:443",
    "advertise": "TERMINAL_PUBLIC_IP:443",
    "trustedForwardInbounds": ["from-first-xray"]
  }
}
```

`from-first-xray` must be the tag of an authenticated inbound dedicated to the
previous Xray. Only listed inbounds may supply a forwarded original-client IP.
The first Xray obtains that address from its actual inbound connection; a
mihomo request cannot specify it. The terminal uses that original address plus
an observed target CID to bind raw, so the intermediate server's address does
not prevent acceleration. Do not share a trusted inbound with untrusted direct
clients. Forwarded metadata is trusted hop by hop, with a maximum of eight
forwarding hops.

The returned target/raw addresses come from the terminal. Consequently the
steady path is mihomo -> terminal Xray -> target, while the reliable path is
mihomo -> first Xray -> terminal Xray -> target. A client whose raw source IP
differs from its first tunnel connection, such as separate NATs or an unaware
intermediate proxy, stays on the reliable path.

## Framing and lifetime

The request consists of `HQS1`, one hop-count byte, one origin-address-length byte
(0, 4 or 16), the optional origin IP bytes, and the destination address. A direct
client sends zero hops and no origin. Addresses use a big-endian uint16 byte
length followed by UTF-8 `host:port`, limited to 259 bytes.

The terminal replies with status byte 0, the actual target IP:port and the raw
IP:port in the same address format. `0.0.0.0:443` means raw is unavailable.
Setup failure closes the stream. No application packet is sent before this
exchange completes, so the client can use native UDP if setup is rejected.
Once accepted, a flow never changes its target connection.

Subsequent frames have a big-endian uint16 prefix:

- 1..65507: that many bytes of one unchanged datagram.
- 0: permanently disable raw in both directions for this stream.
- 65535: keepalive, sent every 30 seconds while the stream exists.
- Other lengths: invalid; close the stream.

All non-short-header packets stay on the stream, including Retry and Version
Negotiation. Short packets initially use the stream, plus one raw probe at most
every 250 ms. No raw reply within three seconds permanently disables raw. A raw
write/read failure, or 15 seconds without a raw reply after activation, also
permanently disables it. The watchdog runs independently of new application
writes. An idle flow can therefore lose raw acceleration after 15 seconds;
it continues on the stream. The server notifies the client on raw socket failure.

A disable frame deletes raw tuple/CID claims; late raw replies cannot reactivate
the client, and late raw requests cannot rebind the server. Packets already in
flight may be lost; application QUIC retransmits. There is no automatic recovery
or re-registration. Stream EOF/cancellation closes the target and removes all
bindings, including flows that never used raw. Keepalives prevent intermediate
proxy idle timers from reclaiming a stream carrying raw traffic.

Zero-length or ambiguous CIDs cannot bind. CID ownership and the original source
IP constrain raw demultiplexing; the relay does not decrypt or authenticate QUIC
packets itself. Target QUIC still performs its own packet authentication.

Routing selects on the real UDP target before local resolution or forwarding.
Local target traffic passes through the selected outbound with user accounting;
it does not use a bare target UDP socket. Intermediate nodes account for stream
traffic they actually carry; terminal raw traffic does not traverse them.
The reserved hostname is intercepted at both dispatcher entry points regardless
of case, trailing dot, port or transport: unsupported uses are closed internally.
