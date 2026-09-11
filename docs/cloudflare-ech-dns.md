# Cloudflare ECH supplementation in tunnel DNS

[返回下游功能目录](features.md) · [中文功能说明](features/cloudflare-ech.md)

When the remote DNS lookup returns only real addresses in Cloudflare's official
proxy ranges, Xray can fill a missing ECH parameter in the HTTPS (TYPE65) answer.
This is DNS metadata synthesis; it does not rewrite forwarded TLS handshakes or
change the destination IP, SNI, ALPN or port of an existing connection.

## Eligibility and source

The prefix snapshot in `app/dns/cloudflare_ech.go` was verified on 2026-09-08:
15 IPv4 and 7 IPv6 ranges from:

- https://www.cloudflare.com/ips-v4
- https://www.cloudflare.com/ips-v6
- https://www.cloudflare.com/ips/

The snapshot must be updated when Cloudflare changes these official lists.
Matching uses the instance's real LookupIP result after its address policy and
filters, never the proxy node address or a possibly unrelated HTTPS hint.
Empty, invalid, non-Cloudflare and mixed-provider address sets are ineligible.

Keys are fetched from the HTTPS record of `cloudflare-ech.com` through this
instance's configured DNS stack, preserving its DNS routing tag. The key is not
hardcoded. One instance-wide cache shares concurrent refreshes across domains,
expires at the source TTL, and never serves an expired key. Fetch failures leave
the original answer intact and trigger a 30-second retry cooldown. The source
lookup has a two-second deadline within the domain bundle's existing deadline;
TCP/QUIC record streams are interrupted on cancellation.

## Answer behavior

- Existing ECH parameters are preserved.
- ServiceMode records for the primary/CNAME-resolved owner can gain ECH while
  retaining their original ALPN, port and other parameters.
- If no HTTPS record exists, a minimal `HTTPS 1 . ech=...` record is generated.
  No ALPN, port or address hints are invented.
- AliasMode, another service target, malformed records, CNAME loops and negative
  DNS responses are left intact.
- Signatures covering a changed HTTPS RRset are removed. The tunnel response
  does not claim DNSSEC authentication of a synthesized record.
- The entire address/HTTPS bundle expires at the minimum address, service,
  CNAME-chain and ECH-source lifetime.

Both explicitly requested bundles and ordinary TYPE65 queries at
`server-dns.invalid:53` use this path. Ordinary queries retain the previous raw
record fallback if bundle/address resolution is unavailable. A/AAAA queries and
non-Cloudflare records keep their existing behavior.

Cloudflare uses `cloudflare-ech.com` as its common public name:
https://developers.cloudflare.com/ssl/edge-certificates/ech/
IP membership is an eligibility heuristic, not proof that every zone or service
will accept ECH. Applications still need ECH support and must handle rejection
normally; this code does not disable certificate verification.

## Verification

Deterministic race tests cover range boundaries (including mapped IPv4), mixed
addresses, preservation, minimal synthesis, CNAME ownership, TTL coupling,
cache expiry, concurrent refresh, failed source lookup, signature removal,
NXDOMAIN and stalled-stream cancellation.

A local temporary Xray was also checked against the public Internet on
2026-09-08. `cloudflare.com` originally had no ECH in its HTTPS response. After
supplementation, an ECH-capable client received 71 bytes of ECH configuration and
successfully connected with HTTP 200, ALPN h2, ECHAccepted=true, and
`sni=encrypted` in the site's trace. No production server was changed for this
check. This observation does not establish compatibility for every Cloudflare
zone or for future keys.
