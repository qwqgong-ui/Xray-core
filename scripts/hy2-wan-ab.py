#!/usr/bin/env python3
"""Private fixture preparation and repeatable HTTP workloads for HY2 WAN A/B."""

import argparse
import copy
import hashlib
import http.server
import json
import os
from pathlib import Path
import statistics
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor

BLOCK = hashlib.shake_256(b"xray-hy2-bbr-fq-wan-ab").digest(65536)


class BenchHTTP(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        count = int(self.path.split("n=", 1)[1].split("&", 1)[0]) if "n=" in self.path else 1024
        count = min(max(count, 1), 128 * 1024 * 1024)
        self.send_response(200)
        self.send_header("Content-Length", str(count))
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            while count:
                part = BLOCK[:min(count, len(BLOCK))]
                self.wfile.write(part)
                count -= len(part)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_POST(self):
        expected = int(self.headers.get("Content-Length", "0"))
        received = 0
        while received < expected:
            data = self.rfile.read(min(65536, expected - received))
            if not data:
                break
            received += len(data)
        body = json.dumps({"received": received}).encode()
        self.send_response(200 if received == expected else 400)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


def prepare(args):
    import yaml
    target = Path(args.workdir)
    target.mkdir(mode=0o700, parents=True, exist_ok=True)
    live = json.loads(Path(args.xray_config).read_text())
    inbound = next(item for item in live["inbounds"] if item.get("protocol") == "hysteria")
    client = yaml.safe_load(Path(args.mihomo_config).read_text())
    node = next(item for item in client["proxies"] if item.get("type") == "hysteria2" and item.get("server") == args.server)
    for name, port, socks in (("before", args.before_port, 45651), ("after", args.after_port, 45652)):
        fixture = copy.deepcopy(inbound)
        fixture.update(tag="hy2-wan-ab-" + name, listen="::", port=port)
        server_config = {"log": {"loglevel": "warning"}, "inbounds": [fixture], "outbounds": [{"tag": "direct", "protocol": "freedom", "settings": {"finalRules": [{"action": "allow", "network": "tcp", "ip": ["127.0.0.1/32"], "port": str(args.http_port)}]}}]}
        (target / (name + ".json")).write_text(json.dumps(server_config, indent=2))
        proxy = copy.deepcopy(node)
        proxy.update(name="hy2-wan-ab-" + name, port=port)
        proxy.pop("ports", None)
        proxy.pop("dialer-proxy", None)
        local = {"mixed-port": socks, "bind-address": "127.0.0.1", "allow-lan": False, "mode": "rule", "log-level": "warning", "ipv6": True, "routing-mark": client.get("routing-mark", 666), "dns": {"enable": False}, "tun": {"enable": False}, "proxies": [proxy], "rules": ["MATCH," + proxy["name"]]}
        (target / ("mihomo-" + name + ".json")).write_text(json.dumps(local, indent=2))
    for file in target.glob("*.json"):
        file.chmod(0o600)
    print("private before/after fixtures prepared; credentials omitted")


def curl(socks, url, upload=None, count=0, seconds=45):
    command = ["curl", "--silent", "--show-error", "--noproxy", "", "--socks5-hostname", "127.0.0.1:" + str(socks), "--http1.1", "--connect-timeout", "10", "--max-time", str(seconds), "--output", "/dev/null", "--write-out", "%{json}", "-H", "Accept-Encoding: identity"]
    if upload:
        command += ["-H", "Expect:", "--data-binary", "@" + str(upload)]
    result = subprocess.run(command + [url], capture_output=True, text=True)
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        data = {"time_total": seconds, "http_code": 0}
    data.update(exit=result.returncode, error=result.stderr.strip())
    if result.returncode or int(data.get("http_code", 0)) != 200:
        raise RuntimeError("curl failed: " + data.get("error", "") + " HTTP=" + str(data.get("http_code")))
    if not upload and count and int(data.get("size_download", 0)) != count:
        raise RuntimeError("incomplete download")
    if upload and int(data.get("size_upload", 0)) != Path(upload).stat().st_size:
        raise RuntimeError("incomplete upload")
    return data


def stats(args, variant):
    unit = args.server_unit or ("xray-hy2-ab-" + variant + ".service")
    command = ["ssh", "-T", "-o", "BatchMode=yes", "-o", "ProxyCommand=sudo -n python3 " + args.ssh_helper + " %h %p", args.ssh_host,
               "systemctl show " + unit + " -p CPUUsageNSec -p MemoryCurrent -p MainPID"]
    text = subprocess.check_output(command, text=True)
    return {key: int(value) for key, value in (line.split("=", 1) for line in text.splitlines()) if value.isdigit()}


def bench(args):
    root = Path(args.workdir)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    upload = root / "upload.bin"
    with upload.open("wb") as file:
        for _ in range(128):
            file.write(BLOCK)
    records = []
    ports = {variant: args.mixed_port or (45651 if variant == "before" else 45652) for variant in args.variants}
    endpoint = "http://127.0.0.1:" + str(args.http_port)
    # Both clients use identical HY2 options and a private local mixed port.
    for variant in ports:
        curl(ports[variant], endpoint + "/blob?n=1048576", count=1048576)
    for repeat in range(args.repeats):
        order = list(ports) if repeat % 2 == 0 else list(reversed(ports))
        for variant in order:
            for workload in ("download", "upload", "parallel_download", "latency"):
                initial = stats(args, variant)
                start = time.monotonic()
                if workload == "download":
                    samples = [curl(ports[variant], endpoint + "/blob?n=16777216", count=16777216)]
                    transferred = 16777216
                elif workload == "upload":
                    samples = [curl(ports[variant], endpoint + "/upload", upload=upload)]
                    transferred = upload.stat().st_size
                elif workload == "parallel_download":
                    with ThreadPoolExecutor(max_workers=4) as pool:
                        samples = list(pool.map(lambda _: curl(ports[variant], endpoint + "/blob?n=4194304", count=4194304), range(4)))
                    transferred = 4 * 4194304
                else:
                    samples = [curl(ports[variant], endpoint + "/blob?n=1024", count=1024) for _ in range(12)]
                    transferred = 12 * 1024
                elapsed = time.monotonic() - start
                final = stats(args, variant)
                row = {"variant": variant, "repeat": repeat + 1, "workload": workload, "bytes": transferred, "seconds": elapsed, "mbps": transferred * 8 / elapsed / 1e6, "cpu_percent": max(0, final.get("CPUUsageNSec", 0) - initial.get("CPUUsageNSec", 0)) / 1e9 / elapsed * 100, "memory_bytes": final.get("MemoryCurrent", 0), "ttfb_ms_median": statistics.median(sample["time_starttransfer"] * 1000 for sample in samples), "curl": samples}
                records.append(row)
                (root / "results.json").write_text(json.dumps(records, indent=2))
                print(json.dumps({key: value for key, value in row.items() if key != "curl"}), flush=True)
    summary = {}
    for workload in ("download", "upload", "parallel_download", "latency"):
        summary[workload] = {}
        for variant in ports:
            rows = [row for row in records if row["variant"] == variant and row["workload"] == workload]
            summary[workload][variant] = {metric: statistics.median(row[metric] for row in rows) for metric in ("mbps", "cpu_percent", "ttfb_ms_median")}
    (root / "summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps({"summary": summary}), flush=True)


parser = argparse.ArgumentParser()
commands = parser.add_subparsers(dest="command", required=True)
server = commands.add_parser("serve")
server.add_argument("--port", type=int, default=28080)
fixtures = commands.add_parser("prepare")
fixtures.add_argument("--workdir", required=True)
fixtures.add_argument("--xray-config", required=True)
fixtures.add_argument("--mihomo-config", required=True)
fixtures.add_argument("--server", required=True)
fixtures.add_argument("--before-port", type=int, default=26001)
fixtures.add_argument("--after-port", type=int, default=26002)
fixtures.add_argument("--http-port", type=int, default=28080)
workloads = commands.add_parser("bench")
workloads.add_argument("--workdir", required=True)
workloads.add_argument("--ssh-helper", required=True)
workloads.add_argument("--ssh-host", default="proxy")
workloads.add_argument("--http-port", type=int, default=28080)
workloads.add_argument("--repeats", type=int, default=3)
workloads.add_argument("--variants", nargs="+", choices=("before", "after"), default=["before", "after"])
workloads.add_argument("--mixed-port", type=int)
workloads.add_argument("--server-unit")
args = parser.parse_args()
if args.command == "serve":
    http.server.ThreadingHTTPServer(("127.0.0.1", args.port), BenchHTTP).serve_forever()
elif args.command == "prepare":
    prepare(args)
else:
    bench(args)
