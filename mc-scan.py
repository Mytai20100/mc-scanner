#!/usr/bin/env python3
"""
Requires  : pip install pyyaml aiohttp aiofiles

Usage:
  python3 mc-scan.py --ip mc.hypixel.net
  python3 mc-scan.py --targets targets.txt
  python3 mc-scan.py --range 192.168.1.1-192.168.1.50
  python3 mc-scan.py --range 10.0.0.0/24 --workers 80
  python3 mc-scan.py help | -h | --h
"""

import sys
import subprocess

REQUIRED = {
    "yaml":     "pyyaml",
    "aiohttp":  "aiohttp",
    "aiofiles": "aiofiles",
}

def _check_and_install():
    import importlib.util
    missing = [(mod, pkg) for mod, pkg in REQUIRED.items()
               if not importlib.util.find_spec(mod)]
    if not missing:
        return

    print("\n  Missing dependencies:")
    for mod, pkg in missing:
        print(f"    {mod}  ({pkg})")

    try:
        ans = input("\n  Auto-install? [Y/n]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        ans = "n"

    if ans in ("", "y", "yes"):
        pkgs = [pkg for _, pkg in missing]
        result = subprocess.run([sys.executable, "-m", "pip", "install", *pkgs], check=False)
        if result.returncode != 0:
            print(f"\n  Install failed. Run manually:\n    pip install {' '.join(pkgs)}\n")
            sys.exit(1)
        subprocess.run([sys.executable, *sys.argv])
        sys.exit(0)
    else:
        print(f"\n  Run manually:\n    pip install {' '.join(p for _, p in missing)}\n")
        sys.exit(1)

_check_and_install()

import asyncio
import socket
import struct
import json
import re
import base64
import argparse
import ipaddress
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import yaml
import aiohttp
import aiofiles

JAVA_PORTS    = [25565, 25566, 25567, 25568, 25569, 25570, 25575, 25580, 25600, 25700]
BEDROCK_PORTS = [19132, 19133, 19134, 19135, 19136, 19137, 19138, 19139, 19140, 19141]
TIMEOUT       = 3
WORKERS       = 80
GEO_URL       = "http://ip-api.com/json/{ip}?fields=country,regionName,city,isp,lat,lon,status"

HELP_TEXT = """\
Minecraft Server Archiver

Usage:
  python3 mc-scan.py --ip <host>
  python3 mc-scan.py --range 192.168.1.1-192.168.1.50
  python3 mc-scan.py --range 10.0.0.0/24 --workers 80
  python3 mc-scan.py --targets targets.txt --out results

Targets (at least one required):
  --ip <host>          Single IP or hostname
  --range <range>      IP range or CIDR block
  --targets <file>     Text file, one host per line

Ports:
  --java-ports    <p,p,...>   default: {java}
  --bedrock-ports <p,p,...>   default: {bedrock}

Options:
  --workers <n>    Concurrent workers  (default: {workers})
  --out <dir>      Output directory    (default: mc_archive)
  help | -h | --h  Show this help
""".format(
    java=",".join(map(str, JAVA_PORTS)),
    bedrock=",".join(map(str, BEDROCK_PORTS)),
    workers=WORKERS,
)


def _pack_varint(v: int) -> bytes:
    out = b""
    for _ in range(5):
        b = v & 0x7F; v >>= 7
        out += bytes([b | (0x80 if v else 0)])
        if not v: break
    return out

def _unpack_vi(buf: bytes, pos: int) -> tuple[int, int]:
    r = s = 0
    for _ in range(5):
        b = buf[pos]; pos += 1
        r |= (b & 0x7F) << s
        if not (b & 0x80): break
        s += 7
    return r, pos

def _pack_str(s: str) -> bytes:
    e = s.encode("utf-8")
    return _pack_varint(len(e)) + e

def _strip_mc(t) -> str:
    if isinstance(t, dict):
        return _strip_mc(t.get("text","")) + "".join(_strip_mc(e) for e in t.get("extra",[]))
    if isinstance(t, list):
        return "".join(_strip_mc(i) for i in t)
    return re.sub(r"§.", "", str(t)).strip()

def _slug(host: str, port: int) -> str:
    return re.sub(r"[^a-zA-Z0-9\-]", "_", host) + f"_{port}"


async def ping_modern(host: str, port: int) -> Optional[dict]:
    try:
        t0 = time.perf_counter()
        r, w = await asyncio.wait_for(asyncio.open_connection(host, port), TIMEOUT)
        ms = round((time.perf_counter() - t0) * 1000, 1)

        hs = _pack_varint(47) + _pack_str(host) + struct.pack(">H", port) + _pack_varint(1)
        pkt = _pack_varint(0x00) + hs
        w.write(_pack_varint(len(pkt)) + pkt)
        req = _pack_varint(0x00)
        w.write(_pack_varint(len(req)) + req)
        await w.drain()

        raw = b""
        while len(raw) < 5:
            c = await asyncio.wait_for(r.read(4096), TIMEOUT)
            if not c: break
            raw += c

        pkt_len, pos = _unpack_vi(raw, 0)
        needed = pkt_len - (len(raw) - pos)
        while needed > 0:
            c = await asyncio.wait_for(r.read(needed), TIMEOUT)
            if not c: break
            raw += c; needed -= len(c)

        _, pos = _unpack_vi(raw, pos)
        slen, pos = _unpack_vi(raw, pos)
        js = raw[pos: pos + slen].decode("utf-8", errors="replace")
        w.close()

        d = json.loads(js)
        d["_ms"] = ms; d["_proto"] = "java_modern"
        return d
    except Exception:
        return None


async def ping_legacy(host: str, port: int) -> Optional[dict]:
    try:
        t0 = time.perf_counter()
        r, w = await asyncio.wait_for(asyncio.open_connection(host, port), TIMEOUT)
        ms = round((time.perf_counter() - t0) * 1000, 1)
        host_enc = host.encode("utf-16-be")
        inner = struct.pack(">bH", 73, len(host_enc) // 2) + host_enc + struct.pack(">I", port)
        plugin_msg = (bytes([0xFA])
            + struct.pack(">H", 11) + "MC|PingHost".encode("utf-16-be")
            + struct.pack(">H", len(inner)) + inner)

        w.write(bytes([0xFE, 0x01]) + plugin_msg)
        await w.drain()

        data = await asyncio.wait_for(r.read(512), TIMEOUT)
        w.close()
        if not data or data[0] != 0xFF: return None

        length = struct.unpack(">H", data[1:3])[0]
        s = data[3: 3 + length * 2].decode("utf-16-be", errors="ignore")

        if s.startswith("\x00\xa7\x001"):
            p = s.split("\x00")
            if len(p) >= 8:
                return {"version": {"name": p[4], "protocol": _safe_int(p[3])},
                        "players": {"online": _safe_int(p[6]), "max": _safe_int(p[7])},
                        "description": p[5], "_ms": ms, "_proto": "java_legacy_16"}
        else:
            p = s.split("§")
            if len(p) >= 3:
                return {"version": {"name": "< 1.4", "protocol": -1},
                        "players": {"online": _safe_int(p[1]), "max": _safe_int(p[2])},
                        "description": p[0], "_ms": ms, "_proto": "java_legacy_old"}
        return None
    except Exception:
        return None

def _safe_int(v, default=0) -> int:
    try: return int(v)
    except: return default


RAKNET_MAGIC = bytes([0x00,0xff,0xff,0x00,0xfe,0xfe,0xfe,0xfe,
                      0xfd,0xfd,0xfd,0xfd,0x12,0x34,0x56,0x78])

async def ping_bedrock(host: str, port: int) -> Optional[dict]:
    try:
        loop = asyncio.get_event_loop()
        t0 = time.perf_counter()
        ts = int(time.time() * 1000) & 0xFFFFFFFFFFFFFFFF
        pkt = bytes([0x01]) + struct.pack(">Q", ts) + RAKNET_MAGIC + struct.pack(">Q", 0)

        class Proto(asyncio.DatagramProtocol):
            def __init__(self): self.fut = loop.create_future()
            def datagram_received(self, d, _):
                if not self.fut.done(): self.fut.set_result(d)
            def error_received(self, e):
                if not self.fut.done(): self.fut.set_exception(e)
            def connection_lost(self, _):
                if not self.fut.done(): self.fut.cancel()

        proto = Proto()
        transport, _ = await loop.create_datagram_endpoint(lambda: proto, remote_addr=(host, port))
        ms = round((time.perf_counter() - t0) * 1000, 1)
        transport.sendto(pkt)
        try:
            resp = await asyncio.wait_for(proto.fut, TIMEOUT)
        finally:
            transport.close()

        if not resp or resp[0] != 0x1C: return None
        offset = 1 + 8 + 8 + 16 + 2
        raw_s = resp[offset:].decode("utf-8", errors="replace")
        p = raw_s.split(";")
        if len(p) < 6: return None
        return {
            "version": {"name": p[3] if len(p) > 3 else "?", "protocol": _safe_int(p[2], -1)},
            "players": {"online": _safe_int(p[4]), "max": _safe_int(p[5])},
            "description": p[1],
            "_ms": ms,
            "_proto": "bedrock",
            "_edition": p[0],
            "_gamemode": p[8] if len(p) > 8 else "Survival",
        }
    except Exception:
        return None


_geo_cache: dict = {}

async def get_geo(host: str, session: aiohttp.ClientSession) -> dict:
    empty = {"country": "?", "regionName": "?", "city": "?", "isp": "?", "lat": 0, "lon": 0}
    try:
        ip = socket.gethostbyname(host)
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback:
            return {**empty, "country": "Local Network", "city": "—", "isp": "—"}
        if ip in _geo_cache: return _geo_cache[ip]
        async with session.get(GEO_URL.format(ip=ip),
                               timeout=aiohttp.ClientTimeout(total=4)) as resp:
            geo = await resp.json(content_type=None)
            if geo.get("status") == "success":
                _geo_cache[ip] = geo
                return geo
    except Exception:
        pass
    return empty


async def scan(host: str, port: int, bedrock: bool,
               session: aiohttp.ClientSession) -> Optional[dict]:
    if bedrock:
        raw = await ping_bedrock(host, port)
    else:
        raw = await ping_modern(host, port)
        if raw is None:
            raw = await ping_legacy(host, port)
    if raw is None: return None

    ver  = raw.get("version", {})
    pl   = raw.get("players", {})
    geo  = await get_geo(host, session)

    return {
        "host":           host,
        "port":           port,
        "edition":        raw.get("_edition", "Java"),
        "protocol_used":  raw.get("_proto", "unknown"),
        "motd":           _strip_mc(raw.get("description", "")),
        "version":        ver.get("name", "?"),
        "protocol_num":   ver.get("protocol", -1),
        "players_online": pl.get("online", 0),
        "players_max":    pl.get("max", 0),
        "gamemode":       raw.get("_gamemode", "—"),
        "ping_ms":        raw.get("_ms", 0),
        "favicon":        bool(raw.get("favicon")),
        "_favicon_data":  raw.get("favicon", ""),
        "geo": {
            "country": geo.get("country", "?"),
            "region":  geo.get("regionName", "?"),
            "city":    geo.get("city", "?"),
            "isp":     geo.get("isp", "?"),
            "lat":     geo.get("lat", 0),
            "lon":     geo.get("lon", 0),
        },
        "archived_at": datetime.now(timezone.utc).isoformat(),
    }


async def save_favicon(info: dict, out_dir: Path) -> Optional[str]:
    data = info.get("_favicon_data", "")
    if not data: return None
    try:
        b64 = re.sub(r"^data:image/\w+;base64,", "", data)
        fav_dir = out_dir / "favicons"
        fav_dir.mkdir(exist_ok=True)
        path = fav_dir / f"{_slug(info['host'], info['port'])}.png"
        async with aiofiles.open(path, "wb") as f:
            await f.write(base64.b64decode(b64))
        return str(path.relative_to(out_dir))
    except Exception:
        return None

async def write_server(info: dict, out_dir: Path):
    fav_rel = await save_favicon(info, out_dir)
    slug = _slug(info["host"], info["port"])
    geo  = info["geo"]

    edition_icon = "" if info["edition"] == "Java" else ""
    fav_md = f"![favicon]({fav_rel})" if fav_rel else "*(no favicon)*"

    md = f"""\
# {edition_icon} {info['host']}:{info['port']}

{fav_md}

| Field | Value |
|---|---|
| **MOTD** | `{info['motd']}` |
| **Edition** | {info['edition']} |
| **Version** | {info['version']} `(protocol {info['protocol_num']})` |
| **Players** | {info['players_online']} / {info['players_max']} |
| **Ping** | {info['ping_ms']} ms |
| **Protocol** | `{info['protocol_used']}` |
| **Country** | {geo['country']} |
| **Region** | {geo['region']}, {geo['city']} |
| **ISP** | {geo['isp']} |
| **Coords** | {geo['lat']}, {geo['lon']} |
| **Archived** | `{info['archived_at']}` |
"""
    yml_info = {k: v for k, v in info.items() if k != "_favicon_data"}
    if fav_rel: yml_info["favicon_file"] = fav_rel

    async with aiofiles.open(out_dir / f"{slug}.md", "w", encoding="utf-8") as f:
        await f.write(md)
    async with aiofiles.open(out_dir / f"{slug}.yml", "w", encoding="utf-8") as f:
        await f.write(yaml.dump(yml_info, allow_unicode=True, sort_keys=False))


async def write_index(results: list[dict], out_dir: Path):
    ts = datetime.now(timezone.utc).isoformat()
    rows = "\n".join(
        f"| `{r['host']}:{r['port']}` | {r['edition']} | {r['motd'][:40]} "
        f"| {r['version']} | {r['players_online']}/{r['players_max']} "
        f"| {r['ping_ms']} ms | {r['geo']['city']}, {r['geo']['country']} |"
        for r in results
    )
    md = f"""\
# Minecraft Archive Index

Generated: `{ts}` | Servers found: **{len(results)}**

| Address | Edition | MOTD | Version | Players | Ping | Location |
|---|---|---|---|---|---|---|
{rows}
"""
    clean = [{k: v for k, v in r.items() if k != "_favicon_data"} for r in results]
    async with aiofiles.open(out_dir / "index.md", "w", encoding="utf-8") as f:
        await f.write(md)
    async with aiofiles.open(out_dir / "index.yml", "w", encoding="utf-8") as f:
        await f.write(yaml.dump(
            {"generated_at": ts, "total": len(results), "servers": clean},
            allow_unicode=True, sort_keys=False
        ))


def expand(args) -> list[tuple[str, int, bool]]:
    hosts: list[str] = []
    if args.ip: hosts.append(args.ip)
    if args.range:
        r = args.range
        if "/" in r:
            hosts += [str(ip) for ip in ipaddress.ip_network(r, strict=False).hosts()]
        elif "-" in r:
            lo, hi = r.split("-")
            cur, end = ipaddress.ip_address(lo.strip()), ipaddress.ip_address(hi.strip())
            while cur <= end: hosts.append(str(cur)); cur += 1
        else: hosts.append(r)
    if args.targets:
        for line in Path(args.targets).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"): hosts.append(line)

    java_ports    = [int(p) for p in args.java_ports.split(",")]
    bedrock_ports = [int(p) for p in args.bedrock_ports.split(",")]

    targets = []
    for h in hosts:
        for p in java_ports:    targets.append((h, p, False))
        for p in bedrock_ports: targets.append((h, p, True))
    return targets


async def amain():
    if len(sys.argv) >= 2 and sys.argv[1].lower().strip("-") in ("h", "help"):
        print(HELP_TEXT)
        return

    ap = argparse.ArgumentParser(description="Minecraft Server Archiver")
    ap.add_argument("--ip",            help="Single IP or hostname")
    ap.add_argument("--range",         help="IP range  1.2.3.4-1.2.3.50  or CIDR  1.2.3.0/24")
    ap.add_argument("--targets",       help="Text file — one host per line")
    ap.add_argument("--java-ports",    default=",".join(map(str, JAVA_PORTS)))
    ap.add_argument("--bedrock-ports", default=",".join(map(str, BEDROCK_PORTS)))
    ap.add_argument("--workers",       type=int, default=WORKERS)
    ap.add_argument("--out",           default="mc_archive")
    args = ap.parse_args()

    targets = expand(args)
    if not targets: ap.print_help(); return

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    java_count    = sum(1 for _, _, b in targets if not b)
    bedrock_count = sum(1 for _, _, b in targets if b)
    print(f"\n  Minecraft Archiver  |  {len(targets)} slots  "
          f"(Java {java_count} + Bedrock {bedrock_count})  |  {args.workers} workers\n"
          f"  {'─' * 60}")

    results: list[dict] = []
    sem = asyncio.Semaphore(args.workers)

    async with aiohttp.ClientSession() as session:
        async def task(host, port, bedrock):
            async with sem:
                info = await scan(host, port, bedrock, session)
                tag  = "B" if bedrock else "J"
                if info:
                    await write_server(info, out_dir)
                    results.append(info)
                    g = info["geo"]
                    fav = "" if info["favicon"] else "  "
                    print(
                        f"  [+][{tag}] {fav} {host}:{port:<6}  "
                        f"{info['version']:<22}  "
                        f"{info['players_online']:>4}/{info['players_max']:<4}  "
                        f"{info['ping_ms']:>5} ms  "
                        f"{g['city']}, {g['country']}"
                    )
                else:
                    print(f"  [ ][{tag}]    {host}:{port}")

        await asyncio.gather(*(task(h, p, b) for h, p, b in targets))

    if results:
        await write_index(results, out_dir)
        print(f"\n  Archived {len(results)} server(s) → {out_dir}/\n"
              f"  index.md  index.yml  <slug>.md  <slug>.yml  favicons/<slug>.png\n")
    else:
        print("\n  No servers found.\n")

def main():
    asyncio.run(amain())

if __name__ == "__main__":
    main()
