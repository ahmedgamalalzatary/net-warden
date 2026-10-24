"""Builds third_party/GeoIP/country.bin.gz from DB-IP's free "IP to Country Lite" database.

Usage:  python scripts/update-geoip.py [path-or-url-of-dbip-country-lite-YYYY-MM.csv.gz]
Without an argument the current month's file is downloaded from download.db-ip.com.

DB-IP Lite is licensed CC BY 4.0 (https://db-ip.com); the app must show the attribution.

Output format (gzip-compressed, big-endian):
  b"NWGEO1"
  u32 n4, then n4 x (u32 start, 2-byte country)      IPv4 ranges, sorted
  u32 n6, then n6 x (u64 start, 2-byte country)      IPv6 ranges by the top 64 bits, sorted
  u32 date length, UTF-8 date of the source (YYYY-MM)
Each range runs to the next start. Country b"\\0\\0" = unknown (DB-IP's ZZ or a gap).
"""
import datetime
import gzip
import ipaddress
import io
import os
import re
import struct
import sys
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "third_party", "GeoIP", "country.bin.gz")


def load(source):
    if source.startswith("http"):
        with urllib.request.urlopen(source) as r:
            return r.read()
    with open(source, "rb") as f:
        return f.read()


def ranges(rows, version, shift):
    """Yields (start, country) with gaps filled and equal neighbours merged."""
    out = []
    expected = 0
    for start_text, end_text, cc in rows:
        start = int(ipaddress.ip_address(start_text)) >> shift
        end = int(ipaddress.ip_address(end_text)) >> shift
        code = b"\0\0" if cc == "ZZ" else cc.encode("ascii")
        if start > expected:
            out.append((expected, b"\0\0"))
        if out and out[-1][0] == start:
            out.pop()  # a range smaller than the 64-bit granularity: the later one wins
        if not out or out[-1][1] != code:
            out.append((start, code))
        expected = end + 1
    return out


def main():
    month = datetime.date.today().strftime("%Y-%m")
    source = sys.argv[1] if len(sys.argv) > 1 else f"https://download.db-ip.com/free/dbip-country-lite-{month}.csv.gz"
    data = gzip.decompress(load(source)).decode("ascii")
    v4, v6 = [], []
    for line in data.splitlines():
        if not line:
            continue
        start, end, cc = line.split(",")
        (v6 if ":" in start else v4).append((start, end, cc))

    r4 = ranges(v4, 4, 0)
    r6 = ranges(v6, 6, 64)
    buf = io.BytesIO()
    buf.write(b"NWGEO1")
    buf.write(struct.pack(">I", len(r4)))
    for start, cc in r4:
        buf.write(struct.pack(">I", start) + cc)
    buf.write(struct.pack(">I", len(r6)))
    for start, cc in r6:
        buf.write(struct.pack(">Q", start) + cc)
    found = re.search(r"\d{4}-\d{2}", os.path.basename(source))
    stamp = (found.group(0) if found else month).encode("utf-8")
    buf.write(struct.pack(">I", len(stamp)) + stamp)

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "wb") as f:
        f.write(gzip.compress(buf.getvalue(), compresslevel=9, mtime=0))
    print(f"IPv4 ranges: {len(r4)}, IPv6 ranges: {len(r6)}, {os.path.getsize(OUT)} bytes -> {OUT}")


if __name__ == "__main__":
    main()
