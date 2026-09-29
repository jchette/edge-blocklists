"""Rebuild the scanner feed files from OpenFilters' published CIDR lists.

Each source list is downloaded, IPv6 entries are dropped, every IPv4 range is
expanded into single IPs (Sophos feeds don't accept CIDR), and the result is
written one IP per line. The run fails instead of writing a file if a source
is unreachable, empty, suspiciously large, or shrank sharply, so a bad
download can never wipe out a working feed.
"""
import ipaddress
import pathlib
import sys
import urllib.request

BASE = "https://raw.githubusercontent.com/OpenFilters/internet-scanners/main/cidr/"
FEEDS = {
    "feed_scanners_censys.txt": "censys_v4.txt",
    "feed_scanners_rootevidence.txt": "rootevidence_v4.txt",
}
MAX_IPS = 50_000        # refuse anything unexpectedly huge
MIN_KEEP_RATIO = 0.5    # refuse if the new list is under half the old one
MIN_PREFIX = 20         # refuse ranges bigger than a /20 (4,096 IPs)


def fetch(url):
    with urllib.request.urlopen(url, timeout=60) as r:
        return r.read().decode("utf-8", "replace").splitlines()


def expand(lines):
    ips = set()
    for raw in lines:
        line = raw.split("#")[0].strip()
        if not line:
            continue
        net = ipaddress.ip_network(line, strict=False)
        if net.version != 4:
            continue
        if net.prefixlen < MIN_PREFIX:
            raise ValueError(f"range too large to expand: {net}")
        ips.update(str(a) for a in net)
    return ips


def main():
    failed = False
    for out_name, src in FEEDS.items():
        out = pathlib.Path(out_name)
        try:
            new = expand(fetch(BASE + src))
            if not new:
                raise ValueError("source returned no IPv4 entries")
            if len(new) > MAX_IPS:
                raise ValueError(f"{len(new)} IPs exceeds limit of {MAX_IPS}")
            old = set(out.read_text().split()) if out.exists() else set()
            if old and len(new) < len(old) * MIN_KEEP_RATIO:
                raise ValueError(f"shrank from {len(old)} to {len(new)} IPs")
            ordered = sorted(new, key=ipaddress.ip_address)
            out.write_text("\n".join(ordered) + "\n")
            print(f"{out_name}: {len(old)} -> {len(new)} IPs")
        except Exception as e:
            print(f"ERROR {out_name} (source {src}): {e}", file=sys.stderr)
            failed = True
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
