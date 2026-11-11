#!/usr/bin/env python3
"""Refresh the embedded security-support snapshot. Never commits or merges changes."""
import argparse
from datetime import date, datetime, timezone
import json
import os
from pathlib import Path
import re
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ROOT / "scripts/lifecycle_sources.json"
SNAPSHOT = ROOT / "pkg/plugins/oseol/data/lifecycle.json"
API = "https://endoflife.date/api/v1/products/"
MAX_RESPONSE_BYTES = 4 * 1024 * 1024


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=SNAPSHOT)
    args = parser.parse_args()
    sources = json.loads(SOURCES.read_text())
    previous = json.loads(args.output.read_text()) if args.output.exists() else None
    snapshot = refresh(sources, previous)
    if snapshot == previous:
        print("Security-support data is unchanged; no update PR needed.")
        return
    write_snapshot(args.output, snapshot)
    print(f"Updated {len(snapshot['products'])} lifecycle feeds; review the diff before merging.")


def refresh(sources, previous, fetch=None, refreshed_at=None):
    fetch = fetch or fetch_json
    products = {}
    for product, policy in sorted(sources.items()):
        if not re.fullmatch(r"[a-z0-9-]+", product):
            raise ValueError(f"Invalid product identifier: {product}")
        products[product] = normalize_product(product, policy, fetch(API + product))
    snapshot = {"schema_version": 2, "products": products}
    if previous is not None:
        validate_previous(previous, snapshot)
        if previous["products"] == products:
            return previous  # No timestamp-only commits or weekly PR churn.
    snapshot["refreshed_at"] = refreshed_at or datetime.now(timezone.utc).isoformat(timespec="seconds")
    return snapshot


def fetch_json(url):
    for attempt in range(3):
        try:
            request = Request(url, headers={"User-Agent": "nerva-lifecycle-refresh/1", "Accept": "application/json"})
            with urlopen(request, timeout=30) as response:
                if not response.headers.get_content_type() == "application/json":
                    raise ValueError(f"Expected JSON from {url}")
                payload = response.read(MAX_RESPONSE_BYTES + 1)
            if len(payload) > MAX_RESPONSE_BYTES:
                raise ValueError(f"Oversized lifecycle response: {url}")
            return json.loads(payload)
        except (HTTPError, URLError) as error:
            if isinstance(error, HTTPError) and error.code not in (429, 500, 502, 503, 504):
                raise
            if attempt == 2:
                raise
            time.sleep(2 ** attempt)
    raise RuntimeError("Unreachable retry state")


def normalize_product(product, policy, payload):
    if not str(payload.get("schema_version", "")).startswith("1."):
        raise ValueError(f"Unsupported upstream schema for {product}")
    result = payload["result"]
    if result["name"] != product or result["labels"]["eol"] != policy["eol_label"]:
        raise ValueError(f"Lifecycle identity or security-support meaning changed for {product}")
    if not isinstance(result["releases"], list) or not result["releases"]:
        raise ValueError(f"Empty release list for {product}")
    releases = {}
    for release in result["releases"]:
        name = release["name"]
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name):
            raise ValueError(f"Invalid release name in {product}")
        if name in releases:
            raise ValueError(f"Duplicate release {product}/{name}")
        end = release["eolFrom"]  # Never eoasFrom (feature support) or eoesFrom (paid extension).
        if end is not None:
            validate_date(end)
            start = release["releaseDate"]
            validate_date(start)
            if end < start:
                raise ValueError(f"Support ends before release: {product}/{name}")
        releases[name] = end
    if product in ("windows-server", "windows"):
        releases = windows_release_families(releases)
    return {
        "source": API + product,
        "vendor_url": policy["vendor_url"],
        "support": policy["eol_label"],
        "releases": releases,
    }


def validate_date(value):
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        raise ValueError(f"Expected an explicit YYYY-MM-DD security-support date, got {value!r}")
    date.fromisoformat(value)


def windows_release_families(releases):
    # A banner rarely identifies the service pack. Use the last ordinary support
    # date across the family's SPs, not the original RTM/SP0 support deadline.
    # Keep distinct R2/SAC/LTSC/edition families distinct.
    families = {}
    for name, end in releases.items():
        family = re.sub(r"-sp\d+$", "", name)
        families.setdefault(family, []).append(end)
    for family, ends in families.items():
        releases[family] = None if None in ends else max(ends)
    # Server 2003 R2 shares Server 2003's support lifecycle. See sources doc.
    if "2003" in releases:
        releases.setdefault("2003-r2", releases["2003"])
    return releases


def validate_previous(previous, snapshot):
    if previous.get("schema_version") != 2:
        raise ValueError("Unsupported previous snapshot schema")
    for product, old in previous["products"].items():
        if product not in snapshot["products"]:
            raise ValueError(f"Refresh would remove product {product}")
        new = snapshot["products"][product]["releases"]
        for release, end in old["releases"].items():
            if release not in new:
                raise ValueError(f"Upstream lost release {product}/{release}; refusing partial refresh")
            if end is not None and new[release] is None:
                raise ValueError(f"Upstream lost date {product}/{release}; review manually")


def write_snapshot(path, snapshot):
    # All feeds validate before touching the known-good snapshot. Atomic replace
    # also preserves it if a download, parser, or process fails mid-refresh.
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, delete=False) as output:
            temporary = output.name
            json.dump(snapshot, output, indent=2, sort_keys=True)
            output.write("\n")
        os.replace(temporary, path)
    finally:
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)


if __name__ == "__main__":
    main()
