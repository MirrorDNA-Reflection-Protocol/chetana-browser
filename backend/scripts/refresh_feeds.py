#!/usr/bin/env python3
"""
Chetana Feed Refresher — downloads fresh threat intelligence feeds.

Downloads free, no-API-key-required blocklists and saves them to
backend/data/feeds/. Skips files > 50 MB. Logs sizes and status.

Feeds refreshed:
  - URLhaus recent URLs (abuse.ch)
  - PhishTank verified phishing URLs
  - OpenPhish community feed
  - Feodo Tracker botnet C2 blocklist (abuse.ch)
  - ThreatFox IOC hostfile (abuse.ch)
  - BlocklistProject: malware, phishing, scam
  - HaGeZi Threat Intelligence Feeds DNS blocklist
  - Jarelllama Scam Blocklist (Adblock format)

All stdlib. No third-party deps.
"""
from __future__ import annotations

import gzip
import io
import json
import logging
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
FEEDS_DIR = Path(__file__).resolve().parent.parent / "data" / "feeds"
MAX_SIZE_BYTES = 50 * 1024 * 1024  # 50 MB
DOWNLOAD_TIMEOUT = 120  # seconds per feed
USER_AGENT = "ChetanaBrowser/1.0 FeedRefresh (+https://github.com/chetana-browser)"

logger = logging.getLogger("chetana.feed_refresh")

_ssl_ctx = ssl.create_default_context()

# ---------------------------------------------------------------------------
# Feed definitions: (filename, url, description)
# ---------------------------------------------------------------------------
FEEDS: list[tuple[str, str, str]] = [
    (
        "urlhaus_recent.json",
        "https://urlhaus.abuse.ch/downloads/json_recent/",
        "URLhaus recent malware URLs (abuse.ch)",
    ),
    (
        "phishtank.json",
        "http://data.phishtank.com/data/online-valid.json",
        "PhishTank verified online phishing URLs",
    ),
    (
        "openphish.txt",
        "https://openphish.com/feed.txt",
        "OpenPhish community phishing feed",
    ),
    (
        "feodo_blocklist.json",
        "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
        "Feodo Tracker botnet C2 IP blocklist (abuse.ch)",
    ),
    (
        "threatfox_hostfile.txt",
        "https://threatfox.abuse.ch/downloads/hostfile/",
        "ThreatFox IOC hostfile (abuse.ch)",
    ),
    (
        "blocklistproject_malware.txt",
        "https://raw.githubusercontent.com/blocklistproject/Lists/master/malware.txt",
        "BlocklistProject malware domains",
    ),
    (
        "blocklistproject_phishing.txt",
        "https://raw.githubusercontent.com/blocklistproject/Lists/master/phishing.txt",
        "BlocklistProject phishing domains",
    ),
    (
        "blocklistproject_scam.txt",
        "https://raw.githubusercontent.com/blocklistproject/Lists/master/scam.txt",
        "BlocklistProject scam domains",
    ),
    (
        "hagezi_tif_domains.txt",
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/tif.txt",
        "HaGeZi Threat Intelligence Feeds DNS blocklist",
    ),
    (
        "scam_blocklist_domains.txt",
        "https://raw.githubusercontent.com/jarelllama/Scam-Blocklist/main/lists/adblock/scams.txt",
        "Jarelllama Scam Blocklist (Adblock format)",
    ),
]


# ---------------------------------------------------------------------------
# Download helper
# ---------------------------------------------------------------------------
def download_feed(url: str, filename: str, description: str) -> dict:
    """Download a single feed. Returns a status dict."""
    dest = FEEDS_DIR / filename
    result = {
        "filename": filename,
        "description": description,
        "url": url,
        "status": "unknown",
        "size_bytes": 0,
        "size_human": "",
        "elapsed_s": 0.0,
    }

    start = time.monotonic()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})

        with urllib.request.urlopen(
            req, context=_ssl_ctx, timeout=DOWNLOAD_TIMEOUT
        ) as resp:
            # Check Content-Length if available
            content_length = resp.headers.get("Content-Length")
            if content_length and int(content_length) > MAX_SIZE_BYTES:
                result["status"] = "skipped_too_large"
                result["size_human"] = _human_size(int(content_length))
                logger.warning(
                    "SKIP %s — Content-Length %s exceeds %s limit",
                    filename,
                    _human_size(int(content_length)),
                    _human_size(MAX_SIZE_BYTES),
                )
                return result

            # Stream download with size check
            chunks = []
            total = 0
            while True:
                chunk = resp.read(1024 * 64)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_SIZE_BYTES:
                    result["status"] = "skipped_too_large"
                    result["size_human"] = f">{_human_size(MAX_SIZE_BYTES)}"
                    logger.warning(
                        "SKIP %s — download exceeded %s mid-stream, aborting",
                        filename,
                        _human_size(MAX_SIZE_BYTES),
                    )
                    return result
                chunks.append(chunk)

            body = b"".join(chunks)

            # Handle gzip encoding
            encoding = resp.headers.get("Content-Encoding", "")
            if encoding == "gzip":
                body = gzip.decompress(body)

        # Write atomically via temp file
        tmp = dest.with_suffix(".tmp")
        tmp.write_bytes(body)
        tmp.rename(dest)

        elapsed = time.monotonic() - start
        result["status"] = "ok"
        result["size_bytes"] = len(body)
        result["size_human"] = _human_size(len(body))
        result["elapsed_s"] = round(elapsed, 2)

        logger.info(
            "OK   %-40s  %8s  %.1fs",
            filename,
            result["size_human"],
            elapsed,
        )

    except urllib.error.HTTPError as exc:
        elapsed = time.monotonic() - start
        result["status"] = f"http_error_{exc.code}"
        result["elapsed_s"] = round(elapsed, 2)
        logger.error("FAIL %s — HTTP %d: %s", filename, exc.code, exc.reason)

    except Exception as exc:
        elapsed = time.monotonic() - start
        result["status"] = f"error: {exc}"
        result["elapsed_s"] = round(elapsed, 2)
        logger.error("FAIL %s — %s", filename, exc)

    return result


def _human_size(nbytes: int) -> str:
    """Format byte count as human-readable string."""
    for unit in ("B", "KB", "MB", "GB"):
        if abs(nbytes) < 1024:
            return f"{nbytes:.1f} {unit}"
        nbytes /= 1024  # type: ignore[assignment]
    return f"{nbytes:.1f} TB"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def refresh_all() -> list[dict]:
    """Download all feeds, return list of status dicts."""
    FEEDS_DIR.mkdir(parents=True, exist_ok=True)

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    logger.info("=" * 60)
    logger.info("Chetana feed refresh started at %s", now)
    logger.info("Feeds directory: %s", FEEDS_DIR)
    logger.info("Max file size: %s", _human_size(MAX_SIZE_BYTES))
    logger.info("=" * 60)

    results = []
    for filename, url, description in FEEDS:
        r = download_feed(url, filename, description)
        results.append(r)
        # Be polite — small delay between requests
        time.sleep(0.5)

    # Summary
    ok = sum(1 for r in results if r["status"] == "ok")
    skipped = sum(1 for r in results if r["status"].startswith("skipped"))
    failed = sum(1 for r in results if r["status"] not in ("ok",) and not r["status"].startswith("skipped"))
    total_bytes = sum(r["size_bytes"] for r in results)

    logger.info("-" * 60)
    logger.info(
        "Done: %d ok, %d skipped, %d failed | Total downloaded: %s",
        ok,
        skipped,
        failed,
        _human_size(total_bytes),
    )
    logger.info("-" * 60)

    # Write a manifest
    manifest = {
        "last_refresh": now,
        "results": results,
        "summary": {
            "ok": ok,
            "skipped": skipped,
            "failed": failed,
            "total_bytes": total_bytes,
        },
    }
    manifest_path = FEEDS_DIR / "_refresh_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    logger.info("Manifest written to %s", manifest_path)

    return results


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(name)s  %(levelname)s  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    results = refresh_all()

    # Exit with non-zero if any feeds failed
    failed = sum(
        1
        for r in results
        if r["status"] not in ("ok",) and not r["status"].startswith("skipped")
    )
    sys.exit(1 if failed else 0)
