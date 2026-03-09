"""
Chetana secrets loader — Keychain-first secret resolution.

Resolution order:
  1. macOS Keychain (account=mirrordna, then account=any)
  2. Environment variables
  3. ~/.mirrordna/secrets.env (legacy flat file)

Caches resolved values in memory for the process lifetime.
All stdlib. No third-party deps.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Dict, Optional

_SECRETS_ENV = Path.home() / ".mirrordna" / "secrets.env"
_KEYCHAIN_ACCOUNT = "mirrordna"

# In-memory cache: name -> resolved value (or "" for confirmed-missing)
_cache: Dict[str, str] = {}

# Alias map: maps Chetana-internal names to alternative Keychain/env names.
# Checked in order if the primary name yields nothing.
_ALIASES: Dict[str, list[str]] = {
    "GOOGLE_SAFE_BROWSING_KEY": ["GEMINI_API_KEY", "GEMINI_KEY"],
    "GEMINI_KEY": ["GEMINI_API_KEY"],
    "VIRUSTOTAL_API_KEY": ["VIRUSTOTAL_KEY"],
    "IPQUALITYSCORE_KEY": ["IPQUALITYSCORE_API_KEY"],
}

# ---------------------------------------------------------------------------
# Keychain helpers
# ---------------------------------------------------------------------------

def _keychain_get(service: str, account: Optional[str] = None) -> str:
    """Retrieve a password from macOS Keychain. Returns '' on failure."""
    cmd = ["security", "find-generic-password", "-s", service, "-w"]
    if account:
        cmd = ["security", "find-generic-password", "-a", account, "-s", service, "-w"]
    try:
        result = subprocess.run(
            cmd, check=False, capture_output=True, text=True, timeout=5,
        )
    except Exception:
        return ""
    if result.returncode != 0:
        return ""
    return result.stdout.strip()


def _keychain_value(name: str) -> str:
    """Try Keychain with mirrordna account first, then without account filter."""
    value = _keychain_get(name, account=_KEYCHAIN_ACCOUNT)
    if value:
        return value
    value = _keychain_get(name)
    return value


# ---------------------------------------------------------------------------
# secrets.env parser
# ---------------------------------------------------------------------------

_env_file_cache: Optional[Dict[str, str]] = None


def _parse_env_file() -> Dict[str, str]:
    global _env_file_cache
    if _env_file_cache is not None:
        return _env_file_cache
    values: Dict[str, str] = {}
    if not _SECRETS_ENV.exists():
        _env_file_cache = values
        return values
    for raw_line in _SECRETS_ENV.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        key, _, val = line.partition("=")
        val = val.strip().strip('"').strip("'")
        if val:
            values[key.strip()] = val
    _env_file_cache = values
    return values


# ---------------------------------------------------------------------------
# Core resolver
# ---------------------------------------------------------------------------

def _resolve(name: str) -> str:
    """Resolve a single name through the cascade (no aliasing)."""
    # 1. macOS Keychain
    value = _keychain_value(name)
    if value:
        return value
    # 2. Environment variable
    value = os.environ.get(name, "").strip()
    if value:
        return value
    # 3. secrets.env file
    return _parse_env_file().get(name, "")


def get_secret(name: str) -> str:
    """Resolve a secret by name. Tries aliases if primary name fails.

    Results are cached in memory for the process lifetime.
    Returns '' if not found anywhere.
    """
    if name in _cache:
        return _cache[name]

    # Try the primary name first
    value = _resolve(name)
    if value:
        _cache[name] = value
        return value

    # Try aliases
    for alias in _ALIASES.get(name, []):
        value = _resolve(alias)
        if value:
            _cache[name] = value
            return value

    _cache[name] = ""
    return ""


# ---------------------------------------------------------------------------
# Bulk helpers
# ---------------------------------------------------------------------------

def load_named_secrets(names) -> Dict[str, str]:
    """Resolve multiple secret names, returning only those found."""
    return {name: value for name in names if (value := get_secret(name))}


def store_keychain(name: str, value: str, account: str = _KEYCHAIN_ACCOUNT) -> bool:
    """Store a secret in macOS Keychain. Returns True on success."""
    # Delete existing entry first (ignore errors if it doesn't exist)
    subprocess.run(
        ["security", "delete-generic-password", "-a", account, "-s", name],
        check=False, capture_output=True,
    )
    try:
        result = subprocess.run(
            ["security", "add-generic-password", "-a", account, "-s", name, "-w", value],
            check=False, capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            # Invalidate cache
            _cache.pop(name, None)
            return True
    except Exception:
        pass
    return False


# ---------------------------------------------------------------------------
# CLI — test resolution
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys
    names = sys.argv[1:] or [
        "VIRUSTOTAL_API_KEY",
        "GOOGLE_SAFE_BROWSING_KEY",
        "GEMINI_KEY",
        "IPQUALITYSCORE_KEY",
    ]
    for n in names:
        v = get_secret(n)
        if v:
            print(f"  {n}: {v[:8]}...{'[keychain/env/file]'}")
        else:
            print(f"  {n}: NOT FOUND")
