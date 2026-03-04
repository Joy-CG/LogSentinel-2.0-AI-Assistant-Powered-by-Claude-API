"""
iplist.py — Persistent IP whitelist and blacklist.

Stored as JSON files alongside the app.
"""

import json
import os

WHITELIST_FILE = "whitelist.json"
BLACKLIST_FILE = "blacklist.json"


def _load(path: str) -> set:
    if os.path.exists(path):
        try:
            with open(path) as f:
                return set(json.load(f))
        except Exception:
            return set()
    return set()


def _save(path: str, data: set) -> None:
    with open(path, "w") as f:
        json.dump(sorted(data), f, indent=2)


class IPLists:
    def __init__(self):
        self._whitelist = _load(WHITELIST_FILE)
        self._blacklist = _load(BLACKLIST_FILE)

    # ── Whitelist ─────────────────────────────────────────────────────────────
    def add_white(self, ip: str) -> None:
        self._whitelist.add(ip.strip())
        self._blacklist.discard(ip.strip())
        _save(WHITELIST_FILE, self._whitelist)
        _save(BLACKLIST_FILE, self._blacklist)

    def remove_white(self, ip: str) -> None:
        self._whitelist.discard(ip.strip())
        _save(WHITELIST_FILE, self._whitelist)

    def is_whitelisted(self, ip: str) -> bool:
        return ip.strip() in self._whitelist

    # ── Blacklist ─────────────────────────────────────────────────────────────
    def add_black(self, ip: str) -> None:
        self._blacklist.add(ip.strip())
        self._whitelist.discard(ip.strip())
        _save(BLACKLIST_FILE, self._blacklist)
        _save(WHITELIST_FILE, self._whitelist)

    def remove_black(self, ip: str) -> None:
        self._blacklist.discard(ip.strip())
        _save(BLACKLIST_FILE, self._blacklist)

    def is_blacklisted(self, ip: str) -> bool:
        return ip.strip() in self._blacklist

    # ── Queries ───────────────────────────────────────────────────────────────
    def status(self, ip: str) -> str:
        """Returns 'blacklisted', 'whitelisted', or 'unknown'."""
        ip = ip.strip()
        if ip in self._blacklist:  return "blacklisted"
        if ip in self._whitelist:  return "whitelisted"
        return "unknown"

    @property
    def whitelist(self) -> list:
        return sorted(self._whitelist)

    @property
    def blacklist(self) -> list:
        return sorted(self._blacklist)
