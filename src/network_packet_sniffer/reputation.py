"""Attributed DROP range matching. Only fixed HTTPS feeds leave this machine."""

from __future__ import annotations

import json
import math
import os
import re
import ssl
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from ipaddress import ip_address, ip_network
from pathlib import Path
from threading import Event, Thread
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

from .paths import data_directory

SOURCE = "The Spamhaus Project · DROP"
CATEGORY = "Hijacked or leased cybercrime networks"
FEED_URLS = {version: f"https://www.spamhaus.org/drop/drop_v{version}.json" for version in (4, 6)}
HOUR, DAY, TTL = 3600, 86400, 93600
MAX_FEED_BYTES, MAX_CACHE_BYTES, MAX_ENTRIES = 2_000_000, 4_100_000, 20_000


def utc(value):
    return datetime.fromtimestamp(value, UTC).strftime("%Y-%m-%d %H:%M UTC")


def valid_time(value, now):
    if type(value) not in (int, float) or not 0 < value <= now + 300 or not math.isfinite(value):
        raise ValueError("Invalid feed/cache timestamp.")
    return value


@dataclass(frozen=True)
class ReputationResult:
    address: str
    status: str
    cidr: str = ""
    evidence: str = ""
    source: str = SOURCE
    category: str = CATEGORY
    fetched_at: float = 0
    expires_at: float = 0

    def alert(self):
        return (
            f"{self.address} · {self.status.upper()} · {self.source} · {self.cidr} · "
            f"{self.evidence} · {self.category} · fetched {utc(self.fetched_at)} · "
            f"expires {utc(self.expires_at)}"
        )


@dataclass(frozen=True)
class FeedSnapshot:
    fetched_at: float
    feeds: dict
    metadata: dict = field(init=False, repr=False)
    index: dict = field(init=False, repr=False)
    count: int = field(init=False)
    prefixes: tuple = field(init=False, repr=False)

    def __post_init__(self):
        now = time.time()
        valid_time(self.fetched_at, now)
        if not isinstance(self.feeds, dict) or set(self.feeds) != {"4", "6"}:
            raise ValueError("Both IPv4 and IPv6 feeds are required.")
        metadata, index, count = {}, {}, 0
        for version in (4, 6):
            raw = self.feeds[str(version)]
            if not isinstance(raw, str) or len(raw.encode("utf-8")) > MAX_FEED_BYTES:
                raise ValueError("Invalid or oversized reputation feed.")
            records, seen_metadata = 0, False
            for line in raw.splitlines():
                if not line.strip():
                    continue
                if len(line) > 4096:
                    raise ValueError("Oversized feed row.")
                item = json.loads(line)
                if not isinstance(item, dict) or seen_metadata:
                    raise ValueError("Invalid feed schema or rows after metadata.")
                if item.get("type") == "metadata":
                    valid_time(item.get("timestamp"), now)
                    if (
                        not isinstance(item.get("copyright"), str)
                        or not 1 <= len(item["copyright"]) <= 512
                    ):
                        raise ValueError("Feed attribution is missing or invalid.")
                    if type(item.get("records")) is not int or item["records"] != records:
                        raise ValueError("Feed record count does not match metadata.")
                    metadata[version], seen_metadata = item, True
                    continue
                network = ip_network(item.get("cidr", ""), strict=True)
                evidence = item.get("sblid", "")
                if (
                    network.version != version
                    or network.prefixlen == 0
                    or not isinstance(evidence, str)
                    or not re.fullmatch(r"SBL\d{1,12}", evidence)
                ):
                    raise ValueError("Invalid feed range or evidence identifier.")
                bucket = index.setdefault((version, network.prefixlen), {})
                number = int(network.network_address)
                previous = bucket.get(number, (str(network), ()))[1]
                evidence_ids = tuple(sorted(set((*previous, evidence))))
                if len(evidence_ids) > 32:
                    raise ValueError("Too many evidence records for one range.")
                bucket[number] = (str(network), evidence_ids)
                records, count = records + 1, count + 1
                if count > MAX_ENTRIES:
                    raise ValueError("Reputation entry limit exceeded.")
            if not seen_metadata:
                raise ValueError("Feed metadata is missing.")
        object.__setattr__(self, "metadata", metadata)
        object.__setattr__(self, "index", index)
        object.__setattr__(self, "count", sum(len(bucket) for bucket in index.values()))
        object.__setattr__(self, "prefixes", tuple(sorted(index, reverse=True)))

    def expiry(self, version):
        return min(self.fetched_at, self.metadata[version]["timestamp"]) + TTL

    def lookup(self, address, now):
        ip = ip_address(address)
        if not ip.is_global or ip.is_multicast or ip.is_reserved:
            return ReputationResult(str(ip), "excluded")
        version, width, number = ip.version, ip.max_prefixlen, int(ip)
        stale = now >= self.expiry(version)
        for family, prefix in self.prefixes:
            if family != version:
                continue
            bucket = self.index[(family, prefix)]
            key = (number >> (width - prefix)) << (width - prefix)
            if key in bucket:
                cidr, evidence_ids = bucket[key]
                evidence = ", ".join(evidence_ids)
                return ReputationResult(
                    str(ip),
                    "stale" if stale else "listed",
                    cidr,
                    evidence,
                    fetched_at=self.fetched_at,
                    expires_at=self.expiry(version),
                )
        return ReputationResult(
            str(ip),
            "stale" if stale else "not listed",
            fetched_at=self.fetched_at,
            expires_at=self.expiry(version),
        )

    def payload(self):
        return {"version": 1, "fetched_at": self.fetched_at, "feeds": self.feeds}


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        raise ValueError("Unexpected redirect from the reputation provider.")


class DropProvider:
    def __init__(self, opener=None):
        self.opener = opener or build_opener(
            HTTPSHandler(context=ssl.create_default_context()), NoRedirects()
        )

    def fetch(self, cancel):
        feeds, deadline = {}, time.monotonic() + 25
        for version, url in FEED_URLS.items():
            if cancel.is_set():
                raise InterruptedError("Refresh cancelled.")
            request = Request(
                url, headers={"User-Agent": "NetworkPacketSniffer/0.4 desktop diagnostic"}
            )
            with self.opener.open(request, timeout=8) as response:
                if response.status != 200 or response.geturl() != url:
                    raise ValueError("Unexpected reputation response.")
                declared = response.headers.get("Content-Length")
                if declared is not None and (
                    not declared.isdecimal() or int(declared) > MAX_FEED_BYTES
                ):
                    raise ValueError("Invalid or oversized feed response.")
                raw = bytearray()
                while True:
                    if cancel.is_set() or time.monotonic() >= deadline:
                        raise InterruptedError("Refresh cancelled or exceeded its time limit.")
                    part = response.read(min(16384, MAX_FEED_BYTES + 1 - len(raw)))
                    if not part:
                        break
                    raw.extend(part)
                    if len(raw) > MAX_FEED_BYTES:
                        raise ValueError("Reputation response exceeded its size limit.")
                if declared is not None and len(raw) != int(declared):
                    raise ValueError("Incomplete reputation response.")
                feeds[str(version)] = raw.decode("utf-8")
        return feeds


@contextmanager
def cache_lock(path):
    """A process-held lock releases automatically after a crash."""
    with path.open("a+b") as handle:
        if path.stat().st_size == 0:
            handle.write(b"0")
            handle.flush()
        handle.seek(0)
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            raise RuntimeError("Another window is updating the reputation cache.") from error
        yield


def atomic_json(path, data):
    raw = json.dumps(data, ensure_ascii=False).encode("utf-8")
    if len(raw) > MAX_CACHE_BYTES:
        raise ValueError("Reputation cache size limit exceeded.")
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, suffix=".tmp", delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def read_json(path, limit):
    with path.open("rb") as handle:
        raw = handle.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("Reputation file size limit exceeded.")
    return json.loads(raw)


class ReputationService:
    """One bounded refresh worker; capture sees complete immutable snapshots only."""

    def __init__(self, directory=None, provider=None, clock=time.time):
        self.directory = Path(directory) if directory else data_directory() / "cache"
        self.provider = provider or DropProvider()
        self.clock = clock
        self.snapshot = None
        self.last_error = ""
        self.next_allowed = 0
        self.auto_due = 0
        self.enabled = True
        self.closed = False
        self.thread = None
        self.cancel = Event()

    @property
    def running(self):
        return self.thread is not None and self.thread.is_alive()

    def set_enabled(self, enabled):
        self.enabled = enabled
        if enabled:
            self.refresh()
        else:
            self.cancel.set()

    def refresh(self, manual=False):
        now = self.clock()
        if self.closed or self.running or not self.enabled or now < self.next_allowed:
            return False
        if not manual and now < self.auto_due:
            return False
        self.cancel.clear()
        self.auto_due = now + HOUR
        self.thread = Thread(
            target=self._refresh, args=(manual,), name="reputation-refresh", daemon=False
        )
        self.thread.start()
        return True

    def _refresh(self, manual):
        now = self.clock()
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
            with cache_lock(self.directory / "reputation.lock"):
                cache = self.directory / "reputation.json"
                if self.snapshot is None and cache.exists():
                    try:
                        data = read_json(cache, MAX_CACHE_BYTES)
                        if not isinstance(data, dict) or data.get("version") != 1:
                            raise ValueError("Unsupported cache schema.")
                        self.snapshot = FeedSnapshot(data["fetched_at"], data["feeds"])
                        self.last_error = ""
                    except (OSError, ValueError, KeyError, TypeError) as error:
                        self.last_error = f"Cache rejected: {error}"
                state = self.directory / "refresh.json"
                if state.exists():
                    timing = read_json(state, 1024)
                    if not isinstance(timing, dict):
                        raise ValueError("Invalid refresh cooldown schema.")
                    attempted = valid_time(timing["attempted_at"], now)
                    delay = timing.get("retry_after", HOUR)
                    if type(delay) not in (int, float) or not math.isfinite(delay) or delay < HOUR:
                        raise ValueError("Invalid refresh cooldown.")
                    self.next_allowed = attempted + delay
                if self.snapshot and not manual:
                    self.auto_due = self.snapshot.fetched_at + DAY
                    if now < self.auto_due:
                        return
                if now < self.next_allowed or self.cancel.is_set():
                    return
                self.next_allowed = now + HOUR
                atomic_json(state, {"attempted_at": now, "retry_after": HOUR})
                try:
                    feeds = self.provider.fetch(self.cancel)
                except HTTPError as error:
                    if error.code == 429:
                        retry = (error.headers or {}).get("Retry-After", "")
                        try:
                            requested = (
                                int(retry)
                                if retry.isdecimal()
                                else parsedate_to_datetime(retry).timestamp() - now
                            )
                            delay = max(HOUR, math.ceil(requested))
                        except ValueError, TypeError, OverflowError:
                            delay = DAY
                        self.next_allowed = now + delay
                        atomic_json(state, {"attempted_at": now, "retry_after": delay})
                    raise
                if self.cancel.is_set():
                    return
                replacement = FeedSnapshot(self.clock(), feeds)
                atomic_json(cache, replacement.payload())
                self.snapshot, self.last_error = replacement, ""
                self.auto_due = replacement.fetched_at + DAY
        except (OSError, ValueError, KeyError, TypeError, RuntimeError, OverflowError) as error:
            if not self.cancel.is_set():
                self.last_error = f"Refresh failed: {str(error)[:180]}"
                self.auto_due = (
                    self.clock() + 5
                    if isinstance(error, RuntimeError)
                    else max(self.clock() + HOUR, self.next_allowed)
                )

    def lookup(self, address):
        ip = ip_address(address)
        if not ip.is_global or ip.is_multicast or ip.is_reserved:
            return ReputationResult(str(ip), "excluded")
        snapshot = self.snapshot
        if not self.enabled or snapshot is None:
            status = "lookup failed" if self.enabled and self.last_error else "unknown"
            return ReputationResult(str(ip), status)
        return snapshot.lookup(str(ip), self.clock())

    def summary(self):
        if not self.enabled:
            return "Reputation disabled · no address uploads"
        snapshot = self.snapshot
        if snapshot is None:
            return self.last_error or "Loading reputation data…"
        now = self.clock()
        states = " / ".join(
            f"IPv{v} {'stale' if now >= snapshot.expiry(v) else 'fresh'}" for v in (4, 6)
        )
        copyrights = " · ".join(dict.fromkeys(m["copyright"] for m in snapshot.metadata.values()))
        action = "Updating…" if self.running else self.last_error
        return (
            f"{SOURCE} · {snapshot.count:,} ranges · {states} · fetched {utc(snapshot.fetched_at)}"
            f" · {copyrights}" + (f" · {action}" if action else "")
        )

    def close(self):
        self.closed = True
        self.cancel.set()
