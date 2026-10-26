"""Offline feed validation, privacy, freshness, caching, concurrency, and alerts."""

import io
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from urllib.error import HTTPError

from network_packet_sniffer.reputation import (
    DAY,
    FEED_URLS,
    HOUR,
    MAX_FEED_BYTES,
    TTL,
    DropProvider,
    FeedSnapshot,
    NoRedirects,
    ReputationService,
    atomic_json,
    cache_lock,
)


def fixture_feeds(now=None, ipv4=None, ipv6=None):
    now = int(time.time() if now is None else now)
    feeds = {}
    for version, ranges in (
        (4, ["8.8.8.0/24"] if ipv4 is None else ipv4),
        (6, ["2001:4860::/32"] if ipv6 is None else ipv6),
    ):
        rows = [{"cidr": cidr, "sblid": f"SBL{number + 1}"} for number, cidr in enumerate(ranges)]
        rows.append(
            {
                "type": "metadata",
                "timestamp": now,
                "records": len(ranges),
                "copyright": "(c) fixture data, not a real-world listing",
            }
        )
        feeds[str(version)] = "\n".join(json.dumps(row) for row in rows)
    return feeds


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.now = time.time()
        self.snapshot = FeedSnapshot(self.now, fixture_feeds(self.now))

    def test_ipv4_ipv6_cidr_boundaries_and_unlisted_are_precise(self):
        for address in (
            "8.8.8.0",
            "8.8.8.255",
            "2001:4860::",
            "2001:4860:ffff:ffff:ffff:ffff:ffff:ffff",
        ):
            with self.subTest(address=address):
                self.assertEqual(self.snapshot.lookup(address, self.now).status, "listed")
        for address in ("8.8.7.255", "8.8.9.0", "2001:4861::", "1.1.1.1"):
            with self.subTest(address=address):
                result = self.snapshot.lookup(address, self.now)
                self.assertEqual(result.status, "not listed")
                self.assertNotIn("safe", result.status)

    def test_most_specific_evidence_wins(self):
        snapshot = FeedSnapshot(self.now, fixture_feeds(ipv4=["8.8.8.0/24", "8.8.8.8/32"]))
        self.assertEqual(snapshot.lookup("8.8.8.8", self.now).evidence, "SBL2")

    def test_real_feed_can_attach_multiple_evidence_records_to_one_cidr(self):
        snapshot = FeedSnapshot(self.now, fixture_feeds(ipv4=["8.8.8.0/24", "8.8.8.0/24"]))
        self.assertEqual(snapshot.lookup("8.8.8.8", self.now).evidence, "SBL1, SBL2")
        self.assertEqual(snapshot.count, 2)  # One v4 network and one v6 network.

    def test_expiry_uses_source_time_and_is_family_specific(self):
        feeds = fixture_feeds(self.now)
        feeds["4"] = fixture_feeds(self.now - TTL - 1)["4"]
        snapshot = FeedSnapshot(self.now, feeds)
        stale = snapshot.lookup("8.8.8.8", self.now)
        self.assertEqual(stale.status, "stale")
        self.assertEqual(stale.cidr, "8.8.8.0/24")
        self.assertIn("STALE", stale.alert())
        self.assertEqual(snapshot.lookup("2001:4860::1", self.now).status, "listed")
        self.assertEqual(snapshot.lookup("1.1.1.1", self.now).status, "stale")

    def test_private_reserved_local_and_multicast_addresses_are_excluded(self):
        for address in (
            "127.0.0.1",
            "10.0.0.1",
            "192.0.2.1",
            "169.254.1.1",
            "224.0.0.1",
            "::1",
            "fe80::1%13",
            "2001:db8::1",
            "ff02::1",
        ):
            with self.subTest(address=address):
                self.assertEqual(self.snapshot.lookup(address, self.now).status, "excluded")

    def test_invalid_schema_ranges_metadata_and_duplicates_are_rejected(self):
        samples = [
            {"4": "[]", "6": self.snapshot.feeds["6"]},
            fixture_feeds(ipv4=["8.8.8.8/24"]),
            fixture_feeds(ipv4=["2001:4860::/32"]),
            fixture_feeds(ipv4=["0.0.0.0/0"]),
            {"4": '{"cidr":"8.8.8.0/24","sblid":"SBL1"}', "6": self.snapshot.feeds["6"]},
            {
                "4": self.snapshot.feeds["4"].replace('"records": 1', '"records": 9'),
                "6": self.snapshot.feeds["6"],
            },
            {
                "4": self.snapshot.feeds["4"].replace('"SBL1"', '"forged id"'),
                "6": self.snapshot.feeds["6"],
            },
            {"4": self.snapshot.feeds["4"] + "\n{}", "6": self.snapshot.feeds["6"]},
        ]
        for feeds in samples:
            with self.subTest(feeds=feeds), self.assertRaises(ValueError):
                FeedSnapshot(self.now, feeds)

    def test_invalid_or_future_cache_times_and_oversized_feeds_are_rejected(self):
        for value in (True, float("nan"), -1, self.now + DAY, 10**1000):
            with self.subTest(value=value), self.assertRaises(ValueError):
                FeedSnapshot(value, self.snapshot.feeds)
        with self.assertRaisesRegex(ValueError, "oversized"):
            FeedSnapshot(self.now, {"4": "x" * (MAX_FEED_BYTES + 1), "6": ""})


class Response(io.BytesIO):
    status = 200

    def __init__(self, body, url, declared=None):
        super().__init__(body)
        self.url = url
        self.headers = {} if declared is None else {"Content-Length": declared}

    def geturl(self):
        return self.url


class ProviderTests(unittest.TestCase):
    def test_only_fixed_https_bulk_urls_are_requested_with_timeouts(self):
        feeds = fixture_feeds()
        opener = Mock()
        opener.open.side_effect = [Response(feeds[str(v)].encode(), FEED_URLS[v]) for v in (4, 6)]
        result = DropProvider(opener).fetch(threading.Event())
        self.assertEqual(result, feeds)
        self.assertEqual(
            [call.args[0].full_url for call in opener.open.call_args_list], list(FEED_URLS.values())
        )
        self.assertTrue(all(call.kwargs["timeout"] == 8 for call in opener.open.call_args_list))

    def test_redirects_and_downgrades_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "redirect"):
            NoRedirects().redirect_request(None, None, 302, "", {}, "http://untrusted.invalid")
        opener = Mock()
        opener.open.return_value = Response(b"{}", "http://www.spamhaus.org/drop/drop_v4.json")
        with self.assertRaisesRegex(ValueError, "Unexpected"):
            DropProvider(opener).fetch(threading.Event())

    def test_response_limits_and_truncation_are_enforced(self):
        for body, length in (
            (b"", str(MAX_FEED_BYTES + 1)),
            (b"{}", "99"),
            (b"x" * (MAX_FEED_BYTES + 1), None),
        ):
            with self.subTest(length=length):
                opener = Mock()
                opener.open.return_value = Response(body, FEED_URLS[4], length)
                with self.assertRaises(ValueError):
                    DropProvider(opener).fetch(threading.Event())

    def test_cancelled_refresh_makes_no_request(self):
        cancel, opener = threading.Event(), Mock()
        cancel.set()
        with self.assertRaises(InterruptedError):
            DropProvider(opener).fetch(cancel)
        opener.open.assert_not_called()


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.now = time.time()
        self.provider = Mock()
        self.provider.fetch.return_value = fixture_feeds(self.now)
        self.service = ReputationService(self.directory, self.provider, lambda: self.now)
        self.addCleanup(self.stop)

    def stop(self):
        self.service.close()
        if self.service.thread:
            self.service.thread.join(timeout=3)

    def refresh(self, manual=True):
        self.assertTrue(self.service.refresh(manual=manual))
        self.service.thread.join(timeout=3)
        self.assertFalse(self.service.running)

    def test_round_trip_cache_retains_metadata_and_enforces_restart_cooldown(self):
        self.refresh()
        data = json.loads((self.directory / "reputation.json").read_text(encoding="utf-8"))
        self.assertIn("copyright", data["feeds"]["4"])
        other_provider = Mock()
        other = ReputationService(self.directory, other_provider, lambda: self.now)
        other._refresh(True)
        self.assertEqual(other.lookup("8.8.8.8").status, "listed")
        other_provider.fetch.assert_not_called()
        self.assertGreater(other.next_allowed, self.now)

    def test_malformed_replacement_keeps_previous_cache_and_snapshot(self):
        self.refresh()
        previous = (self.directory / "reputation.json").read_bytes()
        snapshot = self.service.snapshot
        self.now += HOUR + 1
        self.provider.fetch.return_value = {"4": fixture_feeds()["4"], "6": "malformed"}
        self.refresh()
        self.assertEqual((self.directory / "reputation.json").read_bytes(), previous)
        self.assertIs(self.service.snapshot, snapshot)
        self.assertIn("failed", self.service.last_error)
        self.assertEqual(self.service.lookup("8.8.8.8").status, "listed")

    def test_offline_failure_is_unknown_not_safe_and_is_rate_limited(self):
        self.provider.fetch.side_effect = TimeoutError("offline")
        self.refresh()
        self.assertEqual(self.service.lookup("8.8.8.8").status, "lookup failed")
        self.assertEqual(self.service.lookup("127.0.0.1").status, "excluded")
        self.assertFalse(self.service.refresh(manual=True))
        self.assertEqual(self.provider.fetch.call_count, 1)
        self.assertIn("offline", self.service.summary())

    def test_429_retry_after_survives_restart(self):
        self.provider.fetch.side_effect = HTTPError(
            FEED_URLS[4], 429, "Rate limited", {"Retry-After": "7200"}, None
        )
        self.refresh()
        self.assertEqual(self.service.next_allowed, self.now + 7200)
        other = ReputationService(self.directory, Mock(), lambda: self.now + HOUR + 1)
        other._refresh(True)
        other.provider.fetch.assert_not_called()

    def test_429_http_date_is_respected(self):
        from email.utils import formatdate

        retry = formatdate(self.now + 3 * DAY, usegmt=True)
        self.provider.fetch.side_effect = HTTPError(
            FEED_URLS[4], 429, "Rate limited", {"Retry-After": retry}, None
        )
        self.refresh()
        self.assertGreaterEqual(self.service.next_allowed, self.now + 3 * DAY - 1)

    def test_automatic_refresh_uses_daily_schedule(self):
        self.refresh()
        self.now += HOUR + 1
        self.assertFalse(self.service.refresh())
        self.provider.fetch.assert_called_once()

    def test_corrupt_cache_is_replaced_only_by_fully_validated_feed(self):
        (self.directory / "reputation.json").write_text("[]")
        self.refresh()
        self.assertEqual(self.service.lookup("8.8.8.8").status, "listed")

    def test_overlapping_jobs_are_refused_and_close_cancels_worker(self):
        entered = threading.Event()

        def fetch(cancel):
            entered.set()
            cancel.wait(2)
            raise InterruptedError("cancelled")

        self.provider.fetch.side_effect = fetch
        self.assertTrue(self.service.refresh())
        self.assertTrue(entered.wait(1))
        self.assertFalse(self.service.refresh(manual=True))
        self.service.close()
        self.service.thread.join(timeout=2)
        self.assertFalse(self.service.running)
        self.assertFalse((self.directory / "reputation.json").exists())

    def test_disabled_matching_is_unknown_and_never_requests_feed(self):
        self.service.set_enabled(False)
        self.assertFalse(self.service.refresh())
        self.assertEqual(self.service.lookup("8.8.8.8").status, "unknown")
        self.provider.fetch.assert_not_called()

    def test_cross_instance_lock_prevents_fetch_and_atomic_failure_preserves_file(self):
        with cache_lock(self.directory / "reputation.lock"):
            self.service._refresh(True)
        self.provider.fetch.assert_not_called()
        self.assertIn("Another window", self.service.last_error)
        target = self.directory / "data.json"
        atomic_json(target, {"original": True})
        with patch(
            "network_packet_sniffer.reputation.os.replace", side_effect=OSError("disk error")
        ):
            with self.assertRaises(OSError):
                atomic_json(target, {"replacement": True})
        self.assertEqual(json.loads(target.read_text()), {"original": True})
        self.assertFalse(list(self.directory.glob("*.tmp")))


if __name__ == "__main__":
    unittest.main()
