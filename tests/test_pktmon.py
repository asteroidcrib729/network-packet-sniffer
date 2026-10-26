"""Native backend regressions. All commands, elevation, and capture are mocked."""

import io
import threading
import unittest
from datetime import datetime
from ipaddress import ip_address
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from network_packet_sniffer.pktmon import PktmonBackend, PktmonParser, TerminalLines
from network_packet_sniffer.sniffer import Interface


def header(component=37, edge=1, kind="Ethernet", size=74, clock="12:34:56.123456700"):
    return (
        f"{clock} PktGroupId 562949953437938, PktNumber 1, Appearance 2, "
        f"Direction Rx , Type {kind} , Component {component}, Edge {edge}, "
        f"Filter 0, OriginalSize {size}, LoggedSize 74"
    )


TCP_LINE = (
    "02-00-00-00-00-01 > 02-00-00-00-00-02, ethertype IPv4 (0x0800), length 74: "
    "192.0.2.1.1234 > 198.51.100.2.443: Flags [P.], seq 1:21, ack 1, win 512, length 20"
)
UDP6_LINE = (
    "02-00-00-00-00-01 > 02-00-00-00-00-02, ethertype IPv6 (0x86dd), length 74: "
    "2001:db8::1.53 > 2001:db8::2.4321: UDP, length 20"
)


class ParserTests(unittest.TestCase):
    def parse(self, line, **kwargs):
        parser = PktmonParser(37)
        self.assertIsNone(parser.feed(header(**kwargs)))
        return parser.feed(line)

    def test_live_ipv4_tcp_summary(self):
        record = self.parse(TCP_LINE)
        self.assertEqual((record.version, record.protocol, record.size), (4, "TCP", 74))
        self.assertEqual((record.source, record.source_port), ("192.0.2.1", 1234))
        self.assertEqual((record.destination, record.destination_port), ("198.51.100.2", 443))
        self.assertEqual(datetime.fromisoformat(record.time).utcoffset().total_seconds(), 0)

    def test_live_ipv6_udp_summary(self):
        record = self.parse(UDP6_LINE)
        self.assertEqual((record.version, record.protocol), (6, "UDP"))
        self.assertEqual((record.source, record.source_port), ("2001:db8::1", 53))
        self.assertIn("[2001:db8::1]:53", record.line())

    def test_ipv6_icmp_without_ports(self):
        record = self.parse("IP6 fe80::1 > ff02::1: ICMP6, echo request, seq 1, length 40")
        self.assertEqual(record.protocol, "ICMPv6")
        self.assertEqual(record.destination, "ff02::1")
        self.assertIsNone(record.source_port)

    def test_scope_ids_and_ipv4_embedded_ipv6(self):
        self.assertEqual(PktmonParser.endpoint("fe80::1%13.53"), ("fe80::1%13", 53))
        canonical = str(ip_address("::ffff:192.0.2.1"))
        self.assertEqual(PktmonParser.endpoint("::ffff:192.0.2.1"), (canonical, None))
        self.assertEqual(PktmonParser.endpoint("::ffff:192.0.2.1.53"), (canonical, 53))

    def test_packet_emitted_immediately_before_next_header(self):
        parser = PktmonParser(37)
        parser.feed(header())
        self.assertIsNotNone(parser.feed(TCP_LINE))
        self.assertIsNone(parser.feed(TCP_LINE))  # One summary per snapshot.

    def test_native_filtered_stream_accepts_hyperv_companion_component(self):
        parser = PktmonParser()
        parser.feed(header(component=2))
        record = parser.feed(UDP6_LINE)
        self.assertEqual(record.version, 6)
        self.assertEqual(record.protocol, "UDP")

    def test_drop_diagnostic_does_not_duplicate_normal_snapshot(self):
        parser = PktmonParser()
        parser.feed(header(component=2))
        self.assertIsNotNone(parser.feed(UDP6_LINE))
        drop = (
            "12:34:56.123456700 Drop: PktGroupId 1, PktNumber 1, Appearance 2, "
            "Direction Ingress , Type Ethernet , Component 117, Filter 0, "
            "DropReason Unauthorized MAC , DropLocation 0xE0002019, OriginalSize 86, LoggedSize 86"
        )
        self.assertIsNone(parser.feed(drop))
        self.assertIsNone(parser.feed("Drop: " + UDP6_LINE))

    def test_raw_wifi_and_other_edges_components_are_ignored(self):
        for kwargs in ({"kind": "WiFi"}, {"edge": 2}, {"component": 14}):
            with self.subTest(kwargs=kwargs):
                self.assertIsNone(self.parse(TCP_LINE, **kwargs))

    def test_arp_and_unsupported_summaries_are_counted(self):
        parser = PktmonParser(37)
        parser.feed(header())
        self.assertIsNone(parser.feed("ARP, Request who-has 192.0.2.1 tell 192.0.2.2"))
        parser.feed(header(clock="12:34:57.123456700"))
        self.assertEqual(parser.skipped, 1)
        parser.finish_packet()
        self.assertEqual(parser.skipped, 2)

    def test_unknown_protocol_is_never_inferred_from_port_number(self):
        record = self.parse("192.0.2.1.1234 > 198.51.100.2.53: 12345+ A? example.invalid")
        self.assertEqual(record.protocol, "Unknown")

    def test_ipv6_extension_summary_retains_outer_endpoints_without_guessing_transport(self):
        record = self.parse(
            "IP6 2001:db8::1 > 2001:db8::2: DSTOPT fragment, next-header unavailable"
        )
        self.assertEqual(record.protocol, "Unknown")
        self.assertEqual((record.source, record.destination), ("2001:db8::1", "2001:db8::2"))
        self.assertIsNone(record.source_port)

    def test_damaged_header_is_counted_and_next_packet_recovers_without_stale_flow(self):
        parser = PktmonParser(37)
        parser.feed(header())
        self.assertIsNone(parser.feed("12:34:56 PktGroupId unsupported-layout"))
        self.assertIsNone(parser.feed(TCP_LINE))
        self.assertEqual(parser.skipped, 2)
        parser.feed(header(clock="12:34:57.123456700"))
        self.assertEqual(parser.feed(TCP_LINE).protocol, "TCP")

    def test_fully_unsupported_stream_fails_with_clear_format_error(self):
        parser = PktmonParser(37)
        with self.assertRaisesRegex(ValueError, "output format is unsupported"):
            for _ in range(20):
                parser.feed("12:34:56 PktGroupId unsupported-layout")

    def test_bad_addresses_ports_and_mixed_families(self):
        for endpoint in ("not-an-ip", "192.0.2.1.99999", "192.0.2.1.-1"):
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                PktmonParser.endpoint(endpoint)
        with self.assertRaisesRegex(ValueError, "Mixed"):
            self.parse("192.0.2.1 > 2001:db8::1: UDP")

    def test_first_flow_in_encapsulated_packet_preserves_outer_addresses(self):
        record = self.parse(
            "2001:db8::1 > 2001:db8::2: IP 192.0.2.1.1234 > 192.0.2.2.443: Flags [S]"
        )
        self.assertEqual(record.version, 6)
        self.assertEqual(record.protocol, "IP-in-IP")
        self.assertIsNone(record.source_port)

    def test_header_size_and_nanosecond_timestamp(self):
        record = self.parse(TCP_LINE, size=1500, clock="23:59:59.123456789")
        self.assertEqual(record.size, 1500)
        self.assertIn(".123", record.time)

    def test_terminal_redraws_and_split_escapes_emit_one_live_record(self):
        terminal, parser = TerminalLines(), PktmonParser()
        chunks = [
            b"\x1b[2J\x1b[m\x1b[HC\x1b]0;pktmon.exe\x07",
            b"\x1b[HCollected Data:\x1b[33X\r\nProcessing...\x1b[16;1H",
            (header(component=2) + "\x1b[17;2H" + UDP6_LINE[:-14]).encode(),
            ("\x1b[?25h\r" + UDP6_LINE + "\x1b[81X\r\n").encode(),
            (header(component=2) + "\r\n" + UDP6_LINE + "\r\n").encode(),
        ]
        records = []
        for chunk in chunks:
            # Console byte boundaries can split any escape or UTF-8 sequence.
            for part in (chunk[:3], chunk[3:]):
                for line in terminal.feed(part):
                    if record := parser.feed(line):
                        records.append(record)
        self.assertEqual(len(records), 1)
        self.assertEqual((records[0].version, records[0].protocol), (6, "UDP"))

    def test_terminal_limits_unterminated_escape_buffers(self):
        with self.assertRaisesRegex(ValueError, "escape sequence"):
            TerminalLines().feed(b"\x1b]" + b"x" * 5000)

    def test_partial_protocol_redraw_does_not_publish_a_false_unknown(self):
        terminal, parser = TerminalLines(), PktmonParser()
        records = []
        prefix = header(component=2) + "\r\n" + UDP6_LINE.split("UDP,")[0] + "U"
        for chunk in (prefix.encode(), b"DP, length 20\r\n"):
            for line in terminal.feed(chunk):
                if record := parser.feed(line):
                    records.append(record)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].protocol, "UDP")

    def test_console_cursor_spaces_in_real_pktmon_headers_survive_chunk_boundaries(self):
        # Reproduced on the Wi-Fi adapter: ConPTY encodes a space as erase + cursor-right.
        drawn = header().replace("Type Ethernet", "Type\x1b[1CEthernet")
        drawn = drawn.replace("Filter 0, OriginalSize", "Filter 0,\x1b[140X\x1b[1COriginalSize")
        raw = (drawn + "\r\n" + TCP_LINE + "\r\n").encode()
        for chunk_size in (1, 3, 17, 4096):
            with self.subTest(chunk_size=chunk_size):
                terminal, parser, records = TerminalLines(), PktmonParser(), []
                for offset in range(0, len(raw), chunk_size):
                    for line in terminal.feed(raw[offset : offset + chunk_size]):
                        if record := parser.feed(line):
                            records.append(record)
                self.assertEqual(len(records), 1)
                self.assertEqual(records[0].protocol, "TCP")
                self.assertEqual(parser.unsupported, 0)

    def test_redrawn_header_with_different_whitespace_is_not_another_packet(self):
        parser = PktmonParser()
        parser.feed(header())
        self.assertIsNotNone(parser.feed(TCP_LINE))
        parser.feed(header().replace("Type Ethernet", "Type   Ethernet"))
        self.assertIsNone(parser.feed(TCP_LINE))
        self.assertEqual(parser.headers, 1)

    def test_terminal_horizontal_rewrite_erase_and_cursor_bounds(self):
        terminal = TerminalLines()
        self.assertEqual(terminal.feed(b"abcXX\x1b[2Dde\x1b[K\r\n"), ["abcde"])
        self.assertEqual(terminal.feed(b"old\x1b[1Gnew\x1b[K\r\n"), ["new"])
        with self.assertRaisesRegex(ValueError, "cursor exceeded"):
            terminal.feed(b"\x1b[99999C")


class BackendTests(unittest.TestCase):
    @staticmethod
    def component(identifier, name, kind, **properties):
        return {
            "Id": identifier,
            "Name": name,
            "Type": kind,
            "Properties": [{"Name": key, "Value": value} for key, value in properties.items()],
        }

    def configuration(self, index=13):
        return {
            "index": index,
            "name": "Wi-Fi",
            "addresses": ["192.0.2.2", "fe80::1", None],
            "gateway": [None],
            "ipv4": [{"IPAddress": "192.0.2.2", "PrefixLength": 24}],
        }

    def test_wifi_uses_decrypted_ethernet_component_with_exact_index(self):
        group = {
            "Components": [
                self.component(14, "Wireless", "Miniport", ifIndex=13, NdisMedium="Wi-Fi"),
                self.component(
                    37,
                    "Native WiFi",
                    "Filter",
                    **{"Miniport ifIndex": 13, "NdisMedium": "Ethernet"},
                ),
            ]
        }
        adapters = PktmonBackend.adapters([group], [self.configuration()])
        self.assertEqual(len(adapters), 1)
        self.assertEqual(adapters[0].device, 37)
        self.assertEqual(adapters[0].addresses, ("192.0.2.2", "fe80::1"))
        details = PktmonBackend.details(adapters[0])
        self.assertIn("IPv4 gateway: Not available", details)
        self.assertIn("255.255.255.0", details)

    def test_raw_wifi_without_decryption_component_is_not_offered(self):
        group = {
            "Components": [
                self.component(14, "Wireless", "Miniport", ifIndex=13, NdisMedium="Wi-Fi")
            ]
        }
        self.assertEqual(PktmonBackend.adapters([group], [self.configuration()]), [])

    def test_native_dotnet_inventory_preserves_subnet_masks(self):
        configuration = self.configuration()
        configuration["ipv4"] = [{"IPAddress": "192.0.2.2", "SubnetMask": "255.255.255.128"}]
        group = {
            "Components": [
                self.component(13, "Ethernet", "Miniport", ifIndex=13, NdisMedium="Ethernet")
            ]
        }
        adapter = PktmonBackend.adapters([group], [configuration])[0]
        self.assertIn("255.255.255.128", PktmonBackend.details(adapter))

    def test_duplicate_component_properties_merge_and_first_adapter_is_kept(self):
        group = {
            "Components": [
                self.component(13, "Ethernet", "Miniport", ifIndex=13),
                self.component(13, "Ethernet", "Miniport", NdisMedium="Ethernet"),
            ]
        }
        adapters = PktmonBackend.adapters([group], [self.configuration()])
        self.assertEqual(len(adapters), 1)
        self.assertEqual(adapters[0].device, 13)

    def test_requires_admin_and_never_installs_drivers(self):
        with (
            patch("network_packet_sniffer.pktmon.system_tool", return_value=Path(__file__)),
            patch(
                "network_packet_sniffer.pktmon.is_administrator",
                return_value=False,
            ),
        ):
            with self.assertRaisesRegex(PermissionError, "Restart the app and approve UAC"):
                PktmonBackend().check_ready()

    def test_existing_session_and_unknown_status_refuse_start(self):
        for state in ("Collected Data: active", "Unknown localized output"):
            with (
                self.subTest(state=state),
                patch.object(PktmonBackend, "check_ready"),
                patch.object(
                    PktmonBackend,
                    "command",
                    return_value=state,
                ),
                patch("network_packet_sniffer.pktmon.ConsoleProcess") as start,
            ):
                with self.assertRaisesRegex(RuntimeError, "already in use"):
                    PktmonBackend().capture(
                        Interface("Wi-Fi", "", (), 37), 1, Mock(), threading.Event(), Mock()
                    )
                start.assert_not_called()

    def test_existing_filters_are_preserved_by_refusing_capture(self):
        with (
            patch.object(PktmonBackend, "check_ready"),
            patch.object(
                PktmonBackend,
                "command",
                side_effect=["Packet Monitor is not running.", "Packet Filters: DNS"],
            ) as command,
            patch("network_packet_sniffer.pktmon.ConsoleProcess") as start,
        ):
            with self.assertRaisesRegex(RuntimeError, "filters were found"):
                PktmonBackend().capture(
                    Interface("Wi-Fi", "", (), 37), 1, Mock(), threading.Event(), Mock()
                )
            self.assertEqual(command.call_args_list[-1].args, ("filter", "list"))
            start.assert_not_called()

    def fake_capture(self, output, callback, stop, ready=None):
        child = SimpleNamespace(
            stdout=io.BytesIO(output.encode()), pid=123, poll=lambda: None, close=Mock()
        )
        with (
            patch.object(PktmonBackend, "check_ready"),
            patch.object(
                PktmonBackend,
                "command",
                side_effect=["Packet Monitor is not running.", "Packet Filters: None"],
            ),
            patch("network_packet_sniffer.pktmon.ConsoleProcess", return_value=child),
            patch.object(
                PktmonBackend,
                "stop_process",
            ) as cleanup,
        ):
            try:
                backend = PktmonBackend()
                backend.capture(
                    Interface("Wi-Fi", "", (), 37),
                    30,
                    callback,
                    stop,
                    ready or (lambda: None),
                )
            finally:
                cleanup.assert_called_once_with(child)
                self.assertTrue(child.stdout.closed)

    def test_streams_record_and_stops_before_pipe_eof_or_duration(self):
        stop = threading.Event()
        records = []

        def receive(record):
            records.append(record)
            stop.set()

        self.fake_capture("Processing...\n" + header() + "\n" + TCP_LINE + "\n", receive, stop)
        self.assertEqual(len(records), 1)

    def test_idle_startup_is_confirmed_without_waiting_for_a_packet(self):
        stop = threading.Event()
        callback = Mock()
        self.fake_capture("Collected Data:\n", callback, stop, stop.set)
        self.assertTrue(stop.is_set())
        callback.assert_not_called()

    def test_callback_failure_still_stops_owned_process(self):
        with self.assertRaisesRegex(OSError, "Disk full"):
            self.fake_capture(
                "Processing...\n" + header() + "\n" + TCP_LINE + "\n",
                Mock(side_effect=OSError("Disk full")),
                threading.Event(),
            )

    def test_stop_during_startup_does_not_wait_for_ready_or_misreport_exit(self):
        stop, ready = threading.Event(), Mock()

        class StartupStream(io.BytesIO):
            def read1(self, *args):
                stop.set()
                return super().read1(*args)

        with patch.object(io, "BytesIO", StartupStream):
            self.fake_capture("Starting capture…\n", Mock(), stop, ready)
        ready.assert_not_called()

    def test_busy_pipe_is_drained_during_stop_instead_of_deadlocking(self):
        stopped, drained = threading.Event(), threading.Event()

        class Stream(io.BytesIO):
            def read1(self, *args):
                data = super().read1(*args)
                if not data:
                    drained.set()
                return data

        payload = "Processing...\n" + header() + "\n" + TCP_LINE + "\n" + "extra line\n" * 5000
        child = Mock(pid=123)
        child.stdout = Stream(payload.encode())
        child.poll.return_value = None

        def wait(timeout):
            self.assertTrue(drained.wait(2), "Output stopped draining while waiting for child exit")

        child.wait.side_effect = wait
        with (
            patch.object(PktmonBackend, "check_ready"),
            patch.object(
                PktmonBackend,
                "command",
                side_effect=[
                    "Packet Monitor is not running.",
                    "Packet Filters: None",
                ],
            ),
            patch("network_packet_sniffer.pktmon.ConsoleProcess", return_value=child),
            patch(
                "network_packet_sniffer.pktmon.subprocess.run",
                return_value=SimpleNamespace(returncode=0),
            ),
        ):
            PktmonBackend().capture(
                Interface("Wi-Fi", "", (), 37),
                30,
                lambda record: stopped.set(),
                stopped,
                Mock(),
            )
        self.assertTrue(child.stdout.closed)

    def test_unexpected_process_exit_is_reported(self):
        with self.assertRaisesRegex(RuntimeError, "exited unexpectedly"):
            self.fake_capture("Access denied\n", Mock(), threading.Event())

    def test_oversized_stream_line_is_rejected_and_process_closed(self):
        with self.assertRaisesRegex(ValueError, "line size"):
            self.fake_capture("x" * 9000 + "\n", Mock(), threading.Event())

    def test_stop_interrupts_only_owned_pseudoconsole_and_waits(self):
        child = Mock(pid=123)
        child.poll.return_value = None
        PktmonBackend.stop_process(child)
        child.interrupt.assert_called_once_with()
        child.wait.assert_called_once_with(timeout=8)


if __name__ == "__main__":
    unittest.main()
