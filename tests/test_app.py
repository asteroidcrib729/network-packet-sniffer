"""Offline controller and Tkinter integration regressions."""

import gc
import tempfile
import threading
import time
import tkinter as tk
import unittest
from pathlib import Path
from queue import Empty
from unittest.mock import patch

from network_packet_sniffer.main import DARK, MAX_ROWS, TrafficSnifferApp
from network_packet_sniffer.sniffer import (
    CaptureController,
    Interface,
    PacketRecord,
    TrafficLog,
    validate_duration,
)


def sample_record():
    return PacketRecord(
        "2026-10-25T12:00:00.000+00:00", 4, "TCP", "192.0.2.1", "198.51.100.2", 1234, 443, 64
    )


class FakeBackend:
    def __init__(self, packets=(), block=False, failure=None):
        self.packets = packets
        self.block = block
        self.failure = failure
        self.entered = threading.Event()
        self.exited = threading.Event()
        self.device = object()
        self.adapters = [Interface("Ethernet", "Test adapter", ("192.0.2.2",), self.device)]
        self.calls = 0

    def interfaces(self):
        return self.adapters

    def details(self, interface):
        return "Addresses: 192.0.2.2\nIPv4 gateway: Not available\nIPv4 subnet masks: Not available"

    def capture(self, interface, duration, callback, stop, ready):
        self.calls += 1
        self.received_interface = interface
        try:
            ready()
            self.entered.set()
            for packet in self.packets:
                callback(packet)
                if stop.is_set():
                    break
            if self.failure:
                raise self.failure
            if self.block:
                stop.wait(3)
        finally:
            self.exited.set()


class AppTests(unittest.TestCase):
    def setUp(self):
        # Collect destroyed Tk roots on their owning thread before starting workers.
        gc.collect()
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def controller(self, backend=None):
        controller = CaptureController(
            backend or FakeBackend(),
            self.directory / "logs" / "traffic.log",
        )
        controller.refresh()
        self.addCleanup(self.stop_controller, controller)
        return controller

    @staticmethod
    def stop_controller(controller):
        controller.stop()
        if controller.thread is not None:
            controller.thread.join(timeout=4)

    def finish(self, controller):
        controller.thread.join(timeout=10)
        self.assertFalse(controller.running, "Capture worker did not exit")

    @staticmethod
    def events(controller):
        events = []
        while True:
            try:
                events.append(controller.events.get_nowait())
            except Empty:
                return events

    def test_duration_rejects_invalid_and_out_of_range_inputs(self):
        for value in ("", "abc", "1.5", "0", "-5", "3601", None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_duration(value)
        self.assertEqual(validate_duration(" 60 "), 60)
        self.assertEqual(validate_duration("3600"), 3600)

    def test_invalid_adapter_and_duration_never_reach_capture(self):
        controller = self.controller()
        for index, duration in ((-1, "1"), (1, "1"), (0, "0"), (0, "abc")):
            with self.subTest(index=index, duration=duration), self.assertRaises(ValueError):
                controller.start(index, duration)
        self.assertEqual(controller.backend.calls, 0)
        self.assertIsNone(controller.thread)

    def test_exact_adapter_object_is_used_and_overlap_is_rejected(self):
        backend = FakeBackend(block=True)
        controller = self.controller(backend)
        controller.start(0, "60")
        self.assertTrue(backend.entered.wait(2))
        with self.assertRaises(RuntimeError):
            controller.start(0, "60")
        with self.assertRaises(RuntimeError):
            controller.refresh()
        self.assertIs(backend.received_interface.device, backend.device)
        controller.stop()
        self.finish(controller)
        self.assertTrue(backend.exited.is_set())

    def test_logging_is_opt_in(self):
        backend = FakeBackend([sample_record()])
        controller = self.controller(backend)
        controller.start(0, "1")
        self.finish(controller)
        self.assertFalse(controller.log_path.exists())
        self.assertEqual(controller.count, 1)
        self.assertEqual(controller.alerts, 0)

    def test_log_receives_full_capture_when_display_queue_overflows(self):
        packets = [sample_record()] * 1200
        controller = self.controller(FakeBackend(packets))
        controller.start(0, "1", save_log=True)
        self.finish(controller)
        self.assertEqual(controller.records.qsize(), 1000)
        self.assertEqual(controller.count, 1200)
        self.assertEqual(controller.display_dropped, 200)
        text = controller.log_path.read_text(encoding="utf-8")
        self.assertEqual(text.count("IPv4 TCP"), 1200)
        self.assertIn("SESSION START", text)
        self.assertIn("SESSION END packets=1200", text)
        # The handler was closed before the worker exited.
        controller.log_path.rename(controller.log_path.with_suffix(".closed"))

    def test_capture_error_is_delivered_to_gui_queue(self):
        controller = self.controller(FakeBackend(failure=PermissionError("Capture access denied")))
        controller.start(0, "1")
        self.finish(controller)
        self.assertIn(("error", "Capture failed: Capture access denied"), self.events(controller))

    def test_log_open_failure_prevents_capture(self):
        controller = self.controller()
        controller.log_path.parent.mkdir()
        controller.log_path.mkdir()
        controller.start(0, "1", save_log=True)
        self.finish(controller)
        self.assertEqual(controller.backend.calls, 0)
        self.assertTrue(any(kind == "error" for kind, _ in self.events(controller)))

    def test_callback_log_failure_stops_capture_and_surfaces_error(self):
        controller = self.controller(FakeBackend([sample_record()]))
        with patch.object(TrafficLog, "write", side_effect=[None, None, OSError("Disk full")]):
            controller.start(0, "1", save_log=True)
            self.finish(controller)
        self.assertTrue(controller.stop_event.is_set())
        self.assertIn(("error", "Capture failed: Disk full"), self.events(controller))

    def test_log_write_errors_raise_instead_of_only_printing_to_stderr(self):
        handler = TrafficLog(self.directory / "errors.log")
        self.addCleanup(handler.close)
        with patch.object(handler, "shouldRollover", side_effect=OSError("Disk failure")):
            with self.assertRaisesRegex(OSError, "Cannot write"):
                handler.write("packet")

    def test_log_rotation_bounds_disk_usage(self):
        path = self.directory / "traffic.log"
        handler = TrafficLog(path)
        handler.maxBytes = 100
        try:
            for _ in range(20):
                handler.write("x" * 60)
        finally:
            handler.close()
        files = list(self.directory.glob("traffic.log*"))
        self.assertEqual(len(files), 4)
        self.assertTrue(all(p.stat().st_size <= 100 for p in files))

    def test_refresh_failure_discards_stale_adapters(self):
        controller = self.controller()
        with patch.object(controller.backend, "interfaces", side_effect=OSError("Disconnected")):
            with self.assertRaises(OSError):
                controller.refresh()
        self.assertEqual(controller.interfaces, [])

    def test_restart_clears_previous_session_records(self):
        controller = self.controller(FakeBackend([sample_record()]))
        controller.start(0, "1")
        self.finish(controller)
        self.assertEqual(controller.records.qsize(), 1)
        controller.backend.packets = []
        controller.start(0, "1")
        self.finish(controller)
        self.assertEqual(controller.count, 0)
        self.assertTrue(controller.records.empty())

    def make_gui(self, controller):
        try:
            app = TrafficSnifferApp(controller)
        except tk.TclError as error:
            self.skipTest(f"Tk display unavailable: {error}")
        app.withdraw()

        def cleanup():
            controller.stop()
            if controller.thread:
                controller.thread.join(timeout=4)
            if app.reputation is not None:
                app.reputation.close()
                if app.reputation.thread is not None:
                    app.reputation.thread.join(timeout=3)
            try:
                if app.winfo_exists():
                    for callback in app.tk.splitlist(app.tk.call("after", "info")):
                        app.after_cancel(callback)
                    app.destroy()
            except tk.TclError:
                pass
            # Tk variables must be released here, never by GC in a later worker.
            app.details = app.status = app.stats = app.save_log = None
            app.enable_reputation = None
            gc.collect()

        self.addCleanup(cleanup)
        app.update()
        self.pump(
            app,
            lambda: (
                app.refresh_thread is not None
                and not app.refresh_thread.is_alive()
                and app.refresh_results.empty()
                and "disabled" not in app.duration.state()
            ),
        )
        return app

    def pump(self, app, condition, timeout=3):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            app.update()
            if condition():
                return
            time.sleep(0.01)
        self.fail("Tk did not reach the expected state")

    def test_gui_packet_flow_stays_on_tk_thread_and_bounds_text(self):
        controller = self.controller(FakeBackend([sample_record()]))
        app = self.make_gui(controller)
        ui_thread = threading.get_ident()
        original_insert = app.output.insert
        calls = []

        def insert(*args):
            calls.append(threading.get_ident())
            return original_insert(*args)

        app.output.insert = insert
        app.start()
        self.pump(app, lambda: "192.0.2.1" in app.output.get("1.0", "end"))
        self.assertEqual(set(calls), {ui_thread})
        self.assertEqual(app.metric_labels["packets"].cget("text"), "1")
        self.assertEqual(app.metric_labels["alerts"].cget("text"), "0")
        self.assertFalse(app.empty_state.place_info())
        self.assertIn("Not available", app.details.get())
        app.output.configure(state="normal")
        app.output.insert("end", "row\n" * (MAX_ROWS + 500))
        app.output.configure(state="disabled")
        self.pump(app, lambda: int(app.output.index("end-1c").split(".")[0]) <= MAX_ROWS)

    def test_gui_keeps_manual_scroll_position_while_new_packets_arrive(self):
        app = self.make_gui(self.controller())
        app.output.configure(state="normal")
        app.output.insert("end", "previous packet\n" * 500)
        app.output.configure(state="disabled")
        app.update_idletasks()
        app.output.yview_moveto(0.25)
        app.controller.records.put(sample_record())
        app.poll()
        self.assertLess(app.output.yview()[0], 0.5)
        app.output.yview_moveto(1.0)
        app.controller.records.put(sample_record())
        app.poll()
        self.assertGreaterEqual(app.output.yview()[1], 0.999)

    def test_gui_preserves_capture_error_in_status(self):
        controller = self.controller(FakeBackend(failure=PermissionError("Access denied")))
        app = self.make_gui(controller)
        app.start()
        self.pump(app, lambda: "Access denied" in app.status.get())
        self.assertIn("Capture failed", app.status.get())

    def test_gui_close_waits_for_worker_cleanup(self):
        backend = FakeBackend(block=True)
        controller = self.controller(backend)
        app = self.make_gui(controller)
        app.start()
        self.assertTrue(backend.entered.wait(2))
        with patch.object(app, "destroy", wraps=app.destroy) as destroy:
            app.close()
            self.assertTrue(app.closing)
            self.pump(app, lambda: destroy.called)
            self.assertFalse(controller.running)
            self.assertTrue(backend.exited.is_set())
            self.assertFalse(controller.thread.daemon)

    def test_gui_validation_rejects_bad_duration_before_capture(self):
        controller = self.controller()
        app = self.make_gui(controller)
        app.duration.delete(0, "end")
        app.duration.insert(0, "-1")
        app.start()
        self.assertIn("Cannot start capture", app.status.get())
        self.assertIn("1 to 3600", app.status.get())
        self.assertIsNone(controller.thread)

    def test_gui_is_dark_only_including_dropdown_and_error_feedback(self):
        app = self.make_gui(self.controller())
        self.assertEqual(app.cget("background"), DARK["background"])
        self.assertEqual(app.output.cget("background"), DARK["input"])
        self.assertEqual(app.output.cget("foreground"), DARK["text"])
        from tkinter import ttk

        style = ttk.Style(app)
        self.assertEqual(style.theme_use(), "clam")
        self.assertEqual(style.lookup("TEntry", "fieldbackground"), DARK["input"])
        self.assertEqual(
            style.lookup("TCombobox", "fieldbackground", ("readonly",)),
            DARK["input"],
        )
        popdown = app.tk.call("ttk::combobox::PopdownWindow", str(app.adapter))
        background = app.tk.call(str(popdown) + ".f.l", "cget", "-background")
        self.assertEqual(background, DARK["input"])

    def test_gui_scrollbars_activate_only_on_the_overflowing_axis(self):
        app = self.make_gui(self.controller())
        app.update_idletasks()
        self.assertIn("disabled", app.vertical.state())
        self.assertIn("disabled", app.horizontal.state())
        app.output.configure(state="normal")
        app.output.insert("end", "row\n" * 800)
        app.output.configure(state="disabled")
        app.update_idletasks()
        self.assertTrue(app.vertical.overflow)
        self.assertFalse(app.horizontal.overflow)
        app.output.configure(state="normal")
        app.output.insert("end", "wide " * 2000)
        app.output.configure(state="disabled")
        app.output.see("end")
        app.update_idletasks()
        self.assertTrue(app.horizontal.overflow)
        app.clear_view()
        app.update_idletasks()
        self.assertFalse(app.vertical.overflow)
        self.assertFalse(app.horizontal.overflow)

    def test_disabled_scrollbar_ignores_input_and_layout_has_no_grip(self):
        app = self.make_gui(self.controller())
        with patch.object(app.horizontal, "scroll_command") as scroll:
            app.horizontal.set("0", "1")
            app.horizontal.scroll("scroll", "1", "units")
            scroll.assert_not_called()
            app.horizontal.set("0", "0.4")
            app.horizontal.scroll("scroll", "1", "units")
            scroll.assert_called_once_with("scroll", "1", "units")
        from tkinter import ttk

        for orientation in ("Horizontal", "Vertical"):
            self.assertEqual(int(ttk.Style(app).lookup(f"{orientation}.TScrollbar", "gripsize")), 0)

    def test_capture_completion_is_in_stream_badge_and_duplicate_heading_is_absent(self):
        app = self.make_gui(self.controller(FakeBackend([sample_record()])))
        app.start()
        self.pump(app, lambda: app.phase == "ended" and not app.controller.running)
        self.assertIn("CAPTURE ENDED", app.activity.cget("text"))
        self.assertFalse(app.status_label.grid_info())

        def labels(widget):
            for child in widget.winfo_children():
                if child.winfo_class() == "TLabel":
                    yield child.cget("text")
                yield from labels(child)

        self.assertNotIn("Network Packet Sniffer", list(labels(app)))

    def test_dynamic_alerts_are_attributed_and_deduplicated_per_session(self):
        from test_reputation import fixture_feeds

        from network_packet_sniffer.reputation import FeedSnapshot, ReputationService

        record = sample_record()
        from dataclasses import replace

        record = replace(record, source="8.8.8.8", destination="1.1.1.1")
        controller = self.controller(FakeBackend([record, record]))
        service = ReputationService(self.directory / "cache")
        service.snapshot = FeedSnapshot(time.time(), fixture_feeds())
        controller.reputation = service
        controller.start(0, "1")
        self.finish(controller)
        records = [controller.records.get_nowait() for _ in range(2)]
        self.assertEqual(len(records[0].reputation), 1)
        self.assertIn("SBL1", records[0].line())
        self.assertIn("fetched", records[0].line())
        self.assertFalse(records[1].reputation)
        self.assertEqual(controller.count, 2)
        self.assertEqual(controller.alerts, 1)
        controller.start(0, "1")
        self.finish(controller)
        self.assertEqual(controller.alerts, 1)

    def test_capture_without_reputation_needs_no_address_file(self):
        controller = self.controller(FakeBackend([sample_record()]))
        controller.start(0, "1")
        self.finish(controller)
        self.assertEqual(controller.count, 1)
        self.assertFalse(controller.records.get_nowait().reputation)
        self.assertFalse(any(kind == "error" for kind, _ in self.events(controller)))

    def test_gui_displays_attributed_feed_alerts_without_a_static_address_list(self):
        from dataclasses import replace

        from test_reputation import fixture_feeds

        from network_packet_sniffer.reputation import FeedSnapshot, ReputationService

        record = replace(sample_record(), source="8.8.8.8", destination="1.1.1.1")
        controller = self.controller(FakeBackend([record, record]))
        service = ReputationService(self.directory / "cache")
        service.snapshot = FeedSnapshot(time.time(), fixture_feeds())
        # This integration uses a local fixture; no provider request is permitted.
        service.auto_due = time.time() + 86400
        controller.reputation = service
        with patch.object(service.provider, "fetch", side_effect=AssertionError("Unexpected HTTP")):
            app = self.make_gui(controller)
            app.start()
            self.pump(app, lambda: app.phase == "ended" and not controller.running)
            text = app.output.get("1.0", "end")
            self.assertEqual(text.count("REPUTATION ALERT"), 1)
            self.assertIn("SBL1", text)
            self.assertEqual(app.metric_labels["alerts"].cget("text"), "1")
            self.assertIn("alert", app.output.tag_names(app.output.search("REPUTATION", "1.0")))

    def test_reputation_alert_dedup_state_is_bounded_without_losing_packet_rows(self):
        from dataclasses import replace

        from test_reputation import fixture_feeds

        from network_packet_sniffer.reputation import FeedSnapshot, ReputationService

        service = ReputationService(self.directory / "cache")
        service.snapshot = FeedSnapshot(time.time(), fixture_feeds())
        packets = [replace(sample_record(), source=f"8.8.8.{i}") for i in (1, 2, 3)]
        controller = self.controller(FakeBackend(packets))
        controller.reputation = service
        with patch("network_packet_sniffer.sniffer.MAX_SESSION_ALERTS", 1):
            controller.start(0, "1")
            self.finish(controller)
        self.assertEqual(controller.records.qsize(), 3)
        self.assertEqual(controller.alerts, 1)
        self.assertEqual(controller.suppressed_alerts, 2)

    def test_reputation_refresh_does_not_block_packet_display_or_touch_tk_from_worker(self):
        from test_reputation import fixture_feeds

        from network_packet_sniffer.reputation import ReputationService

        entered, release = threading.Event(), threading.Event()
        self.addCleanup(release.set)

        class Provider:
            def fetch(self, cancel):
                entered.set()
                release.wait(2)
                return fixture_feeds()

        controller = self.controller(FakeBackend([sample_record()], block=True))
        controller.reputation = ReputationService(self.directory / "cache", Provider())
        app = self.make_gui(controller)
        self.assertTrue(entered.wait(1))
        calls, owner = [], threading.get_ident()
        original = app.reputation_summary.configure

        def configure(*args, **kwargs):
            calls.append(threading.get_ident())
            return original(*args, **kwargs)

        app.reputation_summary.configure = configure
        app.start()
        self.pump(app, lambda: "192.0.2.1" in app.output.get("1.0", "end"))
        self.assertTrue(app.reputation.running)
        release.set()
        self.pump(app, lambda: "IPv4 fresh" in app.reputation_summary.cget("text"))
        self.assertEqual(set(calls), {owner})

    def test_gui_has_no_administrator_button(self):
        app = self.make_gui(self.controller())
        self.assertFalse(hasattr(app, "admin_button"))
        self.assertFalse(hasattr(app, "restart_as_administrator"))

    def test_gui_refresh_runs_outside_the_tk_thread(self):
        backend = FakeBackend()
        caller = []
        original = backend.interfaces

        def interfaces():
            caller.append(threading.get_ident())
            return original()

        backend.interfaces = interfaces
        controller = self.controller(backend)
        caller.clear()
        app = self.make_gui(controller)
        self.assertTrue(caller)
        self.assertNotEqual(caller[-1], threading.get_ident())
        self.assertEqual(app.adapter.current(), 0)


if __name__ == "__main__":
    unittest.main()
