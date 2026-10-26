"""Capture and logging logic. This module never touches Tkinter widgets."""

from __future__ import annotations

import logging
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from queue import Full, Queue, SimpleQueue
from threading import Event, Thread

from .paths import data_directory

BASE_DIR = data_directory()
MAX_DURATION = 3600
MAX_SESSION_ALERTS = 4096


def timestamp() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds")


def validate_duration(value: str) -> int:
    try:
        duration = int(value.strip())
    except (ValueError, AttributeError) as error:
        raise ValueError(f"Enter a whole number from 1 to {MAX_DURATION} seconds.") from error
    if not 1 <= duration <= MAX_DURATION:
        raise ValueError(f"Duration must be from 1 to {MAX_DURATION} seconds.")
    return duration


@dataclass(frozen=True)
class Interface:
    name: str
    description: str
    addresses: tuple[str, ...]
    device: object
    gateway: str = "Not available"
    subnet_masks: tuple[str, ...] = ()


@dataclass(frozen=True)
class PacketRecord:
    time: str
    version: int
    protocol: str
    source: str
    destination: str
    source_port: int | None
    destination_port: int | None
    size: int
    reputation: tuple[str, ...] = ()

    def line(self) -> str:
        def endpoint(address: str, port: int | None) -> str:
            if port is None:
                return address
            return f"[{address}]:{port}" if ":" in address else f"{address}:{port}"

        alert = " | REPUTATION ALERT: " + "; ".join(self.reputation) if self.reputation else ""
        return (
            f"{self.time} IPv{self.version} {self.protocol} "
            f"{endpoint(self.source, self.source_port)} -> "
            f"{endpoint(self.destination, self.destination_port)} | {self.size} bytes{alert}"
        )


class TrafficLog(RotatingFileHandler):
    """Keep at most four ~1 MB files; surface disk errors to the controller."""

    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        super().__init__(path, maxBytes=1_000_000, backupCount=3, encoding="utf-8")

    def write(self, line: str) -> None:
        self.emit(logging.makeLogRecord({"msg": line}))

    def handleError(self, record: logging.LogRecord) -> None:
        raise OSError("Cannot write the traffic log. Check disk space and folder permissions.")


class CaptureController:
    """Own one capture worker; publish records and lifecycle events through queues."""

    def __init__(self, backend=None, log_path=None, reputation=None):
        if backend is None:
            from .pktmon import PktmonBackend

            backend = PktmonBackend()
        self.backend = backend
        self.log_path = log_path or BASE_DIR / "logs" / "traffic.log"
        self.reputation = reputation
        self.interfaces: list[Interface] = []
        self.records: Queue[PacketRecord] = Queue(maxsize=1000)
        self.events: SimpleQueue[tuple[str, str]] = SimpleQueue()
        self.stop_event = Event()
        self.thread: Thread | None = None
        self.count = self.alerts = self.display_dropped = 0
        self.suppressed_alerts = 0

    @property
    def running(self) -> bool:
        return self.thread is not None and self.thread.is_alive()

    def refresh(self) -> list[Interface]:
        if self.running:
            raise RuntimeError("Stop the current capture before refreshing adapters.")
        self.interfaces = []  # Do not retain stale adapters if refresh fails.
        self.interfaces = self.backend.interfaces()
        return self.interfaces

    def start(self, index: int, duration: str, save_log: bool = False) -> None:
        if self.running:
            raise RuntimeError("A capture is already running. Stop it before starting another.")
        seconds = validate_duration(duration)
        if not 0 <= index < len(self.interfaces):
            raise ValueError("Select an available network adapter and try again.")
        self.records = Queue(maxsize=1000)
        self.events = SimpleQueue()
        self.count = self.alerts = self.display_dropped = 0
        self.suppressed_alerts = 0
        self.stop_event.clear()
        self.thread = Thread(
            target=self._run,
            args=(self.interfaces[index], seconds, save_log),
            name="packet-capture",
            daemon=False,
        )
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()

    def _run(self, interface, duration, save_log) -> None:
        log = None
        seen_alerts = set()

        def receive(record):
            if self.stop_event.is_set():
                return
            notices = []
            if self.reputation is not None:
                for address in dict.fromkeys((record.source, record.destination)):
                    result = self.reputation.lookup(address)
                    if result.cidr and result.status in ("listed", "stale"):
                        key = (result.address, result.cidr)
                        if key not in seen_alerts:
                            if len(seen_alerts) < MAX_SESSION_ALERTS:
                                seen_alerts.add(key)
                                notices.append(result.alert())
                            else:
                                self.suppressed_alerts += 1
            record = replace(
                record,
                reputation=tuple(notices),
            )
            if log is not None:
                log.write(record.line())
            self.count += 1
            self.alerts += bool(record.reputation)
            try:
                self.records.put_nowait(record)
            except Full:
                self.display_dropped += 1

        try:
            if save_log:
                log = TrafficLog(self.log_path)
                log.write(
                    f"{timestamp()} SESSION START adapter={interface.name} duration={duration}s"
                )
                log.write(
                    "Attributed reputation signals are local feed matches, not proof of an attack."
                )
            self.backend.capture(
                interface,
                duration,
                receive,
                self.stop_event,
                lambda: self.events.put(("status", f"Capturing on {interface.name}")),
            )
            if log is not None:
                log.write(f"{timestamp()} SESSION END packets={self.count} alerts={self.alerts}")
        except Exception as error:
            self.stop_event.set()
            self.events.put(("error", f"Capture failed: {error}"))
        finally:
            try:
                if log is not None:
                    log.close()
            except OSError as error:
                self.events.put(("error", f"Could not close the traffic log: {error}"))
            self.events.put(
                ("done", "Capture stopped" if self.stop_event.is_set() else "Capture ended")
            )
