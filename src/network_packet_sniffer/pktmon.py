"""Live capture through Windows' built-in Pktmon. No capture driver installation."""

from __future__ import annotations

import codecs
import ctypes
import json
import os
import re
import subprocess
import sys
from collections import deque
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Network, ip_address
from pathlib import Path
from queue import Empty, Full, Queue
from threading import Event, Thread
from time import monotonic

from .sniffer import Interface, PacketRecord
from .windows_console import ConsoleProcess

NETWORK_QUERY = """
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
@([Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() | ForEach-Object {
    $adapter = $_
    $properties = $adapter.GetIPProperties()
    $index = $null
    try { $index = $properties.GetIPv4Properties().Index } catch {
        try { $index = $properties.GetIPv6Properties().Index } catch { }
    }
    if ($null -eq $index) { return }
    [pscustomobject]@{
        index = $index
        name = $adapter.Name
        addresses = @($properties.UnicastAddresses | ForEach-Object { $_.Address.ToString() })
        gateway = @($properties.GatewayAddresses | Where-Object {
            $_.Address.AddressFamily -eq 'InterNetwork'
        } | ForEach-Object { $_.Address.ToString() })
        ipv4 = @($properties.UnicastAddresses | Where-Object {
            $_.Address.AddressFamily -eq 'InterNetwork'
        } | ForEach-Object {
            [pscustomobject]@{
                IPAddress = $_.Address.ToString()
                SubnetMask = $_.IPv4Mask.ToString()
            }
        })
    }
}) | ConvertTo-Json -Depth 5 -Compress
"""


def is_administrator() -> bool:
    return sys.platform == "win32" and bool(ctypes.windll.shell32.IsUserAnAdmin())


def system_tool(name: str) -> Path:
    if sys.platform != "win32":
        raise RuntimeError("Live capture requires Windows 10/11 with built-in Pktmon.")
    return Path(os.environ["SystemRoot"]) / "System32" / name


def run_command(arguments: list[str], timeout=20) -> str:
    result = subprocess.run(
        arguments,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    if result.returncode:
        raise RuntimeError((result.stderr or result.stdout).strip() or "Windows command failed.")
    return result.stdout


class PktmonParser:
    """Parse English Pktmon headers and their first IP summary, incrementally."""

    header = re.compile(
        r"^(?P<time>\d{2}:\d{2}:\d{2}\.\d+) PktGroupId (?P<group>\d+), "
        r"PktNumber (?P<number>\d+), Appearance (?P<appearance>\d+), "
        r"Direction \w+\s*, Type (?P<type>\w+)\s*, "
        r"Component (?P<component>\d+), Edge (?P<edge>\d+), Filter \d+, "
        r"OriginalSize (?P<size>\d+), LoggedSize \d+\s*$"
    )
    flow = re.compile(r"([\da-fA-F:.%]+) > ([\da-fA-F:.%]+):\s*(.*)")

    def __init__(self, component: int | None = None):
        self.component = component
        self.pending = None
        self.skipped = 0
        self.headers = 0
        self.unsupported = 0
        self.recent = deque(maxlen=256)
        self.seen = set()

    @staticmethod
    def endpoint(value: str) -> tuple[str, int | None]:
        scoped_port = re.fullmatch(r"(.+%\d+)\.(\d+)", value)
        if scoped_port:
            port = int(scoped_port[2])
            if port > 65535:
                raise ValueError("Invalid transport port in Pktmon output.")
            return str(ip_address(scoped_port[1])), port
        try:
            return str(ip_address(value)), None
        except ValueError:
            address, separator, port = value.rpartition(".")
            if separator and port.isdecimal() and 0 <= int(port) <= 65535:
                return str(ip_address(address)), int(port)
            raise ValueError("Unrecognized IP endpoint in Pktmon output.") from None

    @staticmethod
    def capture_time(value: str) -> str:
        # Pktmon prints local wall time, including fractions up to nanoseconds.
        now = datetime.now().astimezone()
        clock, fraction = value.split(".")
        clock = datetime.strptime(clock, "%H:%M:%S").time()
        moment = now.replace(
            hour=clock.hour,
            minute=clock.minute,
            second=clock.second,
            microsecond=int(fraction[:6].ljust(6, "0")),
        )
        if moment - now > timedelta(hours=12):
            moment -= timedelta(days=1)
        elif now - moment > timedelta(hours=12):
            moment += timedelta(days=1)
        return moment.astimezone(UTC).isoformat(timespec="milliseconds")

    def finish_packet(self):
        if self.pending is not None:
            self.skipped += 1
            self.pending = None

    def feed(self, line: str) -> PacketRecord | None:
        line = line.strip()
        if "PktGroupId" in line:
            line = re.sub(r"\s+", " ", line)
            if re.match(r"^\d{2}:\d{2}:\d{2}\.\d+ Drop: PktGroupId ", line):
                self.finish_packet()
                return None  # Drop diagnostics have no edge; keep the flowing snapshot only.
            match = self.header.fullmatch(line)
            if match is None:
                self.finish_packet()
                self.unsupported += 1
                self.skipped += 1
                if self.headers == 0 and self.unsupported >= 20:
                    raise ValueError(
                        "Pktmon output format is unsupported. English output is required."
                    )
                return None  # A damaged/redrawn snapshot must not terminate a working capture.
            data = match.groupdict()
            identity = tuple(
                data[key]
                for key in ("time", "group", "number", "appearance", "component", "edge", "type")
            )
            if identity in self.seen:
                if self.pending is not None and self.pending.get("identity") != identity:
                    self.finish_packet()
                return None
            self.finish_packet()
            if len(self.recent) == self.recent.maxlen:
                self.seen.remove(self.recent[0])
            self.recent.append(identity)
            self.seen.add(identity)
            self.headers += 1
            data["identity"] = identity
            # Ethernet edge 1 is the decrypted side of the native Wi-Fi translator.
            # Ignore edge 2 and raw Wi-Fi snapshots of the same packet.
            if (
                (self.component is None or int(data["component"]) == self.component)
                and data["edge"] == "1"
                and data["type"] in ("Ethernet", "IP")
            ):
                self.pending = data
            return None
        if self.pending is None:
            return None
        match = self.flow.search(line)
        if match is None:
            return None
        try:
            source, source_port = self.endpoint(match[1])
            destination, destination_port = self.endpoint(match[2])
        except ValueError:
            return None  # ARP/MAC summaries are not IP flows.
        version = ip_address(source).version
        if ip_address(destination).version != version:
            raise ValueError("Mixed IP address families in Pktmon output.")
        detail = match[3]
        if not detail.strip():
            return None  # A terminal redraw may still be completing this summary.
        protocol = "Unknown"
        for prefix, name in (
            ("Flags [", "TCP"),
            ("UDP", "UDP"),
            ("ICMP6", "ICMPv6"),
            ("ICMPv6", "ICMPv6"),
            ("ICMP", "ICMP"),
            ("IP ", "IP-in-IP"),
        ):
            if detail.startswith(prefix):
                protocol = name
                break
        data, self.pending = self.pending, None
        return PacketRecord(
            self.capture_time(data["time"]),
            version,
            protocol,
            source,
            destination,
            source_port,
            destination_port,
            int(data["size"]),
        )


class TerminalLines:
    """Frame console lines across UTF-8 chunks, cursor moves, and carriage redraws."""

    escape = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")

    def __init__(self):
        self.decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        self.pending = ""
        self.line = ""
        self.carriage = False
        self.column = 0

    def feed(self, raw: bytes) -> list[str]:
        text = self.pending + self.decoder.decode(raw)
        self.pending = ""
        result = []

        def emit(force=False):
            value = self.line.strip()
            if not value:
                return
            if "PktGroupId" in value and not re.match(r"^\d\d:\d\d:\d\d\.\d+ ", value):
                return  # A redraw that starts in the middle of a previous row.
            flow = PktmonParser.flow.search(value)
            complete_protocol = flow and (
                flow[3].startswith(("UDP,", "ICMP", "IP "))
                or (flow[3].startswith("Flags [") and "]" in flow[3])
            )
            if force or PktmonParser.header.fullmatch(value) or complete_protocol:
                result.append(value)

        position = 0
        while position < len(text):
            char = text[position]
            if char == "\x1b":
                match = self.escape.match(text, position)
                if match is None:
                    self.pending = text[position:]
                    if len(self.pending) > 4096:
                        raise ValueError("Unsupported or oversized terminal escape sequence.")
                    break
                sequence = match[0]
                if sequence.startswith("\x1b["):
                    code = sequence[-1]
                    parameters = sequence[2:-1]
                    if re.fullmatch(r"[\d;]*", parameters):
                        values = [int(value or "0") for value in parameters.split(";")]
                        count = values[0] or 1
                        if code in "HfABEF":
                            emit()
                            self.line, self.carriage, self.column = "", False, 0
                            if code in "Hf" and len(values) > 1:
                                self.column = max(0, values[1] - 1)
                        elif code in "Ca":
                            self.column += count
                        elif code == "D":
                            self.column = max(0, self.column - count)
                        elif code in "G`":
                            self.column = count - 1
                        elif code == "K":
                            if values[0] == 0:
                                self.line = self.line[: self.column]
                            elif values[0] == 1:
                                self.line = " " * (self.column + 1) + self.line[self.column + 1 :]
                            elif values[0] == 2:
                                self.line = ""
                        elif code == "X":
                            end = min(len(self.line), self.column + count)
                            self.line = (
                                self.line[: self.column]
                                + " " * max(0, end - self.column)
                                + self.line[end:]
                            )
                        if self.column > 8192:
                            raise ValueError(
                                "Pktmon terminal cursor exceeded the supported line size."
                            )
                position = match.end()
                continue
            if char == "\r":
                self.carriage = True
            elif char == "\n":
                emit(force=True)
                self.line, self.carriage, self.column = "", False, 0
            elif char >= " " or char == "\t":
                if self.carriage:
                    self.line, self.carriage, self.column = "", False, 0
                self.line = self.line.ljust(self.column)
                self.line = self.line[: self.column] + char + self.line[self.column + 1 :]
                self.column += 1
                if len(self.line) > 8192:
                    raise ValueError("Pktmon output exceeded the supported line size.")
            position += 1
        # A quiet stream need not print another newline before delivering a row.
        emit()
        return result


class PktmonBackend:
    """Own one hidden real-time Pktmon process and signal only its private console."""

    def __init__(self):
        self.skipped = 0

    def command(self, *arguments: str) -> str:
        return run_command([str(system_tool("pktmon.exe")), *arguments])

    def check_ready(self):
        if not system_tool("pktmon.exe").is_file():
            raise RuntimeError("Built-in pktmon.exe was not found. Windows 10/11 is required.")
        if not is_administrator():
            raise PermissionError(
                "Administrator access is required. Restart the app and approve UAC."
            )

    @staticmethod
    def adapters(components, configurations) -> list[Interface]:
        result = []
        for group in components:
            merged = {}
            for item in group.get("Components", []):
                entry = merged.setdefault(item["Id"], {**item, "properties": {}})
                entry["properties"].update(
                    {p["Name"]: p.get("Value") for p in item.get("Properties", [])}
                )
            nics = [c for c in merged.values() if c["Type"] in ("Miniport", "Host vNic")]
            for nic in nics:
                props = nic["properties"]
                index = props.get("ifIndex")
                config = next((c for c in configurations if c["index"] == index), None)
                if config is None:
                    continue
                component = nic
                if props.get("NdisMedium") == "Wi-Fi":
                    component = next(
                        (
                            c
                            for c in merged.values()
                            if (
                                c["Type"] == "Filter"
                                and c["properties"].get("NdisMedium") == "Ethernet"
                                and c["properties"].get("Miniport ifIndex") == index
                            )
                        ),
                        None,
                    )
                    if component is None:
                        continue  # Do not silently offer encrypted raw Wi-Fi capture.
                elif props.get("NdisMedium") != "Ethernet":
                    continue
                addresses = tuple(dict.fromkeys(a for a in config["addresses"] if a))
                gateway = next((g for g in config["gateway"] if g), "Not available")
                masks = tuple(
                    f"{a['IPAddress']}: "
                    + (
                        a.get("SubnetMask")
                        or str(IPv4Network("0.0.0.0/" + str(a["PrefixLength"])).netmask)
                    )
                    for a in config["ipv4"]
                    if a and a.get("IPAddress")
                )
                result.append(
                    Interface(
                        config["name"],
                        nic["Name"],
                        addresses,
                        component["Id"],
                        gateway,
                        masks,
                    )
                )
        return sorted(
            result,
            key=lambda item: (
                item.gateway == "Not available",
                not bool(item.addresses),
                item.name.casefold(),
            ),
        )

    def interfaces(self) -> list[Interface]:
        self.check_ready()
        components = json.loads(self.command("list", "--json"))
        output = run_command(
            [
                str(system_tool("WindowsPowerShell/v1.0/powershell.exe")),
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                NETWORK_QUERY,
            ]
        )
        configurations = json.loads(output)
        if not isinstance(configurations, list):
            configurations = [configurations]
        return self.adapters(components, configurations)

    @staticmethod
    def details(interface: Interface) -> str:
        return (
            f"Addresses: {', '.join(interface.addresses) or 'Not assigned'}\n"
            f"IPv4 gateway: {interface.gateway}\n"
            f"IPv4 subnet masks: {'; '.join(interface.subnet_masks) or 'Not available'}"
        )

    @staticmethod
    def stop_process(child):
        if child.poll() is not None:
            return
        child.interrupt()
        try:
            child.wait(timeout=8)
        except subprocess.TimeoutExpired as error:
            raise RuntimeError("Pktmon did not finish stopping its capture session.") from error

    def capture(self, interface, duration, callback, stop, ready):
        self.check_ready()
        if stop.is_set():
            return
        state = self.command("status").strip()
        if state != "Packet Monitor is not running.":
            raise RuntimeError(
                "Pktmon is already in use, or its status format is unsupported. "
                "Existing sessions will not be stopped."
            )
        filters = self.command("filter", "list")
        if re.sub(r"\s+", " ", filters).strip() != "Packet Filters: None":
            raise RuntimeError("Existing Pktmon filters were found. They will not be changed.")
        if stop.is_set():
            return
        child = ConsoleProcess(
            [
                str(system_tool("pktmon.exe")),
                "start",
                "--capture",
                "--comp",
                str(interface.device),
                "--type",
                "all",
                "--pkt-size",
                "128",
                "--log-mode",
                "real-time",
            ]
        )
        lines = Queue(maxsize=1024)
        reader_stop, reader_done, reader_discard = Event(), Event(), Event()
        reader_errors = []

        def read_pipe():
            terminal = TerminalLines()
            try:
                while not reader_stop.is_set():
                    raw = child.stdout.read1(4096)
                    if not raw:
                        break
                    if reader_discard.is_set():
                        continue
                    for line in terminal.feed(raw):
                        while not reader_stop.is_set() and not reader_discard.is_set():
                            try:
                                lines.put(line, timeout=0.1)
                                break
                            except Full:
                                continue
            except Exception as error:
                reader_errors.append(error)
            finally:
                reader_done.set()

        reader = Thread(target=read_pipe, name="pktmon-output", daemon=True)
        reader.start()
        # --comp already limits this private stream. Hyper-V can report selected
        # traffic under a companion component ID, so do not discard those rows.
        parser = PktmonParser()
        self.skipped = 0
        startup_deadline, deadline = monotonic() + 10, None
        tail = deque(maxlen=10)
        try:
            while True:
                now = monotonic()
                if stop.is_set() or (deadline is not None and now >= deadline):
                    break
                if deadline is None and now >= startup_deadline:
                    raise RuntimeError(
                        "Pktmon did not confirm live capture startup within 10 seconds."
                    )
                try:
                    line = lines.get(timeout=0.1)
                except Empty:
                    if reader_done.is_set():
                        if reader_errors:
                            raise reader_errors[0] from None
                        raise RuntimeError(
                            "Pktmon exited unexpectedly: " + " ".join(tail)[-600:]
                        ) from None
                    continue
                if deadline is None and "PktGroupId" not in line:
                    tail.append(line[:500])  # Do not echo captured payload text in error messages.
                if deadline is None and (
                    line.strip() in ("Collected Data:", "Processing...") or "PktGroupId" in line
                ):
                    deadline = monotonic() + duration
                    ready()
                record = parser.feed(line)
                self.skipped = parser.skipped
                if record is not None:
                    callback(record)
        finally:
            # Keep draining stdout during shutdown; a full pipe can prevent Pktmon
            # from flushing/exiting after Ctrl+C, especially on busy adapters.
            reader_discard.set()
            try:
                self.stop_process(child)
            finally:
                if reader_done.is_set():
                    child.stdout.close()
                child.close()
                reader_stop.set()
                reader.join(timeout=2)
                if not reader.is_alive():
                    child.stdout.close()
                parser.finish_packet()
                self.skipped = parser.skipped
