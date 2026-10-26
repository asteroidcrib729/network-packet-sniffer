"""The only application entry point: a small, object-oriented Tkinter GUI."""

from __future__ import annotations

import ctypes
import subprocess
import sys
import tkinter as tk
from pathlib import Path
from queue import Empty, Queue
from threading import Thread
from tkinter import font as tkfont
from tkinter import ttk

from .pktmon import is_administrator
from .reputation import ReputationService
from .sniffer import CaptureController

MAX_ROWS = 2000
ELEVATED_ARGUMENT = "--elevated"
DARK = {
    "background": "#0c111b",
    "surface": "#151e2d",
    "input": "#0f1724",
    "text": "#e9f0fa",
    "muted": "#9aaec6",
    "border": "#26354a",
    "active": "#243650",
    "accent": "#59d5df",
    "selection": "#20485d",
    "alert": "#f3c777",
    "error": "#ff9c9c",
}


def configure_dpi():
    """Avoid Windows bitmap stretching; Tk sizes its fonts at the system DPI."""
    if sys.platform != "win32":
        return
    try:
        awareness = ctypes.windll.user32.SetProcessDpiAwarenessContext
        awareness.argtypes = [ctypes.c_void_p]
        awareness.restype = ctypes.c_bool
        awareness(ctypes.c_void_p(-2))  # System aware, supported by Tk 8.6.
    except AttributeError, OSError:
        ctypes.windll.user32.SetProcessDPIAware()


class OverflowScrollbar(ttk.Scrollbar):
    """Reserve a stable gutter; allow scrolling only on an overflowing axis."""

    def __init__(self, parent, *, command, **options):
        self.scroll_command = command
        self.overflow = False
        super().__init__(parent, command=self.scroll, takefocus=False, **options)
        self.state(["disabled"])

    def set(self, first, last):
        self.overflow = float(last) - float(first) < 0.999999
        super().set(first, last)
        self.state(["!disabled" if self.overflow else "disabled"])
        self.configure(takefocus=self.overflow)

    def scroll(self, *arguments):
        if self.overflow:
            self.scroll_command(*arguments)


class TrafficSnifferApp(tk.Tk):
    def __init__(self, controller=None):
        configure_dpi()
        super().__init__()
        self.controller = (
            controller
            if controller is not None
            else CaptureController(reputation=ReputationService())
        )
        self.reputation = self.controller.reputation
        self.closing = False
        self.capture_error = False
        self.phase = "loading"
        self.refresh_thread = None
        self.refresh_pending = False
        self.refresh_results = Queue(maxsize=1)
        self.title("Network Packet Sniffer")
        self.ui_scale = self.winfo_fpixels("1i") / 96
        width = min(self.px(1200), self.winfo_screenwidth() - self.px(48))
        height = min(self.px(800), self.winfo_screenheight() - self.px(80))
        x = max(0, (self.winfo_screenwidth() - width) // 2)
        y = max(0, (self.winfo_screenheight() - height - self.px(40)) // 2)
        self.geometry(f"{width}x{height}+{x}+{y}")
        self.minsize(min(width, self.px(940)), min(height, self.px(650)))
        self.apply_dark_theme()
        self.protocol("WM_DELETE_WINDOW", self.close)
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

        self.build_interface()
        self.after(0, self.refresh)
        if self.reputation is not None:
            self.after(0, self.reputation.refresh)
        self.after(75, self.poll)

    def px(self, value):
        return round(value * self.ui_scale)

    def build_interface(self):
        space = self.px
        frame = ttk.Frame(self, padding=space(20))
        frame.grid(sticky="nsew")
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(3, weight=1)
        metrics = ttk.Frame(frame)
        metrics.grid(row=1, sticky="ew", pady=(0, space(14)))
        self.metric_labels = {}
        for column, (key, caption, tone) in enumerate(
            (
                ("packets", "PACKETS OBSERVED", "Metric.TLabel"),
                ("alerts", "ALERT ROWS", "AlertMetric.TLabel"),
                ("display", "DISPLAY SKIPPED", "Metric.TLabel"),
                ("undecoded", "NON-IP / UNDECODED", "Metric.TLabel"),
            )
        ):
            metrics.columnconfigure(column, weight=1, uniform="metric")
            card = ttk.Frame(metrics, style="Card.TFrame", padding=space(10))
            card.grid(row=0, column=column, sticky="ew", padx=(0 if column == 0 else space(12), 0))
            ttk.Label(card, text=caption, style="Caption.TLabel").pack(anchor="w")
            value = ttk.Label(card, text="0", style=tone)
            value.pack(anchor="w", pady=(space(3), 0))
            self.metric_labels[key] = value

        setup = ttk.Frame(frame, style="Card.TFrame", padding=space(12))
        setup.grid(row=2, sticky="ew", pady=(0, space(14)))
        setup.columnconfigure(0, weight=1)
        selector = ttk.Frame(setup, style="Card.TFrame")
        selector.grid(row=0, sticky="ew")
        selector.columnconfigure(1, weight=1)
        ttk.Label(selector, text="Network adapter", style="Card.TLabel").grid(
            row=0, column=0, padx=(0, space(14))
        )
        self.adapter = ttk.Combobox(selector, state="readonly", width=25, font="TkDefaultFont")
        self.adapter.grid(row=0, column=1, sticky="ew")
        self.adapter.bind("<<ComboboxSelected>>", self.show_details)
        self.refresh_button = ttk.Button(selector, text="Refresh", command=self.refresh)
        self.refresh_button.grid(row=0, column=2, padx=(space(12), 0))
        self.details = tk.StringVar(value="Loading adapters…")
        self.detail_label = ttk.Label(setup, text="Loading adapters…", style="Detail.TLabel")
        self.detail_label.grid(row=1, sticky="ew", pady=(space(8), space(10)))
        self.detail_label.bind(
            "<Configure>", lambda event: self.detail_label.configure(wraplength=event.width)
        )
        duration_row = ttk.Frame(setup, style="Card.TFrame")
        duration_row.grid(row=2, sticky="ew")
        ttk.Label(duration_row, text="Duration", style="Card.TLabel").pack(side="left")
        self.duration = ttk.Entry(duration_row, width=7, font="TkDefaultFont")
        self.duration.insert(0, "60")
        self.duration.pack(side="left", padx=space(10))
        ttk.Label(duration_row, text="sec (1–3600)", style="Detail.TLabel").pack(
            side="left", padx=(0, space(20))
        )
        self.save_log = tk.BooleanVar(value=False)
        self.log_option = ttk.Checkbutton(
            duration_row, text="Save rotating log", variable=self.save_log
        )
        self.log_option.pack(side="left")
        self.stop_button = ttk.Button(
            duration_row, text="Stop", command=self.stop, state="disabled"
        )
        self.stop_button.pack(side="right")
        self.start_button = ttk.Button(
            duration_row, text="Start capture", command=self.start, style="Accent.TButton"
        )
        self.start_button.pack(side="right", padx=space(10))
        reputation_row = ttk.Frame(setup, style="Card.TFrame")
        reputation_row.grid(row=3, sticky="ew", pady=(space(10), 0))
        self.enable_reputation = tk.BooleanVar(
            value=self.reputation is not None and self.reputation.enabled
        )
        self.reputation_option = ttk.Checkbutton(
            reputation_row,
            text="Reputation feeds",
            variable=self.enable_reputation,
            command=self.toggle_reputation,
        )
        self.reputation_option.pack(side="left")
        self.reputation_button = ttk.Button(
            reputation_row,
            text="Update feeds",
            command=self.refresh_reputation,
        )
        self.reputation_button.pack(side="right")
        self.reputation_summary = ttk.Label(setup, style="Detail.TLabel")
        self.reputation_summary.grid(row=4, sticky="ew", pady=(space(6), 0))
        self.reputation_summary.bind(
            "<Configure>", lambda event: self.reputation_summary.configure(wraplength=event.width)
        )
        stream = ttk.Frame(frame, style="Card.TFrame", padding=space(12))
        stream.grid(row=3, sticky="nsew")
        stream.columnconfigure(0, weight=1)
        stream.rowconfigure(2, weight=1)
        toolbar = ttk.Frame(stream, style="Card.TFrame")
        toolbar.grid(row=0, sticky="ew", pady=(0, space(8)))
        ttk.Label(toolbar, text="Live traffic · UTC", style="Section.TLabel").pack(side="left")
        self.activity = ttk.Label(toolbar, text="● READY", style="Badge.TLabel")
        self.activity.pack(side="left", padx=space(14))
        ttk.Button(toolbar, text="Clear view", command=self.clear_view).pack(side="right")
        self.status = tk.StringVar(value="Starting…")
        self.status_label = ttk.Label(stream, textvariable=self.status, style="Detail.TLabel")
        self.status_label.grid(row=1, sticky="ew", pady=(0, space(8)))
        self.status_label.bind(
            "<Configure>", lambda event: self.status_label.configure(wraplength=event.width)
        )
        output_frame = ttk.Frame(stream)
        output_frame.grid(row=2, sticky="nsew")
        output_frame.columnconfigure(0, weight=1)
        output_frame.rowconfigure(0, weight=1)
        self.output = tk.Text(
            output_frame,
            width=1,
            height=1,
            padx=space(12),
            pady=space(10),
            spacing1=space(3),
            spacing3=space(3),
            wrap="none",
            state="disabled",
            font="TkFixedFont",
            background=DARK["input"],
            foreground=DARK["text"],
            insertbackground=DARK["text"],
            selectbackground=DARK["selection"],
            selectforeground=DARK["text"],
            highlightbackground=DARK["border"],
            highlightcolor=DARK["accent"],
            highlightthickness=0,
            borderwidth=0,
        )
        self.output.grid(row=0, column=0, sticky="nsew")
        self.vertical = OverflowScrollbar(
            output_frame, orient="vertical", command=self.output.yview
        )
        self.vertical.grid(row=0, column=1, sticky="ns")
        self.output.configure(yscrollcommand=self.vertical.set)
        self.output.tag_configure("alert", foreground=DARK["alert"])
        self.output.tag_configure("time", foreground=DARK["muted"])
        self.output.tag_configure("protocol", foreground=DARK["accent"])
        self.empty_state = ttk.Label(
            output_frame,
            text="Your live traffic will appear here\n\nChoose an adapter and start a capture.",
            style="Empty.TLabel",
            justify="center",
            anchor="center",
        )
        self.empty_state.place(relx=0.5, rely=0.5, anchor="center")
        self.horizontal = OverflowScrollbar(stream, orient="horizontal", command=self.output.xview)
        self.horizontal.grid(row=3, sticky="ew")
        self.output.configure(xscrollcommand=self.horizontal.set)

    def apply_dark_theme(self):
        """Use a single explicit palette regardless of the Windows app theme."""
        for name in ("TkDefaultFont", "TkTextFont", "TkMenuFont", "TkHeadingFont"):
            tkfont.nametofont(name, root=self).configure(family="Segoe UI", size=10)
        tkfont.nametofont("TkFixedFont", root=self).configure(family="Consolas", size=11)
        self.configure(background=DARK["background"])
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure(
            ".",
            background=DARK["background"],
            foreground=DARK["text"],
            bordercolor=DARK["border"],
            lightcolor=DARK["border"],
            darkcolor=DARK["border"],
            focuscolor=DARK["accent"],
            troughcolor=DARK["background"],
            arrowcolor=DARK["text"],
            font="TkDefaultFont",
        )
        style.map(".", foreground=[("disabled", DARK["muted"])])
        style.configure("Card.TFrame", background=DARK["surface"])
        style.configure("Card.TLabel", background=DARK["surface"])
        style.configure("Title.TLabel", font=("Segoe UI", 20, "bold"))
        style.configure("Muted.TLabel", foreground=DARK["muted"])
        style.configure("Section.TLabel", background=DARK["surface"], font=("Segoe UI", 13, "bold"))
        style.configure("Detail.TLabel", background=DARK["surface"], foreground=DARK["muted"])
        style.configure(
            "Caption.TLabel",
            background=DARK["surface"],
            foreground=DARK["muted"],
            font=("Segoe UI", 8, "bold"),
        )
        style.configure("Metric.TLabel", background=DARK["surface"], font=("Segoe UI", 18, "bold"))
        style.configure(
            "AlertMetric.TLabel",
            background=DARK["surface"],
            foreground=DARK["alert"],
            font=("Segoe UI", 18, "bold"),
        )
        style.configure("Badge.TLabel", background=DARK["surface"], foreground=DARK["accent"])
        style.configure("Empty.TLabel", background=DARK["input"], foreground=DARK["muted"])
        style.configure(
            "TButton", background=DARK["active"], borderwidth=0, padding=(self.px(12), self.px(7))
        )
        style.map(
            "TButton",
            background=[("pressed", DARK["selection"]), ("active", DARK["active"])],
        )
        style.configure("Accent.TButton", background=DARK["accent"], foreground=DARK["input"])
        style.map(
            "Accent.TButton",
            background=[
                ("disabled", DARK["active"]),
                ("pressed", "#3aaaae"),
                ("active", "#85e5ec"),
            ],
            foreground=[("disabled", DARK["muted"]), ("!disabled", DARK["input"])],
        )
        for name in ("TEntry", "TCombobox"):
            style.configure(
                name,
                fieldbackground=DARK["input"],
                insertcolor=DARK["text"],
                selectbackground=DARK["selection"],
                selectforeground=DARK["text"],
                borderwidth=1,
                padding=self.px(6),
                arrowsize=self.px(14),
            )
            style.map(
                name,
                fieldbackground=[("disabled", DARK["surface"]), ("readonly", DARK["input"])],
                foreground=[("disabled", DARK["muted"]), ("readonly", DARK["text"])],
                background=[("active", DARK["active"]), ("!active", DARK["surface"])],
            )
        style.configure(
            "TCheckbutton",
            background=DARK["surface"],
            indicatorbackground=DARK["input"],
            padding=(0, self.px(4)),
        )
        style.map(
            "TCheckbutton",
            background=[("active", DARK["surface"])],
            indicatorbackground=[("selected", DARK["selection"]), ("!selected", DARK["input"])],
        )
        style.configure(
            "TScrollbar",
            background=DARK["border"],
            troughcolor=DARK["input"],
            gripsize=0,
            borderwidth=0,
            arrowsize=self.px(12),
            width=self.px(12),
        )
        style.map("TScrollbar", background=[("active", DARK["active"])])
        # Clam paints its grip inside the native thumb, controlled by gripsize.
        for orientation in ("Horizontal", "Vertical"):
            name = f"{orientation}.TScrollbar"
            style.map(
                name,
                background=[("disabled", DARK["input"]), ("active", DARK["active"])],
                arrowcolor=[("disabled", DARK["border"])],
                bordercolor=[("disabled", DARK["input"])],
                lightcolor=[("disabled", DARK["input"])],
                darkcolor=[("disabled", DARK["input"])],
            )
        style.configure("TSeparator", background=DARK["border"])
        for option, color in (
            ("background", "input"),
            ("foreground", "text"),
            ("selectBackground", "selection"),
            ("selectForeground", "text"),
        ):
            self.option_add(f"*TCombobox*Listbox.{option}", DARK[color])
        self.option_add("*TCombobox*Listbox.borderWidth", 0)
        self.option_add("*TCombobox*Listbox.font", "TkDefaultFont")
        # Request the native dark title bar when the Windows build supports it.
        if sys.platform == "win32":
            self.update_idletasks()
            try:
                parent = ctypes.windll.user32.GetParent
                parent.argtypes = [ctypes.c_void_p]
                parent.restype = ctypes.c_void_p
                set_attribute = ctypes.windll.dwmapi.DwmSetWindowAttribute
                set_attribute.argtypes = [
                    ctypes.c_void_p,
                    ctypes.c_uint,
                    ctypes.c_void_p,
                    ctypes.c_uint,
                ]
                dark = ctypes.c_int(1)
                set_attribute(parent(self.winfo_id()), 20, ctypes.byref(dark), ctypes.sizeof(dark))
            except AttributeError, OSError:
                pass  # Window contents keep their dark palette on older Windows builds.

    def refresh(self):
        if self.closing or self.controller.running or self.refresh_pending:
            return
        self.status.set("Loading Windows adapters…")
        self.phase = "loading"
        self.refresh_pending = True

        def load():
            try:
                self.refresh_results.put((self.controller.refresh(), None))
            except Exception as error:
                self.refresh_results.put(([], str(error)))

        self.refresh_thread = Thread(target=load, name="adapter-refresh", daemon=False)
        self.refresh_thread.start()
        self.set_controls()

    def apply_interfaces(self, interfaces, error):
        self.refresh_pending = False
        if self.closing:
            return
        if error is None:
            self.phase = "ready"
            self.capture_error = False
            self.adapter["values"] = [
                f"{i + 1}. {item.name} — {item.description}" for i, item in enumerate(interfaces)
            ]
            self.adapter.set("")
            if interfaces:
                self.adapter.current(0)
                self.show_details()
                self.status.set("Ready. Select an adapter and press Start.")
            else:
                self.set_details("No capture-capable adapters found.")
                self.status.set(
                    "Connect an adapter and press Refresh. Pktmon must support its IP layer."
                )
        else:
            self.phase = "error"
            self.capture_error = True
            self.adapter["values"] = []
            self.adapter.set("")
            self.set_details("Adapter information is unavailable.")
            self.status.set(error)
        self.set_controls()

    def show_details(self, event=None):
        index = self.adapter.current()
        if not 0 <= index < len(self.controller.interfaces):
            self.set_details("Select a network adapter.")
            return
        try:
            self.set_details(self.controller.backend.details(self.controller.interfaces[index]))
        except Exception as error:
            self.set_details(f"Adapter details unavailable: {error}")

    def set_details(self, text):
        self.details.set(text)
        self.detail_label.configure(text=text.replace("\n", "   ·   "))

    def set_controls(self):
        busy = (
            self.controller.running
            or not self.controller.records.empty()
            or not self.controller.events.empty()
            or self.refresh_pending
            or not self.refresh_results.empty()
        )
        editable = not busy and not self.closing
        self.adapter.configure(state="readonly" if editable else "disabled")
        for widget in (self.refresh_button, self.duration, self.log_option):
            widget.configure(state="normal" if editable else "disabled")
        self.start_button.configure(
            state="normal" if editable and self.controller.interfaces else "disabled",
        )
        self.stop_button.configure(
            state="normal"
            if (
                self.controller.running
                and not self.closing
                and not self.controller.stop_event.is_set()
            )
            else "disabled",
        )
        label = {
            "loading": "● LOADING",
            "ready": "● READY",
            "starting": "● STARTING",
            "capturing": "● CAPTURING",
            "ended": "● CAPTURE ENDED",
            "stopped": "● STOPPED",
            "error": "● CAPTURE ERROR",
        }[self.phase]
        if self.closing or self.controller.stop_event.is_set() and self.controller.running:
            label = "● STOPPING"
        elif self.capture_error:
            label = "● CAPTURE ERROR"
        elif busy and not self.controller.running and self.phase == "loading":
            label = "● LOADING"
        self.activity.configure(
            text=label, foreground=DARK["error" if self.capture_error else "accent"]
        )
        self.status_label.configure(foreground=DARK["error" if self.capture_error else "muted"])
        if (
            self.phase in ("ended", "stopped", "ready")
            and not self.capture_error
            and not self.closing
        ):
            self.status_label.grid_remove()
        else:
            self.status_label.grid()
        if self.output.compare("end-1c", "==", "1.0"):
            self.empty_state.configure(
                text="Listening for IP traffic…"
                if self.controller.running
                else "Your live traffic will appear here\n\nChoose an adapter and start a capture."
            )
            self.empty_state.place(relx=0.5, rely=0.5, anchor="center")
        else:
            self.empty_state.place_forget()

    def start(self):
        if self.closing:
            return
        try:
            self.controller.start(self.adapter.current(), self.duration.get(), self.save_log.get())
        except (ValueError, RuntimeError, OSError) as error:
            self.capture_error = True
            self.status.set(f"Cannot start capture: {error}")
            return
        self.capture_error = False
        self.phase = "starting"
        self.clear_view()
        self.status.set("Opening capture adapter…")
        self.set_controls()

    def stop(self):
        self.controller.stop()
        self.status.set("Stopping capture…")
        self.stop_button.configure(state="disabled")

    def clear_view(self):
        self.output.configure(state="normal")
        self.output.delete("1.0", "end")
        self.output.configure(state="disabled")

    def toggle_reputation(self):
        if self.reputation is not None:
            self.reputation.set_enabled(self.enable_reputation.get())

    def refresh_reputation(self):
        if self.reputation is not None:
            self.reputation.refresh(manual=True)

    def poll(self):
        # Only this Tk thread consumes queues and changes widgets.
        if self.reputation is not None:
            if not self.closing:
                self.reputation.refresh()
            summary = self.reputation.summary()
            if self.controller.suppressed_alerts:
                summary += (
                    f" · {self.controller.suppressed_alerts:,} notices suppressed at session limit"
                )
            self.reputation_summary.configure(text=summary)
            available = (
                not self.closing
                and not self.reputation.running
                and self.reputation.enabled
                and self.reputation.clock() >= self.reputation.next_allowed
            )
            self.reputation_button.configure(state="normal" if available else "disabled")
        else:
            self.reputation_summary.configure(text="Historical local matching only")
            self.reputation_button.configure(state="disabled")
            self.reputation_option.configure(state="disabled")
        try:
            self.apply_interfaces(*self.refresh_results.get_nowait())
        except Empty:
            pass
        follow_tail = self.output.yview()[1] >= 0.999
        appended = False
        self.output.configure(state="normal")
        for _ in range(200):
            try:
                record = self.controller.records.get_nowait()
            except Empty:
                break
            appended = True
            clock = record.time.partition("T")[2].removesuffix("+00:00")
            self.output.insert(
                "end",
                clock,
                "time",
                f"  IPv{record.version} {record.protocol:<7}",
                "protocol",
                "  " + record.line().split(" ", 3)[3] + "\n",
                "alert" if record.reputation else "traffic",
            )
        lines = int(self.output.index("end-1c").split(".")[0])
        if lines > MAX_ROWS:
            self.output.delete("1.0", f"{lines - MAX_ROWS + 1}.0")
        if appended and follow_tail:
            self.output.see("end")
        self.output.configure(state="disabled")
        while True:
            try:
                kind, text = self.controller.events.get_nowait()
            except Empty:
                break
            if kind == "error":
                self.capture_error = True
                self.phase = "error"
                self.status.set(text)
            elif not self.capture_error and not self.closing:
                self.phase = (
                    ("stopped" if self.controller.stop_event.is_set() else "ended")
                    if kind == "done"
                    else "capturing"
                )
                self.status.set(text)
        for key, value in (
            ("packets", self.controller.count),
            ("alerts", self.controller.alerts),
            ("display", self.controller.display_dropped),
            ("undecoded", getattr(self.controller.backend, "skipped", 0)),
        ):
            self.metric_labels[key].configure(text=f"{value:,}")
        if self.closing:
            if (
                not self.controller.running
                and not (self.refresh_thread is not None and self.refresh_thread.is_alive())
                and not (self.reputation is not None and self.reputation.running)
            ):
                if self.controller.thread is not None:
                    self.controller.thread.join()
                if self.refresh_thread is not None:
                    self.refresh_thread.join()
                if self.reputation is not None and self.reputation.thread is not None:
                    self.reputation.thread.join()
                self.destroy()
                return
            self.status.set(
                "Finishing reputation refresh before closing…"
                if self.reputation is not None and self.reputation.running
                else "Stopping capture before closing…"
            )
        self.set_controls()
        self.after(75, self.poll)

    def close(self):
        self.closing = True
        self.controller.stop()
        if self.reputation is not None:
            self.reputation.close()
        self.status.set("Stopping capture before closing…")
        self.set_controls()


def request_administrator(arguments):
    """Use the same environment's windowed interpreter for console-free UAC."""
    frozen = getattr(sys, "frozen", False)
    interpreter = Path(sys.executable) if frozen else Path(sys.executable).with_name("pythonw.exe")
    if not interpreter.is_file():
        raise OSError("pythonw.exe is missing from this Python environment.")
    launch_arguments = (
        [ELEVATED_ARGUMENT, *arguments]
        if frozen
        else ["-m", "network_packet_sniffer", ELEVATED_ARGUMENT, *arguments]
    )
    execute = ctypes.windll.shell32.ShellExecuteW
    execute.argtypes = [
        ctypes.c_void_p,
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_int,
    ]
    execute.restype = ctypes.c_void_p
    result = execute(
        None,
        "runas",
        str(interpreter),
        subprocess.list2cmdline(launch_arguments),
        str(Path.cwd()),
        1,
    )
    return result is not None and result > 32


def main(arguments=None):
    if tuple(sys.version_info) != (3, 14, 7, "final", 0):
        print(
            "This application requires Python 3.14.7 exactly. Run uv sync --locked.",
            file=sys.stderr,
        )
        return 1
    arguments = list(sys.argv[1:] if arguments is None else arguments)
    if sys.platform != "win32":
        print("Live Pktmon capture requires Windows.", file=sys.stderr)
        return 1
    if not is_administrator():
        # Verify the actual token; the marker only prevents an elevation retry loop.
        if ELEVATED_ARGUMENT in arguments:
            print("Administrator access was not granted. Please restart the app.", file=sys.stderr)
            return 1
        try:
            if request_administrator(arguments):
                return 0
        except OSError:
            pass
        print(
            "Administrator startup was cancelled or Windows could not launch it.",
            file=sys.stderr,
        )
        return 1
    # Detach only this Python process, preserving any PowerShell used to launch it.
    # Elevated relaunches use pythonw.exe and have no console to detach from.
    ctypes.windll.kernel32.FreeConsole()
    app = TrafficSnifferApp()
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
