"""A private Windows pseudoconsole for prompt, interactive command output."""

from __future__ import annotations

import ctypes as c
import os
import subprocess
from ctypes import wintypes as w


class Coord(c.Structure):
    _fields_ = [("x", c.c_short), ("y", c.c_short)]


class StartupInfo(c.Structure):
    _fields_ = [
        ("cb", w.DWORD),
        ("reserved", w.LPWSTR),
        ("desktop", w.LPWSTR),
        ("title", w.LPWSTR),
        ("x", w.DWORD),
        ("y", w.DWORD),
        ("width", w.DWORD),
        ("height", w.DWORD),
        ("chars_x", w.DWORD),
        ("chars_y", w.DWORD),
        ("fill", w.DWORD),
        ("flags", w.DWORD),
        ("show", w.WORD),
        ("reserved_size", w.WORD),
        ("reserved_bytes", c.c_void_p),
        ("stdin", w.HANDLE),
        ("stdout", w.HANDLE),
        ("stderr", w.HANDLE),
    ]


class StartupInfoEx(c.Structure):
    _fields_ = [("info", StartupInfo), ("attributes", c.c_void_p)]


class ProcessInfo(c.Structure):
    _fields_ = [
        ("process", w.HANDLE),
        ("thread", w.HANDLE),
        ("pid", w.DWORD),
        ("tid", w.DWORD),
    ]


class ConsoleProcess:
    """Own the child, terminal, input pipe, and output stream; never use a global stop."""

    def __init__(self, arguments: list[str]):
        import msvcrt

        self.arguments = arguments
        self.kernel = k = c.WinDLL("kernel32", use_last_error=True)
        handle_pointer = c.POINTER(w.HANDLE)
        specs = {
            "CreatePipe": ([handle_pointer, handle_pointer, c.c_void_p, w.DWORD], w.BOOL),
            "CreatePseudoConsole": ([Coord, w.HANDLE, w.HANDLE, w.DWORD, handle_pointer], w.LONG),
            "ClosePseudoConsole": ([w.HANDLE], None),
            "CloseHandle": ([w.HANDLE], w.BOOL),
            "InitializeProcThreadAttributeList": (
                [c.c_void_p, w.DWORD, w.DWORD, c.POINTER(c.c_size_t)],
                w.BOOL,
            ),
            "UpdateProcThreadAttribute": (
                [c.c_void_p, w.DWORD, c.c_size_t, c.c_void_p, c.c_size_t, c.c_void_p, c.c_void_p],
                w.BOOL,
            ),
            "DeleteProcThreadAttributeList": ([c.c_void_p], None),
            "CreateProcessW": (
                [
                    w.LPCWSTR,
                    w.LPWSTR,
                    c.c_void_p,
                    c.c_void_p,
                    w.BOOL,
                    w.DWORD,
                    c.c_void_p,
                    w.LPCWSTR,
                    c.POINTER(StartupInfoEx),
                    c.POINTER(ProcessInfo),
                ],
                w.BOOL,
            ),
            "WaitForSingleObject": ([w.HANDLE, w.DWORD], w.DWORD),
            "GetExitCodeProcess": ([w.HANDLE, c.POINTER(w.DWORD)], w.BOOL),
            "WriteFile": ([w.HANDLE, c.c_void_p, w.DWORD, c.POINTER(w.DWORD), c.c_void_p], w.BOOL),
        }
        for name, (arguments_types, result_type) in specs.items():
            function = getattr(k, name)
            function.argtypes, function.restype = arguments_types, result_type
        input_read, self.input_write = w.HANDLE(), w.HANDLE()
        output_read, output_write = w.HANDLE(), w.HANDLE()
        self.console, self.process = w.HANDLE(), None
        attributes = None
        initialized = False
        try:
            self.check(k.CreatePipe(c.byref(input_read), c.byref(self.input_write), None, 0))
            self.check(k.CreatePipe(c.byref(output_read), c.byref(output_write), None, 0))
            status = k.CreatePseudoConsole(
                Coord(1200, 40),
                input_read,
                output_write,
                0,
                c.byref(self.console),
            )
            if status < 0:
                raise OSError(f"Windows pseudoconsole creation failed: 0x{status & 0xFFFFFFFF:08X}")
            size = c.c_size_t()
            k.InitializeProcThreadAttributeList(None, 1, 0, c.byref(size))
            attributes = c.create_string_buffer(size.value)
            self.check(k.InitializeProcThreadAttributeList(attributes, 1, 0, c.byref(size)))
            initialized = True
            self.check(
                k.UpdateProcThreadAttribute(
                    attributes,
                    0,
                    0x00020016,
                    self.console,
                    c.sizeof(w.HANDLE),
                    None,
                    None,
                )
            )
            startup, process = StartupInfoEx(), ProcessInfo()
            startup.info.cb = c.sizeof(startup)
            # Explicit null standard handles let the console attach initialize them;
            # otherwise a redirected Python parent can leak its stdout into the child.
            startup.info.flags = 0x00000100
            startup.attributes = c.cast(attributes, c.c_void_p)
            command = c.create_unicode_buffer(subprocess.list2cmdline(arguments))
            self.check(
                k.CreateProcessW(
                    arguments[0],
                    command,
                    None,
                    None,
                    False,
                    0x00080000,
                    None,
                    None,
                    c.byref(startup),
                    c.byref(process),
                )
            )
            self.process, self.pid = process.process, process.pid
            k.CloseHandle(process.thread)
            descriptor = msvcrt.open_osfhandle(output_read.value, os.O_RDONLY | os.O_BINARY)
            output_read = w.HANDLE()  # The Python stream now owns this handle.
            self.stdout = os.fdopen(descriptor, "rb")
        except BaseException:
            if output_read:
                k.CloseHandle(output_read)
            self.close()
            raise
        finally:
            if initialized:
                k.DeleteProcThreadAttributeList(attributes)
            for handle in (input_read, output_write):
                if handle:
                    k.CloseHandle(handle)

    @staticmethod
    def check(success):
        if not success:
            raise c.WinError(c.get_last_error())

    def poll(self):
        result = self.kernel.WaitForSingleObject(self.process, 0)
        if result == 258:
            return None
        self.check(result == 0)
        code = w.DWORD()
        self.check(self.kernel.GetExitCodeProcess(self.process, c.byref(code)))
        return code.value

    def wait(self, timeout):
        result = self.kernel.WaitForSingleObject(self.process, int(timeout * 1000))
        if result == 258:
            raise subprocess.TimeoutExpired(self.arguments, timeout)
        self.check(result == 0)
        return self.poll()

    def interrupt(self):
        written = w.DWORD()
        self.check(self.kernel.WriteFile(self.input_write, b"\x03", 1, c.byref(written), None))

    def close(self):
        # The caller must keep draining stdout while ClosePseudoConsole runs.
        if self.input_write:
            self.kernel.CloseHandle(self.input_write)
            self.input_write = w.HANDLE()
        if self.console:
            self.kernel.ClosePseudoConsole(self.console)
            self.console = w.HANDLE()
        if self.process:
            self.kernel.CloseHandle(self.process)
            self.process = None
