"""Check Windows' real pseudoconsole without elevation or packet capture."""

import os
import sys
import threading
import unittest
from pathlib import Path

from network_packet_sniffer.windows_console import ConsoleProcess


@unittest.skipUnless(sys.platform == "win32", "Windows pseudoconsole test")
class ConsoleTests(unittest.TestCase):
    def test_console_output_is_captured_and_all_handles_close(self):
        executable = Path(os.environ["SystemRoot"]) / "System32" / "cmd.exe"
        child = ConsoleProcess([str(executable), "/d", "/c", "echo pseudoconsole-regression"])
        output = []

        def read():
            while data := child.stdout.readline():
                output.append(data)

        reader = threading.Thread(target=read, daemon=True)
        reader.start()
        try:
            self.assertEqual(child.wait(5), 0)
        finally:
            child.close()
            reader.join(timeout=3)
            if not reader.is_alive():
                child.stdout.close()
        self.assertFalse(reader.is_alive())
        self.assertIn(b"pseudoconsole-regression", b"".join(output))
        self.assertIsNone(child.process)
        self.assertFalse(child.console)
        self.assertFalse(child.input_write)
