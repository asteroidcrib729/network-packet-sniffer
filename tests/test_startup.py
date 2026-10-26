"""Startup elevation regressions; these never display a UAC prompt."""

import io
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from network_packet_sniffer import main as entry


class StartupTests(unittest.TestCase):
    def setUp(self):
        self.addCleanup(patch.stopall)
        patch("network_packet_sniffer.main.sys.platform", "win32").start()
        self.admin = patch(
            "network_packet_sniffer.main.is_administrator", return_value=False
        ).start()
        self.gui = patch("network_packet_sniffer.main.TrafficSnifferApp").start()
        self.elevate = patch(
            "network_packet_sniffer.main.request_administrator", return_value=True
        ).start()
        self.stderr = patch(
            "network_packet_sniffer.main.sys.stderr", new_callable=io.StringIO
        ).start()
        self.detach = patch(
            "network_packet_sniffer.main.ctypes.windll.kernel32.FreeConsole"
        ).start()

    def test_administrator_opens_gui_without_requesting_elevation(self):
        self.admin.return_value = True
        self.assertEqual(entry.main([entry.ELEVATED_ARGUMENT]), 0)
        self.elevate.assert_not_called()
        self.gui.assert_called_once_with()
        self.gui.return_value.mainloop.assert_called_once_with()
        self.detach.assert_called_once_with()

    def test_normal_startup_relaunches_before_creating_gui(self):
        with patch("network_packet_sniffer.main.sys.argv", ["main.py", "argument with spaces"]):
            self.assertEqual(entry.main(), 0)
        self.elevate.assert_called_once_with(["argument with spaces"])
        self.gui.assert_not_called()
        self.detach.assert_not_called()

    def test_cancelled_uac_exits_without_gui(self):
        self.elevate.return_value = False
        self.assertEqual(entry.main([]), 1)
        self.gui.assert_not_called()
        self.assertIn("cancelled", self.stderr.getvalue())

    def test_windows_launch_error_exits_without_gui(self):
        self.elevate.side_effect = OSError("Launch failed")
        self.assertEqual(entry.main([]), 1)
        self.gui.assert_not_called()
        self.assertIn("could not launch", self.stderr.getvalue())

    def test_marker_does_not_bypass_admin_check_or_repeat_prompt(self):
        self.assertEqual(entry.main([entry.ELEVATED_ARGUMENT]), 1)
        self.admin.assert_called_once_with()
        self.elevate.assert_not_called()
        self.gui.assert_not_called()
        self.assertIn("not granted", self.stderr.getvalue())

    def test_other_python_versions_exit_before_elevation_or_gui(self):
        for version in (
            (3, 14, 6, "final", 0),
            (3, 14, 8, "final", 0),
            (3, 13, 7, "final", 0),
            (3, 15, 0, "final", 0),
            (3, 14, 7, "candidate", 1),
        ):
            with (
                self.subTest(version=version),
                patch("network_packet_sniffer.main.sys.version_info", version),
            ):
                self.assertEqual(entry.main([]), 1)
        self.admin.assert_not_called()
        self.elevate.assert_not_called()
        self.gui.assert_not_called()
        self.assertIn("Python 3.14.7 exactly", self.stderr.getvalue())

    def test_unsupported_platform_exits_without_elevation_or_gui(self):
        with patch("network_packet_sniffer.main.sys.platform", "linux"):
            self.assertEqual(entry.main([]), 1)
        self.admin.assert_not_called()
        self.elevate.assert_not_called()
        self.gui.assert_not_called()
        self.assertIn("requires Windows", self.stderr.getvalue())


@unittest.skipUnless(sys.platform == "win32", "Windows ShellExecute binding")
class ShellExecuteTests(unittest.TestCase):
    def test_frozen_uac_relaunches_itself_without_requiring_pythonw(self):
        executable = Path(r"C:\installed app\NetworkPacketSniffer.exe")
        with (
            patch("network_packet_sniffer.main.sys.frozen", True, create=True),
            patch("network_packet_sniffer.main.sys.executable", str(executable)),
            patch("network_packet_sniffer.main.Path.is_file", return_value=True),
            patch(
                "network_packet_sniffer.main.ctypes.windll.shell32.ShellExecuteW", return_value=33
            ) as launch,
        ):
            self.assertTrue(entry.request_administrator(["argument with spaces"]))
        self.assertEqual(launch.call_args.args[2], str(executable))
        self.assertEqual(
            launch.call_args.args[3],
            subprocess.list2cmdline([entry.ELEVATED_ARGUMENT, "argument with spaces"]),
        )

    def test_uac_uses_windowed_interpreter_package_and_quoted_arguments(self):
        arguments = ["argument with spaces", 'embedded"quote', "trailing\\"]
        with (
            patch(
                "network_packet_sniffer.main.ctypes.windll.shell32.ShellExecuteW", return_value=33
            ) as launch,
        ):
            self.assertTrue(entry.request_administrator(arguments))
        launch.assert_called_once_with(
            None,
            "runas",
            str(Path(sys.executable).with_name("pythonw.exe")),
            subprocess.list2cmdline(
                ["-m", "network_packet_sniffer", entry.ELEVATED_ARGUMENT, *arguments]
            ),
            str(Path.cwd()),
            1,
        )

    def test_missing_windowed_python_does_not_launch_console_python(self):
        with (
            patch("network_packet_sniffer.main.Path.is_file", return_value=False),
            patch("network_packet_sniffer.main.ctypes.windll.shell32.ShellExecuteW") as launch,
        ):
            with self.assertRaisesRegex(OSError, "pythonw.exe"):
                entry.request_administrator([])
        launch.assert_not_called()

    def test_shell_failure_codes_are_rejected(self):
        with patch("network_packet_sniffer.main.ctypes.windll.shell32.ShellExecuteW") as launch:
            for code in (None, 0, 5, 31, 32):
                with self.subTest(code=code):
                    launch.return_value = code
                    self.assertFalse(entry.request_administrator([]))


if __name__ == "__main__":
    unittest.main()
