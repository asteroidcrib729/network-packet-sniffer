"""Writable data stays outside the package in source and wheel installations."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from network_packet_sniffer.paths import data_directory


class DataPathTests(unittest.TestCase):
    def test_frozen_app_never_writes_to_install_directory_even_with_pyproject_present(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "pyproject.toml").touch()
            module = root / "_internal" / "network_packet_sniffer" / "paths.py"
            with (
                patch("network_packet_sniffer.paths.__file__", str(module)),
                patch("network_packet_sniffer.paths.sys.frozen", True, create=True),
                patch.dict("os.environ", {"LOCALAPPDATA": str(root / "AppData")}),
            ):
                self.assertEqual(data_directory(), root / "AppData" / "NetworkPacketSniffer")

    def test_editable_install_keeps_existing_project_data_independent_of_cwd(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "pyproject.toml").touch()
            module = root / "src" / "network_packet_sniffer" / "paths.py"
            with patch("network_packet_sniffer.paths.__file__", str(module)):
                self.assertEqual(data_directory(), root.resolve())

    def test_installed_wheel_uses_local_app_data_outside_site_packages(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            module = root / "Lib" / "site-packages" / "network_packet_sniffer" / "paths.py"
            with (
                patch("network_packet_sniffer.paths.__file__", str(module)),
                patch.dict("os.environ", {"LOCALAPPDATA": str(root / "AppData")}),
            ):
                self.assertEqual(data_directory(), root / "AppData" / "NetworkPacketSniffer")
