"""Release boundaries: source allowlists, exact tags, hashes, and signing modes."""

import hashlib
import json
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from release_tools.inspect_bundle import inspect
from release_tools.prepare import SOURCE_FILES, source_archive, version
from release_tools.release import normalize_tag, resolve, verify


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_source_archive_excludes_user_data_caches_secrets_and_bytecode(self):
        for name in SOURCE_FILES:
            (self.root / name).write_text("fixture")
        for name in (
            "src/app.py",
            "src/__pycache__/app.pyc",
            "src/.env",
            "src/signing.pfx",
            "packaging/private.key",
            "cache/reputation.json",
            "logs/traffic.log",
            "packaged-releases/key.pfx",
            "tests/test_app.py",
        ):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("fixture")
        first, second = self.root / "one.zip", self.root / "two.zip"
        self.assertEqual(source_archive(self.root, first), source_archive(self.root, second))
        self.assertEqual(first.read_bytes(), second.read_bytes())
        with zipfile.ZipFile(first) as archive:
            self.assertEqual(
                set(archive.namelist()), {*SOURCE_FILES, "src/app.py", "tests/test_app.py"}
            )

    def bundle(self):
        executable = self.root / "app.exe"
        data = bytearray(512)
        struct.pack_into("<I", data, 0x3C, 128)
        data[128:132] = b"PE\x00\x00"
        struct.pack_into("<H", data, 128 + 24 + 68, 2)
        data.extend(b'level="requireAdministrator"')
        executable.write_bytes(data)
        analysis = self.root / "Analysis.toc"
        analysis.write_text(
            repr([("runtime.dll", str(self.root / "python/runtime.dll"), "BINARY")])
        )
        return analysis, executable

    def test_bundle_accepts_only_expected_runtime_sources_and_windowed_admin_manifest(self):
        analysis, executable = self.bundle()
        inspect(analysis, executable, allowed=(self.root / "python",))

    def test_bundle_rejects_unrelated_path_dll_and_console_executable(self):
        analysis, executable = self.bundle()
        with self.assertRaisesRegex(ValueError, "Unrelated DLL"):
            inspect(analysis, executable, allowed=(self.root / "another-python",))
        data = bytearray(executable.read_bytes())
        struct.pack_into("<H", data, 128 + 24 + 68, 3)
        executable.write_bytes(data)
        with self.assertRaisesRegex(ValueError, "GUI subsystem"):
            inspect(analysis, executable, allowed=(self.root / "python",))

    def test_version_must_fit_msix_numeric_components(self):
        for value in ("1.2", "1.2.3rc1", "1.2.65536", "1.2.3.4"):
            (self.root / "pyproject.toml").write_text(f'[project]\nversion="{value}"')
            with self.subTest(value=value), self.assertRaises(ValueError):
                version(self.root)

    def test_tag_input_is_normalized_and_rejects_non_tags_and_shell_text(self):
        self.assertEqual(normalize_tag("0.5.0"), "v0.5.0")
        for value in ("main", "v1.2", "v1.2.3; command", "--latest", "../v1.2.3"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize_tag(value)

    def test_branch_preview_has_no_tag_and_drafts_require_existing_matching_commit(self):
        with (
            patch.dict("os.environ", {"GITHUB_REF_TYPE": "branch"}, clear=True),
            patch("release_tools.release.version", return_value="0.5.0"),
            patch("release_tools.release.git", side_effect=["abc", "abc", "def"]),
        ):
            self.assertEqual(resolve()["tag"], "")
            with self.assertRaisesRegex(ValueError, "checked-out commit"):
                resolve(draft=True)

    def test_tag_build_rejects_version_mismatch(self):
        with (
            patch.dict(
                "os.environ", {"GITHUB_REF_TYPE": "tag", "GITHUB_REF_NAME": "v0.4.0"}, clear=True
            ),
            patch("release_tools.release.version", return_value="0.5.0"),
            patch("release_tools.release.git", return_value="abc"),
        ):
            with self.assertRaisesRegex(ValueError, "match pyproject"):
                resolve()

    def fixture(self):
        assets = []
        for name in ("x64-setup.exe", "x64.msix", "source.zip"):
            name = "NetworkPacketSniffer-0.5.0-" + name
            (self.root / name).write_bytes(b"fixture")
            assets.append(
                {"name": name, "size": 7, "sha256": hashlib.sha256(b"fixture").hexdigest()}
            )
        manifest = {
            "version": "0.5.0",
            "python": "3.14.7",
            "source_commit": "abc",
            "source_dirty": False,
            "signing_mode": "preview",
            "assets": assets,
        }
        self.write(manifest)
        return manifest

    def write(self, manifest):
        raw = json.dumps(manifest).encode()
        (self.root / "release.json").write_bytes(raw)
        lines = [f"{item['sha256']}  {item['name']}" for item in manifest["assets"]]
        lines.append(f"{hashlib.sha256(raw).hexdigest()}  release.json")
        (self.root / "SHA256SUMS.txt").write_text("\n".join(lines) + "\n")

    def test_checksum_file_must_cover_manifest_and_all_assets(self):
        self.fixture()
        (self.root / "SHA256SUMS.txt").write_text("")
        with self.assertRaisesRegex(ValueError, "disagrees"):
            verify(self.root)

    def test_preview_can_be_verified_but_cannot_be_published_as_stable(self):
        self.fixture()
        verify(self.root)
        with self.assertRaisesRegex(ValueError, "production certificate"):
            verify(self.root, prerelease=False)

    def test_tampered_or_missing_asset_is_rejected(self):
        manifest = self.fixture()
        (self.root / manifest["assets"][0]["name"]).write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            verify(self.root)

    def test_path_traversal_or_duplicate_asset_names_are_rejected(self):
        manifest = self.fixture()
        manifest["assets"].insert(0, {"name": "../outside", "size": 0, "sha256": ""})
        self.write(manifest)
        with self.assertRaisesRegex(ValueError, "Unsafe"):
            verify(self.root)
        manifest = self.fixture()
        manifest["assets"].append(manifest["assets"][0])
        self.write(manifest)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            verify(self.root)

    def test_release_rejects_dirty_source_or_wrong_commit(self):
        manifest = self.fixture()
        with patch("release_tools.release.git", return_value="different"):
            with self.assertRaisesRegex(ValueError, "tag's commit"):
                verify(self.root, "v0.5.0")
        manifest["source_dirty"] = True
        self.write(manifest)
        with patch("release_tools.release.git", return_value="abc"):
            with self.assertRaisesRegex(ValueError, "unchanged"):
                verify(self.root, "v0.5.0")
