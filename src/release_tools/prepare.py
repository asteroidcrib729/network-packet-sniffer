"""Prepare an allowlisted source archive, attribution, and build provenance."""

import hashlib
import importlib.metadata
import json
import re
import shutil
import ssl
import subprocess
import sys
import tkinter
import tomllib
import zipfile
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE_FILES = (
    "README.md",
    "LICENSE",
    "NOTICE",
    "pyproject.toml",
    "uv.lock",
    ".python-version",
    ".gitignore",
)
SOURCE_DIRECTORIES = ("src", "tests", "packaging", ".github", "development-plan")


def version(root=ROOT):
    value = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"][
        "version"
    ]
    if not re.fullmatch(r"\d+\.\d+\.\d+", value) or any(int(n) > 65535 for n in value.split(".")):
        raise ValueError("Packaging requires a three-part numeric version, each part <= 65535.")
    return value


def source_files(root):
    files = [root / name for name in SOURCE_FILES]
    files.extend(path for name in SOURCE_DIRECTORIES for path in (root / name).rglob("*"))
    for path in sorted(files):
        relative = path.relative_to(root)
        if not path.is_file() or "__pycache__" in relative.parts or path.suffix in (".pyc", ".pyo"):
            continue
        if any(part.startswith(".env") for part in relative.parts) or path.suffix.lower() in (
            ".pfx",
            ".p12",
            ".pem",
            ".key",
        ):
            continue
        path.resolve().relative_to(root.resolve())
        yield relative, path


def source_archive(root, target):
    hashes = {}
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for relative, path in source_files(root):
            data = path.read_bytes()
            name = relative.as_posix()
            hashes[name] = hashlib.sha256(data).hexdigest()
            entry = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            entry.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(entry, data)
    return hashlib.sha256(json.dumps(hashes, sort_keys=True).encode()).hexdigest()


def git(*arguments):
    return subprocess.check_output(["git", *arguments], cwd=ROOT, text=True).strip()


def prepare(output):
    if tuple(sys.version_info) != (3, 14, 7, "final", 0):
        raise RuntimeError("Release builds require Python 3.14.7 final exactly.")
    output = output.resolve()
    output.relative_to((ROOT / "packaged-releases").resolve())
    output.mkdir(parents=True, exist_ok=True)
    current_version = version()
    source = output / f"NetworkPacketSniffer-{current_version}-source.zip"
    source_digest = source_archive(ROOT, source)
    for name in ("LICENSE", "NOTICE", "README.md"):
        shutil.copy2(ROOT / name, output / name)
    licenses = output / "licenses"
    licenses.mkdir(exist_ok=True)
    for notice in (ROOT / "packaging" / "licenses").glob("*"):
        if notice.is_file():
            shutil.copy2(notice, licenses / notice.name)
    shutil.copy2(Path(sys.base_prefix) / "LICENSE.txt", licenses / "Python-LICENSE.txt")
    # Python distributions may keep Tcl/Tk data on disk or embedded in DLL zipfs.
    window = tkinter.Tk()
    window.withdraw()
    try:
        for component, directory in (
            ("Tcl", window.tk.eval("info library")),
            ("Tk", window.tk.eval("set tk_library")),
        ):
            handle = window.tk.call("open", directory + "/license.terms", "r")
            try:
                text = window.tk.call("read", handle)
            finally:
                window.tk.call("close", handle)
            (licenses / f"{component}-license.terms").write_text(text, encoding="utf-8")
        tk_version = window.tk.eval("package present Tk")
    finally:
        window.destroy()
    # Include PyInstaller's bootloader exception and dependency notices verbatim.
    tools = {}
    for name in (
        "pyinstaller",
        "pyinstaller-hooks-contrib",
        "altgraph",
        "packaging",
        "pefile",
        "pywin32-ctypes",
        "setuptools",
    ):
        distribution = importlib.metadata.distribution(name)
        tools[name] = distribution.version
        for item in distribution.files or ():
            if any(token in item.name.lower() for token in ("license", "copying", "notice")):
                if item.suffix.lower() not in (".py", ".pyc") and ".dist-info" in str(item):
                    target = licenses / name / Path(*item.parts[1:])
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(distribution.locate_file(item), target)
    (output / "THIRD_PARTY_NOTICES.txt").write_text(
        "The application bundles CPython 3.14.7, its standard library and native dependencies, "
        "Tcl/Tk, and the PyInstaller bootloader. Original terms are in licenses/.\n"
        "Python-LICENSE.txt includes Python and bundled component terms; Tcl/Tk have their "
        "own license. PyInstaller's license includes its bootloader exception.\n"
        "Additional build-tool notices are retained for transparency; their presence does not "
        "mean every build tool is a runtime dependency.\n"
        "Windows Pktmon and Windows system components are provided by Windows and are not "
        "redistributed. Spamhaus feeds are fetched after launch and are not bundled.\n",
        encoding="utf-8",
    )
    metadata = {
        "version": current_version,
        "python": "3.14.7",
        "architecture": "x64",
        "tk": tk_version,
        "openssl": ssl.OPENSSL_VERSION,
        "zlib": zlib.ZLIB_VERSION,
        "source_commit": git("rev-parse", "HEAD"),
        "source_dirty": bool(git("status", "--porcelain")),
        "source_tree_sha256": source_digest,
        "source_archive": source.name,
        "source_archive_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "lock_sha256": hashlib.sha256((ROOT / "uv.lock").read_bytes()).hexdigest(),
        "license": "Apache-2.0",
        "author": "Faraz Hussain",
        "build_tools": tools,
    }
    (output / "build-info.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    parts = ", ".join([*current_version.split("."), "0"])
    (output / "version-resource.txt").write_text(
        f"VSVersionInfo(ffi=FixedFileInfo(filevers=({parts}), prodvers=({parts}), "
        "mask=0x3f, flags=0, OS=0x40004, fileType=1, subtype=0, date=(0,0)), kids=["
        "StringFileInfo([StringTable('040904B0', ["
        "StringStruct('CompanyName','Faraz Hussain'),"
        "StringStruct('FileDescription','Network Packet Sniffer'),"
        f"StringStruct('FileVersion','{current_version}'),"
        "StringStruct('LegalCopyright','Copyright 2023-2026 Faraz Hussain'),"
        "StringStruct('ProductName','Network Packet Sniffer'),"
        f"StringStruct('ProductVersion','{current_version}')])]),"
        "VarFileInfo([VarStruct('Translation',[1033,1200])])])",
        encoding="utf-8",
    )


if __name__ == "__main__":
    prepare(Path(sys.argv[1]))
