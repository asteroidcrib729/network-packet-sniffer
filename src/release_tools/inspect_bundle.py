"""Reject unrelated DLL sources and require a windowed administrator executable."""

import ast
import os
import struct
import sys
from pathlib import Path


def inspect(analysis, executable, allowed=None):
    allowed = allowed or (Path(sys.base_prefix), Path(sys.prefix), Path(os.environ["SystemRoot"]))
    roots = tuple(path.resolve() for path in allowed)

    def walk(node):
        if not isinstance(node, (tuple, list)):
            return
        if len(node) == 3 and node[2] in ("BINARY", "EXTENSION"):
            source = Path(node[1]).resolve()
            if not any(source.is_relative_to(root) for root in roots):
                raise ValueError(f"Unrelated DLL source in bundle: {source}")
        for child in node:
            walk(child)

    walk(ast.literal_eval(Path(analysis).read_text(encoding="utf-8")))
    data = Path(executable).read_bytes()
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe : pe + 4] != b"PE\x00\x00":
        raise ValueError("Expected a Windows PE executable.")
    if struct.unpack_from("<H", data, pe + 24 + 68)[0] != 2:
        raise ValueError("Expected Windows GUI subsystem; a console must not open.")
    if b'level="requireAdministrator"' not in data:
        raise ValueError("Missing embedded administrator manifest.")


if __name__ == "__main__":
    inspect(sys.argv[1], sys.argv[2])
    print("Bundle DLL origins, GUI subsystem, and administrator manifest verified.")
