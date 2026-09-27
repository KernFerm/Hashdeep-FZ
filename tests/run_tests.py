#!/usr/bin/env python3
"""Deterministic compatibility and repository checks for Hashdeep FZ."""
from __future__ import annotations

import hashlib
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).parents[1]


def digests(path: pathlib.Path, chunk: int = 1024) -> tuple[int, str, str, str]:
    contexts = (hashlib.md5(), hashlib.sha1(), hashlib.sha256())  # nosec: compatibility test
    size = 0
    with path.open("rb") as source:
        while block := source.read(chunk):
            size += len(block)
            for context in contexts:
                context.update(block)
    return (size, *(context.hexdigest() for context in contexts))


def manifest_line(path: pathlib.Path) -> str:
    size, md5, sha1, sha256 = digests(path)
    return f"{size},{md5},{sha1},{sha256},{path}\n"


def parse_line(line: str) -> tuple[int, str, str, str, str]:
    fields = line.rstrip("\r\n").split(",", 4)
    if len(fields) != 5:
        raise ValueError("field count")
    size = int(fields[0])
    lengths = (32, 40, 64)
    for value, length in zip(fields[1:4], lengths):
        if len(value) != length or any(c not in "0123456789abcdefABCDEF" for c in value):
            raise ValueError("digest")
    if not fields[4]:
        raise ValueError("path")
    return size, fields[1], fields[2], fields[3], fields[4]


class HashCompatibilityTests(unittest.TestCase):
    def hash_bytes(self, data: bytes) -> tuple[str, str, str]:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "input.bin"
            path.write_bytes(data)
            return digests(path)[1:]

    def test_known_vectors(self):
        self.assertEqual(self.hash_bytes(b"")[0], "d41d8cd98f00b204e9800998ecf8427e")
        self.assertEqual(self.hash_bytes(b"abc"), (
            "900150983cd24fb0d6963f7d28e17f72",
            "a9993e364706816aba3e25717850c26c9cd0d89d",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ))
        self.assertEqual(self.hash_bytes(b"a")[2], "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb")

    def test_chunk_boundaries_and_large(self):
        for size in (1023, 1024, 1025, 1024 * 1024 + 17):
            data = bytes((index * 31) & 0xFF for index in range(size))
            self.assertEqual(self.hash_bytes(data)[2], hashlib.sha256(data).hexdigest())

    def test_manifest_changed_missing_malformed_duplicate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            first, second = root / "a", root / "b"
            first.write_bytes(b"one")
            second.write_bytes(b"two")
            rows = [manifest_line(first), manifest_line(second)]
            parsed = [parse_line(row) for row in rows]
            self.assertEqual(len({entry[4] for entry in parsed}), 2)
            first.write_bytes(b"changed")
            self.assertNotEqual(parse_line(rows[0])[2], digests(first)[1])
            second.unlink()
            self.assertFalse(second.exists())
            with self.assertRaises(ValueError):
                parse_line("3,not-a-digest,/tmp/a\n")
            duplicate = rows + [rows[0]]
            self.assertNotEqual(len({parse_line(row)[4] for row in duplicate}), len(duplicate))
            third = root / "new.bin"
            third.write_bytes(b"not in manifest")
            listed = {pathlib.Path(parse_line(row)[4]) for row in rows}
            actual = {path for path in root.iterdir() if path.is_file()}
            self.assertEqual(actual - listed, {third})

    def test_source_has_no_unfinished_markers(self):
        sources = list(ROOT.glob("*.c")) + list(ROOT.glob("*.h"))
        for source in sources:
            text = source.read_text(encoding="utf-8")
            self.assertNotIn("TODO", text, source.name)
            self.assertNotIn("placeholder", text.lower(), source.name)
            self.assertNotIn("simulated result", text.lower(), source.name)

    def test_spec_is_ignored(self):
        ignore = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
        self.assertIn("/to-do.md", ignore)


if __name__ == "__main__":
    unittest.main(verbosity=2)
