#!/usr/bin/env python3
"""Bounded UART bridge to the genuine upstream hashdeep executable."""
from __future__ import annotations

import argparse
import os
import pathlib
import re
import signal
import subprocess
import threading
import time
from dataclasses import dataclass

import serial

PROTOCOL = 1
BRIDGE_VERSION = "1.0.4"
ROOT = pathlib.Path("/var/lib/hashdeep-fz")
INPUT = ROOT / "input"
OUTPUT = ROOT / "output"
MANIFEST = ROOT / "known.hashdeep"
REPORT = OUTPUT / "hashdeep-report.txt"
HASHDEEP_CANDIDATES = ("/usr/bin/hashdeep", "/usr/local/bin/hashdeep")


@dataclass
class State:
    name: str = "IDLE"
    files: int = 0
    bytes: int = 0
    matched: int = 0
    changed: int = 0
    missing: int = 0
    new_files: int = 0
    exit_code: int = 0
    target: str = "none"
    error: str = ""


def safe_token(value: str, limit: int = 63) -> str:
    clean = "".join(c if c.isalnum() or c in "._-" else "_" for c in value)
    return (clean or "none")[:limit]


def discover_version(executable: str) -> str:
    for flag in ("-V", "--version"):
        try:
            result = subprocess.run([executable, flag], capture_output=True, text=True, timeout=5, check=False)
            text = (result.stdout or result.stderr).strip().splitlines()
            if text:
                return safe_token(text[0], 31)
        except (OSError, subprocess.TimeoutExpired):
            pass
    return "unknown"


def find_hashdeep() -> str:
    for candidate in HASHDEEP_CANDIDATES:
        path = pathlib.Path(candidate)
        if path.is_file() and os.access(path, os.X_OK):
            return candidate
    raise FileNotFoundError("hashdeep_not_installed_in_usr_bin_or_usr_local_bin")


def measured_tree(path: pathlib.Path) -> tuple[int, int]:
    files = size = 0
    if not path.exists():
        return files, size
    def walk_error(error: OSError) -> None:
        raise error

    for root, dirs, names in os.walk(path, followlinks=False, onerror=walk_error):
        dirs[:] = [name for name in dirs if not (pathlib.Path(root) / name).is_symlink()]
        for name in names:
            candidate = pathlib.Path(root) / name
            if candidate.is_file() and not candidate.is_symlink():
                files += 1
                size += candidate.stat().st_size
    return files, size


class Bridge:
    def __init__(self, port: str, baud: int, executable: str) -> None:
        self.serial = serial.Serial(port, baud, timeout=0.25, write_timeout=1)
        self.executable = executable
        self.version = discover_version(executable)
        self.state = State()
        self.lock = threading.Lock()
        self.process: subprocess.Popen[str] | None = None
        self.thread: threading.Thread | None = None
        self.stop = False

    def send(self, line: str) -> None:
        self.serial.write((line.rstrip("\r\n") + "\n").encode("ascii", "replace"))
        self.serial.flush()

    def send_info(self) -> None:
        self.send(f"HDF1 INFO {PROTOCOL} {self.version}")

    def send_status(self) -> None:
        with self.lock:
            s = self.state
            self.send(
                f"HDF1 STATUS {s.name} {s.files} {s.bytes} {s.matched} "
                f"{s.changed} {s.missing} {s.new_files} {s.exit_code} {safe_token(s.target)}"
            )

    def set_error(self, message: str) -> None:
        with self.lock:
            self.state.error = safe_token(message)
            self.state.name = "ERROR"
        self.send(f"HDF1 ERROR {safe_token(message)}")

    def command_args(self, operation: str) -> tuple[list[str], pathlib.Path]:
        if operation == "HASH":
            return [self.executable, "-r", str(INPUT)], REPORT
        if operation == "MANIFEST":
            return [self.executable, "-r", str(INPUT)], MANIFEST
        if operation == "AUDIT":
            if not MANIFEST.is_file():
                raise FileNotFoundError("known.hashdeep_missing")
            return [self.executable, "-a", "-k", str(MANIFEST), "-r", str(INPUT)], REPORT
        raise ValueError("unsupported_operation")

    def run_operation(self, operation: str) -> None:
        temp: pathlib.Path | None = None
        promoted = False
        try:
            INPUT.mkdir(parents=True, exist_ok=True)
            OUTPUT.mkdir(parents=True, exist_ok=True)
            args, destination = self.command_args(operation)
            files, size = measured_tree(INPUT)
            with self.lock:
                self.state = State(name="STARTING", files=files, bytes=size, target=destination.name)
            self.send_status()
            temp = destination.with_suffix(destination.suffix + ".partial")
            temp.unlink(missing_ok=True)
            with temp.open("w", encoding="utf-8", newline="\n") as output:
                process = subprocess.Popen(
                    args,
                    stdin=subprocess.DEVNULL,
                    stdout=output,
                    stderr=subprocess.STDOUT,
                    text=True,
                    shell=False,
                    cwd=str(ROOT),
                    start_new_session=True,
                )
                with self.lock:
                    self.process = process
                    self.state.name = "RUNNING"
                self.send_status()
                return_code = process.wait()
                output.flush()
                os.fsync(output.fileno())
            with self.lock:
                cancelled = self.state.name == "STOPPING"
                self.process = None
                self.state.exit_code = return_code
            if not cancelled and return_code == 0:
                os.replace(temp, destination)
                promoted = True
                directory_fd = os.open(destination.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            if operation == "AUDIT" and promoted:
                report = destination.read_text(encoding="utf-8", errors="replace")
                def count(label: str) -> int:
                    match = re.search(rf"{re.escape(label)}\s*(\d+)", report)
                    return int(match.group(1)) if match else 0
                with self.lock:
                    self.state.matched = count("Files matched:")
                    self.state.changed = count("Files partially matched:") + count("Files moved:")
                    self.state.missing = count("Known files not found:")
                    self.state.new_files = count("New files found:")
            with self.lock:
                self.state.name = "CANCELLED" if cancelled else ("COMPLETE" if promoted else "FAILED")
            if temp.exists():
                temp.unlink()
            self.send_status()
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            with self.lock:
                self.process = None
            if temp is not None and not promoted:
                try:
                    temp.unlink(missing_ok=True)
                except OSError:
                    pass
            self.set_error(str(error))

    def start_operation(self, operation: str) -> None:
        with self.lock:
            if self.process is not None or (self.thread and self.thread.is_alive()):
                self.send("HDF1 ERROR busy")
                return
            self.thread = threading.Thread(target=self.run_operation, args=(operation,), daemon=True)
            self.thread.start()

    def cancel(self) -> None:
        with self.lock:
            process = self.process
            if process is None:
                self.send("HDF1 ERROR not_running")
                return
            self.state.name = "STOPPING"
        self.send_status()
        try:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            try:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
            except OSError:
                pass
            except subprocess.TimeoutExpired:
                self.set_error("process_would_not_stop")

    def handle(self, line: str) -> None:
        parts = line.strip().split()
        if parts == ["HDF1", "HELLO"]:
            self.send_info()
            self.send_status()
        elif parts == ["HDF1", "STATUS"]:
            self.send_status()
        elif len(parts) == 3 and parts[:2] == ["HDF1", "RUN"] and parts[2] in {"HASH", "AUDIT", "MANIFEST"}:
            self.start_operation(parts[2])
        elif parts == ["HDF1", "CANCEL"]:
            self.cancel()
        else:
            self.send("HDF1 ERROR invalid_command")

    def serve(self) -> None:
        self.send_info()
        while not self.stop:
            raw = self.serial.readline(257)
            if len(raw) > 256:
                self.send("HDF1 ERROR line_too_long")
                self.serial.reset_input_buffer()
                continue
            if raw:
                self.handle(raw.decode("ascii", "replace"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", required=True, help="UART device such as /dev/ttyUSB0")
    parser.add_argument("--baud", type=int, choices=(115200, 230400, 460800), default=115200)
    args = parser.parse_args()
    bridge = Bridge(args.port, args.baud, find_hashdeep())
    try:
        bridge.serve()
    except KeyboardInterrupt:
        bridge.cancel() if bridge.process else None
    finally:
        bridge.serial.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
