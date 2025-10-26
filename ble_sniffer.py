# Yes, the Pi will complain about permissions; give it sudo if it moans.
"""BLE advertisement sniffer with a retro console vibe.

TODO:
    * Replace ``Scanner.on_advert`` with an HTTP POST to transmit adverts to
      a remote collector once the web UI backend is ready.

This module is intentionally self-contained for easy deployment on Raspberry
Pi devices. It prefers ``bleak`` for asynchronous BLE scanning but can fall
back to ``bluepy`` when requested. A simulation mode exists for development
and automated tests.
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import datetime as dt
import json
import logging
import os
import random
import re
import signal
import subprocess
import sys
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
import unittest

LOGGER = logging.getLogger("ble_sniffer")


def utc_now() -> dt.datetime:
    """Return the current UTC datetime with timezone information."""
    return dt.datetime.now(dt.timezone.utc)


def isoformat(ts: dt.datetime) -> str:
    """Format a datetime as ISO-8601 string with Z suffix."""
    return ts.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _parse_bool_field(value: str) -> bool:
    return value.strip().lower() in {"yes", "1", "on", "true"}


def get_rfkill_status(adapter: str) -> Optional[Tuple[bool, bool]]:
    """Return the rfkill soft/hard block state for the given adapter if available."""

    try:
        result = subprocess.run(
            ["rfkill", "list"],
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        LOGGER.debug("rfkill binary not present; skipping rfkill diagnostics")
        return None
    except subprocess.CalledProcessError as exc:
        LOGGER.debug("rfkill invocation failed: %s", exc)
        return None

    active = False
    soft_blocked: Optional[bool] = None
    hard_blocked: Optional[bool] = None
    for raw_line in result.stdout.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        header = re.match(r"(\d+):\s*([^:]+):\s*(.+)", line)
        if header:
            name = header.group(2).strip()
            active = name == adapter
            continue
        if not active:
            continue
        if line.lower().startswith("soft blocked:"):
            soft_blocked = _parse_bool_field(line.split(":", 1)[1])
        elif line.lower().startswith("hard blocked:"):
            hard_blocked = _parse_bool_field(line.split(":", 1)[1])
            # Once we've seen both fields we can stop inspecting further lines
            if soft_blocked is not None:
                break

    if soft_blocked is None and hard_blocked is None:
        return None
    return soft_blocked or False, hard_blocked or False


def log_rfkill_hint(adapter: str) -> None:
    """Emit helpful guidance if rfkill is blocking the Bluetooth adapter."""

    status = get_rfkill_status(adapter)
    if not status:
        return
    soft, hard = status
    if not soft and not hard:
        return
    if soft and hard:
        state = "soft and hard"
    elif soft:
        state = "soft"
    else:
        state = "hard"
    LOGGER.error(
        "!! Adapter %s appears %s-blocked by rfkill. Try: sudo rfkill unblock bluetooth",
        adapter,
        state,
    )
    if hard:
        LOGGER.error(
            "!! Some devices require toggling a physical switch or BIOS setting to clear a hard block"
        )


class DedupeCache:
    """Simple TTL-based cache for advertisement suppression."""

    def __init__(self, ttl: float, max_items: int = 1024) -> None:
        self.ttl = ttl
        self.max_items = max_items
        self._store: "OrderedDict[str, dt.datetime]" = OrderedDict()

    def _purge(self, now: Optional[dt.datetime] = None) -> None:
        now = now or utc_now()
        expired: List[str] = []
        for key, seen_at in list(self._store.items()):
            if (now - seen_at).total_seconds() > self.ttl:
                expired.append(key)
            else:
                break  # OrderedDict by insertion order; early exit once TTL satisfied
        for key in expired:
            self._store.pop(key, None)

    def should_emit(self, key: str, now: Optional[dt.datetime] = None) -> bool:
        """Return True if the key has not been seen recently."""
        now = now or utc_now()
        self._purge(now)
        if key in self._store:
            return False
        self._store[key] = now
        self._store.move_to_end(key)
        if len(self._store) > self.max_items:
            self._store.popitem(last=False)
        return True


@dataclass
class AdvertRecord:
    """Structured advertisement record used throughout the pipeline."""

    timestamp: dt.datetime
    adapter: str
    mac: str
    rssi: Optional[int]
    name: Optional[str]
    service_uuids: List[str] = field(default_factory=list)
    manufacturer_data: Dict[str, str] = field(default_factory=dict)
    payload_hex: str = ""
    source: str = "bleak"

    def as_dict(self) -> Dict[str, Any]:
        """Return a serializable dictionary representation."""
        return {
            "timestamp": isoformat(self.timestamp),
            "adapter": self.adapter,
            "mac": self.mac,
            "rssi": self.rssi,
            "name": self.name,
            "service_uuids": self.service_uuids,
            "manufacturer_data": self.manufacturer_data,
            "payload_hex": self.payload_hex,
            "source": self.source,
        }


class RotatingJSONLWriter:
    """Write JSON Lines entries with UTC daily rotation."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.directory.mkdir(parents=True, exist_ok=True)
        self._current_date: Optional[str] = None
        self._fh: Optional[Any] = None

    def _ensure_file(self, timestamp: dt.datetime) -> None:
        date_str = timestamp.strftime("%Y-%m-%d")
        if date_str != self._current_date:
            if self._fh:
                self._fh.close()
            self._current_date = date_str
            filename = self.directory / f"{date_str}-ble.jsonl"
            self._fh = open(filename, "a", encoding="utf-8")

    def write(self, record: AdvertRecord) -> None:
        self._ensure_file(record.timestamp)
        if not self._fh:
            return
        json.dump(record.as_dict(), self._fh, ensure_ascii=False)
        self._fh.write("\n")
        self._fh.flush()

    def close(self) -> None:
        if self._fh:
            self._fh.close()
            self._fh = None


class CSVWriter:
    """Simple CSV writer with header."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(self.path, "a", newline="", encoding="utf-8")
        self._writer = csv.writer(self._fh)
        if self._fh.tell() == 0:
            self._writer.writerow(
                [
                    "timestamp",
                    "adapter",
                    "mac",
                    "rssi",
                    "name",
                    "service_uuids",
                    "manufacturer_data",
                    "payload_hex",
                    "source",
                ]
            )

    def write(self, record: AdvertRecord) -> None:
        self._writer.writerow(
            [
                isoformat(record.timestamp),
                record.adapter,
                record.mac,
                record.rssi,
                record.name or "",
                ";".join(record.service_uuids),
                json.dumps(record.manufacturer_data, ensure_ascii=False),
                record.payload_hex,
                record.source,
            ]
        )
        self._fh.flush()

    def close(self) -> None:
        self._fh.close()


class ConsoleView:
    """Render advertisement stream with a retro terminal vibe."""

    THEMES = {
        "amber": ("\033[38;5;220m", "\033[0m"),
        "green": ("\033[38;5;46m", "\033[0m"),
        "ice": ("\033[38;5;123m", "\033[0m"),
        "mono": ("", ""),
    }
    SPINNER_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

    def __init__(
        self,
        theme: str = "amber",
        enable_ansi: bool = True,
        enable_box: bool = True,
        enable_spinner: bool = True,
        width: int = 80,
    ) -> None:
        self.width = width
        self.theme = theme if theme in self.THEMES else "amber"
        self.enable_spinner = enable_spinner
        self.enable_box = enable_box
        self.enable_ansi = enable_ansi and sys.stdout.isatty()
        self.is_tty = sys.stdout.isatty()
        if os.environ.get("TERM", "").lower() == "dumb":
            self.is_tty = False
        if not self.is_tty:
            self.enable_spinner = False
            self.enable_ansi = False
            self.enable_box = False
        self._spinner_index = 0
        self._header_last = ""
        self._theme_prefix, self._theme_suffix = (
            self.THEMES.get(self.theme, ("", "")) if self.enable_ansi else ("", "")
        )
        self._spinner_task: Optional[asyncio.Task] = None
        self._stats = {
            "adapter": "hci0",
            "theme": self.theme,
            "state": "idle",
            "seen_total": 0,
            "recent_unique": 0,
        }
        self._recent_counts: deque[dt.datetime] = deque(maxlen=256)

    def start(self) -> None:
        if not self.is_tty:
            return
        banner = self._style_text("┌─ BLE RETRO SNIFFER ─┐")
        print(banner[: self.width])
        if self.enable_spinner:
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = asyncio.get_event_loop()
            self._spinner_task = loop.create_task(self._spinner_loop())

    def stop(self) -> None:
        if self._spinner_task:
            self._spinner_task.cancel()
        if self.is_tty:
            goodbye = self._style_text("└─ GOODBYE, SPACE COWBOY ─┘")
            print(goodbye[: self.width])

    def _style_text(self, text: str) -> str:
        return f"{self._theme_prefix}{text}{self._theme_suffix}" if self.enable_ansi else text

    async def _spinner_loop(self) -> None:
        try:
            while True:
                await asyncio.sleep(0.2)
                self._spinner_index = (self._spinner_index + 1) % len(self.SPINNER_FRAMES)
                self.render_header()
        except asyncio.CancelledError:  # pragma: no cover - loop cancellation is expected
            pass

    def update_stats(
        self,
        *,
        adapter: Optional[str] = None,
        theme: Optional[str] = None,
        state: Optional[str] = None,
        seen_increment: int = 0,
    ) -> None:
        if adapter:
            self._stats["adapter"] = adapter
        if theme:
            self._stats["theme"] = theme
        if state:
            self._stats["state"] = state
        if seen_increment:
            self._stats["seen_total"] += seen_increment
        if seen_increment:
            now = utc_now()
            self._recent_counts.append(now)
            cutoff = now - dt.timedelta(seconds=60)
            while self._recent_counts and self._recent_counts[0] < cutoff:
                self._recent_counts.popleft()
            self._stats["recent_unique"] = len(self._recent_counts)
        self.render_header()

    def render_header(self) -> None:
        if not self.is_tty:
            return
        spinner = " "
        if self.enable_spinner:
            spinner = self.SPINNER_FRAMES[self._spinner_index]
        header = (
            f"Adapter: {self._stats['adapter']} | Theme: {self._stats['theme']} | "
            f"State: {self._stats['state']} | Seen: {self._stats['seen_total']} "
            f"({self._stats['recent_unique']}m) {spinner}"
        )
        header = header[: self.width]
        if header == self._header_last:
            return
        self._header_last = header
        print("\r" + " " * self.width, end="\r")
        print(self._style_text(header), end="" if self.enable_spinner else "\n")
        if not self.enable_spinner:
            sys.stdout.flush()

    def render_row(self, record: AdvertRecord) -> None:
        line = self._format_row(record)
        styled = self._style_text(line)
        print((styled if self.enable_box else line)[: self.width])

    def _box_chars(self) -> Tuple[str, str, str]:
        if not self.enable_box:
            return "|", "-", "+"
        return "│", "─", "┼"

    def _format_row(self, record: AdvertRecord) -> str:
        col_mac = record.mac[:17]
        col_rssi = f"{record.rssi:>4}" if record.rssi is not None else "   ?"
        name = record.name or "?"
        if len(name) > 18:
            name = name[:15] + "…"
        uuid_text = " ".join(u[:8] for u in record.service_uuids[:2])
        mfr_parts = [f"{k}:{v[:8]}" for k, v in list(record.manufacturer_data.items())[:2]]
        detail = " ".join(filter(None, [name, uuid_text, " ".join(mfr_parts)])).strip()
        if len(detail) > 36:
            detail = detail[:33] + "…"
        time_str = isoformat(record.timestamp)[11:19]
        bar, _, _ = self._box_chars()
        columns = [
            (bar, time_str.ljust(9)),
            (bar, col_mac.ljust(17)),
            (bar, col_rssi.rjust(4)),
            (bar, detail.ljust(40)),
            (bar, record.source[:6].ljust(6)),
        ]
        row = ""
        for sep, text in columns:
            row += f" {sep} {text}"
        return row[: self.width]


class OutputManager:
    """Manage optional output sinks."""

    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.json_writer: Optional[RotatingJSONLWriter] = None
        self.csv_writer: Optional[CSVWriter] = None
        outdir = Path(args.outdir)
        if args.jsonl:
            self.json_writer = RotatingJSONLWriter(outdir)
        if args.csv:
            self.csv_writer = CSVWriter(outdir / "ble.csv")

    def handle(self, record: AdvertRecord) -> None:
        if self.json_writer:
            try:
                self.json_writer.write(record)
            except Exception as exc:  # pragma: no cover - IO errors are rare
                LOGGER.error("!! JSONL write failed: %s", exc)
        if self.csv_writer:
            try:
                self.csv_writer.write(record)
            except Exception as exc:  # pragma: no cover
                LOGGER.error("!! CSV write failed: %s", exc)

    def close(self) -> None:
        if self.json_writer:
            self.json_writer.close()
        if self.csv_writer:
            self.csv_writer.close()


class Scanner:
    """BLE scanner orchestrating BLE backend and outputs."""

    def __init__(
        self,
        args: argparse.Namespace,
        console: ConsoleView,
        outputs: OutputManager,
        dedupe: DedupeCache,
    ) -> None:
        self.args = args
        self.console = console
        self.outputs = outputs
        self.dedupe = dedupe
        self.running = False
        self.adapter = args.adapter
        self.backend = "unknown"
        self._stop_event = asyncio.Event()
        self.loop: Optional[asyncio.AbstractEventLoop] = None

    async def start(self) -> None:
        self.running = True
        self.loop = asyncio.get_running_loop()
        self.console.start()
        self.console.update_stats(adapter=self.adapter, state="scanning")
        try:
            if self.args.simulate:
                await self._run_simulation()
            else:
                await self._run_ble()
        finally:
            self.console.update_stats(state="idle")
            self.console.stop()
            self.outputs.close()

    async def stop(self) -> None:
        self.running = False
        self._stop_event.set()

    async def _run_ble(self) -> None:
        backend_attempts: List[str] = []
        if not self.args.fallback_bluepy:
            backend_attempts.append("bleak")
        backend_attempts.append("bluepy")
        errors: List[str] = []
        missing_backends: Set[str] = set()
        for backend in backend_attempts:
            if backend == "bleak":
                try:
                    await self._run_bleak()
                    return
                except ModuleNotFoundError:
                    errors.append("bleak not installed. pip install bleak")
                    missing_backends.add("bleak")
                except Exception as exc:
                    LOGGER.exception("!! Bleak scanner failed: %s", exc)
                    errors.append(f"bleak error: {exc}")
            elif backend == "bluepy":
                try:
                    await self._run_bluepy()
                    return
                except ModuleNotFoundError:
                    errors.append("bluepy not installed. pip install bluepy")
                    missing_backends.add("bluepy")
                except Exception as exc:
                    LOGGER.exception("!! bluepy scanner failed: %s", exc)
                    errors.append(f"bluepy error: {exc}")
        LOGGER.error(
            "!! No BLE backend succeeded. Errors: %s", "; ".join(errors) or "unknown"
        )
        LOGGER.error("!! Ensure bluetooth is up: sudo hciconfig %s up", self.adapter)
        log_rfkill_hint(self.adapter)
        if missing_backends and missing_backends == set(backend_attempts):
            LOGGER.warning(
                "!! Falling back to simulation mode because no optional BLE backends are installed"
            )
            await self._run_simulation()

    async def _run_bleak(self) -> None:
        from bleak import BleakScanner  # type: ignore

        LOGGER.info("Using bleak backend")
        self.backend = "bleak"

        loop = self.loop or asyncio.get_running_loop()

        def detection_callback(device, advertisement_data):
            asyncio.run_coroutine_threadsafe(
                self._handle_advert_bleak(device, advertisement_data),
                loop,
            )

        scanner = BleakScanner(adapter=self.adapter)
        scanner.register_detection_callback(detection_callback)
        async with scanner:
            while self.running:
                await asyncio.sleep(0.1)

    async def _handle_advert_bleak(self, device, advertisement_data) -> None:
        if not self.running:
            return
        payload_bytes = advertisement_data.manufacturer_data or {}
        manufacturer_data = {
            f"0x{k:04X}": (v.hex() if isinstance(v, (bytes, bytearray)) else str(v))
            for k, v in payload_bytes.items()
        }
        raw_bytes = getattr(advertisement_data, "bytes", None)
        if isinstance(raw_bytes, (bytes, bytearray)):
            payload_hex = raw_bytes.hex()
        else:
            payload_hex = ""
        record = AdvertRecord(
            timestamp=utc_now(),
            adapter=self.adapter,
            mac=device.address or "?",
            rssi=advertisement_data.rssi,
            name=advertisement_data.local_name,
            service_uuids=advertisement_data.service_uuids or [],
            manufacturer_data=manufacturer_data,
            payload_hex=payload_hex,
            source="bleak",
        )
        await self._process_record(record)

    async def _run_bluepy(self) -> None:
        from bluepy.btle import BTLEException, DefaultDelegate, Scanner as BluepyScanner  # type: ignore

        LOGGER.info("Using bluepy backend")
        self.backend = "bluepy"

        class Delegate(DefaultDelegate):
            def __init__(self, outer: "Scanner") -> None:
                super().__init__()
                self.outer = outer

            def handleDiscovery(self, dev, isNewDev, isNewData):  # noqa: N802
                manufacturer_data: Dict[str, str] = {}
                payload_hex = dev.getValueText(255) or ""
                if payload_hex:
                    manufacturer_data["0xFFFF"] = payload_hex
                uuids = [
                    value
                    for _, description, value in dev.getScanData()
                    if "uuid" in (description or "").lower()
                ]
                record = AdvertRecord(
                    timestamp=utc_now(),
                    adapter=self.outer.adapter,
                    mac=dev.addr,
                    rssi=dev.rssi,
                    name=dev.getValueText(9),
                    service_uuids=uuids,
                    manufacturer_data=manufacturer_data,
                    payload_hex=payload_hex,
                    source="bluepy",
                )
                if self.outer.loop:
                    asyncio.run_coroutine_threadsafe(
                        self.outer._process_record(record),
                        self.outer.loop,
                    )
                else:  # pragma: no cover - defensive fallback
                    LOGGER.warning("!! Event loop unavailable for bluepy callback")

        delegate = Delegate(self)
        scanner = BluepyScanner().withDelegate(delegate)
        while self.running:
            try:
                scanner.scan(1.0, passive=True)
            except BTLEException as exc:
                LOGGER.error("!! bluepy scan error: %s", exc)
                await asyncio.sleep(1.0)

    async def _run_simulation(self) -> None:
        LOGGER.info("Running in simulation mode")
        rng = random.Random(42)
        rate = max(1, self.args.simulate_rate)
        self.backend = "simulate"
        while self.running and not self._stop_event.is_set():
            await asyncio.sleep(1.0 / rate)
            record = AdvertRecord(
                timestamp=utc_now(),
                adapter=self.adapter,
                mac=self._random_mac(rng),
                rssi=rng.randint(-95, -20),
                name=rng.choice(["RetroTag", "PiPhone", "Beacon", None]),
                service_uuids=["180F", "181A"],
                manufacturer_data={"0xFFFF": "deadbeef"},
                payload_hex="deadbeef",
                source="sim",
            )
            await self._process_record(record)

    @staticmethod
    def _random_mac(rng: random.Random) -> str:
        return ":".join(f"{rng.randint(0, 255):02X}" for _ in range(6))

    async def _process_record(self, record: AdvertRecord) -> None:
        key = f"{record.mac}|{record.rssi}|{record.payload_hex}"
        if not self.dedupe.should_emit(key):
            return
        if self.args.filter_mac and not self._mac_matches(record.mac):
            return
        if self.args.filter_name and not self._name_matches(record.name):
            return
        self.console.update_stats(seen_increment=1)
        if self.args.console:
            self.console.render_row(record)
        self.outputs.handle(record)

    def _mac_matches(self, mac: str) -> bool:
        target = self.args.filter_mac
        if not target:
            return True
        if target.startswith("/") and target.endswith("/"):
            regex = target.strip("/")
            return re.search(regex, mac, re.IGNORECASE) is not None
        return mac.upper().startswith(target.upper())

    def _name_matches(self, name: Optional[str]) -> bool:
        if not self.args.filter_name:
            return True
        if not name:
            return False
        return self.args.filter_name.lower() in name.lower()


def parse_args(argv: Optional[Iterable[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="BLE sniffer with retro console aesthetics",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--adapter", default="hci0", help="Bluetooth adapter to use")
    parser.add_argument("--cooldown", type=float, default=5.0, help="Duplicate cooldown in seconds")
    parser.add_argument("--console", dest="console", action="store_true", help="Enable console output")
    parser.add_argument("--no-console", dest="console", action="store_false", help="Disable console output")
    parser.set_defaults(console=True)
    parser.add_argument("--jsonl", action="store_true", help="Enable JSONL logging")
    parser.add_argument("--csv", action="store_true", help="Enable CSV logging")
    parser.add_argument("--outdir", default="logs", help="Directory for log files")
    parser.add_argument("--filter-mac", dest="filter_mac", help="MAC prefix or /regex/")
    parser.add_argument("--filter-name", dest="filter_name", help="Match device name substring")
    parser.add_argument("--scan-duration", type=float, default=0.0, help="Scan duration (if supported)")
    parser.add_argument("--scan-interval", type=float, default=0.0, help="Scan interval (if supported)")
    parser.add_argument("--fallback-bluepy", action="store_true", help="Force bluepy backend")
    parser.add_argument("--theme", choices=["amber", "green", "ice", "mono"], default="amber")
    parser.add_argument("--no-ansi", action="store_true", help="Disable ANSI colors")
    parser.add_argument("--no-box", action="store_true", help="Disable box drawing")
    parser.add_argument("--no-spinner", action="store_true", help="Disable spinner")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--simulate", action="store_true", help="Run in simulated mode")
    parser.add_argument("--simulate-rate", type=int, default=5, help="Simulated adverts per second")
    parser.add_argument("--run-tests", action="store_true", help="Run unit tests and exit")
    args = parser.parse_args(list(argv) if argv is not None else None)
    if args.no_ansi:
        args.theme = "mono"
    return args


def configure_logging(debug: bool) -> None:
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s: %(message)s",
    )


async def run_scanner(args: argparse.Namespace) -> None:
    console = ConsoleView(
        theme=args.theme,
        enable_ansi=not args.no_ansi,
        enable_box=not args.no_box,
        enable_spinner=not args.no_spinner,
    )
    outputs = OutputManager(args)
    dedupe = DedupeCache(ttl=args.cooldown)
    scanner = Scanner(args, console, outputs, dedupe)

    loop = asyncio.get_running_loop()

    def _handle_signal(signame: str) -> None:
        LOGGER.info("Received %s, shutting down", signame)
        asyncio.ensure_future(scanner.stop())

    for signame in {"SIGINT", "SIGTERM"}:
        if hasattr(signal, signame):
            loop.add_signal_handler(getattr(signal, signame), lambda s=signame: _handle_signal(s))

    await scanner.start()


def main(argv: Optional[Iterable[str]] = None) -> int:
    args = parse_args(argv)
    if args.run_tests:
        import unittest

        suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestDedupeCache)
        suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(TestFormatting))
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        return 0 if result.wasSuccessful() else 1

    configure_logging(args.debug)
    try:
        asyncio.run(run_scanner(args))
    except KeyboardInterrupt:
        LOGGER.info("Interrupted by user")
    except RuntimeError as exc:
        LOGGER.error("!! Runtime error: %s", exc)
        LOGGER.error("!! Is the adapter up? Try: sudo hciconfig %s up", args.adapter)
        log_rfkill_hint(args.adapter)
        return 1
    return 0


class TestDedupeCache(unittest.TestCase):
    """Unit tests for the DedupeCache TTL behavior."""

    def test_should_emit_once_within_ttl(self) -> None:
        cache = DedupeCache(ttl=5)
        now = dt.datetime(2024, 1, 1, tzinfo=dt.timezone.utc)
        self.assertTrue(cache.should_emit("abc", now))
        self.assertFalse(cache.should_emit("abc", now + dt.timedelta(seconds=1)))
        self.assertTrue(cache.should_emit("abc", now + dt.timedelta(seconds=6)))

    def test_cache_max_items(self) -> None:
        cache = DedupeCache(ttl=5, max_items=2)
        now = dt.datetime(2024, 1, 1, tzinfo=dt.timezone.utc)
        self.assertTrue(cache.should_emit("a", now))
        self.assertTrue(cache.should_emit("b", now))
        self.assertTrue(cache.should_emit("c", now))
        self.assertTrue(cache.should_emit("a", now + dt.timedelta(seconds=6)))


class DummyConsole(ConsoleView):
    def __init__(self) -> None:
        super().__init__(enable_ansi=False, enable_box=False, enable_spinner=False)
        self.rows: List[str] = []

    def render_row(self, record: AdvertRecord) -> None:  # type: ignore[override]
        self.rows.append(self._format_row(record))

    def update_stats(self, *args: Any, **kwargs: Any) -> None:  # type: ignore[override]
        pass


class DummyOutputs(OutputManager):
    def __init__(self) -> None:
        self.records: List[AdvertRecord] = []

    def handle(self, record: AdvertRecord) -> None:  # type: ignore[override]
        self.records.append(record)

    def close(self) -> None:  # type: ignore[override]
        pass


class TestFormatting(unittest.TestCase):
    """Ensure adverts produce mandatory fields."""

    def setUp(self) -> None:
        args = argparse.Namespace(
            adapter="hci0",
            cooldown=5,
            console=True,
            jsonl=False,
            csv=False,
            outdir="logs",
            filter_mac=None,
            filter_name=None,
            scan_duration=0.0,
            scan_interval=0.0,
            fallback_bluepy=False,
            theme="amber",
            no_ansi=False,
            no_box=False,
            no_spinner=False,
            debug=False,
            simulate=True,
            simulate_rate=1,
        )
        self.console = DummyConsole()
        self.outputs = DummyOutputs()
        self.cache = DedupeCache(ttl=5)
        self.scanner = Scanner(args, self.console, self.outputs, self.cache)
        self.scanner.running = True

    def test_on_advert_emits_required_fields(self) -> None:
        record = AdvertRecord(
            timestamp=utc_now(),
            adapter="hci0",
            mac="AA:BB:CC:DD:EE:FF",
            rssi=-60,
            name="TestDevice",
            service_uuids=["180F"],
            manufacturer_data={"0xFFFF": "deadbeef"},
            payload_hex="deadbeef",
            source="sim",
        )
        asyncio.run(self.scanner._process_record(record))
        self.assertTrue(self.console.rows)
        self.assertEqual(len(self.outputs.records), 1)
        emitted = self.outputs.records[0].as_dict()
        for field in ["timestamp", "adapter", "mac", "rssi", "payload_hex"]:
            self.assertIn(field, emitted)


if __name__ == "__main__":  # pragma: no cover - manual execution entry point
    sys.exit(main())

# -----------------------------------------------------------------------------
# Setup & Run
# -----------------------------------------------------------------------------
# sudo apt-get update && sudo apt-get install -y \
#     bluez bluez-hcidump libbluetooth-dev python3-venv python3-pip
# python3 -m venv .venv && source .venv/bin/activate
# pip install bleak bluepy colorama blessed
# sudo hciconfig hci0 up
# python ble_sniffer.py --console --jsonl --outdir logs --theme amber
# python ble_sniffer.py --csv --no-ansi
# python ble_sniffer.py --simulate --simulate-rate 5 --theme green
#
# Example console row:
# │ 12:34:56 │ AA:BB:CC:DD:EE │ -60 │ TestDevice 180F mfr:0xFFFF:dead… │ sim
# Example JSONL entry:
# {"timestamp": "2025-01-01T12:34:56.789000Z", "adapter": "hci0", "mac": "AA:BB:CC:DD:EE:FF", "rssi": -60, "name": "TestDevice", "service_uuids": ["180F"], "manufacturer_data": {"0xFFFF": "deadbeef"}, "payload_hex": "deadbeef", "source": "sim"}
