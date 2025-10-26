# Retro BLE Sniffer

`ble_sniffer.py` is a self-contained Python 3 utility for Raspberry Pi-class devices that continuously captures Bluetooth Low Energy (BLE) advertising packets. It delivers an 80×24-friendly retro console interface while simultaneously supporting structured logging that is ready for future integrations.

## Key Features

- Async BLE scanning built on [`bleak`](https://github.com/hbldh/bleak) with automatic fallback to `bluepy` when requested.
- Retro console renderer with amber/green/ice themes, box-drawing tables, spinner header, and TTY fallbacks.
- Daily-rotated JSON Lines logging and optional CSV output so telemetry can be consumed by other tools.
- Configurable duplicate suppression cache (default 5 seconds) to keep the display readable.
- Graceful shutdown with signal handling, minimal CPU load, and simulation mode for development/testing.
- Inline unit tests for the dedupe cache and advertisement formatting pipeline (`--run-tests`).

## System Requirements

- Raspberry Pi OS (Debian based) on a Raspberry Pi 3 or later with onboard Bluetooth.
- Python 3.8 or newer (script is written for 3.8+).
- BLE stack packages:
  - `bluez`
  - `bluez-hcidump`
  - `libbluetooth-dev`
  - `python3-venv`
  - `python3-pip`

## Installation

```bash
sudo apt-get update && sudo apt-get install -y \
  bluez bluez-hcidump libbluetooth-dev python3-venv python3-pip
python3 -m venv .venv
source .venv/bin/activate
pip install bleak bluepy colorama blessed
```

If the Bluetooth adapter is down, bring it up before scanning:

```bash
sudo hciconfig hci0 up
```

> **Tip:** Some operations require elevated permissions. Run the script with `sudo` if BlueZ reports access errors.

## Usage

Run the sniffer with the retro console view and JSONL logging:

```bash
python ble_sniffer.py --console --jsonl --outdir logs --theme amber
```

Useful command-line flags:

- `--adapter hci0` – choose the Bluetooth interface.
- `--cooldown 5` – dedupe suppression window (seconds).
- `--jsonl`, `--csv`, `--console` – enable any combination of output sinks.
- `--outdir logs` – directory for JSONL/CSV files (created automatically).
- `--filter-mac` / `--filter-name` – limit adverts to MAC prefixes/regexes or name substrings.
- `--fallback-bluepy` – force the `bluepy` backend instead of `bleak`.
- `--theme {amber,green,ice,mono}` – select console palette.
- `--no-ansi`, `--no-box`, `--no-spinner` – disable specific console embellishments.
- `--debug` – increase log verbosity for troubleshooting.

### CSV Logging Example

```bash
python ble_sniffer.py --csv --no-ansi
```

### Simulation Mode

Develop without BLE hardware by enabling the built-in simulator:

```bash
python ble_sniffer.py --simulate --simulate-rate 5 --theme green
```

Simulation mode drives the exact same pipeline used for real advertisements, making it safe for unit testing and UI prototyping.

### Output Artifacts

- **Console:** Monochrome/colored table sized for 80 columns with spinner-driven status header.
- **JSON Lines:** Daily rotated files stored as `logs/YYYY-MM-DD-ble.jsonl` containing a JSON object per advertisement (timestamped in UTC).
- **CSV:** Optional flat file with the most relevant fields for spreadsheet analysis.

## Running Tests

Execute the bundled unit tests with:

```bash
python ble_sniffer.py --run-tests
```

These tests validate the TTL-based deduplication cache and ensure the advertisement formatting path includes required fields.

## Troubleshooting

- **Adapter down:** Run `sudo hciconfig hci0 up`.
- **Permission errors:** Run the script via `sudo` or ensure your user is part of the `bluetooth` group.
- **Missing dependencies:** Re-run the installation steps above; the script clearly reports which backend failed to load.
- **No TTY / piped output:** The program automatically disables color, box characters, and spinner to remain readable.

## Example Outputs

Console sample:

```
┌──────────────── Retro BLE Sniffer ────────────────┐
│ Adapter: hci0 | Theme: amber | Scanning: ⠋ | Seen: 37 (5s) │
├──────────────┬───────────┬──────┬──────────────────────────┤
│ 2025-10-26Z  │ A4:C1:38  │ -64  │ “Tile” uuids:180F… mfr:...│
└──────────────┴───────────┴──────┴──────────────────────────┘
```

JSONL sample line:

```json
{"ts": "2025-10-26T09:15:32.123456Z", "adapter": "hci0", "mac": "A4:C1:38:1F:2B:9A", "rssi": -64, "name": "Tile", "uuids": ["180f"], "mfr_data": {"004c": "0215..."}}
```

For full command reference, inline documentation, and customization options, open `ble_sniffer.py` and review the module docstring and CLI help (`python ble_sniffer.py --help`).
