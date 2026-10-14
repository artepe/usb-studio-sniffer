# 🔬 USB Studio Sniffer

**A friendly, local USB hex explorer for hardware hackers.**

Capture readable application-level USB serial / HID reports; analyze and compare packets byte-by-byte; import Wireshark USB bus captures. A fast, dependency-free offline HTML dashboard highlights constant versus changing bytes.

![Status](https://img.shields.io/badge/status-v0.1_MVP-9b84ff) ![Python](https://img.shields.io/badge/python-3.10%2B-blue) ![License](https://img.shields.io/badge/license-MIT-purple)

## macOS / Linux / Windows quick start

```bash
# Clone or unzip this repo and cd into usb-studio-sniffer
python3 -m usb_studio demo
open usb-demo.html         # macOS; Linux: xdg-open usb-demo.html
# Windows: start usb-demo.html

# Show attached serial and HID devices (requires optional extras)
python3 -m pip install '.[all]'
python3 -m usb_studio devices
```

If the `usb-studio` command is installed, it can be used instead of `python3 -m usb_studio`.

## Capture serial reports (USB CDC / USB-to-UART)

```bash
# On macOS the port typically starts /dev/cu.usbmodem... or /dev/cu.usbserial...
python3 -m usb_studio capture serial --port /dev/cu.usbmodem1234 --baud 115200 --seconds 30 -o before.jsonl
python3 -m usb_studio view before.jsonl -o before.html
open before.html
```

**Important:** A serial port is often exclusively opened; the serial capture only records bytes read by this program, not USB requests from another application. Opening some serial ports toggles DTR/RTS and may reset an ESP32 or other development board. No automatic writes are sent.

## Capture HID reports (requires hidapi)

```bash
python3 -m pip install hidapi
python3 -m usb_studio devices
python3 -m usb_studio capture hid --vid 0x0483 --pid 0x5710 --seconds 30 -o hid.jsonl
python3 -m usb_studio view hid.jsonl -o hid.html
```

HID VID/PID above are *illustrative only*; use actual identifiers from `devices`. Reading HID reports is not the same as intercepting all host↔device USB transactions. Access and report data depend on the OS driver, permissions and the specific device.

## USB bus sniffing through Wireshark / tshark

For **true USB bus capture**, install [Wireshark](https://www.wireshark.org/) with `tshark`, configure a supported interface, then:

```bash
# List capture interfaces and choose the actual USB monitor interface
# e.g. Linux usbmon1, Windows USBPcap1, or a supported macOS USB capture interface
tshark -D
python3 -m usb_studio capture bus --interface usbmon1 --seconds 20 -o bus.pcapng
python3 -m usb_studio import-bus bus.pcapng -o bus.jsonl
python3 -m usb_studio view bus.jsonl -o bus.html
```

**Platform limitations**: Linux uses usbmon (may require root/capabilities); Windows can use USBPcap; on macOS modern security and SIP restrictions may prevent low-level capture. **Do not disable SIP just for this tool.** You can still import captures from a different computer. For details see [Wireshark's USB capture guide](https://wiki.wireshark.org/CaptureSetup/USB).

The import currently extracts USB payloads from common Wireshark fields (`usb.capdata` / `usb.data_fragment`). It does **not** reconstruct every multi-frame USB transaction, decode proprietary protocols or guarantee that every payload is visible. No code will bypass USB permissions.

## Compare before and after actions

For example, take a capture before and after changing the temperature setting in a device:

```bash
python3 -m usb_studio compare before.jsonl after.jsonl -o differences.json
```

It reports changed byte offsets in the **first non-empty frame** and per-offset variation/entropy across each session (first 256 offsets). For meaningful comparisons, use captures from the same device/report type and align frames. This is a byte-level hint, **not** proof of field meaning or a checksum algorithm.

## v0.1 features

- ✅ Cross-platform USB serial / HID device enumeration (optional Python dependencies)
- ✅ Live incoming serial or HID reads to `.jsonl`, with duration and max event limits
- ✅ Capture USB bus with `tshark` on supported OS capture interfaces
- ✅ Import Wireshark USB PCAP or PCAPNG captures (requires `tshark`)
- ✅ Offline HTML report viewer with filter, event metadata and hex explorer
- ✅ Compare two capture sessions and analyze variable byte offsets, basic entropy
- ✅ Synthetic demo and automated tests; no cloud account, telemetry or network services

## Roadmap

- [ ] Better transaction pairing and endpoint filters
- [ ] Desktop GUI with connect/capture controls
- [ ] Bit-level diff and inferred counter/checksum candidates
- [ ] Custom protocol profiles / presets for Ouman EH-800 hardware research
- [ ] Export to Python struct parsers and HID/serial decoder templates
- [ ] Streaming large-file import, privacy scrubber

## Safety & responsible use

Run on devices and systems you own or have permission to research. USB reports can include typed passwords, authentication tokens or personal data; carefully review them before sharing. The tool intentionally provides **no automatic write/replay mode**. Never publish unredacted PCAP, HID, or serial logs from real users.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

MIT licensed. Contributions welcome.

### One-click macOS demo

After extracting the ZIP, double-click `START_DEMO_MAC.command` (or right-click → Open if macOS asks for confirmation). It runs an offline demo and opens the HTML file in your browser. No USB device or admin rights required.