"""Read-only USB application-level readers and Wireshark bus capture importer."""
from __future__ import annotations
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path
from .core import clean_hex, record


def list_devices():
    result = {'serial': [], 'hid': [], 'warnings': []}
    try:
        from serial.tools import list_ports
        result['serial'] = [{'port': p.device, 'description': p.description,
                             'vid': f'{p.vid:04x}' if p.vid is not None else None,
                             'pid': f'{p.pid:04x}' if p.pid is not None else None} for p in list_ports.comports()]
    except ImportError:
        result['warnings'].append('pyserial missing; install: python3 -m pip install pyserial')
    try:
        import hid
        result['hid'] = [{'vendor_id': f'{p["vendor_id"]:04x}', 'product_id': f'{p["product_id"]:04x}',
                          'product_string': p.get('product_string', ''),
                          'manufacturer_string': p.get('manufacturer_string', ''),
                          'path': (p.get('path') or b'').decode('utf-8', 'replace') if isinstance(p.get('path'), bytes) else str(p.get('path', ''))}
                         for p in hid.enumerate()]
    except ImportError:
        result['warnings'].append('hidapi missing; HID enumeration requires: python3 -m pip install hidapi')
    return result


def capture_serial(port: str, baud: int, output: Path, seconds: float, max_events: int, chunk: int):
    try:
        import serial
    except ImportError as e:
        raise RuntimeError('Install pyserial: python3 -m pip install pyserial') from e
    if baud <= 0 or chunk < 1 or chunk > 4096:
        raise ValueError('Baud must be positive and chunk between 1 and 4096')
    start = time.monotonic()
    count = 0
    # Opening a serial port may reset boards (DTR/RTS); read the README.
    with serial.Serial(port=port, baudrate=baud, timeout=0.2) as dev, output.open('w', encoding='utf-8') as out:
        print(f'Reading {port} ({baud} baud). Ctrl+C to stop.')
        while count < max_events and (seconds <= 0 or time.monotonic() - start < seconds):
            payload = dev.read(chunk)
            if not payload:
                continue
            item = record(payload, 'serial', port, 'in', baud=baud)
            out.write(json.dumps(item) + '\n')
            out.flush()
            print(f'[{count:05d}] {item["hex"]}', flush=True)
            count += 1
    return count


def capture_hid(vid: int, pid: int, output: Path, seconds: float, max_events: int, report_size: int):
    try:
        import hid
    except ImportError as e:
        raise RuntimeError('Install hidapi: python3 -m pip install hidapi') from e
    if vid < 0 or vid > 65535 or pid < 0 or pid > 65535 or not (1 <= report_size <= 4096):
        raise ValueError('Invalid VID, PID or report size')
    dev = hid.device()
    dev.open(vid, pid)
    count = 0
    start = time.monotonic()
    try:
        with output.open('w', encoding='utf-8') as f:
            print(f'Reading HID {vid:04x}:{pid:04x}. Ctrl+C to stop.')
            while count < max_events and (seconds <= 0 or time.monotonic() - start < seconds):
                raw = dev.read(report_size, 200)  # 200 ms timeout
                if not raw:
                    continue
                item = record(bytes(raw), 'hid', f'{vid:04x}:{pid:04x}', 'in')
                f.write(json.dumps(item) + '\n'); f.flush()
                print(f'[{count:05d}] {item["hex"]}', flush=True)
                count += 1
    finally:
        dev.close()
    return count


# Wireshark dissector fields - no undocumented raw packet parsing.
FIELDS = ['frame.time_epoch', 'frame.number', 'usb.bus_id', 'usb.device_address',
          'usb.endpoint_address', 'usb.urb_type', 'usb.capdata', 'usb.data_fragment']


def parse_tshark_line(line: str) -> dict | None:
    cols = line.rstrip('\r\n').split('\t')
    if len(cols) < len(FIELDS):
        return None
    timestamp, number, bus, addr, endpoint, urb, capdata, fragment = cols[:len(FIELDS)]
    raw = capdata or fragment
    # Wireshark returns hex separated by colons; multi-occurrence fields may contain commas.
    raw = raw.split(',')[0].strip()
    if not raw:
        return None  # URB metadata without bytes cannot contribute to hex diff.
    try:
        buf = bytes.fromhex(clean_hex(raw))
    except ValueError:
        return None
    try:
        ts = float(timestamp)
    except ValueError:
        ts = time.time()
    item = record(buf, 'usb-bus', f'bus={bus} device={addr}', 'unknown',
                  frame=number, endpoint=endpoint, urb_type=urb)
    item['ts'] = ts
    return item


def import_usb_capture(capture: Path, output: Path, max_events: int = 200000) -> int:
    exe = shutil.which('tshark')
    if not exe:
        raise RuntimeError('tshark not installed. Install Wireshark command-line tools (tshark).')
    cmd = [exe, '-r', str(capture), '-Y', 'usb', '-T', 'fields', '-E', 'separator=/t', '-E', 'occurrence=f']
    for field in FIELDS:
        cmd += ['-e', field]
    count = 0
    with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as proc:
        # Capture stderr to a temporary file-like buffer via communicate instead of deadlocking.
        try:
            out, err = proc.communicate(timeout=90)
        except subprocess.TimeoutExpired:
            proc.kill(); proc.communicate()
            raise RuntimeError('tshark import timed out (90 s). Use a smaller capture.')
    if proc.returncode:
        raise RuntimeError(f'tshark failed: {err.strip()[:400]}')
    with output.open('w', encoding='utf-8') as target:
        for line in out.splitlines():
            event = parse_tshark_line(line)
            if event:
                target.write(json.dumps(event) + '\n')
                count += 1
                if count >= max_events:
                    break
    return count


def capture_bus(interface: str, output: Path, seconds: int):
    exe = shutil.which('tshark')
    if not exe:
        raise RuntimeError('Install tshark to record USB bus traffic.')
    if seconds < 1 or seconds > 3600:
        raise ValueError('Duration must be 1–3600 seconds')
    # No shell invocation or privilege changes. Your OS controls capture permissions.
    cmd = [exe, '-i', interface, '-a', f'duration:{seconds}', '-w', str(output)]
    print('USB bus capture requires an OS-supported interface and capture permissions.')
    print('Running:', ' '.join(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=seconds + 25)
    if result.returncode:
        raise RuntimeError(result.stderr.strip()[-500:] or 'USB bus capture failed')
    return output
