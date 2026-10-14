"""USB Studio Sniffer CLI — capture, import, compare and view."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from .core import compare, demo_events, load_events, save_events
from .backends import list_devices, capture_serial, capture_hid, capture_bus, import_usb_capture
from .view import render
from .protocol import analyze_messages


def main(argv=None):
    p = argparse.ArgumentParser(prog='usb-studio', description='Cross-platform USB report explorer')
    sub = p.add_subparsers(dest='command', required=True)
    sub.add_parser('devices', help='List USB serial and HID candidates (optional pyserial/hidapi)')
    d = sub.add_parser('demo', help='Create synthetic USB hex reports and interactive HTML')
    d.add_argument('--jsonl', type=Path, default=Path('usb-demo.jsonl'))
    d.add_argument('--html', type=Path, default=Path('usb-demo.html'))
    v = sub.add_parser('view', help='Build a self-contained HTML viewer from JSONL')
    v.add_argument('capture', type=Path)
    v.add_argument('-o','--output', type=Path, default=Path('usb-report.html'))
    a = sub.add_parser('analyze', help='Automatically infer message families and candidate fields')
    a.add_argument('capture', type=Path)
    a.add_argument('-o', '--output', type=Path, default=Path('usb-analysis.json'))
    a.add_argument('--html', type=Path, help='Also save interactive analysis dashboard')
    c = sub.add_parser('compare', help='Compare two captures: first frame diff and byte variability')
    c.add_argument('before', type=Path)
    c.add_argument('after', type=Path)
    c.add_argument('-o','--output', type=Path, default=Path('usb-diff.json'))
    imp = sub.add_parser('import-bus', help='Import Wireshark USB PCAPNG/PCAP via tshark')
    imp.add_argument('capture', type=Path)
    imp.add_argument('-o','--output', type=Path, default=Path('usb-bus.jsonl'))
    imp.add_argument('--max-events', type=int, default=200_000)
    cap = sub.add_parser('capture', help='Read serial, HID reports, or native USB bus capture')
    modes = cap.add_subparsers(dest='mode', required=True)
    s = modes.add_parser('serial', help='Read from a serial port using pyserial (does not sniff other processes)')
    s.add_argument('--port', required=True)
    s.add_argument('--baud', type=int, default=115200)
    s.add_argument('--chunk', type=int, default=64)
    s.add_argument('-o','--output', type=Path, default=Path('usb-serial.jsonl'))
    h = modes.add_parser('hid', help='Read reports of a HID device using hidapi')
    h.add_argument('--vid', type=lambda x:int(x, 0), required=True)
    h.add_argument('--pid', type=lambda x:int(x, 0), required=True)
    h.add_argument('--report-size', type=int, default=64)
    h.add_argument('-o','--output', type=Path, default=Path('usb-hid.jsonl'))
    b = modes.add_parser('bus', help='Capture USB bus via tshark interface (OS dependent)')
    b.add_argument('--interface', required=True, help='Supported interface e.g. usbmon1 or USBPcap1')
    b.add_argument('--seconds', type=int, default=20)
    b.add_argument('-o','--output', type=Path, default=Path('usb-bus.pcapng'))
    for mode in (s, h):
        mode.add_argument('--seconds', type=float, default=20, help='0 means until Ctrl+C; default 20 s')
        mode.add_argument('--max-events', type=int, default=2000, help='Limit disk use')
    args = p.parse_args(argv)
    try:
        if args.command == 'devices':
            print(json.dumps(list_devices(), indent=2, ensure_ascii=False))
        elif args.command == 'demo':
            events = demo_events()
            save_events(args.jsonl, events)
            args.html.write_text(render(events), encoding='utf-8')
            print(f'SYNTHETIC demo: {args.jsonl.resolve()} and {args.html.resolve()}')
        elif args.command == 'view':
            events = load_events(args.capture)
            args.output.write_text(render(events), encoding='utf-8')
            print(f'HTML report ({len(events)} events): {args.output.resolve()}')
        elif args.command == 'analyze':
            events = load_events(args.capture)
            data = analyze_messages(events)
            args.output.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding='utf-8')
            if args.html:
                args.html.write_text(render(events, analysis=data), encoding='utf-8')
            print(f'Recognized {data["type_count"]} possible message families from {data["analyzed_events"]} samples')
            for g in data['types'][:10]:
                checks = ', '.join(x['algorithm'] for x in g['checksum_candidates']) or 'unknown'
                print(f"{g['id']} {g['samples']}x {g['length']} bytes | {g['signature']} | checksum: {checks}")
            print(f'Analysis JSON: {args.output.resolve()}')
            if args.html:
                print(f'Interactive HTML: {args.html.resolve()}')
        elif args.command == 'compare':
            data = compare(load_events(args.before), load_events(args.after))
            args.output.write_text(json.dumps(data, indent=2), encoding='utf-8')
            print(json.dumps({'changed_offsets': data['changed_offsets'], 'events_a': data['events_a'],
                              'events_b': data['events_b']}, indent=2))
            print(f'Detailed JSON: {args.output.resolve()}')
        elif args.command == 'import-bus':
            n = import_usb_capture(args.capture, args.output, args.max_events)
            print(f'Imported {n} USB payload reports: {args.output.resolve()}')
        elif args.command == 'capture':
            if args.mode == 'serial':
                count = capture_serial(args.port, args.baud, args.output, args.seconds, args.max_events, args.chunk)
                print(f'Saved {count} serial reports in {args.output.resolve()}')
            elif args.mode == 'hid':
                count = capture_hid(args.vid, args.pid, args.output, args.seconds, args.max_events, args.report_size)
                print(f'Saved {count} HID reports in {args.output.resolve()}')
            elif args.mode == 'bus':
                capture_bus(args.interface, args.output, args.seconds)
                print(f'Capture saved: {args.output.resolve()}; run usb-studio import-bus to inspect')
    except KeyboardInterrupt:
        print('\nCapture stopped by user.')
    except (ValueError, RuntimeError, OSError, json.JSONDecodeError) as exc:
        p.exit(1, f'USB Studio error: {exc}\n')

if __name__ == '__main__':
    main()
