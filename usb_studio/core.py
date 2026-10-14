"""USB Studio capture format, comparisons and statistics."""
from __future__ import annotations
from collections import Counter
from datetime import datetime, timezone
import json
import math
from pathlib import Path
import re
import time


def clean_hex(value: str) -> str:
    compact = re.sub(r'[^0-9a-fA-F]', '', value)
    if len(compact) % 2:
        raise ValueError('Odd-length hex bytes')
    if re.search(r'[^0-9a-fA-F:\s-]', value):
        raise ValueError('Not a hex string')
    return compact.lower()


def record(payload: bytes, source: str, device: str, direction: str = 'in', **details) -> dict:
    return {'ts': round(time.time(), 6), 'source': source, 'device': device,
            'direction': direction, 'hex': payload.hex(' '), 'length': len(payload), **details}


def save_events(path: str | Path, events):
    with open(path, 'w', encoding='utf-8') as file:
        for event in events:
            file.write(json.dumps(event, ensure_ascii=False) + '\n')


def load_events(path: str | Path, max_events=200_000) -> list[dict]:
    events = []
    with open(path, encoding='utf-8') as f:
        for n, line in enumerate(f, 1):
            if n > max_events:
                raise ValueError(f'Too many events (limit {max_events})')
            if not line.strip():
                continue
            item = json.loads(line)
            if not isinstance(item, dict) or not isinstance(item.get('hex'), str):
                raise ValueError(f'Invalid capture event on line {n}')
            item['hex'] = clean_hex(item['hex'])
            if len(item['hex']) > 131072:
                raise ValueError(f'Event {n} too large')
            item['length'] = len(item['hex']) // 2
            events.append(item)
    return events


def variability(events: list[dict]):
    packets = [bytes.fromhex(e['hex']) for e in events if e.get('hex')]
    max_length = max((len(b) for b in packets), default=0)
    # Avoid quadratic page explosions and huge captures.
    summary = []
    for index in range(min(max_length, 256)):
        vals = [b[index] for b in packets if len(b) > index]
        freq = Counter(vals)
        if not vals:
            continue
        entropy = -sum((count / len(vals)) * math.log2(count / len(vals)) for count in freq.values())
        summary.append({'offset': index, 'samples': len(vals), 'unique': len(freq),
                        'common_hex': f'{freq.most_common(1)[0][0]:02x}',
                        'entropy_bits': round(entropy, 3), 'changes': len(freq) > 1})
    return summary


def compare(a: list[dict], b: list[dict]) -> dict:
    """Compare the first payload of two recordings and overall byte variability."""
    pa = bytes.fromhex(next((v['hex'] for v in a if v['hex']), ''))
    pb = bytes.fromhex(next((v['hex'] for v in b if v['hex']), ''))
    diff = [{'offset': i, 'before': f'{pa[i]:02x}' if i < len(pa) else '--',
             'after': f'{pb[i]:02x}' if i < len(pb) else '--'}
            for i in range(max(len(pa), len(pb)))
            if i >= len(pa) or i >= len(pb) or pa[i] != pb[i]]
    return {'first_frame_diff': diff, 'changed_offsets': [x['offset'] for x in diff],
            'events_a': len(a), 'events_b': len(b),
            'variability_a': variability(a), 'variability_b': variability(b),
            'note': 'This comparison does not infer protocol fields or device meaning automatically.'}


def demo_events():
    base = 'aa 01 00 19 40 01 00 55'
    payloads = ['aa 01 00 19 40 01 00 55', 'aa 01 00 1a 40 01 00 54',
                'aa 01 00 1c 40 02 00 51', 'aa 01 00 1e 40 02 00 4f',
                'aa 01 00 21 40 03 00 4b']
    events = [record(bytes.fromhex(p), 'DEMO', 'Synthetic sensor', 'in', label='SYNTHETIC — NOT LIVE DATA') for p in payloads]
    now = time.time()
    for i, e in enumerate(events):
        e['ts'] = round(now + i*0.2, 6)
    return events
