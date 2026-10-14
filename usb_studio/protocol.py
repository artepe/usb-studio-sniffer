"""Conservative, offline heuristic recognition of unknown USB/serial messages.

No proprietary protocol definitions, no device writes, and no false assertion
that a sampled HID report or serial read is necessarily a complete frame.
"""
from __future__ import annotations

from collections import Counter, defaultdict

MAX_ANALYZED_EVENTS = 5000
MAX_ANALYZED_BYTES = 128


def _stream_key(event: dict) -> tuple[str, str, str, str]:
    return (str(event.get('source', '?')), str(event.get('device', '?')),
            str(event.get('direction', '?')), str(event.get('endpoint', '')))


def _take_sample(events: list[dict], limit: int) -> list[dict]:
    if len(events) <= limit:
        return events
    # Deterministic chronological sampling spanning the entire capture.
    return [events[(i * len(events)) // limit] for i in range(limit)]


def _split_opcode(packets: list[bytes]) -> tuple[int | None, dict[int, list[bytes]]]:
    """Split only on a repeatedly observed early byte with balanced populations."""
    n = len(packets)
    if n < 8:
        return None, {}
    for offset in range(min(4, len(packets[0]))):
        values = Counter(pkt[offset] for pkt in packets)
        if not 2 <= len(values) <= 6:
            continue
        if min(values.values()) < max(3, (n + 9) // 10):
            continue
        split: dict[int, list[bytes]] = defaultdict(list)
        for pkt in packets:
            split[pkt[offset]].append(pkt)
        return offset, dict(split)
    return None, {}


def _counter_candidates(packets: list[bytes], max_bytes: int) -> list[dict]:
    if len(packets) < 5:
        return []
    out = []
    for offset in range(min(max_bytes, len(packets[0]))):
        series = [p[offset] for p in packets]
        if len(set(series)) < 4:
            continue
        transitions = [(b - a) % 256 for a, b in zip(series, series[1:])]
        increment = transitions.count(1) / len(transitions)
        decrement = transitions.count(255) / len(transitions)
        if max(increment, decrement) >= .80:
            out.append({'offset': offset, 'direction': 'increment' if increment >= decrement else 'decrement',
                        'match_percent': round(100 * max(increment, decrement))})
    return out[:4]


def _xor8(buf: bytes) -> int:
    value = 0
    for b in buf:
        value ^= b
    return value


def _crc8(buf: bytes) -> int:
    crc = 0
    for b in buf:
        crc ^= b
        for _ in range(8):
            crc = ((crc << 1) ^ (0x07 if crc & 0x80 else 0)) & 255
    return crc


def _crc16_modbus(buf: bytes) -> int:
    crc = 0xFFFF
    for b in buf:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (0xA001 if crc & 1 else 0)
    return crc


def _checksum_candidates(packets: list[bytes], meaningful_length: int) -> list[dict]:
    if len(packets) < 5 or not (4 <= meaningful_length <= 512) or len(set(packets)) < 5:
        return []
    packets = [pkt[:meaningful_length] for pkt in packets]
    # Strict agreement is deliberate: a single random match should not pass.
    matches = []
    for start in (0, 1, 2):
        if meaningful_length - start < 4:
            continue
        bodies = [p[start:-1] for p in packets]
        endings = [p[-1] for p in packets]
        if len(set(endings)) >= 3:
            algorithms = [
                ('sum8', [sum(b) & 255 for b in bodies]),
                ('xor8', [_xor8(b) for b in bodies]),
                ('crc8-poly07', [_crc8(b) for b in bodies]),
            ]
            for name, predicted in algorithms:
                if all(p == observed for p, observed in zip(predicted, endings)):
                    matches.append({'algorithm': name, 'start_offset': start,
                                    'field_offset': meaningful_length - 1,
                                    'confidence': 'high', 'matches': len(packets)})
            # A shifted additive sum is useful in proprietary 8-bit protocols,
            # but is weaker evidence than a direct standard checksum.
            residuals = {(sum(body) + actual) & 255 for body, actual in zip(bodies, endings)}
            if len(residuals) == 1:
                matches.append({'algorithm': 'negative-sum8-plus-constant',
                                'constant_hex': f'{next(iter(residuals)):02x}',
                                'start_offset': start, 'field_offset': meaningful_length - 1,
                                'confidence': 'possible', 'matches': len(packets)})
        if meaningful_length - start >= 5:
            # CRC16 is little-endian in Modbus RTU.
            if len({p[-2:] for p in packets}) >= 3 and all(
                _crc16_modbus(p[start:-2]) == int.from_bytes(p[-2:], 'little')
                for p in packets
            ):
                matches.append({'algorithm': 'crc16-modbus-le', 'start_offset': start,
                                'field_offset': meaningful_length - 2,
                                'confidence': 'high', 'matches': len(packets)})
    # Prefer exact checks, then start of frame; show at most 3 explanations.
    matches.sort(key=lambda m: (m['confidence'] != 'high', m['start_offset']))
    return matches[:3]


def _length_candidates(streams: dict[tuple, list[bytes]]) -> list[dict]:
    out = []
    for key, packets in streams.items():
        usable = [p for p in packets if p and len(p) <= 255]
        if len(usable) < 6 or len({len(p) for p in usable}) < 2:
            continue
        for offset in range(min(4, min(len(p) for p in usable))):
            for adjustment in range(-4, 5):
                if all(p[offset] == len(p) + adjustment for p in usable):
                    out.append({'device': key[1], 'endpoint': key[3], 'offset': offset,
                                'formula': f'frame_length {adjustment:+d}',
                                'samples': len(usable), 'confidence': 'possible'})
                    break
    return out[:20]


def analyze_messages(events: list[dict], *, max_samples: int = MAX_ANALYZED_EVENTS) -> dict:
    """Analyze capture events; return JSON-serializable candidates, not facts.

    Events are packet/report *observations*; serial reads may end mid-frame.
    Inferred byte significance is only a hypothesis requiring confirmation.
    """
    if not 1 <= max_samples <= 50_000:
        raise ValueError('max_samples must be from 1 to 50000')
    selected = _take_sample(events, max_samples)
    streams: dict[tuple, list[bytes]] = defaultdict(list)
    ignored = 0
    for event in selected:
        try:
            packet = bytes.fromhex(event.get('hex', ''))
        except (ValueError, TypeError):
            ignored += 1
            continue
        if not packet:
            ignored += 1
            continue
        streams[_stream_key(event)].append(packet)

    groups = []
    by_length: dict[tuple, list[bytes]] = defaultdict(list)
    for key, pkts in streams.items():
        for p in pkts:
            by_length[(key, len(p))].append(p)
    for (key, frame_length), pkts in by_length.items():
        offset, subtypes = _split_opcode(pkts)
        variants = [(value, rows) for value, rows in subtypes.items()] if offset is not None else [(None, pkts)]
        for opcode_value, rows in variants:
            # HID reports with trailing fixed zero padding: don't test checksum on zeros.
            padding = 0
            for pos in range(frame_length - 1, max(0, frame_length - 512), -1):
                if all(row[pos] == 0 for row in rows):
                    padding += 1
                else:
                    break
            meaningful = frame_length - padding if padding >= 2 else frame_length
            scan_length = min(frame_length, MAX_ANALYZED_BYTES)
            constant = []
            variable = []
            for pos in range(scan_length):
                common = Counter(p[pos] for p in rows)
                if len(common) == 1:
                    constant.append({'offset': pos, 'hex': f'{rows[0][pos]:02x}'})
                else:
                    variable.append({'offset': pos, 'values': len(common)})
            signature = ' '.join((f'{rows[0][pos]:02x}' if all(p[pos] == rows[0][pos] for p in rows) else '??')
                                 for pos in range(min(12, frame_length)))
            groups.append({'id': '', 'source': key[0], 'device': key[1], 'direction': key[2],
                           'endpoint': key[3], 'length': frame_length, 'samples': len(rows),
                           'signature': signature, 'type_byte_offset': offset,
                           'type_byte_value': f'{opcode_value:02x}' if opcode_value is not None else None,
                           'fixed_offsets': constant[:16], 'changing_offsets': variable[:32],
                           'counter_candidates': _counter_candidates(rows, meaningful),
                           'checksum_candidates': _checksum_candidates(rows, meaningful),
                           'trailing_zero_padding': padding if padding >= 2 else 0,
                           'examples': [row.hex(' ') for row in rows[:3]],
                           'confidence': 'tentative' if len(rows) < 5 else 'pattern-only'})
    groups.sort(key=lambda g: (-g['samples'], g['device'], g['length']))
    for i, group in enumerate(groups, 1):
        group['id'] = f'T{i:02d}'
    return {'capture_events': len(events), 'analyzed_events': len(selected),
            'ignored_events': ignored, 'stream_count': len(streams), 'type_count': len(groups),
            'types': groups[:50], 'omitted_types': max(0, len(groups) - 50),
            'length_candidates': _length_candidates(streams),
            'warnings': [
                'Heuristics, not proven protocol decoding. Capture at least 5+ diverse samples per type.',
                'Serial read chunks may not align to message boundaries; a signature does not prove framing.',
                'Counters, length fields and checksums are only possible interpretations.',
            ] + (['Analysis sampled events across the capture; not every report was examined.']
                 if len(events) > len(selected) else [])}
