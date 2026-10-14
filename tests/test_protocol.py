"""Tests for conservative message-family and field inference."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from usb_studio.core import record, save_events, demo_events
from usb_studio.protocol import analyze_messages, _crc16_modbus, _crc8
from usb_studio.view import render


def ev(data, device='test', endpoint='0x81'):
    return record(data, 'hid', device, 'in', endpoint=endpoint)


class ProtocolTests(unittest.TestCase):
    def test_demo_infers_checksum_without_claiming_proof(self):
        result = analyze_messages(demo_events())
        self.assertEqual(result['type_count'], 1)
        g = result['types'][0]
        self.assertEqual(g['samples'], 5)
        self.assertEqual(g['signature'].split()[:3], ['aa', '01', '00'])
        self.assertIn(3, [x['offset'] for x in g['changing_offsets']])
        self.assertIn('negative-sum8-plus-constant', [x['algorithm'] for x in g['checksum_candidates']])

    def test_type_byte_splitting_when_repeated(self):
        events = [ev(bytes([0xaa, kind, 0x33, num, 0x55]))
                  for num in range(8) for kind in (1, 2)]
        result = analyze_messages(events)
        self.assertEqual(result['type_count'], 2)
        self.assertEqual(sorted(x['type_byte_value'] for x in result['types']), ['01', '02'])
        self.assertTrue(all(x['type_byte_offset'] == 1 for x in result['types']))
        self.assertTrue(all(x['counter_candidates'][0]['offset'] == 3 for x in result['types']))

    def test_direct_crc8_and_crc16(self):
        crc8 = [ev(bytes([0xaa, 7, 4, n]) + bytes([_crc8(bytes([0xaa, 7, 4, n]))])) for n in range(10)]
        crc16 = []
        for n in range(10):
            body = bytes([0xa5, 0x01, n, 0x72, 0x41])
            crc16.append(ev(body + _crc16_modbus(body).to_bytes(2, 'little'), 'modbus'))
        result8 = analyze_messages(crc8)
        result16 = analyze_messages(crc16)
        self.assertIn('crc8-poly07', [x['algorithm'] for x in result8['types'][0]['checksum_candidates']])
        self.assertIn('crc16-modbus-le', [x['algorithm'] for x in result16['types'][0]['checksum_candidates']])

    def test_length_field_and_stream_isolation(self):
        events = [ev(bytes([0x7e, length]) + bytes([0x10] * (length - 2)))
                  for length in (6, 7, 8, 9, 6, 7, 8, 9)]
        events += [ev(bytes([1, 1, 1]), device='other')]
        result = analyze_messages(events)
        self.assertTrue(any(x['offset'] == 1 and x['formula'] == 'frame_length +0'
                            for x in result['length_candidates']))
        self.assertEqual(result['stream_count'], 2)

    def test_hid_padding_and_sparse_data(self):
        events = [ev(bytes([0xf0, 0x11, i + 1, 0x21, 0, 0, 0, 0])) for i in range(6)]
        result = analyze_messages(events)
        self.assertEqual(result['types'][0]['trailing_zero_padding'], 4)
        self.assertEqual(analyze_messages([])['type_count'], 0)
        with self.assertRaises(ValueError):
            analyze_messages([], max_samples=0)

    def test_view_and_cli_generate_analysis(self):
        # Escape content before embedding it into an HTML script.
        html = render([ev(b'\xaa\x01\x04', device='</script><h1>unsafe</h1>')])
        self.assertIn('Automatic message recognition', html)
        self.assertIn('\\u003c/script\\u003e', html)
        self.assertNotIn('</script><h1>unsafe</h1>', html)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'input.jsonl'
            output = Path(tmp) / 'analysis.json'
            page = Path(tmp) / 'out.html'
            save_events(path, demo_events())
            ret = subprocess.run([sys.executable, '-m', 'usb_studio', 'analyze', str(path),
                                  '--output', str(output), '--html', str(page)],
                                 capture_output=True, text=True, check=True)
            self.assertIn('Recognized 1', ret.stdout)
            self.assertEqual(json.loads(output.read_text())['type_count'], 1)
            self.assertTrue(page.read_text().startswith('<!doctype html>'))


if __name__ == '__main__':
    unittest.main()
