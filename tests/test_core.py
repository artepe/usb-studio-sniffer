import json
import tempfile
import unittest
from pathlib import Path
from usb_studio.core import clean_hex, compare, demo_events, load_events, save_events, variability
from usb_studio.backends import parse_tshark_line
from usb_studio.view import render

class StudioTests(unittest.TestCase):
    def test_demo_and_html(self):
        events = demo_events()
        self.assertEqual(len(events), 5)
        self.assertIn('USB Studio', render(events))
        stats = variability(events)
        self.assertFalse(stats[0]['changes'])
        self.assertTrue(stats[3]['changes'])

    def test_hex_compare(self):
        before = [{'hex':'aa 01 12'}]
        after = [{'hex':'aa 02 12 ff'}]
        self.assertEqual(compare(before, after)['changed_offsets'], [1, 3])
        self.assertEqual(clean_hex('AA:ff-10'), 'aaff10')
        with self.assertRaises(ValueError):
            clean_hex('AG')

    def test_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'data.jsonl'
            save_events(path, demo_events())
            self.assertEqual(len(load_events(path)), 5)

    def test_tshark_parser(self):
        line = '123.5\t42\t1\t7\t0x81\tC\taa:01:ff\t\n'
        event = parse_tshark_line(line)
        self.assertEqual(event['hex'], 'aa 01 ff')
        self.assertEqual(event['endpoint'], '0x81')
        self.assertEqual(event['ts'], 123.5)

if __name__ == '__main__':
    unittest.main()
