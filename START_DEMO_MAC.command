#!/bin/zsh
set -e
cd "$(dirname "$0")"
if ! command -v python3 >/dev/null; then
  echo 'Python 3 is required. Install from python.org or Homebrew.'
  read '?Press Enter to close...'
  exit 1
fi
python3 -m usb_studio demo --jsonl usb-demo.jsonl --html usb-demo.html
open usb-demo.html
echo 'Demo opened in your browser. This is synthetic sample data.'
