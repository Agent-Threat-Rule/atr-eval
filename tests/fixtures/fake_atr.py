"""Test fixture: stands in for the ATR command line. Prints a version, or an empty scan result."""

import json
import sys

if "--version" in sys.argv:
    print("0.0.0-test")
else:
    print(json.dumps({"scan_type": "mcp", "events_scanned": 1, "threats_detected": 0, "results": []}))
