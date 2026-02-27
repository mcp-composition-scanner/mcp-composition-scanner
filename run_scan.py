#!/usr/bin/env python3
"""
Direct-run wrapper for composition analysis.
Use this if `python -m mcp_composition_scanner` doesn't work
(e.g., package not installed in the current venv).

Usage:
    python run_scan.py --files test-servers/a.json test-servers/b.json
    python run_scan.py --files test-servers/a.json test-servers/b.json --output-dir results/evaluation
"""

import sys
import os

# Add src/ to path so we can import without pip install
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

import asyncio
from mcp_composition_scanner.composition_analyser import main

asyncio.run(main())
