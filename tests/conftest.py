"""Pytest configuration for DefendForge tests."""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure blue_agent is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
