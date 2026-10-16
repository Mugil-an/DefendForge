"""Pytest configuration for DefendForge tests."""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Ensure blue_agent and workspace root are importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("RED_SIMULATION_ONLY", "true")
