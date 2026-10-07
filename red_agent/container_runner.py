"""Container entrypoint for a bounded Red Agent campaign."""
from __future__ import annotations

import os
import time

import httpx


def main() -> None:
    print("Red Agent container started. Waiting for campaigns to be triggered via the Blue Agent UI...", flush=True)
    while True:
        time.sleep(3600)

if __name__ == "__main__":
    main()
