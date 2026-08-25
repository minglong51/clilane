#!/usr/bin/env python3

import sys


sys.dont_write_bytecode = True

from provider_capture import collector_main


if __name__ == "__main__":
    raise SystemExit(collector_main("codex"))
