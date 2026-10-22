#!/usr/bin/env python3
"""Run the production controller with a bounded synthetic primary outage."""

import argparse
import importlib.util
import json
from pathlib import Path
import sys
import time


def load_controller(source, runtime):
    sys.path.insert(0, "/opt/freebox-failover")
    sys.path.insert(0, str(Path(source).resolve().parent))
    specification = importlib.util.spec_from_file_location("freebox_ethernet_lan_canary", source)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    module.RUNTIME = Path(runtime)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--runtime", required=True)
    parser.add_argument("--lease-seconds", type=int, default=45)
    arguments = parser.parse_args()
    if not 30 <= arguments.lease_seconds <= 60:
        parser.error("Synthetic primary-down period must be 30..60 seconds")

    module = load_controller(arguments.source, arguments.runtime)
    settings = module.Settings(arguments.config)
    if not settings.enabled or settings.blockers():
        raise SystemExit("Temporary canary configuration must be enabled and unblocked")
    started = time.monotonic()

    class SyntheticFreebox:
        last_error = None

        def __init__(self, unused):
            pass

        def state(self):
            return "up" if time.monotonic() - started >= arguments.lease_seconds else "down"

        def close(self):
            pass

    module.Freebox = SyntheticFreebox
    return module.run(settings)


if __name__ == "__main__":
    raise SystemExit(main())
