#!/usr/bin/env python3
"""Bounded worker for the selected-client production ARP canary."""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import sys
import time


def load_production(source, runtime):
    sys.path.insert(0, "/opt/freebox-failover")
    sys.path.insert(0, str(Path(source).resolve().parent))
    specification = importlib.util.spec_from_file_location("freebox_ethernet_canary", source)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    module.RUNTIME = Path(runtime)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--runtime", required=True)
    parser.add_argument("--client-mac", required=True)
    parser.add_argument("--client-ip", required=True)
    parser.add_argument("--lease-seconds", type=int, default=65)
    parser.add_argument("--recover", action="store_true")
    arguments = parser.parse_args()
    if not 45 <= arguments.lease_seconds <= 90:
        parser.error("Automatic primary recovery lease must be 45..90 seconds")
    if os.geteuid() != 0:
        parser.error("Run this bounded canary as root")
    module = load_production(arguments.source, arguments.runtime)
    settings = module.Settings(arguments.config)
    selected = (arguments.client_mac.lower(), arguments.client_ip)
    if arguments.recover:
        module.Network(settings).cleanup()
        return
    started = time.monotonic()
    state_path = Path(arguments.runtime).parent / "wan-state.json"
    state_path.write_text(json.dumps({"state": "down"}))
    state_path.chmod(0o600)

    class SimulatedFreebox:
        last_error = None

        def __init__(self, unused):
            pass

        def state(self):
            current = json.loads(state_path.read_text())
            if current["state"] == "down" and time.monotonic() - started >= arguments.lease_seconds:
                return "up"
            return current["state"]

        def close(self):
            pass

    module.Freebox = SimulatedFreebox
    return module.run(settings, client_canary=selected)


if __name__ == "__main__":
    raise SystemExit(main())
