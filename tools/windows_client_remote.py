#!/usr/bin/env python3
"""Optional password-authenticated Windows SSH helper with pinned host keys."""

import argparse
import base64
import os
from pathlib import Path

import paramiko


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True)
    parser.add_argument("--user", required=True)
    parser.add_argument("--known-hosts", required=True)
    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument("--command")
    actions.add_argument("--script")
    actions.add_argument("--upload", nargs=2, metavar=("LOCAL", "REMOTE"))
    actions.add_argument("--download", nargs=2, metavar=("REMOTE", "LOCAL"))
    arguments = parser.parse_args()
    with paramiko.SSHClient() as client:
        client.load_host_keys(arguments.known_hosts)
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        client.connect(arguments.host, username=arguments.user,
                       password=os.environ["FAILSAFE_SSH_PASSWORD"],
                       allow_agent=False, look_for_keys=False,
                       timeout=10, auth_timeout=10, banner_timeout=10)
        if arguments.upload or arguments.download:
            with client.open_sftp() as transfer:
                if arguments.upload:
                    transfer.put(*arguments.upload)
                else:
                    transfer.get(*arguments.download)
            return
        code = arguments.command if arguments.command else Path(arguments.script).read_text(encoding="utf-8-sig")
        code = "$ProgressPreference='SilentlyContinue'; $ErrorActionPreference='Stop';\n" + code
        encoded = base64.b64encode(code.encode("utf-16-le")).decode("ascii")
        stdin, stdout, stderr = client.exec_command(
            "powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " + encoded,
            timeout=120)
        stdin.close()
        output, errors = stdout.read().decode("utf-8-sig"), stderr.read().decode("utf-8-sig")
        result = stdout.channel.recv_exit_status()
        print(output, end="")
        if result:
            raise RuntimeError(f"Remote PowerShell failed ({result}): {errors}")


if __name__ == "__main__":
    main()
