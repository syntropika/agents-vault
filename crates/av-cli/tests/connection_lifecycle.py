#!/usr/bin/env python3
"""Synthetic real-terminal connection management lifecycle; Linux/macOS only.

Run with the built av binary and an output directory outside the repository.
The optional interpreter must be snapshot-compatible on the current host.
"""
import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import platform
import pty
import select
import signal
import subprocess
import tempfile
import termios
import time

parser = argparse.ArgumentParser()
parser.add_argument("av", type=Path)
parser.add_argument("--output", type=Path, required=True)
parser.add_argument("--interpreter", type=Path, default=Path("/bin/sh"))
args = parser.parse_args()
av = args.av.resolve()
args.output.mkdir(parents=True, exist_ok=False)
passphrase = "av-synthetic-connection-passphrase"
first_token = "av-synthetic-connection-first"
second_token = "av-synthetic-connection-second"
environment = dict(os.environ)
transcript = []
checks = {}

def run(command, cwd, replies=()):
    if not replies:
        result = subprocess.run(command, cwd=cwd, env=environment, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, timeout=30)
        assert "passphrase:" not in result.stdout.lower(), result.stdout
        return result.returncode, result.stdout
    pid, master = pty.fork()
    if pid == 0:
        os.chdir(cwd)
        os.execve(command[0], command, environment)
    raw = bytearray()
    pending = list(replies)
    consumed = 0
    ended = False
    start = time.monotonic()
    try:
        while time.monotonic() - start < 90:
            ready, _, _ = select.select([master], [], [], 0.1)
            if ready:
                try:
                    block = os.read(master, 65536)
                except OSError as error:
                    if error.errno == errno.EIO:
                        block = b""
                    else:
                        raise
                if not block:
                    break
                raw.extend(block)
            if pending:
                prompt, answer = pending[0]
                index = raw.find(prompt.encode(), consumed)
                if index >= 0 and not termios.tcgetattr(master)[3] & termios.ECHO:
                    os.write(master, answer.encode() + b"\n")
                    consumed = index + len(prompt)
                    pending.pop(0)
            waited, status = os.waitpid(pid, os.WNOHANG)
            if waited:
                ended = True
                break
        if not ended:
            exit_deadline = min(start + 90, time.monotonic() + 5)
            while time.monotonic() < exit_deadline and not ended:
                waited, status = os.waitpid(pid, os.WNOHANG)
                ended = bool(waited)
                if not ended:
                    time.sleep(0.02)
        if not ended:
            diagnostic = raw.decode(errors="replace")
            for value in [passphrase, first_token, second_token]:
                diagnostic = diagnostic.replace(value, "[REDACTED]")
            raise AssertionError("PTY command did not finish: " + diagnostic[-2000:])
        assert not pending, "required input prompt did not appear"
        text = raw.decode(errors="replace")
        assert passphrase not in text, "passphrase was echoed"
        assert first_token not in text and second_token not in text, "token was printed"
        return os.waitstatus_to_exitcode(status), text
    finally:
        if not ended:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
        os.close(master)


try:
    with tempfile.TemporaryDirectory(prefix="project-", dir=args.output) as directory:
        project = Path(directory)
        config, vault = project / "av.toml", project / "vault.db"
        config.write_text("schema=2\n[project]\nid='connection-demo'\n")
        prefix = [str(av), "--config", str(config), "--vault", str(vault)]
        unlock = [("Vault passphrase: ", passphrase)]

        def invoke(arguments, replies=()):
            code, text = run(prefix + arguments, project, replies)
            transcript.append("$ av " + " ".join(arguments) + "\n" + text + "\nExit: " + str(code))
            assert all(value not in text for value in [passphrase, first_token, second_token])
            return code, text

        code, text = invoke(["status"])
        assert code == 0 and "not initialized" in text
        code, text = invoke(["setup", "--direct", "--recovery-file", str(project / "recovery.txt")], [("New vault passphrase: ", passphrase), ("Confirm vault passphrase: ", passphrase)])
        assert code == 0, text
        code, text = invoke(["unlock", "--direct"], unlock)
        assert code == 0 and "no unlock is cached" in text
        checks["setup_and_unlock"] = True

        code, text = invoke(["connect", "add", "service/work", "--host", "api.example.test"], unlock + [("Connection credential: ", first_token)])
        assert code == 0 and '"version": 1' in text and '"host": "api.example.test"' in text
        code, text = invoke(["connect", "list"], unlock)
        assert code == 0 and '"id": "service/work"' in text and "credential" not in text
        code, text = invoke(["connect", "show", "service/work"], unlock)
        assert code == 0 and '"grants": []' in text and "credential" not in text
        code, text = invoke(["secret", "list"], unlock)
        assert code == 0 and "av-connections" not in text
        checks["generic_connection_is_private_and_default_deny"] = True

        code, text = invoke(["connect", "replace", "service/work", "--if-version", "1"], unlock + [("Replacement credential: ", second_token)])
        assert code == 0 and '"version": 2' in text
        code, text = invoke(["connect", "replace", "service/work", "--if-version", "1"], unlock)
        assert code != 0 and "version changed" in text
        code, text = invoke(["connect", "revoke", "service/work", "--if-version", "2"], unlock)
        assert code == 0
        code, text = invoke(["connect", "disconnect", "service/work", "--if-version", "2"], unlock)
        assert code == 0 and '"version": 3' in text and '"active": false' in text
        checks["rotation_revoke_and_disconnect"] = True

    result = {"platform": platform.platform(), "binary_sha256": hashlib.sha256(av.read_bytes()).hexdigest(), "synthetic_only": True, "checks": checks, "limits": "Local credential management; provider-specific execution and protected broker delivery are separate."}
    (args.output / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
finally:
    (args.output / "transcript.txt").write_text("\n\n".join(transcript))
