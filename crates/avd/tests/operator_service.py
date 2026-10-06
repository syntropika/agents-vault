#!/usr/bin/python3
"""Focused management checks inside a disposable root container only."""
import concurrent.futures
import hashlib
import json
import os
import pathlib
import pwd
import pty
import select
import termios
import socket
import subprocess
import time

RUNTIME = pathlib.Path("/run/agents-vault")
STATE = pathlib.Path("/var/lib/agents-vault")
PASSPHRASE = "synthetic-service-test-passphrase"
SECRET = "av-synthetic-operator-private-value"


def identity(account):
    def apply():
        os.setgroups([])
        os.setgid(account.pw_gid)
        os.setuid(account.pw_uid)
    return apply


def main():
    assert pathlib.Path("/.dockerenv").exists() and os.geteuid() == 0, "disposable root container required"
    subprocess.run(["/boundary-tests/install.sh", "--bin-dir", "/input-binaries", "--agent-uid", "21001"], check=True)
    account = pwd.getpwnam("av-broker")
    for directory, mode in [(RUNTIME, 0o755), (STATE, 0o700)]:
        directory.mkdir(exist_ok=True)
        directory.chmod(mode)
        os.chown(directory, account.pw_uid, account.pw_gid)
    vault = STATE / "operator-test.db"
    subprocess.run(["/input-binaries/create-test-vault", str(vault)], preexec_fn=identity(account), check=True)
    policy_path = STATE / "proxy-policy.json"
    ca = STATE / "synthetic-ca.der"
    ca.write_bytes(pathlib.Path("/input-binaries/synthetic-ca.der").read_bytes())
    os.chown(ca, account.pw_uid, account.pw_gid)
    ca.chmod(0o600)
    policy = {"connection": "demo/provider", "secret_name": "demo/provider-token", "host": "api.example.test", "command": ["/usr/bin/true"], "upstream_addr": "127.0.0.1:9", "upstream_ca_der": str(ca), "max_connects": 1, "max_requests": 1, "max_runtime_seconds": 5, "runner_helper": "/usr/libexec/agents-vault/av-runner-helper"}
    policy_path.write_text(json.dumps(policy))
    policy_path.chmod(0o600)
    os.chown(policy_path, account.pw_uid, account.pw_gid)
    config = pathlib.Path("/etc/agents-vault/service.env")
    config.write_text(f"AVD_VAULT_PATH={vault}\nAVD_PROXY_POLICY_PATH={policy_path}\n")
    config.chmod(0o644)
    environment = {"AVD_RUNTIME_DIR": str(RUNTIME), "AVD_SERVICE_AGENT_UID": "21001", "AVD_VAULT_PATH": str(vault), "AVD_PROXY_POLICY_PATH": str(policy_path)}
    daemon = subprocess.Popen(["/usr/libexec/agents-vault/avd"], env=environment, cwd="/", preexec_fn=identity(account), stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def operator(*args, lines=(), expect=True, cwd="/", stdin=None):
        keywords = {"input": "".join(line + "\n" for line in lines)} if stdin is None else {"stdin": stdin}
        result = subprocess.run(["/usr/libexec/agents-vault/av-operator", *args], cwd=cwd, preexec_fn=identity(account), text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **keywords)
        assert SECRET not in result.stdout + result.stderr, "secret was exposed by the operator response"
        assert (result.returncode == 0) == expect, (args, result.stdout, result.stderr)
        return json.loads(result.stdout) if expect else result

    def raw_as_broker(request):
        # The request body travels through a private pipe, never argv or files.
        code = "import json,socket,sys; s=socket.socket(socket.AF_UNIX); s.connect('/run/agents-vault/admin.sock'); s.sendall(sys.stdin.buffer.read()); print(s.makefile().readline(),end='')"
        result = subprocess.run(["/usr/bin/python3", "-c", code], input=json.dumps(request) + "\n", text=True, preexec_fn=identity(account), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        assert SECRET not in result.stdout + result.stderr
        return json.loads(result.stdout)

    try:
        deadline = time.monotonic() + 5
        while not (RUNTIME / "admin.sock").exists():
            assert daemon.poll() is None, daemon.communicate()[1].decode()
            assert time.monotonic() < deadline
            time.sleep(0.02)
        assert operator("status")["locked"]
        operation = {"action": "add", "name": "demo/provider-token", "value": SECRET}
        admin_token = (RUNTIME / "admin.token").read_text()
        assert raw_as_broker({"op": "manage", "token": "00" * 32, "passphrase": PASSPHRASE, "operation": operation})["error"] == "unauthorized"
        assert operator("add", "demo/provider-token", lines=("wrong passphrase", SECRET), expect=False)
        assert operator("add", "demo/provider-token", lines=(PASSPHRASE, SECRET))["grants"] == 0
        operator("add", "demo/provider-token", lines=(PASSPHRASE, SECRET), expect=False)
        assert operator("policy", "demo/provider-token", lines=(PASSPHRASE,))["policy"]["grants"] == []
        granted = operator("grant", "demo/provider-token", lines=(PASSPHRASE,), cwd="/tmp")
        grant = granted["policy"]["grants"][0]
        assert grant["approval"] == "every_run"
        assert grant["request"]["working_directory"] == "/"
        assert grant["request"]["config_sha256"] == hashlib.sha256(policy_path.read_bytes()).hexdigest()
        # A real PTY confirms echo is disabled during secret input and restored.
        master, slave = pty.openpty()
        original_terminal = termios.tcgetattr(slave)
        terminal_cli = subprocess.Popen(["/usr/libexec/agents-vault/av-operator", "policy", "demo/provider-token"], preexec_fn=identity(account), stdin=slave, stderr=slave, stdout=subprocess.PIPE)
        assert select.select([master], [], [], 5)[0], "terminal prompt did not arrive"
        prompt = os.read(master, 1024)
        assert b"Vault passphrase:" in prompt
        assert termios.tcgetattr(slave)[3] & (termios.ECHO | termios.ECHONL) == 0
        os.write(master, (PASSPHRASE + "\n").encode())
        output = terminal_cli.communicate(timeout=10)[0]
        assert terminal_cli.returncode == 0 and PASSPHRASE.encode() not in output
        assert termios.tcgetattr(slave) == original_terminal
        if select.select([master], [], [], 0)[0]:
            assert PASSPHRASE.encode() not in os.read(master, 8192)
        os.close(master)
        os.close(slave)
        operator("rotate", "demo/provider-token", lines=(PASSPHRASE, SECRET + "-rotated"))
        assert operator("policy", "demo/provider-token", lines=(PASSPHRASE,))["policy"] == granted["policy"]
        operator("revoke", "demo/provider-token", lines=("wrong passphrase",), expect=False)
        assert operator("policy", "demo/provider-token", lines=(PASSPHRASE,))["policy"] == granted["policy"]
        operator("unlock", lines=(PASSPHRASE,))
        for action in ["add", "rotate", "grant", "revoke", "policy"]:
            lines = (PASSPHRASE, SECRET) if action in ["add", "rotate"] else (PASSPHRASE,)
            operator(action, "demo/provider-token", lines=lines, expect=False)
        operator("lock")
        # Concurrent unlock and revoke may serialize either way, but must never
        # yield an unlocked broker and a successful revoke in the same race.
        with concurrent.futures.ThreadPoolExecutor() as pool:
            requests = [{"op": "unlock", "token": admin_token, "passphrase": PASSPHRASE}, {"op": "manage", "token": admin_token, "passphrase": PASSPHRASE, "operation": {"action": "revoke", "name": "demo/provider-token"}}]
            unlocked, revoked = list(pool.map(raw_as_broker, requests))
        assert not (unlocked["ok"] and revoked["ok"]), (unlocked, revoked)
        if unlocked["ok"]:
            operator("lock")
            operator("revoke", "demo/provider-token", lines=(PASSPHRASE,))
        assert operator("policy", "demo/provider-token", lines=(PASSPHRASE,))["policy"]["grants"] == []
        operator("unlock", lines=(PASSPHRASE,), expect=False)
        assert operator("status")["locked"]
        # Root and the agent cannot use the management CLI under their own UID.
        root_cli = subprocess.run(["/usr/libexec/agents-vault/av-operator", "policy", "demo/provider-token"], input=PASSPHRASE + "\n", text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert root_cli.returncode != 0
        # A regular file is refused before sensitive bytes are read.
        with open("/etc/hostname") as stream:
            operator("policy", "demo/provider-token", stdin=stream, expect=False)
        # Configuration drift and unsafe authority fail closed.
        config.write_text(f"AVD_VAULT_PATH={STATE / 'other.db'}\nAVD_PROXY_POLICY_PATH={policy_path}\n")
        operator("policy", "demo/provider-token", lines=(PASSPHRASE,), expect=False)
        config.write_text(f"AVD_VAULT_PATH={vault}\nAVD_PROXY_POLICY_PATH={policy_path}\n")
        os.chown(config, account.pw_uid, account.pw_gid)
        operator("policy", "demo/provider-token", lines=(PASSPHRASE,), expect=False)
        print("operator management passed: private input, default deny, pinned installed grant, rotation, revoke, exclusive unlock gate, capability and identity separation, wrong-passphrase preservation, config authority, no secret output")
    finally:
        daemon.terminate()
        daemon.communicate(timeout=5)


if __name__ == "__main__":
    main()
