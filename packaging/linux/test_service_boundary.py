#!/usr/bin/python3
"""Disposable root-container integration test; never run on the host."""

import hashlib
import json
import os
import pathlib
import pwd
import signal
import socket
import struct
import subprocess
import threading
import time

AGENT_UID = 21001
RUNTIME = pathlib.Path("/run/agents-vault")


def as_uid(uid, action):
    read_fd, write_fd = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(read_fd)
        try:
            os.setgroups([])
            os.setgid(uid)
            os.setuid(uid)
            result = {"ok": action()}
        except Exception as error:
            result = {"error_type": type(error).__name__}
        os.write(write_fd, json.dumps(result).encode())
        os._exit(0)
    os.close(write_fd)
    with os.fdopen(read_fd, "rb") as stream:
        result = json.load(stream)
    os.waitpid(child, 0)
    return result


def call(endpoint, request):
    with socket.socket(socket.AF_UNIX) as stream:
        stream.settimeout(3)
        stream.connect(str(RUNTIME / endpoint))
        stream.sendall(json.dumps(request).encode() + b"\n")
        return json.loads(stream.makefile("rb").readline())


def identity(uid):
    def apply():
        os.setgroups([])
        os.setgid(uid)
        os.setuid(uid)
    return apply


def wait_until(predicate, message, timeout=5):
    deadline = time.monotonic() + timeout
    while not predicate():
        assert time.monotonic() < deadline, message
        time.sleep(0.02)


def children(pid):
    try:
        return [int(value) for value in pathlib.Path(f"/proc/{pid}/task/{pid}/children").read_text().split()]
    except FileNotFoundError:
        return []


def descendants(pid):
    result = []
    # The service starts children from worker threads, so inspect every task.
    try:
        threads = list(pathlib.Path(f"/proc/{pid}/task").iterdir())
    except FileNotFoundError:
        return []
    for task in threads:
        for child in map(int, (task / "children").read_text().split()):
            result.append(child)
            result.extend(descendants(child))
    return result


def running(pid):
    try:
        return "State:\tZ" not in pathlib.Path(f"/proc/{pid}/status").read_text()
    except FileNotFoundError:
        return False


def test_runner_service(broker_uid, runner_uid):
    runner_runtime = pathlib.Path("/run/agents-vault-runner")
    runner_runtime.mkdir(exist_ok=True)
    runner_runtime.chmod(0o755)
    os.chown(runner_runtime, runner_uid, runner_uid)
    endpoint = runner_runtime / "launch.sock"
    relay_directory = RUNTIME / "test-relay"
    relay_directory.mkdir(mode=0o711, exist_ok=True)
    os.chown(relay_directory, broker_uid, broker_uid)
    relay_path = relay_directory / "proxy.sock"
    relay = socket.socket(socket.AF_UNIX)
    relay.bind(str(relay_path))
    relay.listen(4)
    relay.settimeout(8)
    relay_path.chmod(0o666)
    os.chown(relay_path, broker_uid, broker_uid)
    canary = pathlib.Path("/usr/libexec/agents-vault/av-runner-canary")
    canary.write_bytes(pathlib.Path("/input-binaries/av-runner-canary").read_bytes())
    canary.chmod(0o755)
    request = {
        "proxy_socket": str(relay_path), "program": str(canary), "args": ["long-parent"],
        "env": [], "ca_file": None, "timeout_seconds": 10,
        "program_sha256": list(hashlib.sha256(canary.read_bytes()).digest()),
        "helper_sha256": list(hashlib.sha256(pathlib.Path("/usr/libexec/agents-vault/av-runner-helper").read_bytes()).digest()),
    }
    def start_service():
        service = subprocess.Popen(["/usr/libexec/agents-vault/av-runner-service"], preexec_fn=identity(runner_uid),
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        def ready():
            if service.poll() is not None:
                return True
            try:
                with socket.socket(socket.AF_UNIX) as probe:
                    probe.connect(str(endpoint))
                    peer_pid = struct.unpack("3i", probe.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[0]
                    return peer_pid == service.pid
            except (FileNotFoundError, ConnectionRefusedError):
                return False
        wait_until(ready, "runner service did not start")
        assert service.poll() is None, service.communicate()[1].decode()
        return service

    def launch(payload):
        return subprocess.Popen(["/usr/libexec/agents-vault/av-runner-client", json.dumps(payload)],
                                preexec_fn=identity(broker_uid), stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def forbidden_launch():
        with socket.socket(socket.AF_UNIX) as connection:
            connection.settimeout(2)
            connection.connect(str(endpoint))
            payload = json.dumps(request).encode()
            try:
                connection.sendall(struct.pack("!I", len(payload)) + payload)
                assert connection.recv(4) == b""
            except (ConnectionResetError, BrokenPipeError):
                pass
            return True

    service = start_service()
    try:
        for uid in [AGENT_UID, 0, runner_uid]:
            assert as_uid(uid, forbidden_launch)["ok"]
        assert not descendants(service.pid), "untrusted peer launched a process"
        for mode in ["cancel", "timeout", "service_crash"]:
            payload = dict(request, timeout_seconds=2 if mode == "timeout" else 10)
            client = launch(payload)
            try:
                wait_until(lambda: len(descendants(service.pid)) >= 4 or client.poll() is not None,
                           "runner process tree did not start")
                process_tree = descendants(service.pid)
                assert len(process_tree) >= 4, f"namespace launch failed: {client.communicate()[1].decode()} service={service.poll()}"
                for pid in process_tree:
                    uid_line = next(line for line in pathlib.Path(f"/proc/{pid}/status").read_text().splitlines() if line.startswith("Uid:"))
                    assert set(map(int, uid_line.split()[1:])) == {runner_uid}, (pid, uid_line)
                if mode == "cancel":
                    client.kill()
                elif mode == "service_crash":
                    service.kill()
                    service.communicate(timeout=5)
                client.communicate(timeout=6)
                if mode == "timeout":
                    assert client.returncode == 124
                wait_until(lambda: not any(running(pid) for pid in process_tree), f"{mode} left runner descendants")
                if mode == "service_crash":
                    # Stale socket and lock are recovered by the next instance.
                    service = start_service()
                    time.sleep(0.1)
                    assert service.poll() is None, service.communicate()[1].decode()
            finally:
                if client.poll() is None:
                    client.kill()
                    client.communicate(timeout=3)
        host_loopback = socket.socket()
        host_loopback.bind(("127.0.0.1", 0))
        host_loopback.listen()
        observed = []
        def relay_once():
            connection, _ = relay.accept()
            with connection:
                observed.append(struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1])
                assert connection.recv(4) == b"PING"
                connection.sendall(b"PONG")
        relay_thread = threading.Thread(target=relay_once)
        relay_thread.start()
        payload = dict(request, args=[], env=[
            ["HOST_TEST_PORT", str(host_loopback.getsockname()[1])],
            ["HOST_SECRET_PATH", "/var/lib/agents-vault/vault-canary"],
            ["HOST_SOCKET_PATH", str(endpoint)],
            ["BROKER_HOST_PID", str(os.getpid())],
        ])
        client = launch(payload)
        output = client.communicate(timeout=10)
        relay_thread.join(timeout=8)
        assert client.returncode == 0, output[1].decode()
        assert observed == [runner_uid], observed
        host_loopback.close()
        # A mismatched digest fails before the policy command starts.
        client = launch(dict(request, program_sha256=[0] * 32))
        client.communicate(timeout=5)
        assert client.returncode != 0
        assert not descendants(service.pid)
        print("runner: distinct host UID; agent/root/runner launch peers rejected; relay peer authenticated; confinement canary passed; cancellation, deadline, crash/restart kill detached descendants; digest mismatch denied", flush=True)
    finally:
        service.terminate()
        _, diagnostic = service.communicate(timeout=5)
        if diagnostic:
            print(diagnostic.decode(), flush=True)
        relay.close()
        relay_path.unlink()
        relay_directory.rmdir()
        canary.unlink()


def test_unlock_lifecycle(broker_uid, runner_uid):
    vault = pathlib.Path("/var/lib/agents-vault/session-test.db")
    subprocess.run(["/input-binaries/create-test-vault", str(vault)], preexec_fn=identity(broker_uid), check=True)
    environment = {"AVD_RUNTIME_DIR": str(RUNTIME), "AVD_SERVICE_AGENT_UID": str(AGENT_UID),
                   "AVD_CLIENT_UID": str(AGENT_UID), "AVD_VAULT_PATH": str(vault)}
    previous_admin_token = None
    for restart in range(2):
        broker = subprocess.Popen(["/usr/libexec/agents-vault/avd"], env=environment,
                                  preexec_fn=identity(broker_uid), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            wait_until(lambda: all((RUNTIME / name).exists() for name in ["agent.sock", "client.sock", "admin.sock"])
                       or broker.poll() is not None, "locked broker did not start")
            assert broker.poll() is None, broker.communicate()[1].decode()
            admin_token = (RUNTIME / "admin.token").read_text()
            if previous_admin_token:
                assert admin_token != previous_admin_token
            previous_admin_token = admin_token
            status = {"op": "status", "token": admin_token}
            for uid in [AGENT_UID, runner_uid]:
                assert as_uid(uid, lambda: (RUNTIME / "admin.token").read_text())["error_type"] == "PermissionError"
                assert as_uid(uid, lambda: call("admin.sock", status))["error_type"] == "PermissionError"
            try:
                call("admin.sock", status)
                raise AssertionError("wrong admin UID accepted with valid token")
            except (ConnectionError, json.JSONDecodeError):
                pass
            assert as_uid(broker_uid, lambda: call("admin.sock", dict(status, token="00" * 32)))["ok"]["error"] == "unauthorized"
            assert as_uid(broker_uid, lambda: call("admin.sock", status))["ok"]["data"]["locked"]
            operation = {"connection": "demo/provider", "action": "proxy.run", "target": "api.example.test", "arguments": {"command": ["/usr/bin/true"]}}
            assert as_uid(AGENT_UID, lambda: call("agent.sock", {"op": "request", "operation": operation}))["ok"]["error"] == "Locked"
            assert as_uid(AGENT_UID, lambda: call("client.sock", {"op": "request", "operation": operation}))["ok"]["error"] == "Locked"
            def operator(action, passphrase=None):
                result = subprocess.run(["/usr/libexec/agents-vault/av-operator", action],
                                        preexec_fn=identity(broker_uid), input=passphrase,
                                        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                return result
            assert operator("unlock", "incorrect\n").returncode != 0
            assert as_uid(broker_uid, lambda: call("admin.sock", status))["ok"]["data"]["locked"]
            assert operator("unlock", "synthetic-service-test-passphrase\n").returncode == 0
            assert not as_uid(broker_uid, lambda: call("admin.sock", status))["ok"]["data"]["locked"]
            assert as_uid(AGENT_UID, lambda: call("agent.sock", {"op": "request", "operation": operation}))["ok"]["error"] == "InvalidOperation"
            assert as_uid(AGENT_UID, lambda: call("client.sock", {"op": "request", "operation": operation}))["ok"]["error"] == "InvalidOperation"
            for endpoint in ["agent.sock", "client.sock"]:
                for forged in [
                    {"op": "decide", "token": admin_token, "passphrase": "synthetic-service-test-passphrase",
                     "request_id": "00000000-0000-0000-0000-000000000000", "approve": True, "ttl_seconds": 30},
                    {"op": "manage", "token": admin_token, "passphrase": "synthetic-service-test-passphrase",
                     "operation": {"action": "list"}},
                    {"op": "unlock", "token": admin_token, "passphrase": "synthetic-service-test-passphrase"},
                ]:
                    response = as_uid(AGENT_UID, lambda: call(endpoint, forged))["ok"]
                    assert response["error"] == "invalid_request", (endpoint, response)
            assert operator("lock").returncode == 0
            assert as_uid(AGENT_UID, lambda: call("agent.sock", {"op": "request", "operation": operation}))["ok"]["error"] == "Locked"
            assert operator("unlock", "synthetic-service-test-passphrase\n").returncode == 0
        finally:
            broker.terminate()
            broker.communicate(timeout=5)
    print("lifecycle: configured vault starts locked; private admin token/socket deny agent/runner and forged UID; public agent/client sockets reject administrative requests even with token and passphrase; bad passphrase denied; local operator unlock/relock works; relock closes the session; SIGTERM/restart relocks and rotates capabilities", flush=True)

def main():
    assert pathlib.Path("/.dockerenv").exists(), "run only in the disposable test container"
    subprocess.run(["/boundary-tests/install.sh", "--bin-dir", "/input-binaries", "--agent-uid", str(AGENT_UID)], check=True)
    public_cli = pathlib.Path("/usr/bin/av")
    packaged_cli = pathlib.Path("/usr/libexec/agents-vault/av")
    assert public_cli.is_symlink() and public_cli.readlink() == pathlib.Path("../libexec/agents-vault/av")
    assert packaged_cli.is_file() and packaged_cli.stat().st_uid == 0
    assert packaged_cli.stat().st_mode & 0o777 == 0o755
    subprocess.run(["systemd-analyze", "verify", "/usr/lib/systemd/system/agents-vault.service", "/usr/lib/systemd/system/agents-vault-runner.service"], check=True)
    subprocess.run(["apparmor_parser", "--skip-kernel-load", "--skip-cache", "/etc/apparmor.d/agents-vault-runner"], check=True)
    account = pwd.getpwnam("av-broker")
    assert account.pw_shell.endswith("/nologin") and account.pw_dir == "/nonexistent"
    for path, mode in [(RUNTIME, 0o755), (pathlib.Path("/var/lib/agents-vault"), 0o700)]:
        path.mkdir(exist_ok=True)
        path.chmod(mode)
        os.chown(path, account.pw_uid, account.pw_gid)
    pathlib.Path("/var/lib/agents-vault/vault-canary").write_text("synthetic-only")
    runner = pwd.getpwnam("av-runner")
    assert runner.pw_shell.endswith("/nologin") and runner.pw_dir == "/nonexistent"
    assert len({account.pw_uid, runner.pw_uid, AGENT_UID, 0}) == 4
    test_runner_service(account.pw_uid, runner.pw_uid)
    test_unlock_lifecycle(account.pw_uid, runner.pw_uid)
    subprocess.run(["/boundary-tests/install.sh", "--bin-dir", "/input-binaries", "--agent-uid", str(AGENT_UID)], check=True)
    assert pwd.getpwnam("av-broker").pw_uid == account.pw_uid
    assert pwd.getpwnam("av-runner").pw_uid == runner.pw_uid
    assert pathlib.Path("/var/lib/agents-vault/vault-canary").read_text() == "synthetic-only"
    subprocess.run(["/boundary-tests/uninstall.sh"], check=True)
    assert not public_cli.exists() and not public_cli.is_symlink()
    assert not packaged_cli.exists()
    assert not pathlib.Path("/usr/libexec/agents-vault/avd").exists()
    assert not pathlib.Path("/usr/lib/systemd/system/agents-vault.service").exists()
    assert not pathlib.Path("/usr/lib/systemd/system/agents-vault-runner.service").exists()
    assert pathlib.Path("/var/lib/agents-vault/vault-canary").read_text() == "synthetic-only"
    assert pwd.getpwnam("av-broker").pw_uid == account.pw_uid
    assert pwd.getpwnam("av-runner").pw_uid == runner.pw_uid
    print("repeat install preserves identity/state; uninstall removes package while preserving recovery state", flush=True)
    print("service boundary tests passed; systemd boot remains a separate gate", flush=True)


if __name__ == "__main__":
    main()
