#!/usr/bin/env python3
"""Destructive fresh-install test for a disposable, administrator-owned Mac.

Requires a Developer ID signed/notarized package. Never weakens the production
signature requirements or substitutes a test client for the installed broker.
The operator calls below run as the broker UID with a synthetic vault
passphrase; this does not validate a desktop approval or whole-agent confinement.
"""

import argparse
import array
import hashlib
import json
import os
import pathlib
import platform
import pwd
import secrets
import signal
import socket
import ssl
import stat
import subprocess
import time

APP = pathlib.Path("/Library/PrivilegedHelperTools/AgentsVault.app")
STATE = pathlib.Path("/private/var/db/agents-vault")
ENDPOINT = STATE / "run/supervisor.sock"
PLIST = "/Library/LaunchDaemons/dev.agentsvault.supervisor.plist"
BROKER_PLIST = "/Library/LaunchDaemons/dev.agentsvault.broker.plist"
AGENT_DIRECTORY = STATE / "agent"
MARKER = pathlib.Path("/private/var/tmp/agents-vault-disposable-service-test")
HOST = "api.example.test"
SECRET = "av-synthetic-service-boundary-token"


def run(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def drop_identity(account):
    os.setgroups([])
    os.setgid(account.pw_gid)
    os.setuid(account.pw_uid)


def as_identity(account, action):
    read_fd, write_fd = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(read_fd)
        try:
            drop_identity(account)
            result = {"value": action()}
        except Exception as error:
            result = {"error": type(error).__name__}
        os.write(write_fd, json.dumps(result).encode())
        os._exit(0)
    os.close(write_fd)
    with os.fdopen(read_fd, "rb") as stream:
        result = json.load(stream)
    _, status = os.waitpid(child, 0)
    assert os.waitstatus_to_exitcode(status) == 0
    return result


def wait_for(predicate, message, seconds=15):
    deadline = time.monotonic() + seconds
    while not predicate():
        assert time.monotonic() < deadline, message
        time.sleep(0.05)



def call(account, runtime, endpoint, request, timeout=5):
    def action():
        with socket.socket(socket.AF_UNIX) as stream:
            stream.settimeout(timeout)
            stream.connect(str(runtime / endpoint))
            stream.sendall(json.dumps(request).encode() + b"\n")
            return json.loads(stream.makefile("rb").readline())
    result = as_identity(account, action)
    assert "error" not in result, result
    return result["value"]


def operator(account, runtime, action, passphrase=None, success=True, name=None, value=None, extra=()):
    arguments = [action]
    if name is not None:
        arguments.append(name)
    elif action in ("status", "unlock", "lock"):
        arguments.append(str(runtime))
    arguments.extend(extra)
    result = subprocess.run([str(APP / "Contents/MacOS/av-operator"), *arguments],
        input=((passphrase + "\n" + (value + "\n" if value is not None else "")).encode() if passphrase is not None else b""),
        env={"PATH": "/usr/bin:/bin", "HOME": "/var/empty"},
        preexec_fn=lambda: drop_identity(account), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    for credential in (SECRET,):
        assert credential.encode() not in result.stdout + result.stderr
    if passphrase is not None:
        assert passphrase.encode() not in result.stdout + result.stderr
    if success:
        assert result.returncode == 0, (
            f"installed operator command failed: {action}: "
            f"{result.stderr.decode(errors='replace').strip()}")
        return json.loads(result.stdout)
    assert result.returncode != 0, "operator command unexpectedly succeeded"
    return None


def operator_decision(account, action, request_id, passphrase=None, success=True):
    result = subprocess.run(
        [str(APP / "Contents/MacOS/av-operator"), action, request_id],
        input=((passphrase + "\n").encode() if passphrase is not None else b""),
        env={"PATH": "/usr/bin:/bin", "HOME": "/var/empty"},
        preexec_fn=lambda: drop_identity(account),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    assert SECRET.encode() not in result.stdout + result.stderr
    if passphrase is not None:
        assert passphrase.encode() not in result.stdout + result.stderr
    if not success:
        assert result.returncode != 0, "operator decision unexpectedly succeeded"
        return None
    assert result.returncode == 0, (action, result.stderr.decode(errors="replace"))
    return result.stdout.decode().strip()


def expect_peer_denied(account, path, request):
    def attempt():
        with socket.socket(socket.AF_UNIX) as stream:
            stream.settimeout(5)
            stream.connect(str(path))
            try:
                stream.sendall(json.dumps(request).encode() + b"\n")
                return stream.recv(1) == b""
            except (BrokenPipeError, ConnectionResetError):
                return True
    result = as_identity(account, attempt)
    assert result.get("error") == "PermissionError" or result.get("value") is True, result


def client_boundary_checks(broker, runner, agent, runtime, fixture_request_id):
    """Check the installed typed endpoint without granting approval authority."""
    client = AGENT_DIRECTORY / "client.sock"
    metadata = client.lstat()
    assert stat.S_ISSOCK(metadata.st_mode) and metadata.st_uid == broker.pw_uid
    typed_operation = {"connection": "demo/missing", "action": "proxy.run",
                       "target": HOST, "arguments": {"command": ["/usr/bin/av-fixture", "request",
                           "--host", HOST, "--method", "get", "--path", "/probe"]}}
    typed_request = {"op": "request", "operation": typed_operation}
    # A request from the selected UID reaches broker validation through client.sock.
    assert call(agent, AGENT_DIRECTORY, "client.sock", typed_request)["error"] == "InvalidOperation"
    for forbidden in [
        {"op": "review", "request_id": fixture_request_id},
        {"op": "decide", "request_id": fixture_request_id,
         "approve": True, "ttl_seconds": 30},
        {"op": "unlock", "passphrase": "synthetic"},
        {"op": "finish_host_proxy", "task_id": fixture_request_id, "exit_code": 0},
        {"op": "request", "operation": typed_operation, "token": "00" * 32},
    ]:
        assert call(agent, AGENT_DIRECTORY, "client.sock", forbidden)["error"] == "invalid_request"
    # The selected CLI endpoint can execute a proxy.run task. While this
    # request is pending, both operations must remain inert.
    assert call(agent, AGENT_DIRECTORY, "client.sock",
                {"op": "execute", "request_id": fixture_request_id})["error"] == "NotApproved"
    assert call(agent, AGENT_DIRECTORY, "client.sock",
                {"op": "task_status", "task_id": fixture_request_id})["error"] == "UnknownRequest"
    for account in [broker, runner, pwd.getpwnam("nobody"), pwd.getpwuid(0)]:
        for request in [
            typed_request,
            {"op": "execute", "request_id": fixture_request_id},
            {"op": "task_status", "task_id": fixture_request_id},
            {"op": "review", "request_id": fixture_request_id},
            {"op": "decide", "request_id": fixture_request_id,
             "approve": True, "ttl_seconds": 30},
        ]:
            expect_peer_denied(account, client, request)


def wrong_signature():
    with socket.socket(socket.AF_UNIX) as control:
        control.settimeout(5)
        control.connect(str(ENDPOINT))
        broker, transport = socket.socketpair()
        try:
            control.sendmsg([b"L"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                     array.array("i", [transport.fileno()]))])
            return control.recv(1) == b""
        except (ConnectionResetError, BrokenPipeError):
            return True
        finally:
            broker.close()
            transport.close()


def tls_material(directory, host):
    """Create a short-lived synthetic CA and a leaf for the selected TLS host."""
    quiet = {"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
    (directory / "ca.cnf").write_text(
        "[req]\ndistinguished_name=dn\nx509_extensions=ca\n[dn]\n"
        "[ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n")
    run("/usr/bin/openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
        "-config", str(directory / "ca.cnf"),
        "-subj", "/CN=Agents Vault synthetic test CA", "-keyout", str(directory / "ca.key"),
        "-out", str(directory / "ca.pem"), **quiet)
    run("/usr/bin/openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
        "-subj", f"/CN={host}", "-keyout", str(directory / "server.key"),
        "-out", str(directory / "server.csr"), **quiet)
    (directory / "server.ext").write_text(
        f"basicConstraints=critical,CA:FALSE\nsubjectAltName=DNS:{host}\n"
        "extendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature,keyEncipherment\n")
    run("/usr/bin/openssl", "x509", "-req", "-in", str(directory / "server.csr"),
        "-CA", str(directory / "ca.pem"), "-CAkey", str(directory / "ca.key"),
        "-CAcreateserial", "-days", "1", "-extfile", str(directory / "server.ext"),
        "-out", str(directory / "server.pem"), **quiet)
    run("/usr/bin/openssl", "x509", "-in", str(directory / "ca.pem"), "-outform", "DER",
        "-out", str(directory / "ca.der"), **quiet)


def provider_fixture(directory):
    """One TLS request, no network access beyond loopback, no real credential."""
    tls_material(directory, HOST)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    address = listener.getsockname()
    read_fd, write_fd = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(read_fd)
        try:
            listener.settimeout(180)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(directory / "server.pem", directory / "server.key")
            connection, _ = listener.accept()
            with context.wrap_socket(connection, server_side=True) as stream:
                stream.settimeout(10)
                request = bytearray()
                while not request.endswith(b"\r\n\r\n"):
                    byte = stream.recv(1)
                    assert byte, "provider received a truncated request"
                    request.extend(byte)
                    assert len(request) < 16384
                assert f"authorization: bearer {SECRET}".encode() in request.lower()
                stream.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            os.write(write_fd, b"verified")
            os._exit(0)
        except BaseException:
            os._exit(1)
    os.close(write_fd)
    listener.close()
    return address, child, read_fd


def synthetic_broker_task(broker, runner, agent):
    directory = STATE / "broker"
    passphrase = secrets.token_urlsafe(32)
    recovery_directory = pathlib.Path("/private/var/root/agents-vault-recovery")
    recovery_directory.mkdir(mode=0o700)
    recovery_path = recovery_directory / "vault.recovery"
    initialized = subprocess.run([str(APP / "Contents/MacOS/av-operator"), "init", "--recovery-file", str(recovery_path)],
        input=(passphrase + "\n" + passphrase + "\n").encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert initialized.returncode == 0, "installed root bootstrap failed"
    assert json.loads(initialized.stdout)["vault"] == str(directory / "vault.db")
    recovery_key = recovery_path.read_bytes()
    assert len(recovery_key) == 64 and bytes.fromhex(recovery_key.decode())
    assert recovery_path.stat().st_uid == 0 and stat.S_IMODE(recovery_path.stat().st_mode) == 0o600
    assert recovery_key not in initialized.stdout + initialized.stderr
    assert passphrase.encode() not in initialized.stdout + initialized.stderr
    for account in [broker, runner, agent]:
        assert as_identity(account, lambda: recovery_path.read_bytes().decode())["error"] == "PermissionError"
    duplicate_output = recovery_directory / "duplicate.recovery"
    duplicate = subprocess.run([str(APP / "Contents/MacOS/av-operator"), "init", "--recovery-file", str(duplicate_output)],
        input=(passphrase + "\n" + passphrase + "\n").encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert duplicate.returncode != 0 and not duplicate_output.exists()
    address, provider, provider_result = provider_fixture(directory)
    command = ["/usr/bin/av-fixture", "request", "--host", HOST, "--method", "get", "--path", "/probe", "--assert-direct-tcp-blocked"]
    policy = {"connection": "demo/fixture", "secret_name": "demo/fixture-token", "host": HOST,
              "command": command, "upstream_addr": f"{address[0]}:{address[1]}",
              "upstream_ca_der": str(directory / "ca.der"), "max_connects": 1,
              "max_requests": 1, "max_runtime_seconds": 30, "mac_service": True}
    policy_path = directory / "proxy-policy.json"
    policy_path.write_text(json.dumps(policy))
    os.chmod(policy_path, 0o600)
    for name in ["proxy-policy.json", "ca.der"]:
        os.chown(directory / name, broker.pw_uid, broker.pw_gid)
    runtime = directory / "runtime"
    run("/bin/sh", str(APP / "Contents/Resources/configure-service.sh"), "--agent-uid", str(agent.pw_uid))
    run("/bin/launchctl", "enable", "system/dev.agentsvault.broker")
    run("/bin/launchctl", "bootstrap", "system", BROKER_PLIST)
    try:
        wait_for(lambda: (AGENT_DIRECTORY / "agent.sock").exists()
                 and (AGENT_DIRECTORY / "client.sock").exists()
                 and (runtime / "admin.sock").exists(), "installed broker did not start")
        assert operator(broker, runtime, "status")["locked"] is True
        assert operator(broker, runtime, "add", name="demo/fixture-token", passphrase=passphrase, value=SECRET)["grants"] == 0
        for account in [runner, agent]:
            for path in [runtime / "admin.token", directory / "vault.db"]:
                assert as_identity(account, lambda: path.read_bytes().decode())["error"] == "PermissionError"
            operator(account, runtime, "status", success=False)
            expect_peer_denied(account, runtime / "admin.sock", {"op": "status", "token": "00" * 32})
        expect_peer_denied(pwd.getpwuid(0), runtime / "admin.sock",
                           {"op": "status", "token": (runtime / "admin.token").read_text()})
        assert call(broker, runtime, "admin.sock", {"op": "status", "token": "00" * 32})["error"] == "unauthorized"
        operation = {"connection": "demo/fixture", "action": "proxy.run", "target": HOST,
                     "arguments": {"command": command}}
        typed_operation = {**operation, "connection": "demo/missing"}
        for account in [runner, broker, pwd.getpwuid(0)]:
            expect_peer_denied(account, AGENT_DIRECTORY / "agent.sock", {"op": "request", "operation": operation})
        assert call(agent, AGENT_DIRECTORY, "agent.sock", {"op": "request", "operation": operation})["error"] == "Locked"
        assert call(agent, AGENT_DIRECTORY, "client.sock",
                    {"op": "request", "operation": typed_operation})["error"] == "Locked"
        operator(broker, runtime, "unlock", passphrase="incorrect synthetic passphrase", success=False)
        assert operator(broker, runtime, "status")["locked"] is True
        # A service recipe must have an exact encrypted per-secret grant before
        # any credential is loaded, including the otherwise valid fixture.
        operator(broker, runtime, "unlock", passphrase=passphrase, success=False)
        assert operator(broker, runtime, "status")["locked"] is True
        operator(broker, runtime, "grant", name="demo/fixture-token",
                 passphrase="incorrect synthetic passphrase", success=False)
        granted = operator(broker, runtime, "grant", name="demo/fixture-token", passphrase=passphrase)
        assert granted["locked"] is True
        request = granted["policy"]["grants"][0]["request"]
        assert request["host"] == HOST and request["arguments"] == command[1:]
        original_policy = policy_path.read_bytes()
        original_ca = (directory / "ca.der").read_bytes()
        assert request["config_sha256"] == hashlib.sha256(original_policy).hexdigest()
        identity = request["macos_service"]
        assert identity["upstream_ca_sha256"] == hashlib.sha256(original_ca).hexdigest()
        resources = APP / "Contents/Resources"
        service = json.loads((resources / "service.json").read_bytes())
        manifest = json.loads((resources / "guest/guest.json").read_bytes())
        assert service["format"] == manifest["format"] == 2
        assert identity["format"] == service["format"] - 1
        assert identity["team_identifier"] == service["team_identifier"]
        for field in ["broker_cdhash", "supervisor_cdhash", "runner_cdhash"]:
            assert identity[field] == service[field].lower()
        for field in ["kernel_sha256", "initramfs_sha256", "fixture_sha256"]:
            assert identity[field] == manifest[field]
        assert identity["service_policy_sha256"] == hashlib.sha256((resources / "service.json").read_bytes()).hexdigest()
        assert identity["guest_manifest_sha256"] == hashlib.sha256((resources / "guest/guest.json").read_bytes()).hexdigest()
        inspected = operator(broker, runtime, "policy", name="demo/fixture-token", passphrase=passphrase)
        assert inspected["policy"] == granted["policy"]
        assert SECRET not in json.dumps(inspected)
        # Whitespace is a policy-byte change even though JSON meaning is equal.
        policy_path.write_bytes(original_policy + b"\n")
        operator(broker, runtime, "unlock", passphrase=passphrase, success=False)
        policy_path.write_bytes(original_policy)
        (directory / "ca.der").write_bytes(original_ca + b"\x00")
        operator(broker, runtime, "unlock", passphrase=passphrase, success=False)
        (directory / "ca.der").write_bytes(original_ca)
        revoked = operator(broker, runtime, "revoke", name="demo/fixture-token", passphrase=passphrase)
        assert revoked["grants"] == 0 and revoked["locked"] is True
        operator(broker, runtime, "unlock", passphrase=passphrase, success=False)
        operator(broker, runtime, "grant", name="demo/fixture-token", passphrase=passphrase)
        assert operator(broker, runtime, "unlock", passphrase=passphrase)["locked"] is False
        operator(broker, runtime, "revoke", name="demo/fixture-token", passphrase=passphrase, success=False)
        assert call(agent, AGENT_DIRECTORY, "agent.sock", {"op": "unlock", "passphrase": "irrelevant"})["error"] == "invalid_request"
        requested = call(agent, AGENT_DIRECTORY, "agent.sock", {"op": "request", "operation": operation})
        request_id = requested["data"]["request_id"]
        assert call(agent, AGENT_DIRECTORY, "agent.sock", {"op": "execute", "request_id": request_id})["error"] == "NotApproved"
        client_boundary_checks(broker, runner, agent, runtime, request_id)
        admin_token = (runtime / "admin.token").read_text()
        for endpoint in ["agent.sock", "client.sock"]:
            forged = {"op": "decide", "token": admin_token, "passphrase": passphrase,
                      "request_id": request_id, "approve": True, "ttl_seconds": 45}
            assert call(agent, AGENT_DIRECTORY, endpoint, forged)["error"] == "invalid_request"
        expect_peer_denied(agent, runtime / "admin.sock", {
            "op": "decide", "token": admin_token, "passphrase": passphrase,
            "request_id": request_id, "approve": True, "ttl_seconds": 45,
        })
        wrong = call(broker, runtime, "admin.sock", {
            "op": "decide", "token": admin_token, "passphrase": "incorrect synthetic passphrase",
            "request_id": request_id, "approve": True, "ttl_seconds": 45,
        }, timeout=30)
        assert not wrong["ok"] and "authentication failed" in wrong["error"], wrong
        review = json.loads(operator_decision(broker, "review", request_id))
        assert review["id"] == request_id and review["state"] == "pending"
        assert review["operation"]["connection"] == "demo/fixture"
        operator_decision(broker, "approve", request_id,
                          passphrase="incorrect synthetic passphrase", success=False)
        assert operator_decision(broker, "approve", request_id, passphrase=passphrase) == "APPROVED"
        started = call(agent, AGENT_DIRECTORY, "agent.sock", {"op": "execute", "request_id": request_id})
        assert started["ok"], started
        # The fixture is intentionally fast; its no-NIC assertion plus the TLS
        # provider receipt prove the guest ran. The supervisor sets the UID.
        deadline = time.monotonic() + 40
        observed_runner = False
        while True:
            processes = subprocess.check_output(["/bin/ps", "-axo", "uid=,comm="], text=True)
            observed_runner |= any(line.split(maxsplit=1)[0] == str(runner.pw_uid)
                                   and str(APP / "Contents/MacOS/av-vmm") in line
                                   for line in processes.splitlines())
            status = call(agent, AGENT_DIRECTORY, "agent.sock", {"op": "task_status", "task_id": request_id})
            if status["data"]["state"] != "running":
                assert status["data"]["state"] == "finished" and status["data"]["exit_code"] == 0, status
                break
            assert time.monotonic() < deadline, "service fixture deadline expired"
            time.sleep(0.02)
        assert observed_runner, "did not observe the VMM under _avrunner"
        assert call(agent, AGENT_DIRECTORY, "agent.sock", {"op": "execute", "request_id": request_id})["error"] == "QuotaExhausted"
        denied = call(agent, AGENT_DIRECTORY, "agent.sock", {"op": "request", "operation": operation})
        denied_id = denied["data"]["request_id"]
        assert operator_decision(broker, "deny", denied_id, passphrase=passphrase) == "DENIED"
        assert call(agent, AGENT_DIRECTORY, "agent.sock", {"op": "execute", "request_id": denied_id})["error"] == "Denied"
        with os.fdopen(provider_result, "rb") as result:
            assert result.read() == b"verified"
        _, status = os.waitpid(provider, 0)
        assert os.waitstatus_to_exitcode(status) == 0
        provider = None
        assert operator(broker, runtime, "lock")["locked"] is True
        assert call(agent, AGENT_DIRECTORY, "agent.sock", {"op": "task_status", "task_id": request_id})["error"] == "Locked"
        previous_token = (runtime / "admin.token").read_text()
        run("/bin/launchctl", "kickstart", "-k", "system/dev.agentsvault.broker")
        wait_for(lambda: (runtime / "admin.token").exists() and (runtime / "admin.token").read_text() != previous_token,
                 "broker did not rotate administration token after restart")
        assert operator(broker, runtime, "status")["locked"] is True
        assert call(agent, AGENT_DIRECTORY, "client.sock", {"op": "request",
                    "operation": typed_operation})["error"] == "Locked"
    finally:
        run("/bin/launchctl", "bootout", "system/dev.agentsvault.broker")
        if provider is not None:
            os.kill(provider, signal.SIGKILL)
            os.waitpid(provider, 0)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", required=True, type=pathlib.Path)
    parser.add_argument("--agent-uid", required=True, type=int,
                        help="Existing ordinary login UID authorized for the public agent socket")
    args = parser.parse_args()
    assert platform.system() == "Darwin" and platform.machine() == "arm64"
    assert os.geteuid() == 0, "run only as administrator on a disposable Mac"
    marker = MARKER.lstat()
    assert stat.S_ISREG(marker.st_mode) and marker.st_uid == 0 and marker.st_mode & 0o022 == 0
    assert MARKER.read_text().strip() == "DISPOSABLE AGENTS_VAULT SERVICE TEST"
    assert args.package.is_absolute() and args.package.is_file()
    agent = pwd.getpwuid(args.agent_uid)
    assert agent.pw_uid >= 500 and agent.pw_shell not in ["/usr/bin/false", "/bin/false", "/usr/sbin/nologin"]
    for path in [APP, STATE, pathlib.Path(PLIST), pathlib.Path(BROKER_PLIST), pathlib.Path("/usr/local/bin/av")]:
        assert not path.exists() and not path.is_symlink(), f"fresh install required: {path}"
    for name in ["_avd", "_avrunner"]:
        try:
            pwd.getpwnam(name)
        except KeyError:
            continue
        raise AssertionError(f"existing service identity: {name}")
    run("/usr/sbin/pkgutil", "--check-signature", str(args.package))
    run("/usr/sbin/spctl", "--assess", "--type", "install", str(args.package))
    run("/usr/sbin/installer", "-pkg", str(args.package), "-target", "/")
    broker, runner = pwd.getpwnam("_avd"), pwd.getpwnam("_avrunner")
    assert broker.pw_uid != runner.pw_uid and broker.pw_gid != runner.pw_gid
    for account in [broker, runner]:
        assert account.pw_dir == "/var/empty" and account.pw_shell == "/usr/bin/false"
        hidden = subprocess.check_output(["/usr/bin/dscl", ".", "-read", "/Users/" + account.pw_name, "IsHidden"], text=True)
        assert hidden.strip() == "IsHidden: 1"
        assert subprocess.check_output(["/usr/bin/id", "-Gn", account.pw_name], text=True).strip() == account.pw_name
    canary = STATE / "broker/custody-canary"
    canary.write_text("synthetic service custody canary")
    os.chown(canary, broker.pw_uid, broker.pw_gid)
    os.chmod(canary, 0o600)
    for account in [runner, pwd.getpwnam("nobody")]:
        assert as_identity(account, lambda: canary.read_text())["error"] == "PermissionError"
        assert as_identity(account, lambda: open(APP / "Contents/MacOS/av-vmm", "ab").close())["error"] == "PermissionError"
    run("/bin/launchctl", "enable", "system/dev.agentsvault.supervisor")
    run("/bin/launchctl", "bootstrap", "system", PLIST)
    wait_for(ENDPOINT.exists, "supervisor failed to start")
    assert as_identity(runner, wrong_signature)["error"] == "PermissionError"
    assert as_identity(broker, wrong_signature)["value"] is True
    synthetic_broker_task(broker, runner, agent)
    run("/bin/launchctl", "kickstart", "-k", "system/dev.agentsvault.supervisor")
    wait_for(lambda: as_identity(broker, wrong_signature).get("value") is True, "supervisor failed to restart")
    print("PASS: root bootstrap with protected recovery output, installed identities, locked LaunchDaemon startup, private operator grants/unlock/relock, missing/revoked/drifted grant denial, selected login UID typed client endpoint, wrong UID/root/_avd/_avrunner client denial, token-only and wrong-passphrase decision rejection, private operator review/approve/deny, no client Review/Decide authority, pinned signed broker, _avrunner VMM, no-NIC synthetic HTTPS, replay denial, restart with a fresh admin token")
    print("Not tested: reboot/logout, production recovery/operator approval, whole-agent confinement, or real providers. Installation remains for inspection; discard the machine snapshot.")


if __name__ == "__main__":
    main()
