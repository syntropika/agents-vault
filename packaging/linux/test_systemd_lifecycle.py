#!/usr/bin/python3
"""Run only inside the disposable guest with its own kernel and systemd PID 1."""

import hashlib
import http.client
import urllib.parse
import json
import os
import pathlib
import pwd
import shutil
import signal
import socket
import ssl
import subprocess
import select
import tempfile
import threading
import time
import traceback

BASE = pathlib.Path("/run/agents-vault")
STATE = pathlib.Path("/var/lib/agents-vault")
BIN = pathlib.Path("/usr/libexec/agents-vault")
AGENT_UID = 21001
SECRET = "av-synthetic-systemd-fixture"
PASSPHRASE = "synthetic-service-test-passphrase\n"


def run(*args, **options):
    return subprocess.run(args, check=True, text=True, **options)


def identity(uid):
    def apply():
        os.setgroups([])
        os.setgid(uid)
        os.setuid(uid)
    return apply


def as_uid(uid, action):
    read_fd, write_fd = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(read_fd)
        try:
            identity(uid)()
            result = {"value": action()}
        except Exception as error:
            result = {"error": type(error).__name__, "message": str(error)}
        os.write(write_fd, json.dumps(result).encode())
        os._exit(0)
    os.close(write_fd)
    with os.fdopen(read_fd, "rb") as stream:
        result = json.load(stream)
    os.waitpid(child, 0)
    return result


def call(name, request):
    with socket.socket(socket.AF_UNIX) as stream:
        stream.settimeout(10)
        stream.connect(str(BASE / name))
        stream.sendall(json.dumps(request).encode() + b"\n")
        return json.loads(stream.makefile("rb").readline())


def approval_http(request_id, body=None, origin="http://127.0.0.1:14323"):
    connection = http.client.HTTPConnection("127.0.0.1", 14323, timeout=10)
    try:
        path = "/requests/" + request_id
        headers = {} if body is None else {"Origin": origin, "Content-Type": "application/x-www-form-urlencoded"}
        connection.request("GET" if body is None else "POST", path, body, headers)
        reply = connection.getresponse()
        return reply.status, dict(reply.getheaders()), reply.read().decode()
    finally:
        connection.close()


def approval_form(request_id, passphrase, decision):
    status, headers, page = approval_http(request_id)
    assert status == 200 and headers["cache-control"] == "no-store", status
    assert SECRET not in page
    nonce = page.split('name="csrf" value="')[1].split('"')[0]
    return urllib.parse.urlencode({"csrf": nonce, "passphrase": passphrase, "decision": decision})


def wait_for(predicate, reason, seconds=20):
    deadline = time.monotonic() + seconds
    while not predicate():
        assert time.monotonic() < deadline, reason
        time.sleep(0.05)


def main_pid(unit):
    return int(subprocess.check_output(["systemctl", "show", "--value", "-p", "MainPID", unit], text=True).strip())


def runner_children(pid):
    children = set()
    for thread in pathlib.Path(f"/proc/{pid}/task").iterdir():
        try:
            children.update(map(int, (thread / "children").read_text().split()))
        except FileNotFoundError:
            pass
    return children


def operator(uid, action, passphrase=None, *arguments):
    result = subprocess.run([str(BIN / "av-operator"), action, *arguments], input=passphrase, capture_output=True, text=True, preexec_fn=identity(uid))
    assert result.returncode == 0, (action, result.stderr)
    return result


def assert_locked(uid):
    wait_for(lambda: all((BASE / name).exists() for name in ["admin.sock", "admin.token", "agent.sock"]), "broker IPC did not become ready")
    assert json.loads(operator(uid, "status").stdout)["locked"]
    reply = as_uid(AGENT_UID, lambda: call("agent.sock", {"op": "request", "operation": {"connection": "demo/provider", "action": "proxy.run", "target": "api.example.test", "arguments": {"command": ["/usr/bin/true"]}}}))
    assert reply["value"]["error"] == "Locked", reply


def certificates():
    tls = pathlib.Path("/var/lib/synthetic-provider")
    tls.mkdir(mode=0o700)
    quiet = {"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
    run("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "1", "-subj", "/CN=Synthetic test CA", "-keyout", str(tls / "ca.key"), "-out", str(tls / "ca.pem"), **quiet)
    run("openssl", "req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-subj", "/CN=api.example.test", "-keyout", str(tls / "leaf.key"), "-out", str(tls / "leaf.csr"), **quiet)
    (tls / "leaf.ext").write_text("basicConstraints=CA:FALSE\nsubjectAltName=DNS:api.example.test\nextendedKeyUsage=serverAuth\n")
    run("openssl", "x509", "-req", "-in", str(tls / "leaf.csr"), "-CA", str(tls / "ca.pem"), "-CAkey", str(tls / "ca.key"), "-CAcreateserial", "-days", "1", "-extfile", str(tls / "leaf.ext"), "-out", str(tls / "leaf.pem"), **quiet)
    run("openssl", "x509", "-in", str(tls / "ca.pem"), "-outform", "DER", "-out", str(STATE / "upstream-ca.der"), **quiet)
    return tls


class Provider:
    def __init__(self, tls):
        self.socket = socket.socket()
        self.socket.bind(("127.0.0.1", 0))
        self.socket.listen(4)
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(tls / "leaf.pem", tls / "leaf.key")
        self.context.set_alpn_protocols(["http/1.1"])
        self.requests = []
        self.errors = []
        self.hold = threading.Event()
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        while True:
            try:
                raw, _ = self.socket.accept()
                with self.context.wrap_socket(raw, server_side=True) as stream:
                    stream.settimeout(20)
                    request = b""
                    while not request.endswith(b"\r\n\r\n"):
                        received = stream.recv(1)
                        assert received, "provider connection closed before request headers"
                        request += received
                        assert len(request) <= 16384
                    self.requests.append(request.decode())
                    while self.hold.is_set():
                        time.sleep(0.02)
                    try:
                        stream.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                    except (BrokenPipeError, ssl.SSLError):
                        pass
            except Exception as error:
                self.errors.append(str(error))
                return


def install():
    run("/boundary-tests/install.sh", "--bin-dir", "/input-binaries", "--agent-uid", str(AGENT_UID))


LIVE_CLIENTS = []


def start_action(arguments, environment):
    process = subprocess.Popen([str(BIN / "av"), *arguments], preexec_fn=identity(AGENT_UID),
        env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    LIVE_CLIENTS.append(process)
    ready, _, _ = select.select([process.stdout], [], [], 10)
    assert ready, "av did not report a pending action"
    line = process.stdout.readline()
    assert line.startswith("Pending broker request: "), line
    return process, line.strip().removeprefix("Pending broker request: ")


def request_task(uid, command):
    home = pathlib.Path(tempfile.mkdtemp(prefix="av-live-cli-"))
    os.chown(home, AGENT_UID, AGENT_UID)
    process, request_id = start_action(
        ["run", "--broker", "--broker-connection", "demo/provider", "--broker-host", "api.example.test", "--", *command],
        {"PATH":"/usr/bin:/bin", "HOME":str(home), "XDG_CONFIG_HOME":str(home / "config"), "AVD_AGENT_SOCKET":str(BASE / "agent.sock")})
    before = as_uid(AGENT_UID, lambda: call("agent.sock", {"op": "execute", "request_id": request_id}))["value"]
    assert before["error"] == "WrongExecutionSession", before
    token = (BASE / "admin.token").read_text()
    approved = as_uid(uid, lambda: call("admin.sock", {"op": "decide", "token": token,
        "passphrase": PASSPHRASE.rstrip("\n"), "request_id": request_id, "approve": True, "ttl_seconds": 60}))["value"]
    assert approved["ok"], approved
    wait_for(lambda: task_status(request_id).get("data", {}).get("state") is not None, "owner did not start its action")
    return request_id


def task_status(task_id):
    return as_uid(AGENT_UID, lambda: call("agent.sock", {"op": "task_status", "task_id": task_id}))["value"]



def main():
    assert pathlib.Path("/boundary-tests/.disposable-vm").exists()
    assert pathlib.Path("/proc/1/comm").read_text().strip() == "systemd"
    assert not pathlib.Path("/.dockerenv").exists()
    print("AV_VM_TEST_ENV", subprocess.check_output(["uname", "-a"], text=True).strip(), flush=True)
    print("AV_VM_TEST_ENV", subprocess.check_output(["systemd", "--version"], text=True).splitlines()[0], flush=True)
    print("AV_VM_TEST_ENV", subprocess.check_output(["apparmor_parser", "--version"], text=True).splitlines()[0], flush=True)
    userns_restricted = pathlib.Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns").read_text().strip()
    print("AV_VM_TEST_ENV apparmor_restrict_unprivileged_userns=" + userns_restricted, flush=True)
    assert userns_restricted == "1", "guest must exercise the restricted-userns AppArmor profile"
    assert pathlib.Path("/sys/module/apparmor/parameters/enabled").read_text().strip() == "Y"
    for name in ["avd", "av-operator", "av-runner-helper", "av-runner-service", "av-runner-client", "av-runner-canary", "av-fixture"]:
        digest = hashlib.sha256((pathlib.Path("/input-binaries") / name).read_bytes()).hexdigest()
        print("AV_VM_TEST_BINARY", name, digest, flush=True)
    install()
    broker = pwd.getpwnam("av-broker")
    runner = pwd.getpwnam("av-runner")
    assert len({0, AGENT_UID, broker.pw_uid, runner.pw_uid}) == 4
    assert broker.pw_shell.endswith("nologin") and runner.pw_shell.endswith("nologin")
    assert broker.pw_dir == runner.pw_dir == "/nonexistent"
    profiles = pathlib.Path("/sys/kernel/security/apparmor/profiles").read_text()
    assert "agents-vault-runner (unconfined)" in profiles, profiles
    unprofiled = subprocess.run(["/usr/bin/unshare", "--user", "--map-root-user", "/usr/bin/true"], text=True, capture_output=True, preexec_fn=identity(runner.pw_uid))
    assert unprofiled.returncode != 0 and "Operation not permitted" in unprofiled.stderr, unprofiled
    assert STATE.stat().st_uid == broker.pw_uid and STATE.stat().st_mode & 0o777 == 0o700
    recovery = pathlib.Path("/root/agents-vault.recovery")
    initialized = run(str(BIN / "av-operator"), "init", "--recovery-file", str(recovery), input=PASSPHRASE * 2, capture_output=True)
    assert recovery.stat().st_uid == 0 and recovery.stat().st_mode & 0o777 == 0o600
    assert recovery.stat().st_size > 0
    assert (STATE / "vault.db").stat().st_uid == broker.pw_uid
    for uid in [broker.pw_uid, runner.pw_uid, AGENT_UID]:
        assert as_uid(uid, lambda: recovery.read_text())["error"] == "PermissionError"
    assert recovery.read_text().strip() not in initialized.stdout
    print("AV_VM_TEST_STAGE offline initialization, broker-owned vault and root-only recovery passed", flush=True)
    run("systemctl", "start", "agents-vault.service")
    assert_locked(broker.pw_uid)
    operator(broker.pw_uid, "unlock", PASSPHRASE)
    assert not json.loads(operator(broker.pw_uid, "status").stdout)["locked"]
    operator(broker.pw_uid, "lock")
    assert_locked(broker.pw_uid)
    run("systemctl", "stop", "agents-vault.service")
    print("AV_VM_TEST_STAGE fresh empty vault unlock and relock passed", flush=True)
    shutil.copy2("/input-binaries/av-fixture", BIN / "av-fixture")
    (BIN / "av-fixture").chmod(0o755)
    tls = certificates()
    provider = Provider(tls)
    command = [str(BIN / "av-fixture"), "request", "--host", "api.example.test", "--method", "get", "--path", "/probe", "--assert-direct-tcp-blocked"]
    policy = {"connection": "demo/provider", "secret_name": "demo/provider-token", "host": "api.example.test", "command": command, "upstream_addr": "127.0.0.1:" + str(provider.socket.getsockname()[1]), "upstream_ca_der": str(STATE / "upstream-ca.der"), "max_connects": 1, "max_requests": 1, "max_runtime_seconds": 60, "runner_helper": str(BIN / "av-runner-helper")}
    policy_path = STATE / "proxy-policy.json"
    policy_path.write_text(json.dumps(policy))
    policy_path.chmod(0o600)
    os.chown(policy_path, broker.pw_uid, broker.pw_gid)
    env = pathlib.Path("/etc/agents-vault/service.env")
    env.write_text(f"AVD_VAULT_PATH={STATE}/vault.db\nAVD_PROXY_POLICY_PATH={policy_path}\n")
    env.chmod(0o644)
    run("systemctl", "enable", "--now", "agents-vault.service")
    broker_pid, runner_pid = main_pid("agents-vault.service"), main_pid("agents-vault-runner.service")
    assert broker_pid and runner_pid
    assert pathlib.Path(f"/proc/{runner_pid}/attr/current").read_text().strip() == "agents-vault-runner (unconfined)"
    assert os.readlink(f"/proc/{runner_pid}/ns/net") != os.readlink("/proc/1/ns/net")
    assert os.readlink(f"/proc/{broker_pid}/ns/net") == os.readlink("/proc/1/ns/net")
    assert_locked(broker.pw_uid)
    admin_token = (BASE / "admin.token").read_text()
    for uid in [AGENT_UID, runner.pw_uid]:
        assert as_uid(uid, lambda: (BASE / "admin.token").read_text())["error"] == "PermissionError"
        assert as_uid(uid, lambda: call("admin.sock", {"op": "status", "token": admin_token}))["error"] == "PermissionError"
        assert as_uid(uid, lambda: (STATE / "vault.db").read_bytes().hex())["error"] == "PermissionError"
    print("AV_VM_TEST_STAGE clean install, exact AppArmor attachment, PID1 readiness, separate UIDs/network, locked startup passed", flush=True)
    operator(broker.pw_uid, "add", PASSPHRASE + SECRET + "\n", "demo/provider-token")
    operator(broker.pw_uid, "grant", PASSPHRASE, "demo/provider-token")
    operator(broker.pw_uid, "unlock", PASSPHRASE)
    task = request_task(broker.pw_uid, command)
    wait_for(lambda: task_status(task).get("data", {}).get("state") != "running", "proxy task did not finish", 40)
    status = task_status(task)
    assert status["data"]["state"] == "finished" and status["data"]["exit_code"] == 0, status
    assert len(provider.requests) == 1 and not provider.errors, (provider.requests, provider.errors)
    request = provider.requests[0].lower()
    assert "authorization: bearer " + SECRET in request, request
    assert "x-av-fixture-input: av-placeholder" in request, request
    print("AV_VM_TEST_STAGE unlock, approval, distinct runner launch and synthetic HTTPS injection passed", flush=True)
    operator(broker.pw_uid, "lock")
    host_command = [str(BIN / "av-fixture"), "request", "--host", "api.example.test", "--method", "get", "--path", "/probe"]
    host_policy = {
        "connection": "service/work", "connection_version": 1,
        "host": "api.example.test", "command": host_command,
        "upstream_addr": policy["upstream_addr"], "upstream_ca_der": policy["upstream_ca_der"],
        "max_connects": 1, "max_requests": 1, "max_runtime_seconds": 60,
        "host_client": True,
    }
    policy_path.write_text(json.dumps(host_policy))
    operator(broker.pw_uid, "connect-add", PASSPHRASE + SECRET + "\n", "service/work", "api.example.test")
    operator(broker.pw_uid, "connect-grant", PASSPHRASE, "service/work", "1")
    operator(broker.pw_uid, "unlock", PASSPHRASE)
    project = pathlib.Path("/tmp/av-agent-project")
    project.mkdir(mode=0o700)
    os.chown(project, AGENT_UID, AGENT_UID)
    config_path = project / "av.toml"
    config_path.write_text("schema = 2\n[project]\nid = 'systemd-test'\n[values.SERVICE_TOKEN]\ntype = 'string'\nconnection = { id = 'service/work', version = 1 }\ndelivery = 'proxy'\nrequired = true\n")
    proxy_config = project / "config"
    proxy_config.mkdir(mode=0o700)
    os.chown(proxy_config, AGENT_UID, AGENT_UID)
    agent_env = {
        "PATH": "/usr/bin:/bin", "HOME": str(project),
        "XDG_CONFIG_HOME": str(proxy_config), "AVD_AGENT_SOCKET": str(BASE / "agent.sock"),
    }
    requested, request_id = start_action(["--config", str(config_path), "run", "--", *host_command], agent_env)
    assert len(request_id) == 36
    before = as_uid(AGENT_UID, lambda: call("agent.sock", {"op": "execute", "request_id": request_id}))["value"]
    assert before["error"] == "WrongExecutionSession", before
    forged = as_uid(AGENT_UID, lambda: call("agent.sock", {
        "op": "decide", "request_id": request_id, "approve": True, "ttl_seconds": 60,
    }))["value"]
    assert forged["error"] == "invalid_request", forged
    token = (BASE / "admin.token").read_text()
    wrong = as_uid(broker.pw_uid, lambda: call("admin.sock", {
        "op": "decide", "token": token, "passphrase": "wrong",
        "request_id": request_id, "approve": True, "ttl_seconds": 60,
    }))["value"]
    assert not wrong["ok"] and "authentication failed" in wrong["error"], wrong
    reviewed = operator(broker.pw_uid, "review", None, request_id)
    assert '"connection": "service/work"' in reviewed.stdout
    assert '"connection_version": 1' in reviewed.stdout
    assert SECRET not in reviewed.stdout
    link = as_uid(AGENT_UID, lambda: call("agent.sock", {"op": "approval_link", "request_id": request_id}))["value"]
    assert link["data"]["url"] == f"http://127.0.0.1:14323/requests/{request_id}", link
    form = approval_form(request_id, "wrong", "approve")
    assert approval_http(request_id, form, "http://evil.test")[0] == 403
    assert approval_http(request_id, form)[0] == 401
    assert as_uid(AGENT_UID, lambda: call("agent.sock", {"op": "execute", "request_id": request_id}))["value"]["error"] == "WrongExecutionSession"
    time.sleep(1.1)
    form = approval_form(request_id, PASSPHRASE.strip(), "approve")
    assert approval_http(request_id, form)[0] == 200
    assert approval_http(request_id, form)[0] == 403
    stdout, stderr = requested.communicate(timeout=30)
    assert requested.returncode == 0, (stdout, stderr)
    assert SECRET not in stdout + stderr
    assert len(provider.requests) == 2 and not provider.errors, (provider.requests, provider.errors)
    assert "authorization: bearer " + SECRET in provider.requests[1].lower()
    denied_request, denied_id = start_action(["--config", str(config_path), "run", "--", *host_command], agent_env)
    time.sleep(1.1)
    assert approval_http(denied_id, approval_form(denied_id, PASSPHRASE.strip(), "deny"))[0] == 200
    blocked = as_uid(AGENT_UID, lambda: call("agent.sock", {
        "op": "execute", "request_id": denied_id,
    }))["value"]
    assert blocked["error"] == "WrongExecutionSession", blocked
    stdout, stderr = denied_request.communicate(timeout=10)
    assert denied_request.returncode != 0 and "denied" in stderr.lower()
    operator(broker.pw_uid, "lock")
    policy_path.write_text(json.dumps(policy))
    operator(broker.pw_uid, "grant", PASSPHRASE, "demo/provider-token")
    operator(broker.pw_uid, "unlock", PASSPHRASE)
    print("AV_VM_TEST_STAGE versioned connection, authenticated local approval, origin/CSRF/replay denial, public av run and host proxy injection passed", flush=True)
    operator(broker.pw_uid, "lock")
    shutil.copy2("/input-binaries/av-runner-canary", BIN / "av-runner-canary")
    (BIN / "av-runner-canary").chmod(0o755)
    canary_command = [str(BIN / "av-runner-canary"), "isolation-only"]
    policy["command"] = canary_command
    policy_path.write_text(json.dumps(policy))
    operator(broker.pw_uid, "grant", PASSPHRASE, "demo/provider-token")
    operator(broker.pw_uid, "unlock", PASSPHRASE)
    task = request_task(broker.pw_uid, canary_command)
    wait_for(lambda: task_status(task).get("data", {}).get("state") != "running", "isolation canary did not finish", 40)
    assert task_status(task)["data"]["exit_code"] == 0, task_status(task)
    operator(broker.pw_uid, "lock")
    policy["command"] = command
    policy_path.write_text(json.dumps(policy))
    operator(broker.pw_uid, "grant", PASSPHRASE, "demo/provider-token")
    operator(broker.pw_uid, "unlock", PASSPHRASE)
    print("AV_VM_TEST_STAGE brokered isolation canary denied namespace creation, host state and direct egress", flush=True)
    provider.hold.set()
    task = request_task(broker.pw_uid, command)
    wait_for(lambda: len(provider.requests) == 3, "second isolated provider request not received", 30)
    assert runner_children(runner_pid), "active task has no runner child"
    operator(broker.pw_uid, "lock")
    wait_for(lambda: not runner_children(runner_pid), "relock left runner children alive")
    provider.hold.clear()
    assert_locked(broker.pw_uid)
    old_admin = (BASE / "admin.token").read_text()
    run("systemctl", "restart", "agents-vault.service")
    assert_locked(broker.pw_uid)
    assert (BASE / "admin.token").read_text() != old_admin
    print("AV_VM_TEST_STAGE active task relock and systemd broker restart passed", flush=True)
    # A crash is handled by Restart=on-failure and RuntimeDirectory cleanup.
    old_pid = main_pid("agents-vault.service")
    old_admin = (BASE / "admin.token").read_text()
    os.kill(old_pid, signal.SIGKILL)
    wait_for(lambda: main_pid("agents-vault.service") not in [0, old_pid] and (BASE / "admin.sock").exists(), "broker crash restart failed", 30)
    assert_locked(broker.pw_uid)
    assert (BASE / "admin.token").read_text() != old_admin
    old_runner = main_pid("agents-vault-runner.service")
    os.kill(old_runner, signal.SIGKILL)
    wait_for(lambda: main_pid("agents-vault-runner.service") not in [0, old_runner], "runner crash restart failed", 30)
    run("systemctl", "start", "agents-vault.service")
    assert_locked(broker.pw_uid)
    print("AV_VM_TEST_STAGE systemd crash cleanup and broker/runner restart passed", flush=True)
    # The added command inherits the unit's identity, mount/network namespaces,
    # capabilities and syscall filter; it does not relax any packaged setting.
    probe_dir = pathlib.Path("/run/systemd/system/agents-vault-runner.service.d")
    probe_dir.mkdir(parents=True, exist_ok=True)
    probe_conf = probe_dir / "kernel-probe.conf"
    probe_conf.write_text("[Service]\nExecStartPost=/usr/bin/python3 /boundary-tests/kernel_denial_probe.py\n")
    run("systemctl", "daemon-reload")
    run("systemctl", "restart", "agents-vault-runner.service")
    probe_conf.unlink()
    run("systemctl", "daemon-reload")
    print("AV_VM_TEST_STAGE service kernel-write/log/hostname restrictions passed", flush=True)
    vault_hash = hashlib.sha256((STATE / "vault.db").read_bytes()).hexdigest()
    install()
    assert pwd.getpwnam("av-broker").pw_uid == broker.pw_uid
    assert pwd.getpwnam("av-runner").pw_uid == runner.pw_uid
    run("systemctl", "restart", "agents-vault-runner.service", "agents-vault.service")
    assert_locked(broker.pw_uid)
    operator(broker.pw_uid, "unlock", PASSPHRASE)
    task = request_task(broker.pw_uid, command)
    wait_for(lambda: task_status(task).get("data", {}).get("state") != "running", "post-update task did not finish", 40)
    assert task_status(task)["data"]["exit_code"] == 0
    run("/boundary-tests/uninstall.sh")
    assert not (BIN / "avd").exists()
    assert not pathlib.Path("/usr/lib/systemd/system/agents-vault.service").exists()
    assert not pathlib.Path("/etc/apparmor.d/agents-vault-runner").exists()
    assert "agents-vault-runner " not in pathlib.Path("/sys/kernel/security/apparmor/profiles").read_text()
    assert hashlib.sha256((STATE / "vault.db").read_bytes()).hexdigest() == vault_hash
    assert pwd.getpwnam("av-broker").pw_uid == broker.pw_uid
    assert pwd.getpwnam("av-runner").pw_uid == runner.pw_uid
    print("AV_VM_TEST_STAGE repeated install/update, post-update execution and uninstall with state retention passed", flush=True)
    print("AV_VM_TEST_PASS", flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        traceback.print_exc()
        subprocess.run(["systemctl", "status", "--no-pager", "agents-vault.service", "agents-vault-runner.service"])
        subprocess.run(["journalctl", "--no-pager", "-u", "agents-vault.service", "-u", "agents-vault-runner.service", "-n", "100"])
        subprocess.run(["dmesg"])
        print("AV_VM_TEST_FAIL", flush=True)
    finally:
        subprocess.run(["systemctl", "poweroff"])
