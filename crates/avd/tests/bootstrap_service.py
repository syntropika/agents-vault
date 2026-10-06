#!/usr/bin/python3
"""Exercise installed bootstrap privilege dropping and interlocks in a disposable container."""
import fcntl
import json
import os
import pathlib
import pwd
import signal
import stat
import subprocess
import time
from types import SimpleNamespace

STATE = pathlib.Path("/var/lib/agents-vault")
RUNTIME = pathlib.Path("/run/agents-vault")
VAULT = STATE / "vault.db"
PENDING = STATE / "vault.init.pending"
OUTPUT = pathlib.Path("/root/bootstrap-recovery")
OPERATOR = "/usr/libexec/agents-vault/av-operator"
PASSPHRASE = "synthetic-bootstrap-passphrase"


def identity(account):
    def apply():
        os.setgroups([])
        os.setgid(account.pw_gid)
        os.setuid(account.pw_uid)
    return apply


def wait_for(condition, child):
    deadline = time.monotonic() + 10
    while not condition():
        assert child.poll() is None, child.communicate()[1].decode()
        assert time.monotonic() < deadline, "process checkpoint timed out"
        time.sleep(0.002)


def main():
    assert pathlib.Path("/.dockerenv").exists() and os.geteuid() == 0, "disposable root container required"
    subprocess.run(["/boundary-tests/install.sh", "--bin-dir", "/input-binaries", "--agent-uid", "21001"], check=True)
    broker = pwd.getpwnam("av-broker")
    runner = pwd.getpwnam("av-runner")
    OUTPUT.mkdir(mode=0o700)
    RUNTIME.mkdir(mode=0o755, exist_ok=True)
    os.chown(RUNTIME, broker.pw_uid, broker.pw_gid)
    environment = {"AVD_RUNTIME_DIR": str(RUNTIME), "AVD_SERVICE_AGENT_UID": "21001", "AVD_VAULT_PATH": str(VAULT)}

    def init(name, *, lines=(PASSPHRASE, PASSPHRASE), expect=False, account=None, stdin=None, extra=()):
        keywords = {"input": "".join(line + "\n" for line in lines)} if stdin is None else {"stdin": stdin}
        result = subprocess.run([OPERATOR, "init", "--recovery-file", str(name), *extra], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=identity(account) if account else None, **keywords)
        assert PASSPHRASE not in result.stdout + result.stderr
        assert (result.returncode == 0) == expect, (result.returncode, result.stdout, result.stderr)
        return result

    def daemon():
        return subprocess.Popen(["/usr/libexec/agents-vault/avd"], env=environment, cwd="/", preexec_fn=identity(broker), stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def denied_daemon():
        process = daemon()
        output, errors = process.communicate(timeout=10)
        assert process.returncode != 0, (output, errors)
        assert not (RUNTIME / "admin.sock").exists()

    # Validation occurs before any passphrase is read or recovery output created.
    init(OUTPUT / "non-root", account=broker)
    init(STATE / "bad-recovery")
    init("relative-recovery")
    init(OUTPUT / "bad-extra", extra=("--vault", "/tmp/other.db"))
    assert list(OUTPUT.iterdir()) == []
    root_status = subprocess.run([OPERATOR, "status"], capture_output=True)
    assert root_status.returncode != 0
    destination = OUTPUT / "existing"
    destination.write_text("preserve this root file")
    destination.chmod(0o600)
    init(destination)
    assert destination.read_text() == "preserve this root file"
    link = OUTPUT / "symlink"
    link.symlink_to(destination)
    init(link)
    assert destination.read_text() == "preserve this root file"
    with open("/etc/hostname") as stream:
        init(OUTPUT / "regular-input", stdin=stream)
    mismatch = init(OUTPUT / "mismatch", lines=(PASSPHRASE, "different passphrase"))
    assert "root-owned recovery output may remain" in mismatch.stderr
    assert not VAULT.exists() and not PENDING.exists()
    assert (OUTPUT / "regular-input").stat().st_size == 0
    assert (OUTPUT / "mismatch").stat().st_size == 0

    # The initializer has dropped every root credential before waiting for input.
    waiting = subprocess.Popen([OPERATOR, "init", "--recovery-file", str(OUTPUT / "interrupted-input")], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        def has_dropped():
            status = pathlib.Path(f"/proc/{waiting.pid}/status").read_text()
            return f"Uid:\t{broker.pw_uid}\t{broker.pw_uid}\t{broker.pw_uid}\t{broker.pw_uid}" in status
        wait_for(has_dropped, waiting)
        # Private pipes have no terminal prompt; inspect the actual lock instead.
        def lock_is_held():
            with (STATE / "broker-state.lock").open("r") as lock:
                try:
                    fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    return False
                except BlockingIOError:
                    return True
        wait_for(lock_is_held, waiting)
        status = pathlib.Path(f"/proc/{waiting.pid}/status").read_text()
        assert next(line.split(":", 1)[1].strip() for line in status.splitlines() if line.startswith("Groups:")) == ""
        assert "CapEff:\t0000000000000000" in status
        assert "NoNewPrivs:\t1" in status
        denied_daemon()
        init(OUTPUT / "concurrent")
        waiting.kill()
        waiting.communicate(timeout=5)
        assert waiting.returncode == -signal.SIGKILL
        assert not VAULT.exists() and not PENDING.exists()
    finally:
        if waiting.poll() is None:
            waiting.kill()
            waiting.communicate()

    # Death during creation leaves the durable pending marker and blocks both
    # service startup and automatic retry. Only this disposable test repairs it.
    interrupted = subprocess.Popen([OPERATOR, "init", "--recovery-file", str(OUTPUT / "interrupted-create")], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    interrupted.stdin.write((PASSPHRASE + "\n" + PASSPHRASE + "\n").encode())
    interrupted.stdin.flush()
    try:
        wait_for(PENDING.exists, interrupted)
        interrupted.kill()
        interrupted.communicate(timeout=5)
        assert interrupted.returncode == -signal.SIGKILL
        assert PENDING.exists()
        denied_daemon()
        init(OUTPUT / "retry-partial")
        assert not (OUTPUT / "retry-partial").exists()
    finally:
        if interrupted.poll() is None:
            interrupted.kill()
            interrupted.communicate()
    for entry in STATE.iterdir():
        assert entry.is_file(), "unexpected test artifact requires manual inspection"
        if entry.name != "broker-state.lock":
            entry.unlink()

    # Bootstrap uses installed configuration despite caller-controlled variables.
    os.environ["AVD_VAULT_PATH"] = "/tmp/attacker-vault.db"
    result = init(OUTPUT / "complete", expect=True)
    response = json.loads(result.stdout)
    assert response["vault"] == str(VAULT) and response["locked"]
    recovery = (OUTPUT / "complete").read_text()
    assert len(recovery) == 64 and all(character in "0123456789abcdef" for character in recovery)
    assert recovery not in result.stdout + result.stderr
    metadata = (OUTPUT / "complete").stat()
    assert metadata.st_uid == 0 and stat.S_IMODE(metadata.st_mode) == 0o600 and metadata.st_nlink == 1
    assert VAULT.stat().st_uid == broker.pw_uid and stat.S_IMODE(VAULT.stat().st_mode) == 0o600
    assert not PENDING.exists() and not pathlib.Path("/tmp/attacker-vault.db").exists()
    for account in (broker, runner, SimpleNamespace(pw_uid=21001, pw_gid=21001)):
        denied = subprocess.run(["/usr/bin/cat", str(OUTPUT / "complete")], preexec_fn=identity(account), capture_output=True)
        assert denied.returncode != 0 and recovery.encode() not in denied.stdout + denied.stderr
    before = VAULT.read_bytes()
    init(OUTPUT / "duplicate")
    assert not (OUTPUT / "duplicate").exists() and VAULT.read_bytes() == before

    process = daemon()
    try:
        wait_for(lambda: (RUNTIME / "admin.sock").exists(), process)
        status = subprocess.run([OPERATOR, "status"], preexec_fn=identity(broker), capture_output=True, text=True, check=True)
        assert json.loads(status.stdout)["locked"]
        added = subprocess.run([OPERATOR, "add", "demo/bootstrap-token"], preexec_fn=identity(broker), input=PASSPHRASE + "\nav-synthetic-bootstrap-token\n", text=True, capture_output=True, check=True)
        assert json.loads(added.stdout)["grants"] == 0
        assert "av-synthetic-bootstrap-token" not in added.stdout + added.stderr
        init(OUTPUT / "live-service")
        assert not (OUTPUT / "live-service").exists()
    finally:
        process.terminate()
        process.communicate(timeout=5)
    print("bootstrap passed: permanent credential drop, private recovery output, identity/input validation, fixed installed target, lock exclusion, SIGKILL pending state, fail-closed restart, duplicate refusal, locked default-deny management")


if __name__ == "__main__":
    main()
