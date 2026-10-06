#!/usr/bin/python3
"""Test-only ExecStartPost probe under the installed runner service controls."""
import ctypes
import errno
import os
import pathlib
import pwd

assert os.getuid() == pwd.getpwnam("av-runner").pw_uid
status = pathlib.Path("/proc/self/status").read_text()
assert "CapEff:\t0000000000000000\n" in status
assert "NoNewPrivs:\t1\n" in status and "Seccomp:\t2\n" in status
for path, flags in [
    ("/proc/sys/kernel/hostname", os.O_WRONLY),
    ("/proc/sys/kernel/domainname", os.O_WRONLY),
    ("/proc/sys/kernel/sysrq", os.O_WRONLY),
    ("/proc/kmsg", os.O_RDONLY | os.O_NONBLOCK),
]:
    try:
        fd = os.open(path, flags)
    except OSError as error:
        assert error.errno in [errno.EACCES, errno.EPERM], (path, error)
    else:
        os.close(fd)
        raise AssertionError("protected kernel path opened: " + path)
assert not pathlib.Path("/dev/kmsg").exists()
libc = ctypes.CDLL(None, use_errno=True)
for function, path in [(libc.sethostname, "/proc/sys/kernel/hostname"), (libc.setdomainname, "/proc/sys/kernel/domainname")]:
    # Use the existing value, so even an unexpected success cannot rename it.
    value = pathlib.Path(path).read_bytes().rstrip(b"\n")
    assert function(ctypes.c_char_p(value), len(value)) == -1
    assert ctypes.get_errno() == errno.EPERM
assert libc.klogctl(10, None, 0) == -1
assert ctypes.get_errno() == errno.EPERM
print("AV_VM_TEST_KERNEL_DENIALS_PASS", flush=True)
