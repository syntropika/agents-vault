#!/usr/bin/python3
"""Prepare a disposable ext4 guest disk inside the unprivileged test container."""
import os
import pathlib
import shutil
import subprocess

work = pathlib.Path("/work")
root = work / "rootfs"
root.mkdir()
subprocess.run(["tar", "--numeric-owner", "-xf", str(work / "guest.tar"), "-C", str(root)], check=True)
(root / ".dockerenv").unlink(missing_ok=True)
(root / "etc/machine-id").write_text("")
(root / "etc/hostname").write_text("av-linux-disposable\n")
(root / "etc/fstab").write_text("# Disposable test root is provided by the kernel command line.\n")
inputs = root / "input-binaries"
inputs.mkdir()
for name in ["av", "avd", "av-operator", "av-runner-helper", "av-runner-service", "av-runner-client", "av-runner-canary", "av-fixture"]:
    source = pathlib.Path("/input-binaries") / name
    shutil.copyfile(source, inputs / name)
    (inputs / name).chmod(0o755)
for pattern, name in [("vmlinuz-*", "vmlinuz"), ("initrd.img-*", "initrd.img")]:
    matches = list((root / "boot").glob(pattern))
    assert len(matches) == 1, (pattern, matches)
    shutil.copyfile(matches[0], work / name)
subprocess.run(["truncate", "-s", "3G", str(work / "guest.ext4")], check=True)
subprocess.run(["mke2fs", "-q", "-F", "-t", "ext4", "-d", str(root), str(work / "guest.ext4")], check=True)
shutil.rmtree(root)
(work / "guest.tar").unlink()
owner = work.stat()
for name in ["vmlinuz", "initrd.img", "guest.ext4"]:
    os.chown(work / name, owner.st_uid, owner.st_gid)
    (work / name).chmod(0o600)
print("Prepared disposable disk with its own kernel and initramfs.")
