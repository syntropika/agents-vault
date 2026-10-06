#!/usr/bin/env python3
"""Offline staging checks for the public Linux CLI package entry."""

import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest


PACKAGE = Path(__file__).resolve().parent
BASE_BINARIES = (
    "av", "avd", "av-operator", "av-runner-helper", "av-runner-service",
    "av-runner-client",
)


class InstallCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="av-linux-install-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "bin"
        self.stage = self.root / "stage"
        self.source.mkdir()
        for name in BASE_BINARIES:
            path = self.source / name
            path.write_text(f"#!/bin/sh\nprintf '%s\\n' '{name} fixture'\n")
            path.chmod(0o755)

    def install(self, *extra, check=True, installer=None):
        return subprocess.run(
            [str(installer or PACKAGE / "install.sh"), "--bin-dir", str(self.source),
             "--agent-uid", "21001", "--destdir", str(self.stage), *extra],
            capture_output=True, text=True, check=check,
        )

    def assert_public_cli(self):
        executable = self.stage / "usr/libexec/agents-vault/av"
        entry = self.stage / "usr/bin/av"
        self.assertTrue(executable.is_file())
        self.assertEqual(executable.stat().st_mode & 0o777, 0o755)
        self.assertEqual(entry.readlink(), Path("../libexec/agents-vault/av"))
        self.assertEqual(
            hashlib.sha256(executable.read_bytes()).digest(),
            hashlib.sha256((self.source / "av").read_bytes()).digest(),
        )
        self.assertEqual(subprocess.check_output([entry], text=True).strip(), "av fixture")

    def test_base_install_reinstall_and_uninstall(self):
        self.install()
        self.assert_public_cli()
        self.install()
        self.assert_public_cli()
        subprocess.run([str(PACKAGE / "uninstall.sh"), "--destdir", str(self.stage)], check=True)
        self.assertFalse((self.stage / "usr/bin/av").exists())
        self.assertFalse((self.stage / "usr/libexec/agents-vault/av").exists())
        self.assertTrue((self.stage / "etc/agents-vault/service.env").is_file())

    def test_missing_cli_or_foreign_entry_is_rejected_before_writes(self):
        (self.source / "av").unlink()
        result = self.install(check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.stage.exists())
        (self.source / "av").write_text("fixture")
        result = self.install(check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.stage.exists())
        (self.source / "av").chmod(0o755)
        entry = self.stage / "usr/bin/av"
        entry.parent.mkdir(parents=True)
        entry.symlink_to("/some/other/av")
        result = self.install(check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(entry.readlink(), Path("/some/other/av"))
        self.assertFalse((self.stage / "usr/libexec/agents-vault/av").exists())
        subprocess.run([str(PACKAGE / "uninstall.sh"), "--destdir", str(self.stage)], check=True)
        self.assertEqual(entry.readlink(), Path("/some/other/av"))

    def test_unrecognized_argument_is_rejected_before_writes(self):
        result = self.install("--unsupported-option", check=False)
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.stage.exists())


if __name__ == "__main__":
    unittest.main()
