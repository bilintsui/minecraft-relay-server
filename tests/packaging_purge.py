#!/usr/bin/env python3
"""Exercise Debian maintainer-script isolation and systemd instance cleanup."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


POSTRM = Path(__file__).resolve().parents[1] / "packaging/deb/postrm"
TEMPLATE = "/usr/lib/systemd/system/mcrelay@.service"


class PackagingPurge(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="mcrelay-purge-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.units = self.root / "etc/systemd/system"
        self.wants = self.units / "multi-user.target.wants"
        self.wants.mkdir(parents=True)
        self.tools = self.root / "bin"
        self.tools.mkdir()
        for name in ("find", "rmdir"):
            (self.tools / name).symlink_to(shutil.which(name))
        self.calls = self.root / "calls"
        self.calls.touch()
        self.env = dict(os.environ, LC_ALL="C", PATH=str(self.tools), DPKG_ROOT="", CALLS=str(self.calls))

    def purge_units(self):
        # Source with an inert action, then exercise the same cleanup function as dpkg.
        # Only the live manager notification is substituted. find and rmdir operate on the fixture.
        script = '. "$1"; reload_systemd() { echo reload >> "$CALLS"; }; purge_systemd_units "$2"'
        subprocess.run(["/bin/sh", "-c", script, "sh", str(POSTRM), str(self.units)], env=self.env, check=True)

    def test_offline_scripts_enter_target_before_running_tools(self):
        commands = self.root / "entry"
        commands.mkdir()
        chroot = commands / "chroot"
        chroot.write_text('#!/bin/sh\nprintf "%s\\n" "$DPKG_ROOT" "$SYSTEMD_OFFLINE" "$@" > "$CALLS"\n/bin/cat > "$CALLS.script"\nexit 51\n')
        chroot.chmod(0o755)
        env = dict(self.env, DPKG_ROOT=str(self.root), PATH=str(commands))
        for maintscript, args in ((POSTRM, ["purge"]), (POSTRM.with_name("postinst"), ["configure", "1.2.3-1"])):
            with self.subTest(script=maintscript.name):
                result = subprocess.run(["/bin/sh", str(maintscript), *args], env=env, capture_output=True)
                self.assertEqual(result.returncode, 51)
                self.assertEqual(self.calls.read_text().splitlines(), ["", "1", str(self.root), "/bin/sh", "-s", "--", *args])
                self.assertEqual(self.calls.with_suffix(".script").read_bytes(), maintscript.read_bytes())
        self.calls.write_text("")
        subprocess.run(["/bin/sh", str(POSTRM), "remove"], env=env, check=True)
        self.assertEqual(self.calls.read_text(), "")

    @unittest.skipUnless(shutil.which("systemctl"), "requires systemctl for offline enablement")
    def test_reinstall_leaves_instance_disabled(self):
        old_mask = os.umask(0)
        self.addCleanup(os.umask, old_mask)
        installed = self.root / TEMPLATE.lstrip("/")
        installed.parent.mkdir(parents=True)
        target = installed.parent / "multi-user.target"
        target.write_text("[Unit]\nDescription=Multi-user target\n")
        target.chmod(0o644)
        source = POSTRM.parent / "systemd/mcrelay@.service"
        systemctl = ["systemctl", "--root", str(self.root)]
        instance = "mcrelay@proxy.service"

        def install_template():
            shutil.copyfile(source, installed)
            installed.chmod(0o644)

        def check_state(expected):
            result = subprocess.run([*systemctl, "is-enabled", instance], capture_output=True, text=True, env=dict(os.environ, LC_ALL="C"))
            self.assertEqual(result.stdout.strip(), expected)
            self.assertEqual(result.returncode == 0, expected == "enabled")
            self.assertNotIn("world-writable", result.stderr)

        install_template()
        subprocess.run([*systemctl, "enable", instance], check=True, capture_output=True)
        check_state("enabled")
        installed.unlink()
        self.purge_units()
        install_template()
        check_state("disabled")

    def test_purge_after_remove(self):
        links = []
        for directory, name, target in (
            (self.wants, "first", "/lib/systemd/system/mcrelay@.service"),
            (self.wants, "second", TEMPLATE),
            (self.units / "custom.target.requires", r"escaped\x2dname", "../../../../usr/lib/systemd/system/mcrelay@.service"),
            (self.units / "custom.target.upholds", "fourth", "../../../../lib/systemd/system/mcrelay@.service"),
        ):
            directory.mkdir(exist_ok=True)
            link = directory / ("mcrelay@" + name + ".service")
            link.symlink_to(target)
            links.append(link)

        subprocess.run(["/bin/sh", str(POSTRM), "remove"], env=dict(self.env, DPKG_ROOT=str(self.root)), check=True)
        for link in links:
            self.assertTrue(link.is_symlink(), link)
        untouched = self.units / "unrelated.target.wants"
        untouched.mkdir()
        self.purge_units()
        for link in links:
            self.assertFalse(os.path.lexists(link), link)
            self.assertFalse(link.parent.exists(), link.parent)
        self.assertTrue(untouched.is_dir())
        self.purge_units()
        self.assertEqual(self.calls.read_text().splitlines(), ["reload"])

    def test_helper_sees_pruned_directory_before_manager_reload(self):
        directory = self.units / "multi-user.target.requires"
        directory.mkdir()
        (directory / "mcrelay@required.service").symlink_to(TEMPLATE)
        helper = self.tools / "deb-systemd-helper"
        helper.write_text('#!/bin/sh\n[ ! -d "$REQUIRES" ] || echo stale >> "$CALLS"\nprintf "%s\\n" "$*" >> "$CALLS"\n')
        helper.chmod(0o755)
        self.env["REQUIRES"] = str(directory)
        self.purge_units()
        self.purge_units()
        self.assertEqual(self.calls.read_text().splitlines(), ["purge mcrelay.service mcrelay@.service", "reload", "purge mcrelay.service mcrelay@.service"])

    def test_preserve_administrator_files_and_unrelated_links(self):
        other = self.root / "other.target.wants"
        other.mkdir()
        (self.units / "linked.target.wants").symlink_to(other, target_is_directory=True)
        dropin = self.units / "mcrelay@local.service.d"
        dropin.mkdir()
        templates = {
            self.wants / "mcrelay@local.service": "/etc/systemd/system/mcrelay@.service",
            self.wants / "mcrelay@manual.service": "/usr/local/lib/systemd/system/mcrelay@.service",
            self.wants / "mcrelay@masked.service": "/dev/null",
            self.wants / "mcrelay@.service": TEMPLATE,
            self.wants / "other@name.service": TEMPLATE,
            self.units / "mcrelay@override.service": TEMPLATE,
            dropin / "mcrelay@local.service": TEMPLATE,
            other / "mcrelay@outside.service": TEMPLATE,
        }
        for link, target in templates.items():
            link.symlink_to(target)
        regular = self.wants / "mcrelay@regular.service"
        regular.write_text("admin unit\n")
        (self.wants / "mcrelay@packaged.service").symlink_to(TEMPLATE)
        self.purge_units()
        for link, target in templates.items():
            self.assertEqual(os.readlink(link), target)
        self.assertEqual(regular.read_text(), "admin unit\n")


if __name__ == "__main__":
    unittest.main()
