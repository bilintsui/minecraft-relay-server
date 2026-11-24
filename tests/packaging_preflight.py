#!/usr/bin/env python3
"""Package preflight preserves builds; archive permissions ignore the caller's umask."""

import io
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class PackagingPermissions(unittest.TestCase):
    def fixture(self, root):
        package = root / "packaging/deb"
        shutil.copytree(ROOT / "packaging/deb", package, ignore=shutil.ignore_patterns("out"))
        for name in ("README.md", "doc/configuration/mcrelay/config.json", "doc/configuration/mcrelay/config.jsonc",
                     "doc/information/loglevel.info", "doc/information/metrics.md", "doc/information/metrics-report.md", "tools/metrics-report.py"):
            destination = root / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / name, destination)
        (root / "src/define").mkdir(parents=True)
        (root / "src/define/global.h").write_text('#define MCRELAY_VERSION_DISPLAY "1.0-test"\n')
        (package / "changelog").write_text("mcrelay (1.0~test-1) unstable; urgency=low\n")
        tools = root / "bin"
        tools.mkdir()
        commands = {
            "cmake": 'if [ "$1" = --build ]; then printf "#!/bin/sh\\nexit 0\\n" >"$2/mcrelay"; chmod 0755 "$2/mcrelay"; fi\n',
            "gcc": 'if [ "$1" = -print-prog-name=strip ]; then printf "strip\\n"; exit 0; fi\n'
                   'while [ "$#" -gt 0 ]; do if [ "$1" = -o ]; then shift; printf "probe\\n" >"$1"; break; fi; shift; done\n',
            "pandoc": 'while [ "$#" -gt 0 ]; do if [ "$1" = -o ]; then shift; printf ".TH MCRELAY 1\\n" >"$1"; break; fi; shift; done\n',
            "strip": 'exit 0\n',
        }
        for name, body in commands.items():
            path = tools / name
            path.write_text("#!/bin/sh\nset -eu\n" + body)
            path.chmod(0o755)
        environment = os.environ.copy()
        environment["PATH"] = str(tools) + os.pathsep + os.defpath
        return package / "build-deb.sh", environment

    def test_archive_permissions_ignore_caller_umask(self):
        architecture = subprocess.check_output(["dpkg", "--print-architecture"], text=True).strip()
        for mask in ("0000", "0002", "0022", "0027", "0077"):
            with self.subTest(umask=mask), tempfile.TemporaryDirectory(prefix="mcrelay-permissions-test-") as directory:
                root = Path(directory)
                script, environment = self.fixture(root)
                result = subprocess.run(["/bin/sh", "-c", 'umask "$1"; shift; exec /bin/sh "$@"', "package-permissions", mask, str(script)],
                                        env=environment, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                self.assertEqual(result.returncode, 0, result.stdout)
                package = root / ("packaging/deb/out/mcrelay_1.0~test-1_" + architecture + ".deb")
                self.assertEqual(stat.S_IMODE(package.stat().st_mode), 0o644)
                for option, executable, required in (
                    ("--ctrl-tarfile", {"postinst", "postrm", "prerm"}, {"control", "conffiles", "md5sums", "postinst", "postrm", "prerm"}),
                    ("--fsys-tarfile", {"usr/bin/mcrelay"}, {"usr/bin/mcrelay", "etc/mcrelay/config.json", "usr/share/doc/mcrelay/changelog.Debian.gz"}),
                ):
                    data = subprocess.check_output(["dpkg-deb", option, str(package)])
                    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
                        members = archive.getmembers()
                    names = set()
                    for member in members:
                        name = member.name[2:] if member.name.startswith("./") else member.name
                        names.add(name)
                        with self.subTest(umask=mask, archive=option, path=member.name):
                            self.assertTrue(member.isdir() or member.isfile())
                            self.assertEqual((member.uid, member.gid), (0, 0))
                            self.assertEqual(member.mode, 0o755 if member.isdir() or name in executable else 0o644)
                    self.assertTrue(required <= names, required - names)


class PackagingPreflight(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="mcrelay-package-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.package = self.root / "packaging/deb"
        self.package.mkdir(parents=True)
        self.script = self.package / "build-deb.sh"
        shutil.copy2(ROOT / "packaging/deb/build-deb.sh", self.script)
        (self.root / "src/define").mkdir(parents=True)
        (self.root / "src/define/global.h").write_text('#define MCRELAY_VERSION_DISPLAY "1.0-test"\n')
        (self.package / "changelog").write_text("mcrelay (1.0~test-1) unstable; urgency=low\n")
        self.architecture = subprocess.check_output(["dpkg", "--print-architecture"], text=True).strip()
        self.build = self.root / ("build-deb-" + self.architecture)
        self.build.mkdir()
        self.marker = self.build / "existing-build"
        self.marker.write_text("preserve on preflight failure\n")
        self.calls = self.root / "calls"
        self.environment = os.environ.copy()
        self.environment.update(PATH=str(self.bin), PREFLIGHT_CALLS=str(self.calls), TMPDIR=str(self.root / "tmp"))
        (self.root / "tmp").mkdir()
        for name in ("dirname", "dpkg", "grep", "sed", "head", "cat", "mktemp", "rm", "mkdir", "nproc", "du", "cut", "chmod", "find", "sort", "xargs", "md5sum"):
            (self.bin / name).symlink_to(shutil.which(name))
        for name in ("cmake", "gcc", "strip", "pandoc", "dpkg-deb", "gzip", "install"):
            self.tool(name, 77 if name == "cmake" else 0)

    def tool(self, name, status):
        path = self.bin / name
        path.write_text('#!/bin/sh\nprintf "%s\\n" "$0 $*" >>"$PREFLIGHT_CALLS"\nexit {}\n'.format(status))
        path.chmod(0o755)

    def invoke(self, *arguments):
        return subprocess.run(["/bin/sh", str(self.script), *arguments], env=self.environment, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    def compiler(self, name, strip):
        path = self.bin / name
        path.write_text('#!/bin/sh\nprintf "%s\\n" "$0 $*" >>"$PREFLIGHT_CALLS"\n'
                        'if [ "$1" = -print-prog-name=strip ]; then printf "%s\\n" "' + strip + '"; exit 0; fi\n'
                        'while [ "$#" -gt 0 ]; do\n'
                        '  if [ "$1" = -o ]; then\n'
                        '    shift\n'
                        '    printf "#!/bin/sh\\nexit 99\\n" >"$1"\n'
                        '    chmod +x "$1"\n'
                        '    break\n'
                        '  fi\n'
                        '  shift\n'
                        'done\n')
        path.chmod(0o755)

    def test_help_without_build_dependencies(self):
        for path in self.bin.iterdir():
            if path.name not in ("dirname", "cat"):
                path.unlink()
        result = self.invoke("--help")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("default: native dpkg architecture", result.stdout)
        self.assertTrue(self.marker.exists())

    def test_missing_values(self):
        for arguments in (("--arch",), ("--cc",), ("--arch", ""), ("--cc", "--arch", "amd64")):
            with self.subTest(arguments=arguments):
                result = self.invoke(*arguments)
                self.assertEqual(result.returncode, 2, result.stdout)
                self.assertIn("Missing value", result.stdout)
                self.assertTrue(self.marker.exists())
                self.assertFalse(self.calls.exists())

    def test_invalid_architecture(self):
        result = self.invoke("--arch", "../other")
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertTrue(self.marker.exists())

    def test_changelog_mismatch_precedes_build_and_dependency_probe(self):
        (self.package / "changelog").write_text("mcrelay (0.9-1) unstable; urgency=low\n")
        result = self.invoke()
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("top changelog entry", result.stdout)
        self.assertTrue(self.marker.exists())
        self.assertFalse(self.calls.exists())

    def test_missing_packaging_tool_preserves_build(self):
        (self.bin / "pandoc").unlink()
        result = self.invoke()
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("required command not found: pandoc", result.stdout)
        self.assertTrue(self.marker.exists())
        self.assertFalse(self.calls.exists())

    def test_missing_late_packaging_tools_preserve_build(self):
        for name in ("mkdir", "nproc", "du", "cut", "chmod", "find", "sort", "xargs", "md5sum"):
            with self.subTest(tool=name):
                (self.bin / name).unlink()
                result = self.invoke()
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertIn("required command not found: " + name, result.stdout)
                self.assertTrue(self.marker.exists())
                self.assertFalse(self.calls.exists())
                (self.bin / name).symlink_to(shutil.which(name))

    def test_compile_link_failure_preserves_build(self):
        self.tool("gcc", 1)
        result = self.invoke()
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("compiler/development-library preflight failed", result.stdout)
        self.assertTrue(self.marker.exists())
        self.assertNotIn("cmake", self.calls.read_text())
        self.assertEqual(list((self.root / "tmp").iterdir()), [])

    def test_defaults_reach_configuration_only_after_preflight(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 77, result.stdout)
        self.assertFalse(self.marker.exists())
        calls = self.calls.read_text()
        self.assertIn("/gcc -std=c99 -D_GNU_SOURCE", calls)
        self.assertLess(calls.index("/strip --remove-section=.comment --strip-unneeded"), calls.index("/cmake -S"))
        self.assertIn("-DCMAKE_C_COMPILER=gcc", calls)
        self.assertIn("build-deb-" + self.architecture, calls)

    def test_cross_compiler_probe_is_not_executed(self):
        self.compiler("aarch64-linux-gnu-gcc", "aarch64-linux-gnu-strip")
        self.tool("aarch64-linux-gnu-strip", 0)
        result = self.invoke("--arch", "arm64", "--cc", "aarch64-linux-gnu-gcc")
        self.assertEqual(result.returncode, 77, result.stdout)
        self.assertIn("/aarch64-linux-gnu-gcc -std=c99", self.calls.read_text())
        self.assertIn("-DCMAKE_C_COMPILER=aarch64-linux-gnu-gcc", self.calls.read_text())
        self.assertTrue(self.marker.exists())

    def test_strip_failure_preserves_build(self):
        self.compiler("gcc", "strip")
        self.tool("strip", 88)
        result = self.invoke()
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("strip preflight failed", result.stdout)
        self.assertTrue(self.marker.exists())
        self.assertNotIn("/cmake ", self.calls.read_text())
        self.assertEqual(list((self.root / "tmp").iterdir()), [])

    def test_versioned_cross_compiler_selects_its_strip(self):
        self.compiler("aarch64-linux-gnu-gcc-12", "aarch64-linux-gnu-strip")
        self.tool("aarch64-linux-gnu-strip", 0)
        self.tool("strip", 88)
        result = self.invoke("--arch", "arm64", "--cc", "aarch64-linux-gnu-gcc-12")
        self.assertEqual(result.returncode, 77, result.stdout)
        calls = self.calls.read_text()
        self.assertIn("/aarch64-linux-gnu-strip --remove-section=.comment --strip-unneeded", calls)
        self.assertNotIn("/strip --remove-section", calls)
        self.assertEqual(list((self.root / "tmp").iterdir()), [])

    def test_incompatible_cross_strip_preserves_target_build(self):
        target = self.root / "build-deb-arm64"
        target.mkdir()
        marker = target / "existing-build"
        marker.write_text("preserve foreign build\n")
        self.compiler("aarch64-linux-gnu-gcc-12", "strip")
        self.tool("strip", 88)
        result = self.invoke("--arch", "arm64", "--cc", "aarch64-linux-gnu-gcc-12")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("strip preflight failed", result.stdout)
        self.assertTrue(marker.exists())
        self.assertNotIn("/cmake ", self.calls.read_text())

    def test_missing_compiler_selected_strip_preserves_build(self):
        self.compiler("gcc", "missing-target-strip")
        result = self.invoke()
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("required command not found: missing-target-strip", result.stdout)
        self.assertTrue(self.marker.exists())
        self.assertNotIn("/cmake ", self.calls.read_text())


if __name__ == "__main__":
    unittest.main()
