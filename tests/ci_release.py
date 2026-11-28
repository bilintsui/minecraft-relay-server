#!/usr/bin/env python3
"""Release gating and draft writes use simulated GitHub responses only."""

import contextlib
import hashlib
import importlib.util
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import urllib.parse


ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location("release_workflow", ROOT / ".github/scripts/release.py")
RELEASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RELEASE)
SHA = "a" * 40


def run(number=1, conclusion="success", status="completed", sha=SHA, event="push", attempt=1):
    return {"id": number, "run_number": number, "head_sha": sha, "event": event, "workflow_id": 12,
            "status": status, "conclusion": conclusion, "run_attempt": attempt, "html_url": "https://example.invalid/run/" + str(number)}


class FakeGitHub:
    upload = RELEASE.GitHub.upload

    def __init__(self):
        self.calls = []
        self.observations = [[]]
        self.details = {}
        self.releases = []
        self.assets = {}
        self.tag_object = {"type": "commit", "sha": SHA}
        self.publish_on_read = False
        self.bad_digest = False
        self.next_asset_id = 1000

    def request(self, method, path, data=None):
        self.calls.append((method, path, data))
        endpoint = path.split("?", 1)[0]
        if endpoint.startswith("/actions/workflows/"):
            item = self.observations.pop(0) if len(self.observations) > 1 else self.observations[0]
            if isinstance(item, Exception):
                raise item
            return {"workflow_runs": item}
        if endpoint.startswith("/actions/runs/"):
            return self.details[int(endpoint.rsplit("/", 1)[1])]
        if endpoint.startswith("/git/ref/tags/"):
            return {"object": self.tag_object}
        if endpoint.startswith("/git/tags/"):
            return {"object": {"type": "commit", "sha": SHA}}
        if endpoint == "/releases":
            if method == "GET":
                return self.releases
            release = {**data, "id": 101, "html_url": "https://example.invalid/draft", "upload_url": "https://example.invalid/assets{?name,label}"}
            self.releases.append(release)
            return release
        if endpoint == "/releases/101":
            if self.publish_on_read:
                self.releases[0]["draft"] = False
            return self.releases[0]
        if endpoint == "/releases/101/assets":
            return list(self.assets.values())
        if endpoint.startswith("/releases/assets/") and method == "DELETE":
            identifier = int(endpoint.rsplit("/", 1)[1])
            name = next(name for name, item in self.assets.items() if item["id"] == identifier)
            del self.assets[name]
            return None
        raise AssertionError((method, path, data))

    def send(self, method, url, data, content_type):
        assert method == "POST" and content_type == "application/octet-stream"
        requested = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)["name"][0]
        self.calls.append(("UPLOAD", url, requested))
        name = requested.replace("~", ".")
        if name in self.assets:
            raise RELEASE.GitHubError("POST", 422)
        self.next_asset_id += 1
        item = {"id": self.next_asset_id, "name": name, "size": len(data), "state": "uploaded",
                "digest": "sha256:" + ("bad" if self.bad_digest else hashlib.sha256(data).hexdigest())}
        self.assets[name] = item
        return item


class ReleaseWorkflow(unittest.TestCase):
    def setUp(self):
        self.api = FakeGitHub()
        self.clock = 0
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.object(RELEASE.time, "monotonic", side_effect=lambda: self.clock))
        self.stack.enter_context(mock.patch.object(RELEASE.time, "sleep", side_effect=self.advance))
        self.stack.enter_context(mock.patch.object(RELEASE.urllib.request, "urlopen", side_effect=AssertionError("real API calls forbidden")))
        self.stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        temporary = self.stack.enter_context(tempfile.TemporaryDirectory(prefix="mcrelay-release-test-"))
        self.directory = Path(temporary)
        for architecture in RELEASE.ARCHITECTURES:
            (self.directory / ("mcrelay-" + architecture)).write_bytes(b"binary")
            (self.directory / ("mcrelay_1.0-1_" + architecture + ".deb")).write_bytes(b"package")

    def advance(self, seconds):
        self.clock += seconds

    def gate(self):
        return RELEASE.wait_for_ci(self.api, SHA, timeout=2, interval=1)

    def draft(self, tag="v1.0"):
        return RELEASE.prepare_draft(self.api, SHA, tag, self.directory)

    def writes(self):
        return [call for call in self.api.calls if call[0] != "GET"]

    def existing_draft(self):
        self.api.releases = [{"id": 101, "tag_name": "v1.0", "draft": True, "body": "maintainer notes", "name": "custom title",
                              "prerelease": True, "html_url": "https://example.invalid/draft", "upload_url": "https://example.invalid/assets{?name,label}"}]

    def test_already_passed_commit_does_not_wait_or_write(self):
        self.api.observations = [[run()]]
        self.api.details[1] = run(attempt=2)
        self.assertEqual(self.gate()["run_attempt"], 2)
        self.assertEqual(self.clock, 0)
        self.assertEqual(self.writes(), [])
        self.assertIn("head_sha=" + SHA, self.api.calls[0][1])
        self.assertIn("/build.yml/runs?event=push", self.api.calls[0][1])

    def test_immediate_tag_waits_for_record_and_completion(self):
        self.api.observations = [[], [run(status="queued", conclusion=None)], [run()]]
        original = self.api.request

        def request(method, path, data=None):
            if path == "/actions/runs/1":
                self.api.details[1] = run() if self.clock >= 2 else run(status="in_progress", conclusion=None)
            return original(method, path, data)

        self.api.request = request
        self.gate()
        self.assertEqual(self.clock, 2)
        self.assertEqual(self.writes(), [])

    def test_new_workflow_not_indexed_yet(self):
        self.api.observations = [RELEASE.GitHubError("GET", 404), [run()]]
        self.api.details[1] = run()
        self.gate()
        self.assertEqual(self.clock, 1)

    def test_latest_failure_blocks_older_success(self):
        self.api.observations = [[run(), run(2, conclusion="failure")]]
        self.api.details[2] = run(2, conclusion="failure")
        with self.assertRaisesRegex(RuntimeError, "did not pass"):
            self.gate()

    def test_other_sha_and_pr_cannot_satisfy_gate(self):
        self.api.observations = [[run(sha="b" * 40), run(2, event="pull_request")]]
        with self.assertRaisesRegex(RuntimeError, "timed out"):
            self.gate()
        self.assertFalse(any(path.startswith("/actions/runs/") for _, path, _ in self.api.calls))

    def test_non_success_conclusions_block(self):
        for conclusion in ("cancelled", "timed_out", "skipped", "neutral", "action_required"):
            with self.subTest(conclusion=conclusion):
                self.api.observations = [[run(conclusion=conclusion)]]
                self.api.details[1] = run(conclusion=conclusion)
                with self.assertRaises(RuntimeError):
                    self.gate()

    def test_authentication_error_is_not_a_missing_record(self):
        self.api.observations = [RELEASE.GitHubError("GET", 403)]
        with self.assertRaises(RELEASE.GitHubError):
            self.gate()
        self.assertEqual(self.clock, 0)

    def test_changed_run_identity_blocks(self):
        self.api.observations = [[run()]]
        self.api.details[1] = run(sha="b" * 40)
        with self.assertRaisesRegex(ValueError, "identity changed"):
            self.gate()

    def test_workflow_run_pagination_does_not_hide_latest_failure(self):
        original = self.api.request

        def request(method, path, data=None):
            if path.startswith("/actions/workflows/"):
                self.api.calls.append((method, path, data))
                return {"workflow_runs": [run(101, conclusion="failure")] if "page=2" in path else [run(i) for i in range(1, 101)]}
            return original(method, path, data)

        self.api.request = request
        self.api.details[101] = run(101, conclusion="failure")
        with self.assertRaisesRegex(RuntimeError, "did not pass"):
            self.gate()

    def test_api_transport_uses_readable_json_and_token_header(self):
        with mock.patch.dict(RELEASE.os.environ, {"GH_TOKEN": "test-token", "GITHUB_API_URL": "https://example.invalid"}):
            api = RELEASE.GitHub("owner/repository")
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = b'{"draft": true}'
        with mock.patch.object(RELEASE.urllib.request, "urlopen", return_value=response) as opener:
            self.assertEqual(api.request("POST", "/releases", {"draft": True}), {"draft": True})
            request = opener.call_args[0][0]
            self.assertEqual(request.get_header("Authorization"), "Bearer test-token")
            self.assertEqual(request.full_url, "https://example.invalid/repos/owner/repository/releases")
            self.assertEqual(request.data, b'{"draft": true}')

    def test_create_draft_with_all_assets(self):
        release = self.draft()
        self.assertTrue(release["draft"])
        self.assertEqual(len(self.api.assets), 12)
        creates = [call for call in self.writes() if call[:2] == ("POST", "/releases")]
        self.assertEqual(len(creates), 1)
        self.assertTrue(creates[0][2]["draft"])
        self.assertEqual(creates[0][2]["target_commitish"], SHA)

    def test_prerelease_package_names_on_upload_and_retry(self):
        for package in self.directory.glob("*.deb"):
            package.rename(package.with_name(package.name.replace("1.0-1", "1.3~beta2-1")))
        binaries = {"mcrelay-" + arch for arch in RELEASE.ARCHITECTURES}
        public_packages = {"mcrelay_1.3.beta2-1_" + arch + ".deb" for arch in RELEASE.ARCHITECTURES}
        for attempt in range(2):
            with self.subTest(attempt=attempt):
                self.api.calls.clear()
                self.draft("v1.3-beta2")
                self.assertEqual(set(self.api.assets), binaries | public_packages)
                self.assertEqual({name for method, _, name in self.writes() if method == "UPLOAD"}, binaries | public_packages)
                self.assertEqual(sum(method == "DELETE" for method, _, _ in self.writes()), 12 * attempt)
        self.assertEqual({p.name for p in self.directory.glob("*.deb")}, {name.replace("1.3.beta2", "1.3~beta2") for name in public_packages})

    def test_unexpected_upload_name_is_rejected(self):
        send = self.api.send

        def renamed(*args):
            return {**send(*args), "name": "unexpected.deb"}

        self.api.send = renamed
        with self.assertRaisesRegex(RuntimeError, "uploaded asset verification failed"):
            self.draft()

    def test_rerun_updates_draft_and_preserves_notes(self):
        self.existing_draft()
        self.draft()
        self.draft()
        self.assertEqual(len(self.api.assets), 12)
        self.assertEqual(self.api.releases[0]["body"], "maintainer notes")
        self.assertTrue(self.api.releases[0]["prerelease"])
        self.assertFalse(any(method in ("POST", "PATCH") and path == "/releases" for method, path, _ in self.writes()))

    def test_stale_packages_removed_and_manual_assets_preserved(self):
        self.existing_draft()
        self.api.releases[0]["target_commitish"] = "previous-metadata"
        stale = {"mcrelay_1.0.beta1-1_" + arch + ".deb" for arch in RELEASE.ARCHITECTURES}
        manual = {"checksums.txt", "release-notes.pdf", "other_0.9-1_amd64.deb", "mcrelay_0.9-1_custom.deb"}
        for index, name in enumerate(sorted(stale | manual)):
            self.api.assets[name] = {"id": 800 + index, "name": name, "size": 7, "state": "uploaded"}
        self.draft()
        self.assertEqual(set(self.api.assets), {path.name for path in self.directory.iterdir()} | manual)
        self.assertEqual(len([call for call in self.writes() if call[0] == "DELETE"]), len(stale))
        self.assertEqual(self.api.releases[0]["target_commitish"], "previous-metadata")
        self.assertEqual(self.api.releases[0]["body"], "maintainer notes")

    def test_publication_before_stale_cleanup_blocks_deletion(self):
        self.existing_draft()
        name = "mcrelay_0.9-1_amd64.deb"
        self.api.assets[name] = {"id": 800, "name": name, "size": 7, "state": "uploaded"}
        self.api.publish_on_read = True
        with self.assertRaisesRegex(RuntimeError, "already published"):
            self.draft()
        self.assertIn(name, self.api.assets)
        self.assertEqual(self.writes(), [])

    def test_tag_move_before_stale_cleanup_blocks_deletion(self):
        self.existing_draft()
        name = "mcrelay_0.9-1_amd64.deb"
        self.api.assets[name] = {"id": 800, "name": name, "size": 7, "state": "uploaded"}
        original = self.api.request

        def request(method, path, data=None):
            if path == "/releases/101":
                self.api.tag_object = {"type": "commit", "sha": "b" * 40}
            return original(method, path, data)

        self.api.request = request
        with self.assertRaisesRegex(RuntimeError, "tag moved during stale asset cleanup"):
            self.draft()
        self.assertIn(name, self.api.assets)
        self.assertEqual(self.writes(), [])

    def test_publication_between_stale_deletions_stops_cleanup(self):
        self.existing_draft()
        for index, arch in enumerate(("amd64", "arm64")):
            name = "mcrelay_0.9-1_" + arch + ".deb"
            self.api.assets[name] = {"id": 800 + index, "name": name, "size": 7, "state": "uploaded"}
        original = self.api.request

        def request(method, path, data=None):
            result = original(method, path, data)
            if method == "DELETE":
                self.api.releases[0]["draft"] = False
            return result

        self.api.request = request
        with self.assertRaisesRegex(RuntimeError, "already published"):
            self.draft()
        self.assertEqual(len(self.api.assets), 1)
        self.assertEqual(len(self.writes()), 1)
        self.assertEqual(self.writes()[0][0], "DELETE")

    def test_final_check_rejects_unexpected_managed_asset(self):
        original = self.api.send

        def upload(*args):
            result = original(*args)
            name = "mcrelay_0.9-1_amd64.deb"
            self.api.assets[name] = {"id": 800, "name": name, "size": 7, "state": "uploaded"}
            return result

        self.api.send = upload
        with self.assertRaisesRegex(RuntimeError, "managed asset set differs"):
            self.draft()
        self.assertTrue(self.api.releases[0]["draft"])

    def test_published_release_cannot_be_overwritten(self):
        self.existing_draft()
        self.api.releases[0]["draft"] = False
        with self.assertRaisesRegex(RuntimeError, "already published"):
            self.draft()
        self.assertEqual(self.writes(), [])

    def test_publication_before_upload_blocks_asset_writes(self):
        self.existing_draft()
        self.api.publish_on_read = True
        with self.assertRaisesRegex(RuntimeError, "already published"):
            self.draft()
        self.assertEqual(self.writes(), [])

    def test_incomplete_or_mixed_assets_do_not_call_api(self):
        (self.directory / "mcrelay-amd64").unlink()
        with self.assertRaises(ValueError):
            self.draft()
        self.assertEqual(self.api.calls, [])

    def test_mixed_package_versions_do_not_call_api(self):
        (self.directory / "mcrelay_1.0-1_amd64.deb").rename(self.directory / "mcrelay_2.0-1_amd64.deb")
        with self.assertRaisesRegex(ValueError, "versions differ"):
            self.draft()
        self.assertEqual(self.api.calls, [])

    def test_distinct_package_versions_with_same_public_spelling(self):
        for package in self.directory.glob("*.deb"):
            version = "1.3.beta2-1" if package.name.endswith("_amd64.deb") else "1.3~beta2-1"
            package.rename(package.with_name(package.name.replace("1.0-1", version)))
        with self.assertRaisesRegex(ValueError, "versions differ"):
            self.draft("v1.3-beta2")
        self.assertEqual(self.api.calls, [])

    def test_annotated_tag_is_peeled(self):
        self.api.tag_object = {"type": "tag", "sha": "c" * 40}
        self.draft()
        self.assertTrue(any(path.startswith("/git/tags/") for _, path, _ in self.api.calls))

    def test_moved_tag_blocks_before_draft_creation(self):
        self.api.tag_object = {"type": "commit", "sha": "b" * 40}
        with self.assertRaisesRegex(RuntimeError, "no longer points"):
            self.draft()
        self.assertEqual(self.writes(), [])

    def test_bad_upload_digest_fails_without_publication(self):
        self.api.bad_digest = True
        with self.assertRaisesRegex(RuntimeError, "digest differs"):
            self.draft()
        self.assertTrue(self.api.releases[0]["draft"])


if __name__ == "__main__":
    unittest.main()
