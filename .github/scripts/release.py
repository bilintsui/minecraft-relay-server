#!/usr/bin/env python3
"""Check existing build CI and prepare unpublished release assets."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


ARCHITECTURES = ("amd64", "arm64", "armhf", "ppc64el", "riscv64", "s390x")


class GitHubError(RuntimeError):
    def __init__(self, method, status):
        super().__init__("GitHub {} failed: HTTP {}".format(method, status))
        self.status = status


class GitHub:
    def __init__(self, repository):
        if not re.fullmatch(r"[\w.-]+/[\w.-]+", repository):
            raise ValueError("invalid repository name")
        self.repository = repository
        self.base = os.environ.get("GITHUB_API_URL", "https://api.github.com").rstrip("/")
        self.token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
        if not self.token:
            raise ValueError("GitHub token is required")
        self.prefix = "/repos/" + repository

    def request(self, method, path, data=None):
        payload = None if data is None else json.dumps(data).encode()
        return self.send(method, self.base + self.prefix + path, payload, "application/json")

    def send(self, method, url, data, content_type):
        request = urllib.request.Request(url, data=data, method=method, headers={
            "Accept": "application/vnd.github+json", "Authorization": "Bearer " + self.token,
            "Content-Type": content_type, "X-GitHub-Api-Version": "2022-11-28",
        })
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                content = response.read()
                return json.loads(content) if content else None
        except urllib.error.HTTPError as error:
            raise GitHubError(method, error.code) from None
        except urllib.error.URLError as error:
            raise RuntimeError("GitHub request failed: {}".format(error.reason)) from None

    def upload(self, upload_url, name, asset):
        url = upload_url.split("{", 1)[0] + "?" + urllib.parse.urlencode({"name": name})
        return self.send("POST", url, asset.read_bytes(), "application/octet-stream")


def pages(api, path, key=None):
    separator = "&" if "?" in path else "?"
    page = 1
    while True:
        response = api.request("GET", path + separator + "per_page=100&page=" + str(page))
        items = response[key] if key else response
        if not isinstance(items, list):
            raise ValueError("unexpected GitHub list response")
        yield from items
        if len(items) < 100:
            return
        page += 1


def tag_commit(api, tag):
    reference = api.request("GET", "/git/ref/tags/" + urllib.parse.quote(tag, safe=""))["object"]
    for _ in range(32):
        if reference["type"] == "commit":
            return reference["sha"]
        if reference["type"] != "tag":
            break
        reference = api.request("GET", "/git/tags/" + reference["sha"])["object"]
    raise ValueError("release tag does not resolve to a commit")


def wait_for_ci(api, sha, workflow="build.yml", timeout=1800, interval=15):
    deadline = time.monotonic() + timeout
    path = "/actions/workflows/{}/runs?{}".format(urllib.parse.quote(workflow, safe=""), urllib.parse.urlencode({"event": "push", "head_sha": sha}))
    while True:
        try:
            runs = [run for run in pages(api, path, "workflow_runs") if run["head_sha"] == sha and run["event"] == "push"]
        except GitHubError as error:
            if error.status != 404:
                raise
            runs = []
        if runs:
            latest = max(runs, key=lambda run: (run["run_number"], run["id"]))
            current = api.request("GET", "/actions/runs/" + str(latest["id"]))
            if current["head_sha"] != sha or current["event"] != "push" or current["workflow_id"] != latest["workflow_id"]:
                raise ValueError("build CI identity changed")
            if current["status"] == "completed":
                if current["conclusion"] != "success":
                    raise RuntimeError("latest build CI did not pass: {} ({})".format(current["conclusion"], current["html_url"]))
                print("Build CI passed: {} (attempt {})".format(current["html_url"], current["run_attempt"]), flush=True)
                return current
            if current["status"] not in ("queued", "in_progress", "waiting", "pending", "requested"):
                raise ValueError("unexpected build CI status: " + current["status"])
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError("timed out waiting for {} on {}".format(workflow, sha))
        print("Waiting for {} on {}...".format(workflow, sha), flush=True)
        time.sleep(min(interval, remaining))


def assets_in(directory):
    assets, versions = {}, set()
    for architecture in ARCHITECTURES:
        binary = directory / ("mcrelay-" + architecture)
        packages = sorted(directory.glob("mcrelay_*_" + architecture + ".deb"))
        if len(packages) != 1:
            raise ValueError("expected exactly one package for " + architecture)
        package = packages[0]
        versions.add(package.name[len("mcrelay_"):-len("_" + architecture + ".deb")])
        for asset in (binary, package):
            if not asset.is_file() or asset.is_symlink() or asset.stat().st_size == 0:
                raise ValueError("missing/invalid release asset: " + asset.name)
            # GitHub release assets use dots for Debian version tildes.
            assets[asset.name.replace("~", ".")] = asset
    if len(versions) != 1:
        raise ValueError("release package versions differ across architectures")
    return assets


def require_draft(api, release_id, tag):
    release = api.request("GET", "/releases/" + str(release_id))
    if release.get("draft") is not True or release["tag_name"] != tag:
        raise RuntimeError("release is already published or its tag changed; refusing to modify assets")
    return release


def managed_asset(name):
    return any(name == "mcrelay-" + arch or re.fullmatch(r"mcrelay_[^_]+_" + re.escape(arch) + r"\.deb", name) for arch in ARCHITECTURES)


def prepare_draft(api, sha, tag, directory):
    assets = assets_in(directory)
    if tag_commit(api, tag) != sha:
        raise RuntimeError("remote tag no longer points to the checked commit")
    matches = [release for release in pages(api, "/releases") if release["tag_name"] == tag]
    if len(matches) > 1:
        raise ValueError("multiple releases match the tag")
    if matches:
        release = matches[0]
        if release.get("draft") is not True:
            raise RuntimeError("release is already published; refusing to overwrite it")
    else:
        release = api.request("POST", "/releases", {"tag_name": tag, "target_commitish": sha, "name": tag, "draft": True})
    release_id = release["id"]
    existing = {asset["name"]: asset for asset in pages(api, "/releases/{}/assets".format(release_id))}
    for name, asset in existing.items():
        if managed_asset(name) and name not in assets:
            require_draft(api, release_id, tag)
            if tag_commit(api, tag) != sha:
                raise RuntimeError("remote tag moved during stale asset cleanup")
            api.request("DELETE", "/releases/assets/" + str(asset["id"]))
    for name, asset in assets.items():
        current = require_draft(api, release_id, tag)
        if tag_commit(api, tag) != sha:
            raise RuntimeError("remote tag moved during release preparation")
        if name in existing:
            api.request("DELETE", "/releases/assets/" + str(existing[name]["id"]))
        uploaded = api.upload(current["upload_url"], name, asset)
        digest = "sha256:" + hashlib.sha256(asset.read_bytes()).hexdigest()
        if uploaded["name"] != name or uploaded["size"] != asset.stat().st_size or uploaded["state"] != "uploaded":
            raise RuntimeError("uploaded asset verification failed: " + name)
        if uploaded.get("digest") not in (None, digest):
            raise RuntimeError("uploaded asset digest differs: " + name)
    current = require_draft(api, release_id, tag)
    actual = {asset["name"]: asset for asset in pages(api, "/releases/{}/assets".format(release_id))}
    if {name for name in actual if managed_asset(name)} != assets.keys() or any(actual[name]["size"] != asset.stat().st_size for name, asset in assets.items()):
        raise RuntimeError("draft release managed asset set differs from the expected build")
    if tag_commit(api, tag) != sha:
        raise RuntimeError("remote tag moved before release preparation completed")
    print("Draft ready for manual publication: " + current["html_url"], flush=True)
    return current


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("verify-ci", "draft"))
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY"), required="GITHUB_REPOSITORY" not in os.environ)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--workflow", default="build.yml")
    parser.add_argument("--timeout", type=int, default=1800)
    parser.add_argument("--interval", type=int, default=15)
    parser.add_argument("--tag")
    parser.add_argument("--assets", type=Path)
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.sha) or args.timeout <= 0 or args.interval <= 0:
        parser.error("a full commit SHA and positive time limits are required")
    api = GitHub(args.repository)
    if args.mode == "verify-ci":
        run = wait_for_ci(api, args.sha, args.workflow, args.timeout, args.interval)
        if os.environ.get("GITHUB_OUTPUT"):
            with open(os.environ["GITHUB_OUTPUT"], "a") as output:
                output.write("ci_run_id={}\nci_run_attempt={}\n".format(run["id"], run["run_attempt"]))
    else:
        if not args.tag or not args.assets:
            parser.error("draft requires --tag and --assets")
        prepare_draft(api, args.sha, args.tag, args.assets)


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, ValueError, KeyError, OSError) as error:
        print("FATAL: " + str(error), file=sys.stderr)
        sys.exit(1)
