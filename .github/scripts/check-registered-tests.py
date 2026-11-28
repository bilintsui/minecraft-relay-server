#!/usr/bin/env python3
"""Check that the configured CTest build contains the tests required by CI."""

import argparse
import json
import subprocess


REQUIRED_TESTS = {
    "ci_release",
    "inbound_proxy",
    "listener_assembly_proxy",
    "listener_assembly_proxy_v2",
    "metrics_report",
    "packaging_preflight",
    "packaging_purge",
    "proxy_chain",
    "proxy_short_abort",
    "proxy_socket_errors",
    "proxy_v2",
    "version",
    "version_log",
    "version_log_report",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("build_dir")
    parser.add_argument("extra_tests", nargs="*", help="additional tests required by this job")
    args = parser.parse_args()

    listing = subprocess.check_output(["ctest", "--test-dir", args.build_dir, "--show-only=json-v1"])
    registered = {test["name"] for test in json.loads(listing)["tests"]}
    missing = (REQUIRED_TESTS | set(args.extra_tests)) - registered
    if missing:
        raise SystemExit("Missing CTest registrations: " + ", ".join(sorted(missing)))


if __name__ == "__main__":
    main()
