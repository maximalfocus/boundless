"""Command-line demo runner for the secure baseline.

Usage (inside the Compose network)::

    python -m boundless.cli --base-url http://secure:8000

It waits for the target to become healthy, runs the secure + legitimate walkthrough over
real HTTP, prints a readable report, and exits non-zero if any step failed. Later slices
extend this into the full vulnerable/secure comparison; here it exercises the secure app.
"""

from __future__ import annotations

import argparse
import sys
import time
from collections.abc import Sequence

import httpx

from .scenario import Check, all_passed, run_secure_baseline


def _wait_for_health(base_url: str, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    with httpx.Client(base_url=base_url, timeout=2.0) as client:
        while time.monotonic() < deadline:
            try:
                if client.get("/healthz").status_code == 200:
                    return True
            except httpx.HTTPError:
                pass
            time.sleep(0.25)
    return False


def _print_report(checks: list[Check]) -> None:
    group_titles = {
        "legitimate": "Legitimate behaviour (authenticated, benign)",
        "secure-read": "Secure retrieval — every unsafe name is an indistinguishable 404",
        "secure-import": "Secure import — well-formed accepted, traversing rejected whole",
        "auth": "Authentication — generic 401",
    }
    current = ""
    for check in checks:
        if check.group != current:
            current = check.group
            print(f"\n== {group_titles.get(current, current)} ==")
        mark = "PASS" if check.passed else "FAIL"
        print(f"  [{mark}] {check.name}")
        print(f"         submitted : {check.submitted}")
        print(f"         expected  : {check.expectation}")
        print(f"         observed  : {check.observed}")


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point; returns a process exit code."""
    parser = argparse.ArgumentParser(description="boundless secure-baseline demo runner")
    parser.add_argument("--base-url", default="http://secure:8000")
    parser.add_argument("--health-timeout", type=float, default=30.0)
    args = parser.parse_args(argv)

    print(f"boundless demo — target {args.base_url}")
    if not _wait_for_health(args.base_url, args.health_timeout):
        print(f"error: {args.base_url} did not become healthy in time", file=sys.stderr)
        return 2

    with httpx.Client(base_url=args.base_url, timeout=10.0) as client:
        checks = run_secure_baseline(client)

    _print_report(checks)
    passed = sum(1 for c in checks if c.passed)
    print(f"\n{passed}/{len(checks)} checks passed")
    if all_passed(checks):
        print("RESULT: secure baseline behaves as specified.")
        return 0
    print("RESULT: one or more checks FAILED.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
