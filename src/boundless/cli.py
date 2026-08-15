"""Command-line demo runner.

Two subcommands, both driven over real HTTP:

- ``demo`` exercises the secure baseline (secure + legitimate behaviour).
- ``compare`` runs the traversal ladder against the vulnerable and secure apps side by
  side, printing the contrast.

Each waits for its target(s) to become healthy, prints a readable report, and exits
non-zero if any check failed. The scenario/comparison engines are pure functions over
``httpx`` clients, so tests drive them exactly as the CLI does.
"""

from __future__ import annotations

import argparse
import sys
import time
from collections.abc import Sequence

import httpx

from .comparison import Row, run_comparison
from .comparison import all_passed as comparison_passed
from .scenario import Check, run_secure_baseline
from .scenario import all_passed as scenario_passed


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


def _print_checks(checks: list[Check]) -> None:
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


def _print_rows(rows: list[Row]) -> None:
    group_titles = {
        "traversal": "Traversal ladder — vulnerable crosses, secure refuses",
        "parity": "Legitimate parity — both apps agree",
    }
    current = ""
    for row in rows:
        if row.group != current:
            current = row.group
            print(f"\n== {group_titles.get(current, current)} ==")
        mark = "PASS" if row.passed else "FAIL"
        print(f"  [{mark}] {row.name}")
        print(f"         submitted  : {row.submitted}")
        print(f"         secure     : {row.secure_observed}")
        print(f"         vulnerable : {row.vulnerable_observed}")
        print(f"         verdict    : {row.verdict}")


def _run_demo(args: argparse.Namespace) -> int:
    print(f"boundless demo — target {args.base_url}")
    if not _wait_for_health(args.base_url, args.health_timeout):
        print(f"error: {args.base_url} did not become healthy in time", file=sys.stderr)
        return 2
    with httpx.Client(base_url=args.base_url, timeout=10.0) as client:
        checks = run_secure_baseline(client)
    _print_checks(checks)
    passed = sum(1 for c in checks if c.passed)
    print(f"\n{passed}/{len(checks)} checks passed")
    if scenario_passed(checks):
        print("RESULT: secure baseline behaves as specified.")
        return 0
    print("RESULT: one or more checks FAILED.", file=sys.stderr)
    return 1


def _run_compare(args: argparse.Namespace) -> int:
    print(f"boundless compare — secure {args.secure_url} vs vulnerable {args.vulnerable_url}")
    for url in (args.secure_url, args.vulnerable_url):
        if not _wait_for_health(url, args.health_timeout):
            print(f"error: {url} did not become healthy in time", file=sys.stderr)
            return 2
    with (
        httpx.Client(base_url=args.secure_url, timeout=10.0) as secure,
        httpx.Client(base_url=args.vulnerable_url, timeout=10.0) as vulnerable,
    ):
        rows = run_comparison(secure, vulnerable)
    _print_rows(rows)
    passed = sum(1 for r in rows if r.passed)
    print(f"\n{passed}/{len(rows)} rows passed")
    if comparison_passed(rows):
        print("RESULT: vulnerable app crosses the boundary; secure app refuses; parity holds.")
        return 0
    print("RESULT: one or more comparison rows FAILED.", file=sys.stderr)
    return 1


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point; returns a process exit code."""
    parser = argparse.ArgumentParser(description="boundless demo runner")
    sub = parser.add_subparsers(dest="command", required=True)

    demo = sub.add_parser("demo", help="exercise the secure baseline")
    demo.add_argument("--base-url", default="http://secure:8000")
    demo.add_argument("--health-timeout", type=float, default=30.0)
    demo.set_defaults(func=_run_demo)

    compare = sub.add_parser("compare", help="vulnerable vs secure read comparison")
    compare.add_argument("--secure-url", default="http://secure:8000")
    compare.add_argument("--vulnerable-url", default="http://vulnerable:8001")
    compare.add_argument("--health-timeout", type=float, default=30.0)
    compare.set_defaults(func=_run_compare)

    args = parser.parse_args(argv)
    result: int = args.func(args)
    return result


if __name__ == "__main__":
    raise SystemExit(main())
