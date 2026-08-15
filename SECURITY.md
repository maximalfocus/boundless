# Security policy

`boundless` is an **educational demonstration of a vulnerability**. It deliberately contains
insecure code. That makes the usual "report anything that looks vulnerable" policy misleading, so
this document draws the line explicitly.

## This project is not deployed, and must not be

There is no hosted instance, no published package, and no container image. Everything runs locally
inside Docker, on loopback-published ports. Nothing here is production software, and none of it
should be copied into production software except the secure pattern it teaches.

## What is intentionally vulnerable — please do not report these

The whole point of the project is a side-by-side contrast, so the following are **working as
designed** and are not accepted as vulnerability reports:

- **`src/boundless/vulnerable/app.py` in its entirety.** It joins a user-supplied name to a base
  directory and opens the result without confining it. That is the demonstrated flaw
  (CWE-22 / CWE-23 / CWE-36 / CWE-59).
- **The deliberately broken "hardened" endpoint.** Its sanitizer strips `../` once and inspects the
  name before decoding, so it is defeated by `....//` and by `%2e%2e%2f`. Being bypassable is the
  lesson.
- **The hand-rolled Zip-Slip import.** The vulnerable import writes archive entries by joining each
  entry name to the destination with no per-entry confinement, so a `../`-bearing entry escapes the
  caller's directory. Python's `zipfile.extractall` would have sanitized the names; the hand-rolled
  loop is the realistic vulnerable pattern and is the point of the exercise.
- **Static demo bearer tokens and fictional "secrets" in fixtures.** Every token, tenant, user,
  statement, and key in this repository is synthetic and conspicuously labelled as such. They
  authenticate nothing outside this demo.

## What *would* be a real vulnerability here — please do report these

The safety boundary around the demonstration is a genuine contract, and a hole in it is a real bug:

- The **secure** application (`src/boundless/secure/app.py`) failing to confine a path — any name
  that returns content from outside the caller's tenant directory, or any archive entry that lands
  outside it.
- The vulnerable application **starting without both opt-in actions** (the `vulnerable` Compose
  profile *and* `ALLOW_VULNERABLE_DEMO=true`), or being reachable on a non-loopback interface.
- Any write **escaping the demo's own disposable in-container fixture tree** — in particular any
  write to the host filesystem, to an execution-reaching path (interpreter import path, startup
  script, scheduled-job directory, shell profile, credential store, container-runtime path), or any
  delete or truncation outside the two documented fixture targets.
- The demonstration **executing a command**, gaining network egress from the hardened vulnerable
  container, or escalating privileges out of it.
- A **real** credential, key, token, or item of personal data committed anywhere in this repository
  or its history.
- A vulnerability in the **supporting** code — the container definitions, the CI workflow, or the
  dependency set — that is not part of the demonstration.

## How to report

Please use **GitHub's private vulnerability reporting** on this repository:
**Security → Report a vulnerability**. That keeps the report non-public until it is resolved.

Please do not open a public issue for a suspected real vulnerability, and please do not include real
credentials or personal data in a report.

A useful report says what you did, what happened, and what you expected — ideally the exact request
or archive, and whether you hit the secure or the vulnerable application.

## What to expect

This is a personal educational project with **no service-level agreement, no guaranteed response
time, no support window, and no long-term compatibility commitment**. Reports about the safety
boundary are taken seriously, but the response is best-effort.

Supported version: the current `main` branch only. There are no maintained release branches and no
backports.
