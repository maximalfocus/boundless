# Contributing

Thanks for looking. `boundless` is a small teaching demo about one idea — **resolve a
user-supplied path, then confine it to its base directory** — so the most valuable contributions are
the ones that make that idea land faster for a reader.

Please read [`SECURITY.md`](SECURITY.md) first. It explains which insecure code here is intentional
(and therefore not a bug) and which safety property is a real contract.

## The one requirement: Docker

Everything runs in containers. You need **Docker with the Compose plugin** and nothing else — no
local Python, no `uv`, no installed project packages. Python, dependencies, `pytest`, Ruff, and
mypy all live inside the image.

```sh
docker compose build
docker compose run --rm verify     # Ruff + mypy + the full test suite
```

`verify` is the gate. It is exactly what CI runs, so if it is green locally it will be green in CI.

The end-to-end checks:

```sh
docker compose run --rm demo                       # secure walkthrough over real HTTP
docker compose down --volumes --remove-orphans     # reset to fresh fixtures

ALLOW_VULNERABLE_DEMO=true docker compose --profile vulnerable run --rm compare
docker compose --profile vulnerable down --volumes --remove-orphans
```

Reset between the demo and the comparison: the demo's legitimate import mutates the secure
container's fixtures, and the comparison needs both applications to start from identical state.

## Invariants a change must not break

These are the properties that keep an intentionally vulnerable project safe to hand to someone.
A change that weakens one of them will not be merged.

1. **The secure application stays secure.** Every name-accepting path funnels through
   `boundless.safepath.confine`. Resolve first, then confine against the resolved base. Rejections
   stay indistinguishable — the same generic `404` for traversing, absolute, encoded, symlinked, and
   merely-missing names, and a whole-archive generic `400` that writes no entry.
2. **The vulnerable application stays opt-in and hardened.** It must never start on the default
   Compose path. Both actions stay required — the `vulnerable` profile *and*
   `ALLOW_VULNERABLE_DEMO=true`. Its container stays non-root, with all capabilities dropped,
   `no-new-privileges`, a read-only root filesystem, no network egress, and loopback-only ports.
3. **Writes stay contained.** The demonstration executes no command. Every write lands inside the
   disposable in-container fixture tree, which is recreated from scratch on every run, and only on
   the two documented targets. No host filesystem write, no execution-reaching target, no delete or
   truncation elsewhere. Verification asserts everything outside those two targets is byte-for-byte
   unchanged.
4. **All data stays fictional.** Every organization, person, statement, token, key, and "secret" is
   invented and conspicuously fake. Never commit a real credential, a real key, personal data, or
   anything traceable to a real organization — including in tests, fixtures, comments, and commit
   messages.
5. **Audit output stays clean.** A rejection emits exactly one generic structured event. It must
   never carry a token, a secret, an absolute path, the base directory, or the submitted name in a
   form that reveals the traversal target.
6. **Nothing gets deployed.** No hosting configuration, no published image, no package release.

## Making a change

- Keep the diff small and focused; one idea per pull request.
- Add or update tests at the boundary you changed — a regression test for a bug, focused behaviour
  tests for a change. The suite already covers both the read and the write axis; follow the nearest
  existing test.
- Match the surrounding style. Ruff and mypy (strict) both run in `verify`.
- Update the README when you change observable behaviour or a documented command.
- Say in the pull request what you ran and what it printed.

## Reporting something instead

- A **suspected real vulnerability** (a hole in the safety boundary above): use private reporting as
  described in [`SECURITY.md`](SECURITY.md) — not a public issue.
- Anything else — a confusing explanation, a broken command, a teaching improvement: open a normal
  issue.

## No promises

This is a personal educational project. There is no support commitment, no response-time guarantee,
no compatibility promise, and no roadmap. Contributions are welcome but may not be merged.

By contributing you agree that your contribution is licensed under the [MIT License](LICENSE).
