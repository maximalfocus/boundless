# boundless

**A container-only teaching demo for path traversal — the safe way first.**

`boundless` is a small, fully fictional, **local-only** project that shows how a service
should handle a user-supplied filename: **resolve the candidate path, then confine it to
its base directory**, applied identically to reading a document and to importing an
archive. It is built for a mixed technical audience and runs entirely inside Docker.

> ⚠️ **This is educational code. Do not deploy it.** Every organization, user, statement,
> token, and "secret" here is synthetic. The demo executes no command, reads nothing
> outside its own container except that container's own `/etc/passwd`, and writes only
> inside a disposable in-container fixture tree.

The demo shows the deliberately *vulnerable* contrast in **both directions** — **read**
(the naive join and the broken sanitizer) and **write** (Zip-Slip archive extraction) —
side by side with the secure app. The vulnerable app is **opt-in** and hardened, and every
write it performs is confined to two documented targets inside a disposable in-container
fixture tree.

## The one idea

Joining a user-supplied name to a base directory proves **nothing** about where the
joined path *lands*:

```text
base = /data/archive/aurora-freight
name = ../../config/integration.key
join(base, name) = /data/archive/aurora-freight/../../config/integration.key
                 = /data/config/integration.key      # outside the base!
```

The only reliable question is: **after full resolution — `.` and `..` collapsed, symlinks
followed — is the path still inside the resolved base?** That is exactly what
[`boundless.safepath.confine`](src/boundless/safepath.py) asks, and every name-accepting
endpoint funnels through it.

## Three lessons

1. **Resolve, then confine** — the primary fix, applied to reads *and* to every archive
   entry before a single byte is written. (This milestone.)
2. **Blocklist filtering of `../` is not a boundary check** — stripping `../` once, or
   inspecting a string before it is decoded, is defeated by `....//` (which collapses back
   into `../` after one strip) and by percent-encoded `%2e%2e%2f` (only decoded *after* the
   check). Shown against the vulnerable app's deliberately broken "hardened" endpoint.
3. **Addressing by opaque id removes the class entirely** — if no user-supplied path
   component ever participates in locating a file, there is nothing to traverse. The
   secure app already exposes this via `GET /documents/{document_id}`.

## Terminology

The vulnerability class is **Path Traversal** (a.k.a. **directory traversal**, the
**`../` / dot-dot-slash attack**, and — in its archive-extraction form — **Zip Slip**).

| Term | Maps to |
|---|---|
| OWASP | **A01:2021 — Broken Access Control** |
| CWE-22 | Improper limitation of a pathname to a restricted directory |
| CWE-23 | Relative path traversal (`../`) |
| CWE-36 | Absolute path traversal (`/etc/passwd`) |
| CWE-59 | Link following (a symlink whose target is outside the base) |

## The fictional model

A supplier-facing **statement archive** for several tenant organizations of a shared SaaS.
Each tenant has users and a per-tenant archive directory of monthly statements, and can
import a `.zip` of statements. Two files sit **outside** every tenant directory but inside
the data tree: a fictional **integration key** (carrying a `DEMO_SENTINEL` marker) and a
**branding configuration** whose footer the statement summary reads at request time. One
tenant directory contains a planted **symlink** whose target is outside the archive root.

```text
/data/
  archive/                         <- the common archive root
    aurora-freight/                <- a tenant base directory
      statement-2026-05.txt
      statement-2026-06.txt
      statement-2026-07.txt
      vault-link  ->  ../../config/integration.key   <- planted symlink (CWE-59)
    northwind-mills/ ...
    borealis-supply/ ...
  config/                          <- outside the archive root
    integration.key                <- fictional; carries DEMO_SENTINEL
    branding.conf                  <- footer read by the statement summary
```

The fixtures are deterministic and are **recreated fresh on every container start**.

## API (secure app)

All endpoints authenticate with an unmistakably demo-only static bearer token that maps
to one user, hence one tenant.

| Method & path | Purpose |
|---|---|
| `GET /documents?name=…` | Retrieve a document by name — resolved and confined before opening. |
| `GET /documents/{document_id}` | Retrieve by opaque catalog id — no path component accepted. |
| `POST /documents/import` | Import a `.zip`, all-or-nothing, every entry confined first. |
| `GET /statements/summary` | Tenant summary; footer read from `branding.conf` at request time. |
| `GET /healthz` | Readiness. |

Any traversing, absolute, percent-encoded, double-encoded, or symlink-escaping name — and
any well-formed-but-missing name — returns the **same generic `404 Not Found`**, so no
response distinguishes "outside the base" from "does not exist". A traversing, absolute, or
link archive entry causes the **whole** import to fail with a generic `400`, writing no
entry. Each security rejection emits exactly one generic structured audit event to stdout
that names the actor, tenant, operation, and outcome — and never the submitted name, the
base directory, an absolute path, a token, or a secret.

## Requirements

- Docker with the Compose plugin. **Nothing else** — no local Python, no `uv`. Python,
  dependencies, `pytest`, `ruff`, and `mypy` all run inside the container.

## Run it

**One-shot walkthrough** (brings up the secure app, exercises the secure + legitimate
behaviour over real localhost HTTP, prints a report, exits non-zero on any failure):

```sh
docker compose run --rm demo
docker compose down --volumes            # clean up the background secure service
```

**Verification** (lint, type-check, and the full test suite — the same boundary CI runs):

```sh
docker compose run --rm verify
```

**Explore the API manually** (long-running secure service on `127.0.0.1:8000`, loopback
only; interactive OpenAPI docs at `/docs`):

```sh
docker compose up secure
# then, in another shell:
TOKEN=demo-token-aurora-uma-NOT-A-REAL-SECRET
curl -s -H "Authorization: Bearer $TOKEN" \
  'http://127.0.0.1:8000/documents?name=statement-2026-07.txt'      # 200, own statement
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $TOKEN" \
  'http://127.0.0.1:8000/documents?name=../../config/integration.key'  # 404, confined
docker compose down --volumes
```

## The vulnerable read contrast (opt-in)

The vulnerable app demonstrates what the secure app refuses. Starting it takes **two
deliberate actions** — enabling the `vulnerable` Compose profile **and** setting
`ALLOW_VULNERABLE_DEMO=true` (the app refuses to boot without the acknowledgement). Its
container is hardened (non-root, all capabilities dropped, `no-new-privileges`, read-only
root filesystem) and has **no network egress** beyond its loopback-published port.

Run the side-by-side comparison (vulnerable vs secure, over real HTTP):

```sh
ALLOW_VULNERABLE_DEMO=true docker compose --profile vulnerable run --rm compare
docker compose --profile vulnerable down --volumes
```

The comparison walks the traversal ladder against both apps:

| Rung | Vulnerable app | Secure app |
|---|---|---|
| `../northwind-mills/statement-2026-07.txt` | another tenant's statement | generic `404` |
| `../../config/integration.key` | the integration key + `DEMO_SENTINEL` | generic `404` |
| `/etc/passwd` | the container's own `/etc/passwd` | generic `404` |
| `vault-link` (planted symlink) | out-of-root content | generic `404` |
| `....//....//config/integration.key` (hardened) | bypassed → integration key | generic `404` |
| `%2e%2e%2f…config%2fintegration.key` (hardened) | bypassed → integration key | generic `404` |

…and confirms the two apps return **identical** output for benign requests. For manual
exploration the vulnerable API is available on `127.0.0.1:8001`:

```sh
ALLOW_VULNERABLE_DEMO=true docker compose --profile vulnerable up vulnerable
```

### The write escape (Zip Slip)

The same `compare` run then demonstrates the **write** direction. The vulnerable import is a
hand-rolled per-entry write loop that joins each archive entry name to the destination and
writes it, with no confinement (Python's `zipfile.extractall` already sanitizes member
names — the hand-rolled loop is the realistic vulnerable pattern). Importing an archive
whose entries are `../../config/branding.conf` and `../northwind-mills/statement-2026-07.txt`
writes **outside** the caller's directory:

- the branding configuration is overwritten, so a subsequent **legitimate**
  `GET /statements/summary` returns the attacker's footer text — the tamper is observable
  through the normal boundary; and
- another tenant's statement document is overwritten, visible when that tenant reads its own
  statement.

The secure app rejects the identical archive **as a whole** with a generic `400`, writing no
entry. Every write the demonstration performs lands only on those **two documented targets**
inside the disposable in-container fixture tree, which is recreated from scratch on every
run; verification asserts everything else is byte-for-byte unchanged. The same write
primitive could target execution-reaching paths (an interpreter import path, a startup
script, a shell profile, a credential store) in a real system — this demonstration
deliberately does not, and its read-only container root filesystem would refuse it.

To keep the teaching artifact non-weaponizable, the vulnerable import has an outer,
demo-only safety rail: ordinary members may land inside the caller's tenant directory, and
the two documented traversal members may land on the two fixture targets above; every other
resolved destination is rejected before any member is written. This is **not** the product
fix—the two intended members still escape the tenant directory. The secure app instead
applies the real rule uniformly: resolve every candidate and confine it to the tenant base.

## Expected outcomes

- The legitimate reads, import, and summary succeed and return only the caller's own data.
- Every unsafe name is an indistinguishable `404`; every unsafe archive is a whole-archive
  `400` with nothing written; the fixture tree is byte-for-byte unchanged after each.
- `docker compose run --rm verify` is green (Ruff, mypy, pytest), locally and in CI.

## Layout

```text
src/boundless/
  config.py      identity.py     fixtures.py     safepath.py    <- resolve-and-confine
  archive.py     catalog.py      audit.py        samples.py     webcommon.py
  scenario.py    comparison.py   cli.py
  secure/app.py       <- the secure FastAPI application
  vulnerable/app.py   <- the intentionally vulnerable app (opt-in, read direction)
tests/           Dockerfile      docker-compose.yml            .github/workflows/ci.yml
```

## Safety boundary

The demonstration is wholly synthetic and local. It executes **no command**. Starting the
vulnerable app requires two deliberate actions, and its container is hardened (non-root, all
capabilities dropped, `no-new-privileges`, read-only root filesystem) with **no network
egress** beyond its loopback port. Every write the demonstration performs is confined to
**two documented targets** — the branding config and one other tenant's statement — inside a
disposable in-container fixture tree recreated on every run; it performs no delete and no
truncation outside those two targets, touches nothing on the host, and verification asserts
everything else is byte-for-byte unchanged. It writes to **no execution-reaching path**
(interpreter import path, startup script, scheduled-job directory, shell profile, credential
store, container-runtime path): the same primitive could in a real system, and this demo
deliberately does not. Do not deploy it.
