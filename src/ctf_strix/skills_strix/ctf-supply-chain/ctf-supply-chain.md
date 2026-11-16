---
name: ctf-supply-chain
description: Software supply chain CTF challenges - dependency confusion, typosquatting, namespace confusion, maintainer compromise, mutable pins, CI/CD pipeline abuse, build artifact poisoning, postinstall hooks, lockfile bypass. Use when the target has install / build / publish / update / deploy functions, or when tags mention supply_chain, npm, pypi, rubygems, registry, artifact, cicd, or lockfile.
license: MIT
compatibility: Filesystem agent with bash and Python 3. No internet needed - every probe targets the challenge's own registry or mirror.
metadata:
  author: ctf-strix
---

# CTF Supply Chain

## The one thing that matters

The entry point is almost never an HTTP route you have to guess. It is **an install /
build / deploy action the application performs on your behalf**. Any button or endpoint
that says install, add, publish, build, sync, update, import, restore or deploy is the
attack surface, and reading its dependency configuration beats enumerating 200 paths.

## First three probes (in this order)

1. **Find the install action and read what it installs.**
   `GET /` and every list endpoint; look for a package name, a version, a source URL.
   Then read the config that decides *where* that name is fetched from.
2. **Read the dependency configuration** (whichever the app exposes): `package.json`,
   `package-lock.json`, `.npmrc`, `requirements.txt`, `pyproject.toml`, `pip.conf`,
   `Gemfile.lock`, `go.mod`, `.github/workflows/*.yml`, `Dockerfile`, `Makefile`.
   If none is readable, look for an endpoint that echoes one (debug page, build log).
3. **Compare the two lists.** The vulnerability is the *difference* between
   "what the app says it depends on" and "what the resolver will actually pick".

## The mechanism table

Each row is a distinct bug. Pick the one matching what you already saw.

| Symptom you already have | Bug | Answer is usually |
|---|---|---|
| A private package name appears in config, and a *public* registry is also configured | **dependency confusion** | a package you upload, or a metadata field on the attacker package that the app reads back |
| The app installs by name only, no scope/namespace | **namespace confusion** | the un-scoped name resolving to a different owner |
| A near-miss name (`lodahs`, `reqeusts`, `pipekit-logger` vs `pipekit-log`) is accepted | **typosquatting** | the typosquatted package's metadata / its postinstall output |
| A version is pinned to a tag/branch, or `latest`, or `^`/`~` | **mutable pin / loose semver** | a re-published version under the same constraint |
| A lockfile exists but the install path ignores it | **lockfile bypass** | the version actually resolved at install time |
| The app downloads an artifact by URL/hash and never checks the hash | **integrity theatre** | the artifact you substitute (same URL, different bytes) |
| A CI workflow runs on `pull_request_target` with secrets in scope | **CI/CD secret exfil** | a workflow/log that prints the secret, or the secret itself |
| Build output is cached/reused and writable | **build artifact poisoning** | the poisoned artifact picked up by the next build |
| The app installs an LLM plugin / MCP server / skill pack | **plugin poisoning** | the instruction or tool the plugin gains |

## Reading a registry (offline)

The target usually *is* the registry, or proxies one. One call each, in this order:

- PyPI-style: `/simple/`, `/simple/<name>/`, `/pypi/<name>/json`, `/#/<name>`
- npm-style: `/<name>`, `/@<scope>%2f<name>`, `/-/<name>-<version>.tgz`
- RubyGems-style: `/api/v1/gems/<name>.json`, `/gems/<name>-<version>.gem`,
  `/specs.4.8.gz`
- Generic artifact: `/api/v1/search?q=`, `/api/packages`, `/artifacts`, `/repository/`

A 200 with a JSON body is the metadata. Read `description`, `homepage`, `author`,
`maintainers`, and any custom field - CTF authors put the flag or the next hop there
far more often than in an exploit chain.

## The install is a shell command: read it, then look for the second index

A redeploy / install endpoint usually returns the raw command it ran - the single most
valuable artefact in the challenge, because it names **which package** is installed,
**which indexes** are consulted and **in what order**, and whether `--extra-index-url`
(not `--index-url`) is in play. `pip` resolves `--extra-index-url` across **both** indexes
and picks the highest version regardless of origin: listing the internal one first does not
save it, because version wins, not order.

```
Looking in indexes: http://internal-pypi:8080/simple/, http://public-pypi:8080/simple/
Collecting orders-lib
  Downloading http://internal-pypi:8080/packages/orders_lib-1.0.0.tar.gz (1.4 kB)
```

- `Looking in indexes:` - the resolution order, and every registry you must probe.
- `Downloading <url>` - **the index that actually won**, plus a live artifact URL. An
  sdist carries `setup.py` / `pyproject.toml`, and authors hide metadata, next-hop URLs
  or the flag path there.
- `Installing build dependencies` - the build backend runs **as the installer**, so a
  malicious `setup.py` executes as the service user. That is the payload mechanism.

### The four moves after you see the command

1. **List each index in the output.** `GET /simple/`, then `GET /simple/<installed name>/`
   on every one. Which index has the name, and which versions does it offer?
2. **Compare versions across indexes.** If the internal one pins `1.0.0` and the other can
   serve higher, publishing a higher version there is the exploit. If the second has no
   such name at all, it is namespace confusion - one index already holds the attacker copy.
3. **Find the write side.** `/api/upload`, `/upload`, `/pypi/<name>/upload`,
   `/-/package/publish`, `/api/publish`, or a docs page naming a twine endpoint. A mirror
   that only reads is a dead end; one you can write to **is** the challenge.
4. **Re-trigger and read the resolved version.** The `Downloading` line is the proof; the
   upload section below covers what to do when it does not move.

### A 200 from an upload is not proof

On a `pypiserver`-style registry **success is `200` with an empty body**, so neither the
status nor the body length carries information: a wrong `:action`, a filename that does not
parse as `<name>-<version>.tar.gz`, and a multipart body field sent as a query parameter all
look the same. `409` means that filename already exists - publish a higher version.

Verify by **reading the index back** (`GET /simple/<name>/` lists your exact filename)
*before* triggering, then **trigger the install yourself**: a rebuild described as
"automatic" or "on deploy" may never run inside your budget, and waiting for it is
indistinguishable from a broken exploit. Read the version it actually resolved. If it is
still the old one, either the artifact is not listed or the constraint is tighter than your
version, and one probe separates the two.

If the version changed but nothing executed, the cause is usually PEP 517: pip builds the
sdist in isolation and installs the declared build requirements from the configured index
first. With no `setuptools` there the build fails before your `setup.py` is imported, so a
prebuilt wheel - or an in-tree backend with no requirements - is the way in.

## When the answer is "the install already happened"

An install log or a resolved dependency tree is evidence: it names the source URL, the
version and the maintainer. Read it before writing any payload - half of these challenges
are solved by reading one log line.

## What not to do

- Do not brute-force package names. The name is in the config you have not read yet.
- Do not treat this as a web challenge. The surface is the dependency graph behind it.
- Do not try to reach the public internet. The mirror is the target.

## References

- OWASP Top 10 CI/CD Security Risks (CICD-SEC-1..10)
- OWASP Top 10 2025 A03: Software Supply Chain Failures
