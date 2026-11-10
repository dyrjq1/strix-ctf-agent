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

The entry point is almost never an HTTP route you have to guess. It is **an install / build / deploy action the application performs on your behalf**.
If the app has a button or endpoint that says install, add, publish, build, sync,
update, upgrade, import, restore or deploy, that is the attack surface. Reading its
dependency configuration is worth more than enumerating 200 paths.

## First three probes (in this order)

1. **Find the install action and read what it installs.**
   `GET /` and every list endpoint; look for a package name, a version, a source URL.
   Then read the config that decides *where* that name is fetched from.
2. **Read the dependency configuration files** (whichever the app exposes):
   `package.json`, `package-lock.json`, `.npmrc`, `requirements.txt`,
   `pyproject.toml`, `pip.conf`, `Pipfile`, `Gemfile`, `Gemfile.lock`,
   `.gemrc`, `go.mod`, `.github/workflows/*.yml`, `Dockerfile`, `Makefile`.
   If they are not directly readable, look for an endpoint that echoes them
   (debug page, admin panel, build log, error page).
3. **Compare the two lists.** The vulnerability is the *difference* between
   "what the app says it depends on" and "what the resolver will actually pick".

## The mechanism table

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

The challenge target usually *is* the registry, or proxies one. Endpoints worth one
call each, in this order:

- PyPI-style: `/simple/`, `/simple/<name>/`, `/pypi/<name>/json`, `/#/<name>`
- npm-style: `/<name>`, `/@<scope>%2f<name>`, `/-/<name>-<version>.tgz`
- RubyGems-style: `/api/v1/gems/<name>.json`, `/gems/<name>-<version>.gem`,
  `/versions`, `/specs.4.8.gz`
- Generic artifact: `/api/v1/search?q=`, `/api/packages`, `/artifacts`, `/repository/`

A 200 with a JSON body is the metadata. Read `description`, `homepage`, `author`,
`maintainers`, and any custom field - CTF authors put the flag or the next hop there
far more often than in an exploit chain.

## The install is a shell command: read it, then look for the second index

A redeploy / install endpoint usually returns the raw command it ran. That output is the
single most valuable artefact in the whole challenge, because it tells you three things
at once:

- **which package name** is installed,
- **which indexes** are consulted, and **in what order**,
- whether `--extra-index-url` (not `--index-url`) is in play.

`pip` resolves `--extra-index-url` across **both** indexes and picks the highest version,
regardless of which index it came from. That is the dependency-confusion bug. Two indexes
listed with the internal one first does not save it: version wins, not order.

### Reading the pip output line by line

```
Looking in indexes: http://internal-pypi:8080/simple/, http://public-pypi:8080/simple/
Collecting bistro-rate-limiter
  Downloading http://internal-pypi:8080/packages/bistro_rate_limiter-1.0.0.tar.gz (1.4 kB)
```

- `Looking in indexes:` - the resolution order, and the list of registries you must probe.
- `Downloading <url>` - **the index that actually won**, plus the exact artifact path.
  That URL is a live endpoint. Fetch it: an sdist carries `setup.py` / `pyproject.toml`,
  and CTF authors put metadata, next-hop URLs, or the flag path there.
- `Installing build dependencies` - the install runs a build backend **as the installer**.
  A malicious `setup.py` therefore executes as the service user. That is the payload
  delivery mechanism for this whole family.

### The four moves after you see the command

1. **List each index named in the output.** `GET /simple/` on every one of them, then
   `GET /simple/<the installed package>/` on each. You are looking for which index has
   the name and which versions it offers.
2. **Compare versions across the two indexes.** If the internal index pins `1.0.0` and
   the other index can serve something higher, publishing a higher version to the second
   index is the exploit. If the public index has no such name at all, the challenge is
   namespace confusion instead - one of the two indexes already holds the attacker copy
   and you need to find which.
3. **Find the write side.** `/api/upload`, `/upload`, `/pypi/<name>/upload`,
   `/-/package/publish`, `/api/publish`, or a docs page naming a twine endpoint. A mirror
   that only reads is a dead end; a mirror you can write to **is** the challenge.
4. **Re-trigger the install and read the resolved version.** The `Downloading` line in the
   new output is your proof. If it still says `1.0.0` from the internal index, your
   publish did not land or the version constraint is too tight - check the pin before
   trying anything else.

### If the rebuild always resolves the same version

Then the pin is not mutable and confusion is not the bug. Stop publishing attempts and
go read the artefact itself: fetch the `Downloading` URL, unpack the sdist, and read
`setup.py`, `pyproject.toml`, and any `README` / `PKG-INFO`. The flag or the next host is
frequently inside package metadata rather than behind an exploit.

## When the answer is "the install already happened"

If the app shows an install log, or a resolved dependency tree, that log is evidence:
it names the source URL, the version, and the maintainer. Read it before writing any
payload. Half of these challenges are solved by reading one log line.

## What not to do

- Do not brute-force package names. The name is in the config you have not read yet.
- Do not treat this as a web challenge. `route_map` will show 3 routes and that is
  the whole app; the surface is the dependency graph behind it.
- Do not try to reach the public internet. The mirror is the target.

## References

- OWASP Top 10 CI/CD Security Risks (CICD-SEC-1..10)
- OWASP Top 10 2025 A03: Software Supply Chain Failures
