---
name: ctf-web
description: Provides web exploitation techniques for CTF challenges. Use when the target is primarily an HTTP application, API, browser client, template engine, identity flow, or smart-contract frontend/backend surface, including XSS, SQLi, SSTI, SSRF, XXE, JWT, auth bypass, file upload, request smuggling, OAuth/OIDC, SAML, prototype pollution, and similar web bugs. Do not use it for native binary memory corruption, reverse engineering of standalone executables, disk or memory forensics, or pure cryptanalysis unless the web flaw is still the main path to the flag.
license: MIT
compatibility: Requires filesystem-based agent (Claude Code or similar) with bash and Python 3.
allowed-tools: Bash Read Write Edit Glob Grep Task Skill
metadata:
  user-invocable: "false"
  author: Lukasz Jagiello
---

# CTF Web Exploitation

Use this skill as a routing and execution guide for web-heavy challenges. Keep the first pass short: map the app, confirm the trust boundary, and only then dive into the detailed technique notes.

## Prerequisites

**Offline image: no installs and no internet.** `python3` already ships `requests`,
`httpx`, `PIL` and `Crypto`, and `curl` works; `sqlmap`, `ffuf`, `impacket` and `flask-unsign` are installed;
`nuclei` and templates are **not available** -- write the request in Python or with `curl`.

## When to Pivot

- If the target is a native binary, custom VM, or firmware image, switch to `/ctf-reverse` first.
- If the HTTP bug only gives you code execution and the hard part becomes memory corruption or seccomp escape, switch to `/ctf-pwn`.
- If the "web" challenge really turns on JWT math, custom MACs, or crypto primitives, switch to `/ctf-crypto`.
- If the web challenge involves analyzing logs, PCAPs, or recovering artifacts from a web server, switch to `/ctf-forensics`.
- If the challenge requires gathering intelligence from public web sources, DNS records, or social media before exploitation, switch to `/ctf-osint`.

## First-Pass Workflow

1. Identify the real boundary: browser only, backend only, mixed app, or auth flow.
2. Capture one normal request/response pair for every major feature before fuzzing.
3. Enumerate hidden functionality from JS bundles, response headers, routes, and alternate methods.
4. Classify the likely bug family: injection, authz, parser mismatch, upload, trust proxy, state machine, or client-side execution.
5. Build the smallest proof first: leak, bypass, or primitive. Save full exploit chaining for later.

### Bulk payloads (PayloadsAllTheThings -- offline index only)

No PAT clone is possible offline and no network fetch will succeed. Use
[pat-reference.md](pat-reference.md) instead: it indexes the payload families by bug
class with exemplar payloads. Pick the matching section, adapt those exemplars and
the inline samples in this file, and send the request yourself.

## Quick Start Commands

```bash
# Recon
curl -si https://target.com/
curl -s https://target.com/robots.txt
curl -sI https://target.com/

# SQLi quick test (sqlmap is installed; or send the payload yourself)
curl -s "https://target.com/page?id=1%27"

# JWT decode (no verification)
python3 -c "import base64,json,sys;p=sys.argv[1].split('.')[1];print(json.loads(base64.urlsafe_b64decode(p+'='*(-len(p)%4))))" '<token>'

# SSTI probes
curl "https://target.com/page?name={{7*7}}"
curl "https://target.com/page?name={{config}}"

# Request inspection
curl -v -X POST https://target.com/api -H "Content-Type: application/json" -d '{}'
```

## Login Brute-Force — Hard Rules

When a challenge requires brute-forcing a login form, follow these rules EXACTLY. Do NOT improvise.

1. **Username is ALWAYS `admin`.** Do NOT enumerate usernames. Do NOT create username lists. Even when the challenge says "弱口令" (weak password) or "常用用户名" (common usernames), those hints describe the PASSWORD — the target account is still `admin`. Only use a different username if the challenge gives a SPECIFIC different string (e.g., "the username is root").

2. **Password file MUST be an existing Kali wordlist.** The default is `/usr/share/wordlists/metasploit/burnett_top_1024.txt`. Do NOT create your own password file — no `cat > passwords.txt`, no hardcoded password lists in code, no reading from a local `Top1000.txt`. Your script must read lines from the Kali wordlist file directly.

For complex scenarios (CSRF tokens, frontend encryption, JSON APIs, Basic Auth, threading), see the reference scripts in [auth-and-access.md](auth-and-access.md) — but those scripts must still follow the two rules above.

## First Questions to Answer

- Is the flag likely in the browser, an API response, a local file, a database row, or an internal service?
- Does the app trust user-controlled data in templates, redirects, file paths, headers, serialized objects, or background jobs?
- Are there multiple parsers disagreeing with each other: proxy vs app, URL parser vs fetcher, sanitizer vs browser, serializer vs filter?
- Can you turn the bug into a smaller primitive first: read one file, forge one token, call one internal endpoint, trigger one bot visit?

## High-Value Recon Checks

- Read the HTML, inline scripts, and bundled JS before guessing the API surface.
- Compare what the UI submits with what the backend accepts; optional JSON fields often unlock hidden paths.
- Check obvious metadata and helper paths early: `/robots.txt`, `/sitemap.xml`, `/.well-known/`, `/admin`, `/debug`, `/.git/`, `/.env`.
- Try alternate verbs and content types on interesting routes: `GET`, `POST`, `PUT`, `PATCH`, `TRACE`, JSON, form, multipart, XML.
- Treat file upload, PDF/export, webhook, OAuth callback, and admin bot features as likely exploit multipliers.

## Fast Pattern Map

- SQL errors, odd filtering, or state-dependent DB behavior: start with [sql-injection.md](sql-injection.md).
- Templating, file reads, SSRF, command execution, XML, or parser bugs: start with [server-side.md](server-side.md) and [server-side-exec.md](server-side-exec.md).
- XSS, CSP bypass, admin bot, client routing, DOM issues, or scriptless exfiltration: start with [client-side.md](client-side.md).
- Session forgery, hidden admin routes, JWT, OAuth, SAML, or weak trust boundaries: start with [auth-and-access.md](auth-and-access.md), [auth-jwt.md](auth-jwt.md), and [auth-infra.md](auth-infra.md).
- Node.js apps, prototype pollution, VM sandboxes, or SSRF into internal services: add [node-and-prototype.md](node-and-prototype.md).
- Smart contract frontends or blockchain-integrated apps: add [web3.md](web3.md).

## Common Chain Shapes

- Recon -> hidden route -> auth bypass -> internal file read -> token or flag
- XSS or HTML injection -> admin bot -> privileged action -> secret leak
- Traversal or upload -> config/source leak -> secret recovery -> session forgery
- SSRF -> metadata or internal API -> credential leak -> code execution
- SQLi or NoSQL injection -> credential bypass -> second-stage template or upload abuse

## Common Flag Locations

- Files: `/flag.txt`, `/flag`, `/app/flag.txt`, `/home/*/flag*`
- Environment: `/proc/self/environ`, process command line, debug config dumps
- Database: tables named `flag`, `flags`, `secret`, or seeded challenge content
- HTTP: custom headers, archived responses, hidden routes, admin exports
- Browser: hidden DOM nodes, `data-*` attributes, inline state objects, source maps

**Deep-dive map** (sections moved verbatim under the 8KB gate; `exec_command` reads them, do NOT `load_skill`):
- [archive-deep-dive.md](archive-deep-dive.md): Additional Resources + similar-writeup finder + offline callbacks + deep-dive notes
