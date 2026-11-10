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

## Additional Resources

- [sql-injection.md](sql-injection.md) - SQL injection techniques: auth bypass, UNION extraction, filter bypasses, second-order SQLi, truncation, race-assisted leaks, INSERT ON DUPLICATE KEY UPDATE password overwrite, innodb_table_stats WAF bypass; DBMS fingerprinting, per-DBMS enumeration/timing/file-read primitives, sqlmap headless card, tool-gap manual recipes
- [server-side.md](server-side.md) - PHP type juggling, php://filter LFI, Python str.format traversal, SSTI (Jinja2, Twig, ERB, Mako, EJS, Vue.js, Smarty), SSRF (Host header, DNS rebinding, curl redirect, unescaped-dot regex, SNI FTP smuggling, mod_vhost_alias), PHP hash_hmac NULL
- [server-side-2.md](server-side-2.md) - XXE (basic, OOB, DOCX upload), XML injection via X-Forwarded-For, PHP variable variables, PHP uniqid predictable filename, sequential regex replacement bypass, command injection (newline, blocklist, sendmail CGI, multi-barcode, git CLI), GraphQL injection (introspection, batching, interpolation)
- [server-side-exec.md](server-side-exec.md) - Direct code execution paths, upload-to-RCE, deserialization-adjacent execution, LaTeX injection, header and API abuses
- [server-side-exec-2.md](server-side-exec-2.md) - More execution chains: SQLi fragmentation, path parser tricks, polyglot uploads, wrapper abuse, filename injection, BMP pixel webshell with filename truncation
- [server-side-deser.md](server-side-deser.md) - Java/Python/PHP deserialization and race-condition playbooks, PHP SoapClient CRLF SSRF via deserialization
- [server-side-advanced.md](server-side-advanced.md) - Advanced SSRF, traversal, archive, parser, framework, and modern app-server issues, Nginx alias traversal
- [server-side-advanced-2.md](server-side-advanced-2.md) - Docker API SSRF, Castor/XML, Apache expression reads, parser discrepancies, Windows path tricks, rogue MySQL server file read
- [server-side-advanced-3.md](server-side-advanced-3.md) - Part 3 (CSAW/35C3/ASIS/PlaidCTF 2018): WAV polyglot upload, multi-slash URL `path.startswith` bypass, Xalan XSLT `math:random()` seed guess, SoapClient `_user_agent` CRLF method smuggling, `gopher:///` no-host URL scheme bypass, SSRF credential leak via attacker-specified outbound URL
- [server-side-advanced-4.md](server-side-advanced-4.md) - Part 4: WeasyPrint SSRF/file read (CVE-2024-28184), MongoDB regex/$where blind oracle, Pongo2 Go template injection, ZIP PHP webshell, basename() bypass, wget CRLF SSRF→SMTP, Gopher SSRF to MySQL blind SQLi, React Server Components Flight RCE (CVE-2025-55182), AMQP/TLS interception via sslsplit+arpspoof, CairoSVG XXE, Bazaar repo reconstruction
- [client-side.md](client-side.md) - XSS, CSRF, cache poisoning, DOM tricks, admin bot abuse, request smuggling, paywall bypass
- [client-side-advanced.md](client-side-advanced.md) - CSP bypasses, Unicode tricks, XSSI, CSS exfiltration, browser normalization quirks, postMessage null origin bypass
- [auth-and-access.md](auth-and-access.md) - Auth/authz bypasses, hidden endpoints, IDOR, redirect chains, subdomain takeover, AI chatbot jailbreaks
- [auth-and-access-2.md](auth-and-access-2.md) - Part 2 (2018-era): `std::unordered_set` bucket collision auth bypass, `nodeprep.prepare` Unicode homograph username collision, SRP A=0/A=N auth bypass, ArangoDB AQL MERGE privilege escalation
- [auth-jwt.md](auth-jwt.md) - JWT/JWE manipulation, weak secrets, header injection, key confusion, replay
- [auth-infra.md](auth-infra.md) - OAuth/OIDC, SAML, CORS, CI/CD secrets, IdP abuse, login poisoning
- [node-and-prototype.md](node-and-prototype.md) - Prototype pollution, JS sandbox escape, Node.js attack chains
- [prototype-pollution-server-side.md](prototype-pollution-server-side.md) - Read this BEFORE writing any __proto__ payload: non-destructive detection, the baseline rule, and why constructor.prototype often shreds the response shape
- [web3.md](web3.md) - Solidity and Web3 challenge notes
- [frameworks-2026.md](frameworks-2026.md) - Nuxt 3/4, SvelteKit and Vue 3 decision cards: fingerprint in one request, the path-normalization differential batch, SSR payload cache leak (CVE-2026-71316), server-island template injection (CVE-2026-71320) and component instantiation (CVE-2026-71318), SvelteKit __data.json surface, remote-form prototype pollution (GHSA-866w-xmhq-wj7x), enhanced-form open redirect (CVE-2026-114060)
- [cves.md](cves.md) - CVE-driven techniques you can match against challenge banners, headers, dependency leaks, or version strings
- [field-notes.md](field-notes.md) - Long-form exploit notes: quick references for SQLi, XSS, LFI, JWT, SSTI, SSRF, command injection, XXE, deserialization, race conditions, auth bypass, and multi-stage chains
- [tools-mcp.md](tools-mcp.md) - MCP server integration for web: Playwright MCP (admin-bot DOM XSS reproduction, live DOM/console/network inspection, `browser_network_requests` lists endpoints but only `browser_network_request part="response-body"` returns payloads) and Burp Suite official MCP (27 tools, approval gates that block the agent on a modal dialog, target triple decoupling socket from `Host:` header, `normalizeHttpContent` rewriting CR/LF in the request prelude, map-based HTTP/2 that cannot express duplicate headers, `send_to_intruder` stages only, proxy history truncating items at 5000 chars, Collaborator `payloadId`/`customData` Pro-only); when to use each vs plain `curl`
- [python-requests.md](python-requests.md) - Python requests toolkit: session scaffold, Burp-Intruder-like fuzzer (sync + ThreadPoolExecutor + httpx async), payload deploy from pat-reference.md wordlists, header/param spray, cookie/JWT, proxy
- [pat-reference.md](pat-reference.md) — PayloadsAllTheThings index: offline exemplar payloads for XSS/SQLi/SSRF/SSTI/LFI/Command Injection/Upload

## When to Pivot

- If the target is a native binary, custom VM, or firmware image, switch to `/ctf-reverse` first.
- If the HTTP bug only gives you code execution and the hard part becomes memory corruption or seccomp escape, switch to `/ctf-pwn`.
- If the "web" challenge really turns on JWT math, custom MACs, or crypto primitives, switch to `/ctf-crypto`.
- If the web challenge involves analyzing logs, PCAPs, or recovering artifacts from a web server, switch to `/ctf-forensics`.
- If the challenge requires gathering intelligence from public web sources, DNS records, or social media before exploitation, switch to `/ctf-osint`.

## Find Similar Writeups

Offline: no search API and no web access from this image, so reference writeups
cannot be fetched and no `ctf-similar-search` skill is registered. Work from the
local subfiles -- they index the techniques by bug class -- and from the
challenge's own artifacts instead.

## Built-in web tools (already registered in this image)

These are tools the agent can call directly; the notes below only need to say
*when*. Do not rebuild one in a shell loop.

| Tool | Reach for it when |
|---|---|
| `http_probe` | one structured exchange (status, headers, body, timing); the way to send a header set or a body without writing a script |
| `route_map` | crawl once to list API paths and `?` candidates taken from the page's own vocabulary |
| `method_sweep` | one method across many paths in one call, to find which route answers at all |
| `path_variants` | retry one protected path under case, encoding, dot/semi and prefix variants |
| `authdiff` | same request under anon / proxy-header / path variants, comparing status, length and body hash |
| `jsrecon` | fetch the page plus bundles and extract API paths, params, routes, keys, sourceMaps, comments |
| `http_burst` | race windows (Barrier-synchronised) or a batch of values in one call, max 24 |
| `jwt_forge` | forge or resign a JWT locally: `none`, HMAC, RSA test key, claim edit |
| `traffic_list` / `traffic_view` | read back an exchange already made, without re-sending it |
| `web_cve_lookup` | offline CVE index keyed by product/version from a banner |

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

## Callbacks (offline)

No outbound callback receiver is reachable from this image: blind and reverse-connection
payloads cannot be observed from outside. Route those needs through timing-based blind
injection, or a same-host service log / polling endpoint you can read from the target.

## Deep-Dive Notes

Use [field-notes.md](field-notes.md) once you have confirmed the challenge is truly web-heavy and you need the long exploit catalog.

- Recon, SQLi, XSS, traversal, JWT, SSTI, SSRF, XXE, and command injection quick notes
- Deserialization, race conditions, file upload to RCE, and multi-stage chain examples
- Node, OAuth/SAML, CI/CD, Web3, bot abuse, CSP bypasses, and modern browser tricks
- CVE-shaped playbooks and older challenge patterns that still show up in modern CTFs

## Common Flag Locations

- Files: `/flag.txt`, `/flag`, `/app/flag.txt`, `/home/*/flag*`
- Environment: `/proc/self/environ`, process command line, debug config dumps
- Database: tables named `flag`, `flags`, `secret`, or seeded challenge content
- HTTP: custom headers, archived responses, hidden routes, admin exports
- Browser: hidden DOM nodes, `data-*` attributes, inline state objects, source maps
