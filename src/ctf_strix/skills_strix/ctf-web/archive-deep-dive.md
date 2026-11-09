# ctf-web — deep-dive archive

> Moved verbatim from the index under the 8KB gate. Read with `exec_command` (`cat` / `sed -n`); reference notes, not a skill — do NOT `load_skill`.

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

## Find Similar Writeups

Offline: no search API and no web access from this image, so reference writeups
cannot be fetched and no `ctf-similar-search` skill is registered. Work from the
local subfiles -- they index the techniques by bug class -- and from the
challenge's own artifacts instead.

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

