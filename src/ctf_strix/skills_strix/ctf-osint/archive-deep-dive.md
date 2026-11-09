# ctf-osint — deep-dive archive

> Moved verbatim from the index under the 8KB gate. Read with `exec_command` (`cat` / `sed -n`); reference notes, not a skill — do NOT `load_skill`.

## Additional Resources

- [social-media.md](social-media.md) - Twitter/X (user IDs, Snowflake timestamps, syndication API, memory.lol, Wayback CDX), Tumblr (blog checks, post JSON, avatars), BlueSky search + API, Unicode homoglyph steganography, Discord API, username OSINT (namechk, whatsmyname, Osint Industries), username metadata mining (postal codes), platform false positives, multi-platform chains, Strava fitness route OSINT
- [geolocation-and-media.md](geolocation-and-media.md) - Image analysis, reverse image search (including Baidu for China), Google Lens cropped region search, reflected/mirrored text reading, geolocation techniques (railroad signs, infrastructure maps, MGRS), Google Plus Codes, EXIF/metadata, hardware identification, newspaper archives, IP geolocation, Google Street View panorama matching, What3Words micro-landmark matching, Google Maps crowd-sourced photo verification, Overpass Turbo spatial queries, music-themed landmark geolocation with key encoding
- [web-and-dns.md](web-and-dns.md) - Google dorking (including TBS image filters), Google Docs/Sheets enumeration, DNS recon (TXT, zone transfers), Wayback Machine, FEC research, Tor relay lookups, GitHub repository analysis, Telegram bot investigation, WHOIS investigation (reverse WHOIS, historical WHOIS, IP/ASN lookup), fake service banner detection via nmap fingerprinting
- [tools-mcp.md](tools-mcp.md) - Playwright MCP for OSINT: reading JS-rendered pages, screenshots, interactive reverse-image and map/Street View search flows, social media and Wayback snapshots, profile-API mining via `browser_network_requests` (list) + `browser_network_request part="response-body"` (payload)

---

## Tumblr Investigation

- Blog check: `curl -sI` for `x-tumblr-user` header. Avatar at `/avatar/512`. See [social-media.md](social-media.md).

## Google Docs/Sheets

- Try `/export?format=csv`, `/pub`, `/gviz/tq?tqx=out:csv`, `/htmlview`. See [web-and-dns.md](web-and-dns.md).

## Telegram Bot Investigation

- Find bot references in browser history, interact via `/start`, answer verification questions. See [web-and-dns.md](web-and-dns.md).

## FEC Political Donation Research

- FEC.gov for committee receipts; 501(c)(4) orgs obscure original funders. See [web-and-dns.md](web-and-dns.md).

## Unicode Homoglyph Steganography

**Pattern:** Visually-identical Unicode characters from different blocks (Cyrillic, Greek, Math) encode binary data in social media posts. ASCII = 0, homoglyph = 1. Group bits into bytes for flag. See [social-media.md](social-media.md#unicode-homoglyph-steganography-on-bluesky-metactf-2026).

## BlueSky Public API

No auth needed. Endpoints: `public.api.bsky.app/xrpc/app.bsky.feed.searchPosts?q=...`, `app.bsky.actor.searchActors`, `app.bsky.feed.getAuthorFeed`. Check all replies to official posts. See [social-media.md](social-media.md#unicode-homoglyph-steganography-on-bluesky-metactf-2026).

## Fake Service Banner Detection

**Pattern:** Port appears open on a standard service port (22/SSH, 80/HTTP) but runs a fake service. `nmap -sV` or `nc host port` reveals the flag in the banner. Never trust port numbers alone -- always fingerprint the service. See [web-and-dns.md](web-and-dns.md#fake-service-banner-detection-via-fingerprinting-metactf-flash-2026).

## Shodan SSH Fingerprint Lookup

Search Shodan by SSH host key fingerprint to identify servers (Shodan is a web lookup -- the CLI is not in this image). See [web-and-dns.md](web-and-dns.md#shodan-ssh-fingerprint-lookup-ekoparty-ctf-2016).

## Gaming Platform OSINT

Lookup usernames across gaming platforms (Steam, Xbox, PSN, MMOs) for character profiles, activity, and linked accounts. See [social-media.md](social-media.md#gaming-platform-osint--mmo-character-lookup-csaw-ctf-2016).

