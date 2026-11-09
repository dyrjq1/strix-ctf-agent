---
name: ctf-osint
description: Provides open source intelligence techniques for CTF challenges. Use when gathering information from public sources, social media, geolocation, DNS records, username enumeration, reverse image search, Google dorking, Wayback Machine, Tor relays, FEC filings, or identifying unknown data like hashes and coordinates.
license: MIT
compatibility: Requires filesystem-based agent (Claude Code or similar) with bash and Python 3.
allowed-tools: Bash Read Write Edit Glob Grep Task
metadata:
  user-invocable: "false"
  author: Lukasz Jagiello
---

# CTF OSINT

Quick reference for OSINT CTF challenges. Each technique has a one-liner here; see supporting files for full details.

## Prerequisites

**Python packages:** the image already ships `Pillow`. `shodan` is **not
available** (and there is no internet) -- work on local artifacts with
`requests` or plain Python instead.

**Offline image: no installs and no internet.** `python3` ships `requests` and
the usual stdlib, and `curl` works; `nmap` and `exiftool` (image/GPS/document
metadata) are installed; `dig` ships with the dnsutils package, `whois` is not,
and no public lookup service (Shodan,
Wayback, social APIs) can be reached. Work from the artifacts the challenge
hands you.

**MCP servers (optional):** Playwright MCP ([microsoft/playwright-mcp](https://github.com/microsoft/playwright-mcp)) for browser-driven OSINT (JS-rendered pages, reverse-image/map flows) — see [tools-mcp.md](tools-mcp.md).

## When to Pivot

- If you already have the files or packets locally and now need extraction or carving, switch to `/ctf-forensics`.
- If the task becomes active exploitation of a live HTTP service, switch to `/ctf-web`.
- If you uncover malware samples, beacons, or suspicious binaries during attribution, switch to `/ctf-malware`.

## Quick Start Commands

```bash
# DNS recon
dig +short -t txt target.com
dig +short -t cname target.com
dig +short -t mx target.com
dig -t txt target.com
dig axfr @ns.target.com target.com
whois target.com

# Image metadata
exiftool image.jpg
identify -verbose image.jpg | head -30

# Web archive
curl "https://web.archive.org/web/20230101*/target.com"

# Username lookup (offline: no clone and no browser -- probe handles with curl
# and use the platform list in social-media.md as the checklist)

# Shodan / ip-api style lookups need the internet, which this image lacks:
# start from the artifacts in the challenge, not from a live API.
```

## String Identification

- 40 hex chars -> SHA-1 (Tor fingerprint)
- 64 hex chars -> SHA-256
- 32 hex chars -> MD5

## Twitter/X Account Tracking

- Persistent numeric User ID: `https://x.com/i/user/<id>` works even after renames.
- Snowflake timestamps: `(id >> 22) + 1288834974657` = Unix ms.
- Wayback CDX, syndication API, memory.lol for historical data (Nitter is dead — do not use). See [social-media.md](social-media.md).

## Username OSINT

- [whatsmyname.app](https://whatsmyname.app) (~717 sites as of 2026-10; browser-only, no JSON API — for scripting use the [WebBreacher/WhatsMyName](https://github.com/WebBreacher/WhatsMyName) dataset), [namechk.com](https://namechk.com). Watch for platform false positives. See [social-media.md](social-media.md).

## Image Analysis & Reverse Image Search

- Google Lens (crop to region of interest), Google Images, TinEye, Yandex (faces). Check corners for visual stego. Twitter strips EXIF. See [geolocation-and-media.md](geolocation-and-media.md).
- **Cropped region search:** Isolate distinctive elements (shop signs, building facades) and search via Google Lens for better results than full-scene search. See [geolocation-and-media.md](geolocation-and-media.md).
- **Reflected text:** Flip mirrored/reflected text (water, glass) horizontally; search partial text with quoted strings. See [geolocation-and-media.md](geolocation-and-media.md).

## Geolocation

- Railroad signs, infrastructure maps (OpenRailwayMap, OpenInfraMap), process of elimination. See [geolocation-and-media.md](geolocation-and-media.md).
- **Street View panorama matching:** Feature extraction + multi-metric image similarity ranking against candidate panoramas. Useful when challenge image is a crop of a Street View photo. See [geolocation-and-media.md](geolocation-and-media.md).
- **Road sign OCR:** Extract text from directional signs (town names, route numbers) to pinpoint road corridors. Driving side + sign style + script identify the country. See [geolocation-and-media.md](geolocation-and-media.md).
- **Architecture + brand identification:** Post-Soviet concrete = Russia/CIS; named businesses → search locations/branches → cross-reference with coastline/terrain. See [geolocation-and-media.md](geolocation-and-media.md).
- **Music-themed landmark geolocation:** Multiple images of music-related landmarks worldwide; each yields a piano key number encoding one flag character. Identify all locations first, then decode the key sequence. See [geolocation-and-media.md](geolocation-and-media.md).

## MGRS Coordinates

- Grid format "4V FH 246 677" -> online converter -> lat/long -> Google Maps. See [geolocation-and-media.md](geolocation-and-media.md).

## Google Plus Codes

- Format `XXXX+XXX` (chars: `23456789CFGHJMPQRVWX`). Drop a pin on Google Maps → Plus Code appears in details. Free, no API key needed. See [geolocation-and-media.md](geolocation-and-media.md).

## Metadata Extraction

```bash
exiftool image.jpg           # EXIF data
pdfinfo document.pdf         # PDF metadata
mediainfo video.mp4          # Video metadata
```

## Google Dorking

```text
site:example.com filetype:pdf
intitle:"index of" password
```

**Image TBS filters:** Append `&tbs=itp:face` to Google Image URLs to filter for faces only (strips logos/banners). See [web-and-dns.md](web-and-dns.md).

## DNS Reconnaissance

```bash
dig -t txt subdomain.ctf.domain.com
dig axfr @ns.domain.com domain.com  # Zone transfer
```

Always check TXT, CNAME, MX for CTF domains. See [web-and-dns.md](web-and-dns.md).

## Tor Relay Lookups

- `https://metrics.torproject.org/rs.html#simple/<FINGERPRINT>` -- check family, sort by "first seen". See [web-and-dns.md](web-and-dns.md).

## GitHub Repository Analysis

- Check issue comments, PR reviews, commit messages, wiki edits via `gh api`. See [web-and-dns.md](web-and-dns.md).

## IP Geolocation

```bash
curl "http://ip-api.com/json/103.150.68.150"
```

See [geolocation-and-media.md](geolocation-and-media.md).

## Resources

- **Shodan** - Internet-connected devices
- **Censys** - Certificate and host search
- **VirusTotal** - File/URL reputation
- **WHOIS** - Domain registration
- **Wayback Machine** - Historical snapshots

**Deep-dive map** (sections moved verbatim under the 8KB gate; `exec_command` reads them, do NOT `load_skill`):
- [archive-deep-dive.md](archive-deep-dive.md): Additional Resources + platform-specific lookup notes
