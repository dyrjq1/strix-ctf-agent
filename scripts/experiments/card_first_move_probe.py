"""For the two biggest solved clusters, count which sub-technique actually worked.

Compares against what our method cards prescribe as the first move.
"""
import collections
import json

recs = [json.loads(l) for l in open("/home/rjq/solve_notes.jsonl", encoding="utf-8")]

def has(blob, words):
    return any(w in blob for w in words)

CUES = {
    "info_disclosure": ["disclosure", "leak", "exposed", "secret", "credential",
                        "telemetry", "diagnostic", "debug"],
    "idor_authz": ["idor", "broken access control", "object-level", "object level",
                   "bola", "authoriz"],
    "upload_plugin": ["upload", "plugin"],
}

SUB = {
    "info_disclosure": {
        "sourcemap/bundle": ["sourcemap", ".js.map", "bundle", "chunk"],
        "published package/registry": ["npm", "tarball", "package", "registry", "pypi"],
        "debug/diagnostic/telemetry endpoint": ["debug endpoint", "/debug", "telemetry",
                                                "diagnostic", "actuator"],
        "classic files (robots/.git/.env/D-S)": ["robots.txt", ".git/head", ".ds_store",
                                                 "sitemap"],
        "inline in page/header/response": ["in the page", "response body", "header",
                                           "banner", "html"],
    },
    "idor_authz": {
        "unauthenticated id swap": ["without authentication", "unauthenticated",
                                    "anonymous", "no authentication", "no auth"],
        "two accounts swap": ["registered", "login", "logged in", "session",
                              "another user", "low-privilege"],
    },
    "upload_plugin": {
        "classic upload bypass": ["extension", "mime", "magic", "multipart", "webshell"],
        "plugin/config drives file read": ["plugin", "kind `file`", "trigger phrase",
                                           "configuration"],
    },
}

cluster = collections.defaultdict(list)
for rec in recs:
    blob = (rec["summary"] + " " + rec["methodology"]).lower()
    for name, words in CUES.items():
        if has(blob, words):
            cluster[name].append(blob)

for name, blobs in cluster.items():
    print(f"\n== {name}: {len(blobs)} runs")
    for sub, words in SUB[name].items():
        n = sum(1 for b in blobs if has(b, words))
        print(f"   {n:3d}  {sub}")