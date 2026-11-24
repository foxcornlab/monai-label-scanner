#!/usr/bin/env python3
"""Detection-only triage for MONAI Label CVE-2026-133968.

Path traversal with resultant remote code execution in MONAI Label,
the open-source medical-imaging annotation server from Project MONAI
(NVIDIA, Kitware and academic partners). Every release through 0.8.5
is affected. `PUT /datastore/image` takes the caller-supplied `image`
value and uses it as the file name without checking that the path it
builds stays inside the datastore; `PUT /datastore/label` does the
same with the image ID and the label tag. The vendor advisory uses
`../../../tmp/x` as the example value. Authentication is disabled by
default (`MONAI_LABEL_AUTH_ENABLE=False`), so on a default install
any client that can reach the server — default port 8000 — can write
files anywhere the server process can write, with no login at all.
With authentication on, any user holding the annotator role can
still do it. CVSS 3.1 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H),
CWE-22 (path traversal). CNA: MITRE.

This is not theoretical. Amazon Threat Intelligence reported on
20 November 2026 that a China-nexus operator running the open-source
Cairn framework — autonomous AI agents doing penetration testing —
found this zero-day on its own, went from mapping the API to an
arbitrary file write in about 11 minutes, and in a later session
wrote a Python reverse shell into `sitecustomize.py` (a file the
interpreter imports at startup) and called a training endpoint to
spawn a fresh Python process, getting a root shell on a university
server in East Asia. The campaign ran 8-10 September 2026. CISA
added CVE-2026-133968 to its Known Exploited Vulnerabilities catalog
on 23 November 2026, due 26 November 2026.

Detection only. This scanner never sends a payload, never requests
a crafted path, and never uploads a file. What it does instead is
version-table grading against the vendor's fixed release, plus
reading the version your install already discloses, plus a plain
GET of `/info/` on a live server (the endpoint MONAI Label itself
exposes for app info), plus hunting your logs and your datastore
for the compromise signs Amazon published. A public exploit path
exists (the advisory example, plus a nuclei template); this tool is
the defensive counterpart.

Fixed release, per the vendor (primary source — Project MONAI
release 0.8.6, 22 November 2026):

    MONAI Label 0.8.5 and earlier -> 0.8.6 (or later)

Note the date: the fix shipped on 22 November, two days after the
CVE record was published on 20 November — and a month after the fix
was merged (PR #1915, 19 October). Write-ups from 20-21 November
still say "no fixed release exists". That was true for about 36
hours and is stale now: 0.8.6 is on PyPI and Docker Hub, and this
scanner grades against it, not the tracker lag.

The same release also fixes a second path traversal with no CVE
yet: `PUT /session/?uncompress=true` unpacked uploaded tar archives
without checking member names, and used session IDs as paths without
validation (PR #1942). It affects the same versions (0.8.5 and
earlier) and is fixed by the same upgrade, so this scanner flags it
in the same verdict rather than pretending it is a separate problem.

There is no workaround that keeps the server exposed. Enable
authentication, take the server off untrusted networks, run it as
an unprivileged user — and upgrade to 0.8.6. Patching alone is not
enough if the server was already hit: this is unauthenticated RCE
with a published attack chain, so check for rogue `sitecustomize.py`
files and unexpected files under your datastore before returning
the server to service (`--ioc-dir` hunts for exactly that, and
`--access-log` greps for the traversal pattern in upload requests).
"""

import argparse
import importlib.metadata
import json
import re
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

VERSION = "1.0.0"

CVE_MAIN = "CVE-2026-133968"
CVSS = "9.8"
CWE = "CWE-22"
PRODUCT = "MONAI Label"
PACKAGE = "monailabel"
DOCKER_IMAGE = "projectmonai/monailabel"
FIXED_VERSION = (0, 8, 6)
FIXED_LABEL = "0.8.6"
CVE_PUBLISHED = "2026-11-20"
FIX_RELEASED = "2026-11-22"
KEV_ADDED = "2026-11-23"
KEV_DUE = "2026-11-26"
DEFAULT_PORT = 8000

EXIT_CLEAN = 0
EXIT_VULNERABLE = 1
EXIT_UNKNOWN = 2
EXIT_USAGE = 3

# A version token: "0.8.5", "0.8.6", "0.8", "0". Extra components
# ("0.8.6.1") and suffixes ("rc1", "-dev", "+g1234") are tolerated
# and ignored past the third component; the numeric prefix grades.
VERSION_TOKEN = re.compile(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?")

# The datastore upload endpoints take the traversal in the query
# string: image=../../../tmp/x (or the URL-encoded form). A log line
# for one of those endpoints carrying dot-dot segments — plain,
# percent-encoded, or slash-encoded — is a compromise probe worth
# investigating. It is not a normal upload.
TRAVERSAL_MARKERS = (
    "..%2f", "..%5c", "%2e%2e", "%252e%252e", "..\\", "../", "..%2F",
    "..%5C",
)
UPLOAD_PATHS = ("/datastore/image", "/datastore/label")

# The published attack chain plants a Python startup hook:
# sitecustomize.py (auto-imported at interpreter startup), then a
# training endpoint spawns a fresh Python process as the server user.
# A sitecustomize.py / usercustomize.py anywhere under a datastore
# or server tree that is not a real site-packages directory is a
# compromise sign, not a config file.
STARTUP_HOOKS = ("sitecustomize.py", "usercustomize.py")

# Path fragments that mark a location as a real Python install, where
# a sitecustomize.py can be legitimate. Anything else is suspicious.
LEGIT_HOOK_DIRS = ("site-packages", "dist-packages", "lib/python")

MAX_LOG_BYTES = 50 * 1024 * 1024  # per file, so a giant log cannot OOM us


def parse_version(raw):
    """Parse "0.8.5" (or "0.8", "0", "0.8.6rc1") into (0, 8, 5).

    Returns None when the string carries no version token at all.
    Missing components default to 0, so "0.8" means (0, 8, 0).
    """
    if raw is None:
        return None
    match = VERSION_TOKEN.search(str(raw).strip())
    if not match:
        return None
    major = int(match.group(1))
    minor = int(match.group(2)) if match.group(2) is not None else 0
    patch = int(match.group(3)) if match.group(3) is not None else 0
    return (major, minor, patch)


def fmt_version(version):
    """Render a version tuple the way the package writes it: 0.8.5."""
    return "%d.%d.%d" % version


def grade(version, auth_enabled=False):
    """Grade a parsed version tuple.

    Returns (verdict, detail) with verdict VULNERABLE, FIXED or
    UNKNOWN. `auth_enabled` matters only for the wording: with auth
    on, an annotator-role account can still reach the upload
    endpoints, so auth narrows the hole to trusted users, it does
    not close it. A version at or above 0.8.6 is FIXED either way —
    the fix confines the write to the datastore for every caller.
    """
    if version is None:
        return "UNKNOWN", "no parseable version"

    if version >= FIXED_VERSION:
        return "FIXED", (
            "%s is at or above the fixed release %s (shipped %s, two "
            "days after the CVE record was published on %s)"
            % (fmt_version(version), FIXED_LABEL, FIX_RELEASED,
               CVE_PUBLISHED)
        )

    detail = (
        "%s is below the fixed release %s; upgrade to %s or later "
        "(pip install -U monailabel==%s, or docker pull "
        "projectmonai/monailabel:%s)"
        % (fmt_version(version), FIXED_LABEL, FIXED_LABEL,
           FIXED_LABEL, FIXED_LABEL)
    )
    if version == (0, 8, 5):
        detail += (
            " — 0.8.5 is the last vulnerable release, one patch "
            "behind the fix, and it was the newest release for two "
            "years (Nov 2024 to Nov 2026); do not mistake 'latest "
            "before the CVE' for 'patched'"
        )
    if auth_enabled:
        detail += (
            "; authentication is enabled, which limits this to users "
            "holding the annotator role — but the annotator role can "
            "still call both upload endpoints, so auth narrows the "
            "hole, it does not close it"
        )
    else:
        detail += (
            "; authentication is disabled by default, so any client "
            "that can reach the server can write files anywhere the "
            "server process can write — patch, then hunt for rogue "
            "sitecustomize.py files, because patching alone does not "
            "evict an attacker who already got in"
        )
    return "VULNERABLE", detail + (
        "; path traversal RCE via PUT /datastore/image and "
        "/datastore/label, exploited in the wild since September 2026 "
        "(CISA KEV, due %s)" % KEV_DUE
    )


def read_installed_version():
    """Read the installed monailabel version from package metadata.

    Uses importlib.metadata, which reads the dist-info METADATA of
    the environment this Python runs in. Returns (version tuple or
    None, notes list). No subprocess, no network.
    """
    try:
        raw = importlib.metadata.version(PACKAGE)
    except importlib.metadata.PackageNotFoundError:
        return None, [
            "no installed package named %r found in this Python "
            "environment — run this on the box that runs the server, "
            "or pass --version, --url or --docker instead" % PACKAGE
        ]
    except Exception as exc:  # metadata unreadable for another reason
        return None, ["cannot read installed package metadata: %s" % exc]
    version = parse_version(raw)
    if version is None:
        return None, ["installed %s version %r is not parseable" % (PACKAGE, raw)]
    return version, []


def read_metadata_file(path):
    """Read a Version: out of a dist-info METADATA / PKG-INFO file."""
    try:
        text = Path(path).read_text(errors="replace")
    except OSError as exc:
        return None, ["cannot read %s: %s" % (path, exc)]
    match = re.search(r"^Version:\s*([0-9][^\s]*)\s*$", text, re.MULTILINE)
    if not match:
        return None, ["%s carries no parseable Version:" % path]
    version = parse_version(match.group(1))
    if version is None:
        return None, ["%s version %r is not parseable" % (path, match.group(1))]
    return version, []


def read_local_install(path):
    """Grade a local install from a directory.

    Accepts a dist-info directory, a METADATA / PKG-INFO file, a
    site-packages directory, or a source checkout (which carries a
    `monailabel` package directory — the version then comes from the
    installed metadata in the same tree, if any). Returns (version
    tuple or None, notes list).
    """
    target = Path(path)
    if target.is_file() and target.name in ("METADATA", "PKG-INFO"):
        return read_metadata_file(target)
    if target.is_dir():
        dist_info = target / ("%s.dist-info" % PACKAGE)
        if dist_info.is_dir():
            return read_metadata_file(dist_info / "METADATA")
        for child in sorted(target.iterdir()):
            if child.name.startswith("%s-" % PACKAGE) and child.suffix == ".dist-info":
                return read_metadata_file(child / "METADATA")
        if (target / PACKAGE / "__init__.py").is_file():
            return None, [
                "source checkout at %s carries no installed metadata — "
                "grade the running install with --local (no path) or "
                "pass --version" % path
            ]
    return None, [
        "no %s install found under %s — pass a site-packages dir, a "
        "dist-info dir, or run --local with no path on the server box"
        % (PACKAGE, path)
    ]


def read_docker_tags():
    """Grade projectmonai/monailabel images present in local Docker.

    Runs `docker images` and grades every tag found. Returns
    (worst version tuple or None, per-tag notes list). Docker missing
    or no matching image is not an error — it just means there is
    nothing local to grade.
    """
    try:
        proc = subprocess.run(
            ["docker", "images", "--format", "{{.Repository}}:{{.Tag}}",
             DOCKER_IMAGE],
            capture_output=True, text=True, timeout=30,
        )
    except FileNotFoundError:
        return None, ["docker is not installed here"]
    except (subprocess.SubprocessError, OSError) as exc:
        return None, ["docker images failed: %s" % exc]
    tags = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    if not tags:
        return None, ["no %s image found in local Docker" % DOCKER_IMAGE]
    notes = []
    worst = None
    for ref in tags:
        tag = ref.rsplit(":", 1)[-1]
        if tag in ("latest", "<none>"):
            notes.append(
                "%s: tag %r cannot be graded — pin the version tag "
                "and grade it with --version" % (ref, tag))
            continue
        version = parse_version(tag)
        if version is None:
            notes.append("%s: tag %r is not parseable" % (ref, tag))
            continue
        notes.append("%s: image version %s" % (ref, fmt_version(version)))
        if worst is None or version < worst:
            worst = version
    return worst, notes


def _unverified_context():
    """MONAI Label servers in labs often run self-signed certificates;
    the probe only reads a public info endpoint, so verification is
    skipped the way a browser in a lab does it. Never send
    credentials over this channel — this tool never sends any."""
    return ssl._create_unverified_context()


def fetch(url, timeout=10):
    """Plain GET. Returns (status, body, error).

    Status None means the connection itself failed; the error string
    says why. HTTPS uses an unverified context (see above).
    """
    headers = {
        "User-Agent": "monai-label-scanner/1.0 (detection-only triage)"
    }
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(
            request, timeout=timeout, context=_unverified_context()
        ) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace"), None
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read().decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return exc.code, body, None
    except Exception as exc:  # connection refused, DNS, timeout, TLS
        return None, "", str(exc)


def looks_like_monai_label(body):
    """Does this JSON look like a MONAI Label /info/ response?

    The endpoint returns the app info dict: name, description,
    version (the *app* version — default "2.0", NOT the package
    version), labels, models, trainers, strategies, scoring,
    train_stats and datastore (total / completed / label_tags).
    The fingerprint is the combination of keys, not any one value.
    """
    try:
        data = json.loads(body)
    except ValueError:
        return False
    if not isinstance(data, dict):
        return False
    keys = set(data)
    if not {"name", "models", "datastore"} <= keys:
        return False
    datastore = data.get("datastore")
    if not isinstance(datastore, dict):
        return False
    return bool({"total", "completed", "label_tags"} & set(datastore))


def probe_url(base_url):
    """Grade a live server from one plain GET of /info/.

    No payload, no crafted path, no upload, no POST — the request is
    a read of the info endpoint the server itself exposes. Returns
    (verdict, detail, notes list).

    The hard limit of the remote probe, stated plainly: /info/
    returns the *app* version (default "2.0"), not the monailabel
    package version, and the package version is not disclosed by any
    public endpoint. So a reachable server with authentication off
    grades VULNERABLE-as-exposed — every release through 0.8.5 is
    affected, and 0.8.5 was the newest release for two years, so an
    exposed server is vulnerable until you prove 0.8.6+ locally with
    --local or --version. A server with authentication on grades
    UNKNOWN, because an annotator-role account can still exploit a
    <= 0.8.5 server and the version cannot be graded from outside.
    """
    notes = []
    base = base_url.rstrip("/")
    url = "%s/info/" % base
    status, body, error = fetch(url)
    if status is None:
        return "UNKNOWN", "could not reach %s: %s" % (url, error), notes
    if status in (401, 403):
        return "UNKNOWN", (
            "%s returned HTTP %d — authentication is enabled on this "
            "server, so the version cannot be graded from outside; "
            "an annotator-role account can still exploit a 0.8.5 or "
            "earlier server, so grade the package version locally "
            "with --local or --version" % (url, status)
        ), notes
    if status != 200:
        return "UNKNOWN", (
            "%s returned HTTP %d — not a recognisable MONAI Label "
            "info endpoint (a custom MONAI_LABEL_API_STR prefix moves "
            "it; try the full base URL with the prefix)" % (url, status)
        ), notes
    if not looks_like_monai_label(body):
        return "UNKNOWN", (
            "%s returned HTTP 200 but the body is not a MONAI Label "
            "info response — this is probably not a MONAI Label server"
            % url
        ), notes
    try:
        app_version = json.loads(body).get("version")
    except ValueError:
        app_version = None
    notes.append(
        "confirmed MONAI Label: /info/ returned the app info dict "
        "(datastore status included)")
    if app_version is not None:
        notes.append(
            "/info/ reports app version %r — that is the *app* "
            "version, not the monailabel package version; it is never "
            "graded here, because grading it would call a 2.0 app "
            "fixed" % (app_version,))
    return "VULNERABLE", (
        "MONAI Label server reachable at %s with authentication "
        "disabled (default) — any client that can connect can call "
        "PUT /datastore/image and /datastore/label; the API does not "
        "disclose the package version, so treat this as exposed until "
        "you prove 0.8.6+ locally (pip show monailabel, or this "
        "tool's --local). 0.8.5 was the newest release for two years, "
        "so an exposed server is vulnerable until proven otherwise"
        % base
    ), notes


def scan_access_log(path):
    """Grep access logs for the traversal pattern in upload requests.

    Accepts one log file or a directory of .log files. Flags lines
    for /datastore/image or /datastore/label (PUT or any method, the
    log line is what it is) carrying a dot-dot segment — plain,
    percent-encoded or slash-encoded — and any line mentioning a
    Python startup hook. Returns (hits, notes). A hit is a compromise
    probe worth investigating, not proof of a breach — and no hits is
    not a clean bill, because logs rotate and attackers clean up.
    """
    hits = []
    notes = []
    target = Path(path)
    if target.is_file():
        files = [target]
    elif target.is_dir():
        files = sorted(target.glob("*.log"))
        if not files:
            return hits, ["no .log files under %s" % path]
    else:
        return hits, ["access log path %s does not exist" % path]
    for logfile in files:
        try:
            size = logfile.stat().st_size
        except OSError:
            continue
        with logfile.open(errors="replace") as handle:
            if size > MAX_LOG_BYTES:
                handle.seek(size - MAX_LOG_BYTES)
                handle.readline()  # drop the partial first line
            for lineno, line in enumerate(handle, start=1):
                lowered = line.lower()
                is_upload = any(p in lowered for p in UPLOAD_PATHS)
                has_traversal = any(m in lowered for m in TRAVERSAL_MARKERS)
                has_hook = any(h in lowered for h in STARTUP_HOOKS)
                if (is_upload and has_traversal) or has_hook:
                    hits.append((str(logfile), lineno, line.rstrip("\n")))
                    if len(hits) >= 50:
                        notes.append("hit cap reached (50), refine the search")
                        return hits, notes
    return hits, notes


def scan_ioc_dir(path):
    """Hunt a directory tree for the published persistence files.

    Walks the tree (a datastore dir, a server home, /tmp, wherever
    the server process could write) for sitecustomize.py and
    usercustomize.py. A hit inside a real site-packages /
    dist-packages tree can be legitimate and is flagged as such; a
    hit anywhere else — a datastore dir, /tmp, a home directory, a
    session dir — is a compromise sign: that is exactly where the
    Cairn agents planted the reverse shell. Returns (hits, notes)
    with hits as (path, looks_legit bool).
    """
    target = Path(path)
    if not target.exists():
        return [], ["IOC path %s does not exist" % path]
    hits = []
    for hook in STARTUP_HOOKS:
        for found in sorted(target.rglob(hook)):
            if not found.is_file():
                continue
            parts = str(found).lower()
            legit = any(d in parts for d in LEGIT_HOOK_DIRS)
            hits.append((str(found), legit))
            if len(hits) >= 50:
                return hits, ["hit cap reached (50), refine the search"]
    return hits, []


def grade_one(entry):
    """Grade one inventory entry.

    Entry keys: "version" (string), "url" (server base URL),
    "local" (bool, or a path string for a local install dir),
    "docker" (bool). Optional: "auth_enabled" bool, "access_log"
    path, "ioc_dir" path. Returns a result dict.
    """
    result = {"host": entry.get("host", entry.get("url", entry.get("version", "?")))}
    version = None
    notes = []
    if "version" in entry:
        version = parse_version(entry["version"])
        if version is None:
            notes.append("version %r is not parseable" % entry["version"])
        verdict, detail = grade(version,
                                auth_enabled=bool(entry.get("auth_enabled")))
        result["verdict"] = verdict
        result["detail"] = detail
    elif "url" in entry:
        verdict, detail, url_notes = probe_url(entry["url"])
        result["verdict"] = verdict
        result["detail"] = detail
        notes.extend(url_notes)
    elif entry.get("local") is True:
        version, local_notes = read_installed_version()
        notes.extend(local_notes)
        verdict, detail = grade(version,
                                auth_enabled=bool(entry.get("auth_enabled")))
        result["verdict"] = verdict
        result["detail"] = detail
    elif isinstance(entry.get("local"), str):
        version, local_notes = read_local_install(entry["local"])
        notes.extend(local_notes)
        verdict, detail = grade(version,
                                auth_enabled=bool(entry.get("auth_enabled")))
        result["verdict"] = verdict
        result["detail"] = detail
    elif entry.get("docker"):
        version, docker_notes = read_docker_tags()
        notes.extend(docker_notes)
        verdict, detail = grade(version,
                                auth_enabled=bool(entry.get("auth_enabled")))
        result["verdict"] = verdict
        result["detail"] = detail
    else:
        return dict(result, verdict="UNKNOWN",
                    detail="entry has no version, url, local or docker",
                    notes=notes)
    if version is not None:
        result["version"] = fmt_version(version)
    result["notes"] = notes
    log_path = entry.get("access_log")
    if log_path:
        hits, log_notes = scan_access_log(log_path)
        notes.extend(log_notes)
        result["access_log_hits"] = [
            {"file": f, "line": n, "text": t} for f, n, t in hits
        ]
        if hits:
            result["detail"] += (
                "; %d access-log line(s) carry the traversal pattern "
                "in a datastore upload request or mention a Python "
                "startup hook — investigate, patching alone does not "
                "evict an attacker who already got in" % len(hits))
    ioc_path = entry.get("ioc_dir")
    if ioc_path:
        hits, ioc_notes = scan_ioc_dir(ioc_path)
        notes.extend(ioc_notes)
        result["ioc_hits"] = [
            {"file": f, "looks_legit": legit} for f, legit in hits
        ]
        suspicious = [f for f, legit in hits if not legit]
        if suspicious:
            result["detail"] += (
                "; %d suspicious Python startup hook file(s) under %s "
                "(%s) — the published attack chain plants exactly "
                "this; investigate before returning the server to "
                "service" % (len(suspicious), ioc_path,
                             ", ".join(suspicious[:3])))
    return result


def worst_verdict(results):
    """The fleet verdict is the worst of its members."""
    order = {"VULNERABLE": 0, "UNKNOWN": 1, "FIXED": 2}
    return min(results, key=lambda r: order.get(r["verdict"], 1))["verdict"]


def print_result(result, as_json=False):
    """One result, human or machine readable."""
    if as_json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return
    print("[%s] %s" % (result["verdict"], result["host"]))
    if "version" in result:
        print("  version: %s" % result["version"])
    print("  %s" % result["detail"])
    for note in result.get("notes", []):
        print("  note: %s" % note)
    for hit in result.get("access_log_hits", []):
        print("  log hit %s:%s: %s" % (hit["file"], hit["line"], hit["text"]))
    for hit in result.get("ioc_hits", []):
        print("  ioc %s%s" % (hit["file"],
                              "" if hit["looks_legit"] else " (SUSPICIOUS — not in site-packages)"))


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Detection-only triage for MONAI Label %s (CVSS %s). "
                    "Grades the installed package version against the %s "
                    "fix. Never sends payloads."
                    % (CVE_MAIN, CVSS, FIXED_LABEL))
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--version", metavar="VERSION",
                       help="grade a version string, e.g. 0.8.5")
    group.add_argument("--version-file", metavar="FILE",
                       help="read the version from a file (first line)")
    group.add_argument("--url", metavar="URL",
                       help="grade a live server from one GET of /info/ "
                            "(default port %d)" % DEFAULT_PORT)
    group.add_argument("--local", nargs="?", const=True, metavar="DIR",
                       help="grade the installed package on this box, or "
                            "a site-packages / dist-info / checkout dir")
    group.add_argument("--docker", action="store_true",
                       help="grade projectmonai/monailabel images in "
                            "local Docker")
    group.add_argument("--inventory-json", metavar="FILE",
                       help="grade a fleet from a JSON list of entries")
    group.add_argument("--list", action="store_true",
                       help="print the fixed-version table and exit")
    parser.add_argument("--auth-enabled", action="store_true",
                        help="this server has authentication enabled "
                             "(narrows the hole to annotator-role users)")
    parser.add_argument("--access-log", metavar="PATH",
                       help="grep an access log (file or dir of .log) for "
                            "the traversal pattern in datastore uploads")
    parser.add_argument("--ioc-dir", metavar="PATH",
                        help="hunt a directory tree for rogue Python "
                             "startup hooks (sitecustomize.py)")
    parser.add_argument("--json", action="store_true",
                        help="machine-readable output")
    args = parser.parse_args(argv)

    if args.list:
        print("%s — %s — %s" % (PRODUCT, CVE_MAIN, CVSS))
        print("affected: %s 0.8.5 and earlier" % PRODUCT)
        print("fixed:    %s %s (released %s; CVE published %s; CISA KEV "
              "due %s)"
              % (PRODUCT, FIXED_LABEL, FIX_RELEASED, CVE_PUBLISHED, KEV_DUE))
        print("needs:    network reachability to the server (auth is off "
              "by default); with auth on, the annotator role")
        print("also:     PUT /session/?uncompress=true tar traversal, "
              "same versions, same fix (PR #1942, no CVE yet)")
        return EXIT_CLEAN

    if args.inventory_json:
        try:
            entries = json.loads(Path(args.inventory_json).read_text())
        except (OSError, ValueError) as exc:
            print("cannot read inventory: %s" % exc, file=sys.stderr)
            return EXIT_USAGE
        if not isinstance(entries, list) or not entries:
            print("inventory must be a non-empty JSON list", file=sys.stderr)
            return EXIT_USAGE
        results = [grade_one(entry) for entry in entries]
        if args.json:
            print(json.dumps(results, indent=2, sort_keys=True))
        else:
            for result in results:
                print_result(result)
        verdict = worst_verdict(results)
        return {"VULNERABLE": EXIT_VULNERABLE, "UNKNOWN": EXIT_UNKNOWN}.get(
            verdict, EXIT_CLEAN)

    entry = {}
    if args.version is not None:
        entry["version"] = args.version
    elif args.version_file is not None:
        try:
            entry["version"] = Path(args.version_file).read_text().splitlines()[0]
        except (OSError, IndexError) as exc:
            print("cannot read version file: %s" % exc, file=sys.stderr)
            return EXIT_USAGE
    elif args.url is not None:
        entry["url"] = args.url
    elif args.local is not None:
        entry["local"] = args.local
    elif args.docker:
        entry["docker"] = True
    entry["host"] = entry.get("url") or entry.get("version") or \
        (str(entry["local"]) if isinstance(entry.get("local"), str) else None) or \
        ("local install" if entry.get("local") else None) or \
        ("docker images" if entry.get("docker") else "?")
    if args.auth_enabled:
        entry["auth_enabled"] = True
    if args.access_log:
        entry["access_log"] = args.access_log
    if args.ioc_dir:
        entry["ioc_dir"] = args.ioc_dir

    result = grade_one(entry)
    print_result(result, as_json=args.json)
    return {"VULNERABLE": EXIT_VULNERABLE, "UNKNOWN": EXIT_UNKNOWN}.get(
        result["verdict"], EXIT_CLEAN)


if __name__ == "__main__":
    sys.exit(main())
