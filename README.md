# `monai-label-scanner`

Detection-only triage for `CVE-2026-133968`, the path traversal with resultant remote code execution in `MONAI Label` (Project MONAI) that `Amazon Threat Intelligence` reported on `2026-11-20` — and that `CISA` added to its `Known Exploited Vulnerabilities` catalog on `2026-11-23`, due `2026-11-26`. Grades your installed package version against the fixed release, fingerprints a live server from the info it already discloses, and hunts your logs and datastore for the compromise signs from the published attack chain. Nothing here sends a payload, requests a crafted path, or uploads a file.

## `What it checks`

* `CVE-2026-133968` — `PUT /datastore/image` takes the caller-supplied `image` value and uses it as the file name without checking that the path it builds stays inside the datastore; `PUT /datastore/label` does the same with the image ID and the label tag. The vendor advisory uses `../../../tmp/x` as the example value. Authentication is disabled by default (`MONAI_LABEL_AUTH_ENABLE=False`), so on a default install any client that can reach the server — default port `8000` — can write files anywhere the server process can write, with no login at all. With authentication on, any user holding the annotator role can still do it. `CVSS 3.1 9.8` (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`), `CWE-22` (path traversal). The affected conditions ship enabled by default and need no configuration — but the server must be reachable, and it must use the built-in local datastore (the default). A server behind auth with no annotator-role accounts is narrowed, not fixed.

Fixed version, per the vendor (primary source):

| `Build` | `Upgrade to` |
| --- | --- |
| `MONAI Label 0.8.5` and earlier | `0.8.6` (or later) |

* The second traversal, same release, no `CVE` yet. `PUT /session/?uncompress=true` unpacked uploaded tar archives without checking member names, and used session IDs as paths without validation. Same versions affected (`0.8.5` and earlier), same fix (`0.8.6`, `PR #1942`). This scanner flags it in the same verdict rather than pretending it is a separate problem.

There is no workaround that keeps the server exposed. Enable authentication, take the server off untrusted networks, run it as an unprivileged user — and upgrade to `0.8.6`.

## `Usage`

```bash
# grade a version string
python3 monai_label_scanner.py --version "0.8.5"
python3 monai_label_scanner.py --version "0.8.6"

# the box that runs the server (reads installed package metadata)
python3 monai_label_scanner.py --local
python3 monai_label_scanner.py --local /path/to/site-packages

# a live server: one plain GET of /info/, nothing else
python3 monai_label_scanner.py --url http://192.168.1.10:8000

# Docker images on this box
python3 monai_label_scanner.py --docker

# hunt the access logs for the traversal pattern in upload requests
python3 monai_label_scanner.py --version "0.8.5" --access-log /var/log/nginx/access.log

# hunt a datastore / server tree for rogue Python startup hooks
python3 monai_label_scanner.py --version "0.8.5" --ioc-dir /data/monailabel

# a whole fleet at once
python3 monai_label_scanner.py --inventory-json fleet.json

# machine output / the fixed-version table
python3 monai_label_scanner.py --version "0.8.5" --json
python3 monai_label_scanner.py --list
```

`--url` `GET`s `/info/` and reads the app info dict the server itself exposes — `name`, `models`, `datastore` status. It also tells you whether authentication is on (a `401`/`403` on `/info/`). `--local` reads the installed `monailabel` package version from metadata, or from a `dist-info` directory you point it at. `--docker` grades every `projectmonai/monailabel` image tag on the box. `--access-log` greps for dot-dot segments (plain or percent-encoded) in `/datastore/image` and `/datastore/label` requests, and for `sitecustomize.py` mentions. `--ioc-dir` walks a tree for `sitecustomize.py` / `usercustomize.py` — the published attack chain plants exactly that file, then calls a training endpoint to spawn a fresh `Python` process.

Exit codes: `0` patched / no hits, `1` vulnerable or hits found, `2` unknown, `3` usage error.

## `Traps`

* The no-fix trap. Write-ups from `20-21 Nov 2026` say "no fixed release exists" — that was true for about 36 hours and is stale now. `0.8.6` shipped on `22 Nov` (PyPI `01:27 UTC`, Docker `01:39 UTC`). This scanner grades against the vendor release, not the tracker lag.
* The `0.8.5` trap. `0.8.5` is the last vulnerable release, one patch behind the fix, and it was the newest release for two years (`Nov 2024` to `Nov 2026`). "Latest before the `CVE`" is not "patched". This scanner says so out loud.
* The app-version trap. `/info/` returns the *app* version (default `"2.0"`), not the `monailabel` package version — and no public endpoint discloses the package version. Grading `"2.0"` as a package version would call a vulnerable server fixed. This scanner never grades it: `--url` reports exposure and auth state, and tells you to prove the package version locally with `--local` or `pip show monailabel`.
* The auth trap. Authentication narrows the hole to annotator-role users, it does not close it — the annotator role can still call both upload endpoints on a `<= 0.8.5` server. A server with auth on and an old version is still vulnerable; `--url` grades it `UNKNOWN` (version not visible from outside) and tells you to grade it locally.
* The custom-prefix trap. If a deployment sets `MONAI_LABEL_API_STR`, the info endpoint moves off `/info/` and this probe returns `404` and grades `UNKNOWN`. Pass the full base URL with the prefix, or grade locally.
* The patch-is-not-enough trap. Patching closes the hole, it does not undo a break-in. This is unauthenticated `RCE` with a published attack chain and confirmed exploitation, so a vulnerable install may already be owned. Patch, then hunt for rogue `sitecustomize.py` files and unexpected files under your datastore, and review the server for unexpected file changes before returning it to service — the vendor's own release notes say exactly that. `--ioc-dir` checks the published persistence file for you, and no hits in the places checked is not a clean bill — attackers clean up.
* The `AI` trap. This one was found by autonomous agents, not a human: `Cairn` agents went from API mapping to arbitrary file write in about 11 minutes. The lesson is not about `AI`, it is about exposure — a medical-imaging server with auth off and a world-reachable port is a soft target for anything that can send `HTTP` requests. Take it off untrusted networks.

## `Sources`

* Project MONAI release `0.8.6` (`22 Nov 2026`, primary source for the fix, the affected range `<= 0.8.5`, the mechanism, and the second session-upload flaw `PR #1942`)
* Project MONAI advisory `GHSA-qc22-rmgc-vg94` (published `18 Nov 2026`, primary source for the `PUT /datastore/image` and `/datastore/label` mechanism and the `../../../tmp/x` example)
* `CVE-2026-133968` record, `MITRE` (CNA), published `20 Nov 2026` (primary source for the `9.8` rating, the vector, and "exploited in the wild starting in September 2026")
* `Amazon Threat Intelligence` (`20 Nov 2026`, primary source for the exploitation: `Cairn` agents, ~11 minutes to arbitrary file write, `sitecustomize.py` reverse shell, root via a training endpoint, campaign `8-10 Sep 2026` against East Asian universities)
* `CISA KEV` catalog version `2026.11.23` (added `23 Nov 2026`, due `26 Nov 2026`; corroborated by the `23 Nov` threat briefs and the `KEV` trackers — one tracker page checked earlier on the 23rd still showed it absent, which is a timing artefact of the catalog update, not a disagreement about the listing)
* `MONAILabel` source, tag `0.8.5` vs `main` (read directly: `0.8.5` uses the raw `image` value as the file name in `add_image` and `save_label`; `main` reduces it with `os.path.basename` and rejects empty or dot-prefixed IDs with `HTTP 400`, and confines the write with `_confine_path`; `MONAI_LABEL_AUTH_ENABLE` defaults to `False`, `MONAI_LABEL_API_STR` defaults to `""`, default port `8000`)

Where sources disagree, this scanner follows the vendor release and the `CVE` record and says so. The one live disagreement is the `CWE`: the `CVE` record and advisory say `CWE-22`, some aggregators say `CWE-24` — same weakness family, same fix, no effect on the verdict.

## `Related work`

A `nuclei` template for `CVE-2026-133968` exists in `projectdiscovery/nuclei-templates` (a single detection probe), and the `CVE` has a `Sigma` rule and `SIEM` hunting queries in circulation. This tool is the defensive counterpart that covers what a single probe does not: version grading from `pip` / `Docker` / local installs, exposure and auth-state fingerprinting of a live server, the second session-upload flaw in the same verdict, and the `sitecustomize.py` IOC hunt from the published attack chain — all without sending exploit traffic. No `foxcornlab` scanner covered `MONAI Label` before this one.

## `Thanks to`

* Project MONAI — for the advisory that names the flaw plainly, the `0.8.6` security release two days after the `CVE` record, and the release notes that tell operators to hunt before returning a server to service
* `Amazon Threat Intelligence` — for publishing the campaign reconstruction, including the 11-minute timeline and the `sitecustomize.py` persistence detail defenders can actually hunt for
* The `MONAILabel` maintainers who merged `PR #1915` on `19 Oct 2026`, a month before the `CVE` record existed

Educational and defensive use only. This tool detects exposure, it does not exploit anything. If you run `MONAI Label`, update it to `0.8.6` — then hunt, because patching alone does not evict an attacker who already ran code on your box.

> Research by `Vineeth Kumar` (`foxcornlab`). Found a bug or want a feature, open an `issue`.
