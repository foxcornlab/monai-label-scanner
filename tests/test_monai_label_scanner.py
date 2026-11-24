"""Tests for monai_label_scanner.py.

Everything runs against local fixtures: a synthetic dist-info tree,
a mock MONAI Label server on localhost, synthetic access logs and a
synthetic datastore tree. No real MONAI Label server is touched, and
no payload is ever sent — the remote probe is one plain GET of
/info/, the same request a browser or a health check would make.
"""

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import monai_label_scanner as scanner

# ---------------------------------------------------------------- version

GRADE_CASES = [
    # (version string, expected verdict)
    ("0.8.5", "VULNERABLE"),   # last vulnerable release, one patch behind
    ("0.8.4", "VULNERABLE"),
    ("0.8.0", "VULNERABLE"),
    ("0.1.0", "VULNERABLE"),   # NVD range starts at the beginning
    ("0.8", "VULNERABLE"),     # bare 0.8 == 0.8.0
    ("0", "VULNERABLE"),
    ("0.8.6", "FIXED"),        # first fixed release, shipped 22 Nov 2026
    ("0.8.7", "FIXED"),
    ("0.9.0", "FIXED"),
    ("1.0.0", "FIXED"),
    ("banana", "UNKNOWN"),
    ("", "UNKNOWN"),
]


@pytest.mark.parametrize("raw,expected", GRADE_CASES)
def test_grade_versions(raw, expected):
    verdict, _detail = scanner.grade(scanner.parse_version(raw))
    assert verdict == expected, raw


def test_grade_none_is_unknown():
    assert scanner.grade(None)[0] == "UNKNOWN"


def test_parse_version_tolerates_suffixes():
    assert scanner.parse_version("0.8.5.1") == (0, 8, 5)
    assert scanner.parse_version("0.8.6rc1") == (0, 8, 6)
    assert scanner.parse_version("v0.8.5") == (0, 8, 5)
    assert scanner.parse_version("0.8.6+g1234abc") == (0, 8, 6)


def test_0_8_5_trap_names_it_last_vulnerable():
    _verdict, detail = scanner.grade(scanner.parse_version("0.8.5"))
    assert "last vulnerable" in detail
    assert "two years" in detail


def test_fixed_detail_names_the_fix_date():
    _verdict, detail = scanner.grade(scanner.parse_version("0.8.6"))
    assert "2026-11-22" in detail


def test_auth_enabled_narrows_but_does_not_close():
    verdict, detail = scanner.grade(
        scanner.parse_version("0.8.5"), auth_enabled=True)
    assert verdict == "VULNERABLE"
    assert "annotator" in detail
    assert "does not close it" in detail


def test_auth_off_detail_says_disabled_by_default():
    _verdict, detail = scanner.grade(scanner.parse_version("0.8.5"))
    assert "disabled by default" in detail


def test_fixed_with_auth_is_still_fixed():
    verdict, _detail = scanner.grade(
        scanner.parse_version("0.8.6"), auth_enabled=True)
    assert verdict == "FIXED"


# ------------------------------------------------------- local install

def test_read_local_install_from_dist_info(tmp_path):
    dist_info = tmp_path / "monailabel-0.8.5.dist-info"
    dist_info.mkdir()
    (dist_info / "METADATA").write_text(
        "Metadata-Version: 2.1\nName: monailabel\nVersion: 0.8.5\n")
    version, notes = scanner.read_local_install(str(tmp_path))
    assert version == (0, 8, 5)
    assert notes == []


def test_read_local_install_fixed_version(tmp_path):
    dist_info = tmp_path / "monailabel-0.8.6.dist-info"
    dist_info.mkdir()
    (dist_info / "METADATA").write_text(
        "Metadata-Version: 2.1\nName: monailabel\nVersion: 0.8.6\n")
    version, _notes = scanner.read_local_install(str(tmp_path))
    assert scanner.grade(version)[0] == "FIXED"


def test_read_local_install_missing_dir(tmp_path):
    version, notes = scanner.read_local_install(str(tmp_path / "nope"))
    assert version is None
    assert notes


def test_read_local_install_source_checkout_has_no_metadata(tmp_path):
    pkg = tmp_path / "monailabel"
    pkg.mkdir()
    (pkg / "__init__.py").write_text('__version__ = "0.8.5"\n')
    version, notes = scanner.read_local_install(str(tmp_path))
    assert version is None
    assert "no installed metadata" in notes[0]


def test_read_metadata_file_unparseable(tmp_path):
    meta = tmp_path / "METADATA"
    meta.write_text("Metadata-Version: 2.1\nName: monailabel\n")
    version, notes = scanner.read_metadata_file(str(meta))
    assert version is None
    assert notes


# ------------------------------------------------------- mock servers

INFO_BODY = {
    "name": "radiology",
    "description": "test app",
    "version": "2.0",
    "labels": ["spleen"],
    "models": {},
    "trainers": {},
    "strategies": {"random": {}},
    "scoring": {},
    "train_stats": {},
    "datastore": {"total": 3, "completed": 1, "label_tags": {"final": 1}},
}


def make_handler(mode):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            if mode == "auth-on":
                self._send(401, b'{"detail": "Not authenticated"}')
            elif mode == "not-monai":
                self._send(200, b'{"hello": "world"}')
            elif mode == "wrong-path":
                self._send(404, b'{"detail": "Not Found"}')
            else:  # vulnerable server, auth off, default install
                self._send(200, json.dumps(INFO_BODY).encode())

        def _send(self, status, body):
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return Handler


def run_mock_server(mode):
    server = HTTPServer(("127.0.0.1", 0), make_handler(mode))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, "http://127.0.0.1:%d" % server.server_address[1]


def test_probe_vulnerable_server_grades_exposed():
    server, base = run_mock_server("vulnerable")
    try:
        verdict, detail, notes = scanner.probe_url(base)
    finally:
        server.shutdown()
    assert verdict == "VULNERABLE"
    assert "authentication disabled" in detail
    assert "prove 0.8.6+" in detail
    assert any("app version" in n for n in notes)


def test_probe_never_grades_the_app_version():
    # /info/ reports app version "2.0". Grading that as a package
    # version would wrongly call the server FIXED. The probe must
    # not do that: the verdict comes from exposure, and the notes
    # must say the app version is not graded.
    server, base = run_mock_server("vulnerable")
    try:
        verdict, _detail, notes = scanner.probe_url(base)
    finally:
        server.shutdown()
    assert verdict == "VULNERABLE"
    assert any("never" in n and "graded" in n for n in notes)


def test_probe_auth_on_is_unknown():
    server, base = run_mock_server("auth-on")
    try:
        verdict, detail, _notes = scanner.probe_url(base)
    finally:
        server.shutdown()
    assert verdict == "UNKNOWN"
    assert "annotator" in detail


def test_probe_not_monai_is_unknown():
    server, base = run_mock_server("not-monai")
    try:
        verdict, _detail, _notes = scanner.probe_url(base)
    finally:
        server.shutdown()
    assert verdict == "UNKNOWN"


def test_probe_404_is_unknown():
    server, base = run_mock_server("wrong-path")
    try:
        verdict, detail, _notes = scanner.probe_url(base)
    finally:
        server.shutdown()
    assert verdict == "UNKNOWN"
    assert "API_STR" in detail


def test_probe_unreachable_is_unknown():
    verdict, detail, _notes = scanner.probe_url("http://127.0.0.1:1")
    assert verdict == "UNKNOWN"
    assert "could not reach" in detail


def test_looks_like_monai_label_requires_datastore_keys():
    assert scanner.looks_like_monai_label(json.dumps(INFO_BODY))
    assert not scanner.looks_like_monai_label('{"name": "x"}')
    assert not scanner.looks_like_monai_label('not json')
    assert not scanner.looks_like_monai_label(
        json.dumps({"name": "x", "models": {}, "datastore": {}}))


# ------------------------------------------------------- access logs

LOG_LINES = [
    '10.0.0.1 - - [24/Nov/2026:09:00:00 +0000] "GET /info/ HTTP/1.1" 200 512',
    '10.0.0.2 - - [24/Nov/2026:09:01:00 +0000] "PUT /datastore/image?image=scan001 HTTP/1.1" 200 64',
    '10.0.0.3 - - [24/Nov/2026:09:02:00 +0000] "PUT /datastore/image?image=..%2F..%2F..%2Ftmp%2Fx HTTP/1.1" 200 64',
    '10.0.0.4 - - [24/Nov/2026:09:03:00 +0000] "PUT /datastore/label?image=..%2F..%2Fsitecustomize&tag=final HTTP/1.1" 200 64',
    '10.0.0.5 - - [24/Nov/2026:09:04:00 +0000] "GET /datastore/image?image=..%2F..%2Fetc%2Fpasswd HTTP/1.1" 404 32',
]


def test_scan_access_log_flags_traversal_uploads(tmp_path):
    log = tmp_path / "access.log"
    log.write_text("\n".join(LOG_LINES) + "\n")
    hits, _notes = scanner.scan_access_log(str(log))
    assert len(hits) == 3
    assert hits[0][1] == 3
    assert hits[1][1] == 4
    assert hits[2][1] == 5


def test_scan_access_log_clean_log_has_no_hits(tmp_path):
    log = tmp_path / "access.log"
    log.write_text("\n".join(LOG_LINES[:2]) + "\n")
    hits, _notes = scanner.scan_access_log(str(log))
    assert hits == []


def test_scan_access_log_directory(tmp_path):
    (tmp_path / "a.log").write_text(LOG_LINES[2] + "\n")
    (tmp_path / "b.log").write_text(LOG_LINES[0] + "\n")
    (tmp_path / "notes.txt").write_text(LOG_LINES[2] + "\n")
    hits, _notes = scanner.scan_access_log(str(tmp_path))
    assert len(hits) == 1
    assert hits[0][0].endswith("a.log")


def test_scan_access_log_missing_path(tmp_path):
    hits, notes = scanner.scan_access_log(str(tmp_path / "nope.log"))
    assert hits == []
    assert notes


# ------------------------------------------------------- IOC hunt

def test_scan_ioc_dir_finds_startup_hook(tmp_path):
    datastore = tmp_path / "studies"
    datastore.mkdir()
    (datastore / "sitecustomize.py").write_text("# planted\n")
    hits, _notes = scanner.scan_ioc_dir(str(tmp_path))
    assert len(hits) == 1
    assert hits[0][0].endswith("sitecustomize.py")
    assert hits[0][1] is False  # not in site-packages: suspicious


def test_scan_ioc_dir_legit_site_packages_flagged_legit(tmp_path):
    venv = tmp_path / "venv" / "lib" / "python3.12" / "site-packages"
    venv.mkdir(parents=True)
    (venv / "sitecustomize.py").write_text("# legit\n")
    hits, _notes = scanner.scan_ioc_dir(str(tmp_path))
    assert len(hits) == 1
    assert hits[0][1] is True


def test_scan_ioc_dir_clean_tree(tmp_path):
    (tmp_path / "scan001.nii.gz").write_text("fake nifti")
    hits, _notes = scanner.scan_ioc_dir(str(tmp_path))
    assert hits == []


def test_scan_ioc_dir_missing_path(tmp_path):
    hits, notes = scanner.scan_ioc_dir(str(tmp_path / "nope"))
    assert hits == []
    assert notes


# ------------------------------------------------------- grade_one / CLI

def test_grade_one_version_entry():
    result = scanner.grade_one({"version": "0.8.5"})
    assert result["verdict"] == "VULNERABLE"
    assert result["version"] == "0.8.5"


def test_grade_one_url_entry():
    server, base = run_mock_server("vulnerable")
    try:
        result = scanner.grade_one({"url": base})
    finally:
        server.shutdown()
    assert result["verdict"] == "VULNERABLE"


def test_grade_one_with_log_hits_appends_detail(tmp_path):
    log = tmp_path / "access.log"
    log.write_text(LOG_LINES[2] + "\n")
    result = scanner.grade_one({"version": "0.8.5",
                                "access_log": str(log)})
    assert result["verdict"] == "VULNERABLE"
    assert len(result["access_log_hits"]) == 1
    assert "access-log" in result["detail"]


def test_grade_one_with_suspicious_ioc_appends_detail(tmp_path):
    (tmp_path / "sitecustomize.py").write_text("# planted\n")
    result = scanner.grade_one({"version": "0.8.6",
                                "ioc_dir": str(tmp_path)})
    assert result["verdict"] == "FIXED"
    assert "suspicious Python startup hook" in result["detail"]


def test_grade_one_empty_entry_is_unknown():
    result = scanner.grade_one({})
    assert result["verdict"] == "UNKNOWN"


def test_worst_verdict():
    assert scanner.worst_verdict(
        [{"verdict": "FIXED"}, {"verdict": "VULNERABLE"}]) == "VULNERABLE"
    assert scanner.worst_verdict(
        [{"verdict": "FIXED"}, {"verdict": "UNKNOWN"}]) == "UNKNOWN"
    assert scanner.worst_verdict([{"verdict": "FIXED"}]) == "FIXED"


def test_main_list_exits_clean(capsys):
    assert scanner.main(["--list"]) == 0
    assert "0.8.6" in capsys.readouterr().out


def test_main_version_vulnerable_exits_1(capsys):
    assert scanner.main(["--version", "0.8.5"]) == 1
    assert "[VULNERABLE]" in capsys.readouterr().out


def test_main_version_fixed_exits_0(capsys):
    assert scanner.main(["--version", "0.8.6"]) == 0
    assert "[FIXED]" in capsys.readouterr().out


def test_main_version_unknown_exits_2(capsys):
    assert scanner.main(["--version", "banana"]) == 2
    assert "[UNKNOWN]" in capsys.readouterr().out


def test_main_json_output(capsys):
    assert scanner.main(["--version", "0.8.5", "--json"]) == 1
    data = json.loads(capsys.readouterr().out)
    assert data["verdict"] == "VULNERABLE"
    assert data["version"] == "0.8.5"
