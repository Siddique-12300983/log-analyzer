"""The shipped sample files must keep producing the documented findings."""

import pathlib

from loganalyzer.analyzer import analyze
from loganalyzer.parsers import parse_auth_log, parse_windows_csv

SAMPLES = pathlib.Path(__file__).resolve().parent.parent / "samples"


def test_sample_auth_log_flags_brute_force_and_success():
    lines = (SAMPLES / "auth.log").read_text().splitlines()
    findings = analyze(parse_auth_log(lines, year=2026))
    titles = " ".join(f.title for f in findings)
    assert "Brute-force from 203.0.113.45" in titles
    assert "successful brute-force from 203.0.113.45" in titles


def test_sample_windows_csv_flags_kerberoasting():
    lines = (SAMPLES / "windows-security-events.csv").read_text().splitlines()
    findings = analyze(parse_windows_csv(lines))
    titles = " ".join(f.title for f in findings)
    assert "RC4 service ticket" in titles
    assert "SPN fan-out" in titles
    assert "Brute-force from 10.10.10.30" in titles
