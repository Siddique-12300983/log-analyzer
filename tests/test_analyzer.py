from datetime import datetime, timedelta

from loganalyzer.analyzer import (
    analyze,
    detect_brute_force,
    detect_kerberoasting,
    detect_successful_after_failures,
)
from loganalyzer.model import (
    ACCEPTED_LOGIN,
    FAILED_LOGIN,
    KERBEROS_TGS,
    AuthEvent,
)

BASE = datetime(2026, 10, 24, 10, 0, 0)


def failed(ip, offset, user="root"):
    return AuthEvent(BASE + timedelta(seconds=offset), "auth.log", FAILED_LOGIN,
                     user=user, src_ip=ip)


def accepted(ip, offset, user="deploy"):
    return AuthEvent(BASE + timedelta(seconds=offset), "auth.log", ACCEPTED_LOGIN,
                     user=user, src_ip=ip)


def tgs(user, offset, service, enc):
    return AuthEvent(BASE + timedelta(seconds=offset), "winsec", KERBEROS_TGS,
                     user=user, service=service, enc_type=enc)


def test_brute_force_fires_above_threshold_in_window():
    events = [failed("10.0.0.1", i) for i in range(6)]
    findings = detect_brute_force(events, threshold=5, window_seconds=60)
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert "10.0.0.1" in findings[0].title


def test_brute_force_quiet_below_threshold():
    events = [failed("10.0.0.1", i) for i in range(4)]
    assert detect_brute_force(events, threshold=5, window_seconds=60) == []


def test_brute_force_respects_time_window():
    # Six failures, but spread 120s apart, so no 60s window holds five.
    events = [failed("10.0.0.1", i * 120) for i in range(6)]
    assert detect_brute_force(events, threshold=5, window_seconds=60) == []


def test_successful_after_failures():
    events = [failed("10.0.0.1", i) for i in range(5)]
    events.append(accepted("10.0.0.1", 30, user="deploy"))
    findings = detect_successful_after_failures(events, min_failures=5)
    assert len(findings) == 1
    assert "deploy" in findings[0].detail


def test_no_success_finding_when_few_failures():
    events = [failed("10.0.0.1", 0), accepted("10.0.0.1", 10)]
    assert detect_successful_after_failures(events, min_failures=5) == []


def test_kerberoasting_rc4_ticket():
    events = [tgs("jack", 0, "MSSQLSvc/sql01:1433", "0x17")]
    findings = detect_kerberoasting(events)
    assert any("RC4" in f.title for f in findings)
    assert findings[0].severity == "high"


def test_kerberoasting_aes_single_spn_is_quiet():
    events = [tgs("jack", 0, "MSSQLSvc/sql01:1433", "0x12")]
    assert detect_kerberoasting(events) == []


def test_kerberoasting_spn_fanout_even_with_aes():
    events = [
        tgs("jack", 0, "MSSQLSvc/sql01:1433", "0x12"),
        tgs("jack", 1, "HTTP/web01", "0x12"),
        tgs("jack", 2, "CIFS/fs01", "0x12"),
    ]
    findings = detect_kerberoasting(events, spn_fanout=3)
    assert len(findings) == 1
    assert "fan-out" in findings[0].title
    assert findings[0].severity == "medium"


def test_analyze_sorts_high_before_medium():
    events = [
        tgs("jack", 0, "a", "0x12"),
        tgs("jack", 1, "b", "0x12"),
        tgs("jack", 2, "c", "0x17"),  # RC4 -> high
    ]
    findings = analyze(events, spn_fanout=3)
    assert findings[0].severity == "high"
    assert findings[-1].severity == "medium"
