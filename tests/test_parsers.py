from datetime import datetime

from loganalyzer.model import ACCEPTED_LOGIN, FAILED_LOGIN, INVALID_USER, KERBEROS_TGS
from loganalyzer.parsers import parse_auth_log, parse_windows_csv


def test_parse_failed_password_with_ip_and_user():
    line = "Oct 24 10:15:02 web01 sshd[2203]: Failed password for root from 203.0.113.45 port 51010 ssh2"
    (event,) = parse_auth_log([line], year=2026)
    assert event.event_type == FAILED_LOGIN
    assert event.user == "root"
    assert event.src_ip == "203.0.113.45"
    assert event.timestamp == datetime(2026, 10, 24, 10, 15, 2)


def test_parse_failed_password_invalid_user_strips_prefix():
    line = "Oct 24 10:15:00 web01 sshd[2201]: Failed password for invalid user admin from 203.0.113.45 port 51002 ssh2"
    (event,) = parse_auth_log([line], year=2026)
    assert event.event_type == FAILED_LOGIN
    assert event.user == "admin"
    assert event.src_ip == "203.0.113.45"


def test_parse_accepted_publickey():
    line = "Oct 24 18:20:05 web01 sshd[4502]: Accepted publickey for deploy from 198.51.100.7 port 44512 ssh2"
    (event,) = parse_auth_log([line], year=2026)
    assert event.event_type == ACCEPTED_LOGIN
    assert event.user == "deploy"


def test_parse_invalid_user_line():
    line = "Oct 24 10:14:59 web01 sshd[2200]: Invalid user admin from 203.0.113.45 port 51000 ssh2"
    (event,) = parse_auth_log([line], year=2026)
    assert event.event_type == INVALID_USER


def test_non_ssh_lines_are_ignored():
    lines = [
        "Oct 24 10:00:00 web01 systemd[1]: Started Session 3 of user deploy.",
        "Oct 24 10:00:01 web01 sudo: deploy : TTY=pts/0 ; PWD=/home ; USER=root",
    ]
    assert parse_auth_log(lines, year=2026) == []


def test_windows_csv_event_ids():
    rows = [
        "TimeCreated,EventID,TargetUserName,IpAddress,ServiceName,TicketEncryptionType,LogonType",
        "2026-10-24 10:31:00,4625,administrator,10.10.10.30,-,-,3",
        "2026-10-24 12:15:40,4624,deploy,10.10.10.20,-,-,2",
        "2026-10-24 11:05:22,4769,jack.wilson,10.10.10.20,MSSQLSvc/sql01:1433,0x17,-",
    ]
    events = parse_windows_csv(rows)
    kinds = [e.event_type for e in events]
    assert kinds == [FAILED_LOGIN, ACCEPTED_LOGIN, KERBEROS_TGS]
    tgs = events[2]
    assert tgs.enc_type == "0x17"
    assert tgs.service == "MSSQLSvc/sql01:1433"


def test_windows_csv_blank_fields_become_none():
    rows = [
        "TimeCreated,EventID,TargetUserName,IpAddress,ServiceName,TicketEncryptionType,LogonType",
        "2026-10-24 10:31:00,4625,administrator,-,-,-,3",
    ]
    (event,) = parse_windows_csv(rows)
    assert event.src_ip is None


def test_windows_csv_unknown_event_id_skipped():
    rows = [
        "TimeCreated,EventID,TargetUserName,IpAddress,ServiceName,TicketEncryptionType,LogonType",
        "2026-10-24 10:31:00,4688,administrator,10.10.10.30,-,-,3",
    ]
    assert parse_windows_csv(rows) == []
