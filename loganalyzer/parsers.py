"""Parsers that turn raw log files into AuthEvent objects."""

from __future__ import annotations

import csv
import re
from datetime import datetime
from typing import Iterable, List, Optional

from .model import (
    ACCEPTED_LOGIN,
    FAILED_LOGIN,
    INVALID_USER,
    KERBEROS_TGS,
    AuthEvent,
)

# ---------------------------------------------------------------------------
# Linux auth.log
# ---------------------------------------------------------------------------

# syslog month names to numbers; auth.log has no year, so we add one ourselves.
_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

_SYSLOG_TS = re.compile(r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s")

_FAILED = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
_ACCEPTED = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
_INVALID = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)


def _syslog_timestamp(line: str, year: int) -> Optional[datetime]:
    m = _SYSLOG_TS.match(line)
    if not m:
        return None
    hour, minute, second = (int(x) for x in m.group("time").split(":"))
    return datetime(year, _MONTHS[m.group("mon")], int(m.group("day")), hour, minute, second)


def parse_auth_log(lines: Iterable[str], year: Optional[int] = None) -> List[AuthEvent]:
    """Parse OpenSSH lines from a Linux auth.log.

    auth.log does not record the year, so pass one in; it defaults to the
    current year, which is what you want for a live log.
    """
    if year is None:
        year = datetime.now().year

    events: List[AuthEvent] = []
    for line in lines:
        line = line.rstrip("\n")
        if "sshd" not in line:
            continue
        ts = _syslog_timestamp(line, year)
        if ts is None:
            continue

        m = _FAILED.search(line)
        if m:
            events.append(AuthEvent(ts, "auth.log", FAILED_LOGIN,
                                    user=m.group("user"), src_ip=m.group("ip"), raw=line))
            continue

        m = _ACCEPTED.search(line)
        if m:
            events.append(AuthEvent(ts, "auth.log", ACCEPTED_LOGIN,
                                    user=m.group("user"), src_ip=m.group("ip"), raw=line))
            continue

        m = _INVALID.search(line)
        if m:
            events.append(AuthEvent(ts, "auth.log", INVALID_USER,
                                    user=m.group("user"), src_ip=m.group("ip"), raw=line))
    return events


# ---------------------------------------------------------------------------
# Windows Security event CSV export
# ---------------------------------------------------------------------------

# A CSV exported from Event Viewer / Get-WinEvent. We read these columns by name
# and ignore the rest, so extra columns in a real export do no harm.
#   TimeCreated, EventID, TargetUserName, IpAddress, ServiceName, TicketEncryptionType
_WIN_TS_FORMATS = (
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%d/%m/%Y %H:%M:%S",
    "%m/%d/%Y %I:%M:%S %p",
)


def _win_timestamp(value: str) -> Optional[datetime]:
    value = (value or "").strip()
    for fmt in _WIN_TS_FORMATS:
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    return None


def _clean(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    value = value.strip()
    # Windows writes "-" for an empty field.
    return None if value in ("", "-") else value


def parse_windows_csv(lines: Iterable[str]) -> List[AuthEvent]:
    """Parse a Windows Security log exported to CSV.

    Recognised events:
      4625  failed logon         -> FAILED_LOGIN
      4624  successful logon     -> ACCEPTED_LOGIN
      4769  Kerberos service ticket requested -> KERBEROS_TGS
    """
    events: List[AuthEvent] = []
    reader = csv.DictReader(lines)
    for row in reader:
        event_id = _clean(row.get("EventID"))
        ts = _win_timestamp(row.get("TimeCreated", ""))
        if event_id is None or ts is None:
            continue

        user = _clean(row.get("TargetUserName"))
        ip = _clean(row.get("IpAddress"))

        if event_id == "4625":
            events.append(AuthEvent(ts, "winsec", FAILED_LOGIN, user=user, src_ip=ip,
                                    raw=f"4625 {user} {ip}"))
        elif event_id == "4624":
            events.append(AuthEvent(ts, "winsec", ACCEPTED_LOGIN, user=user, src_ip=ip,
                                    raw=f"4624 {user} {ip}"))
        elif event_id == "4769":
            events.append(AuthEvent(
                ts, "winsec", KERBEROS_TGS,
                user=user, src_ip=ip,
                service=_clean(row.get("ServiceName")),
                enc_type=(_clean(row.get("TicketEncryptionType")) or "").lower() or None,
                raw=f"4769 {user} {row.get('ServiceName')}"))
    return events
