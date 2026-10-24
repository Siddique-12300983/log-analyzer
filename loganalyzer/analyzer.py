"""Turn a stream of AuthEvents into findings."""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from typing import Dict, List, Sequence

from .model import (
    ACCEPTED_LOGIN,
    FAILED_LOGIN,
    INVALID_USER,
    KERBEROS_TGS,
    AuthEvent,
    Finding,
)

# RC4 ticket encryption on a 4769. On a modern AES domain this is unusual and a
# classic Kerberoasting indicator. See the note in the README about why AES-only
# domains need behavioural detection as well.
RC4_ENC_TYPES = {"0x17", "0x18", "23", "24"}

# Default thresholds. Tunable from the CLI.
DEFAULT_BRUTE_THRESHOLD = 5
DEFAULT_BRUTE_WINDOW_SECONDS = 60
DEFAULT_SPN_FANOUT = 3


def _max_in_window(timestamps: Sequence, window_seconds: int) -> int:
    """Largest number of timestamps falling inside any window_seconds span."""
    ts = sorted(timestamps)
    window = timedelta(seconds=window_seconds)
    best = 0
    start = 0
    for end in range(len(ts)):
        while ts[end] - ts[start] > window:
            start += 1
        best = max(best, end - start + 1)
    return best


def detect_brute_force(events: Sequence[AuthEvent],
                       threshold: int = DEFAULT_BRUTE_THRESHOLD,
                       window_seconds: int = DEFAULT_BRUTE_WINDOW_SECONDS) -> List[Finding]:
    """Flag source IPs with many failed logins in a short window."""
    by_ip: Dict[str, List] = defaultdict(list)
    for e in events:
        if e.event_type in (FAILED_LOGIN, INVALID_USER) and e.src_ip:
            by_ip[e.src_ip].append(e.timestamp)

    findings: List[Finding] = []
    for ip, stamps in sorted(by_ip.items()):
        peak = _max_in_window(stamps, window_seconds)
        if peak >= threshold:
            findings.append(Finding(
                severity="high",
                title=f"Brute-force from {ip}",
                detail=(f"{len(stamps)} failed logins total, peaking at {peak} "
                        f"within {window_seconds}s (threshold {threshold})."),
            ))
    return findings


def detect_successful_after_failures(events: Sequence[AuthEvent],
                                     min_failures: int = DEFAULT_BRUTE_THRESHOLD) -> List[Finding]:
    """Flag an IP that failed many times and then logged in successfully."""
    failures: Dict[str, int] = defaultdict(int)
    success_users: Dict[str, set] = defaultdict(set)
    for e in sorted(events, key=lambda x: x.timestamp):
        if not e.src_ip:
            continue
        if e.event_type in (FAILED_LOGIN, INVALID_USER):
            failures[e.src_ip] += 1
        elif e.event_type == ACCEPTED_LOGIN and failures[e.src_ip] >= min_failures:
            success_users[e.src_ip].add(e.user or "?")

    findings: List[Finding] = []
    for ip, users in sorted(success_users.items()):
        findings.append(Finding(
            severity="high",
            title=f"Possible successful brute-force from {ip}",
            detail=(f"{failures[ip]} failed logins from {ip} were followed by a "
                    f"successful login as {', '.join(sorted(users))}."),
        ))
    return findings


def detect_kerberoasting(events: Sequence[AuthEvent],
                         spn_fanout: int = DEFAULT_SPN_FANOUT) -> List[Finding]:
    """Flag Kerberoasting indicators in 4769 events.

    Two signals:
      1. RC4-encrypted service tickets (0x17), the classic indicator.
      2. One account requesting tickets for many distinct SPNs, which catches
         the attack even when the tickets are AES.
    """
    findings: List[Finding] = []
    tgs = [e for e in events if e.event_type == KERBEROS_TGS]

    # Signal 1: RC4 tickets.
    for e in tgs:
        if e.enc_type in RC4_ENC_TYPES:
            findings.append(Finding(
                severity="high",
                title="Kerberoasting indicator: RC4 service ticket (4769)",
                detail=(f"{e.user or 'unknown'} requested a ticket for "
                        f"{e.service or 'an SPN'} with encryption {e.enc_type} (RC4)."),
            ))

    # Signal 2: SPN fan-out per requesting account.
    spns_by_user: Dict[str, set] = defaultdict(set)
    for e in tgs:
        if e.user and e.service:
            spns_by_user[e.user].add(e.service)
    for user, spns in sorted(spns_by_user.items()):
        if len(spns) >= spn_fanout:
            findings.append(Finding(
                severity="medium",
                title=f"Kerberoasting indicator: SPN fan-out by {user}",
                detail=(f"{user} requested service tickets for {len(spns)} distinct "
                        f"SPNs (threshold {spn_fanout}): {', '.join(sorted(spns))}."),
            ))
    return findings


def analyze(events: Sequence[AuthEvent],
            brute_threshold: int = DEFAULT_BRUTE_THRESHOLD,
            brute_window: int = DEFAULT_BRUTE_WINDOW_SECONDS,
            spn_fanout: int = DEFAULT_SPN_FANOUT) -> List[Finding]:
    """Run every detector and return findings sorted worst-first."""
    findings: List[Finding] = []
    findings += detect_brute_force(events, brute_threshold, brute_window)
    findings += detect_successful_after_failures(events, brute_threshold)
    findings += detect_kerberoasting(events, spn_fanout)
    findings.sort(key=lambda f: f.rank)
    return findings
