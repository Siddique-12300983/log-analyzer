"""Plain terminal summary of events and findings."""

from __future__ import annotations

from collections import Counter
from typing import List, Sequence

from .model import FAILED_LOGIN, INVALID_USER, KERBEROS_TGS, ACCEPTED_LOGIN, AuthEvent, Finding

_SEV_TAG = {"high": "[HIGH]", "medium": "[MED ]", "low": "[LOW ]"}


def build_report(events: Sequence[AuthEvent], findings: List[Finding]) -> str:
    lines: List[str] = []
    lines.append("=" * 60)
    lines.append(" log-analyzer summary")
    lines.append("=" * 60)

    counts = Counter(e.event_type for e in events)
    lines.append(f" events parsed        : {len(events)}")
    lines.append(f"   failed logins      : {counts.get(FAILED_LOGIN, 0)}")
    lines.append(f"   invalid users      : {counts.get(INVALID_USER, 0)}")
    lines.append(f"   accepted logins    : {counts.get(ACCEPTED_LOGIN, 0)}")
    lines.append(f"   kerberos tickets   : {counts.get(KERBEROS_TGS, 0)}")

    # Top source IPs by failed attempts.
    fail_ips = Counter(e.src_ip for e in events
                       if e.event_type in (FAILED_LOGIN, INVALID_USER) and e.src_ip)
    if fail_ips:
        lines.append("")
        lines.append(" top source IPs by failed logins")
        for ip, n in fail_ips.most_common(5):
            lines.append(f"   {ip:<18} {n}")

    lines.append("")
    if not findings:
        lines.append(" findings             : none")
    else:
        lines.append(f" findings             : {len(findings)}")
        lines.append("-" * 60)
        for f in findings:
            tag = _SEV_TAG.get(f.severity, "[????]")
            lines.append(f" {tag} {f.title}")
            lines.append(f"        {f.detail}")
    lines.append("=" * 60)
    return "\n".join(lines)
