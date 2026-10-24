"""Shared data model for parsed authentication events."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Optional

# Normalised event types the parsers emit.
FAILED_LOGIN = "failed_login"
ACCEPTED_LOGIN = "accepted_login"
INVALID_USER = "invalid_user"
KERBEROS_TGS = "kerberos_tgs"  # Windows 4769, Kerberos service ticket request


@dataclass
class AuthEvent:
    """One authentication-related line, normalised across log sources."""

    timestamp: datetime
    source: str          # "auth.log" or "winsec"
    event_type: str
    user: Optional[str] = None
    src_ip: Optional[str] = None
    service: Optional[str] = None     # SPN / service name for Kerberos events
    enc_type: Optional[str] = None    # ticket encryption type, e.g. "0x17"
    raw: str = ""


@dataclass
class Finding:
    """Something worth a human's attention, produced by the analyzer."""

    severity: str   # "high", "medium", "low"
    title: str
    detail: str

    # Sort order so the report shows the worst first.
    _ORDER = {"high": 0, "medium": 1, "low": 2}

    @property
    def rank(self) -> int:
        return self._ORDER.get(self.severity, 99)
