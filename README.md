# log-analyzer

A Python tool that reads an authentication log and flags activity worth a second
look: brute-force attempts, a brute-force that ended in a successful login, and
Kerberoasting indicators in Windows 4769 events.

I wrote this while building my Active Directory lab in
[purple-team-journey](https://github.com/Siddique-12300983/purple-team-journey).
Reading raw `auth.log` and Security event exports by eye gets old fast, so this
does the first pass and prints a short summary.

## Why it matters

Failed logins and Kerberos ticket requests are normal on their own. What matters
is the pattern: the same IP failing again and again, a login that finally
succeeds after a run of failures, or one account pulling service tickets for a
pile of different SPNs. Those patterns are the difference between noise and an
incident, and they are easy to miss in a flat file.

## What it detects

| Detector | Signal | Severity |
|---|---|---|
| Brute force | Many failed logins from one source IP inside a time window | high |
| Successful brute force | An IP that failed repeatedly and then logged in | high |
| Kerberoasting (RC4) | A 4769 service ticket requested with RC4 encryption (`0x17`) | high |
| Kerberoasting (fan-out) | One account requesting tickets for several distinct SPNs | medium |

### A note on RC4 vs AES

The RC4 check (`0x17`) is the classic Kerberoasting indicator and still worth
having. But in my own lab, Windows Server 2025 refuses to issue RC4 tickets, so
a real roast there shows up as AES (`0x12`), and an RC4-only rule would miss it.
That is why the SPN fan-out detector exists: it catches the attack by behaviour,
not encryption type. The full write-up is in the flagship repo under
[labs/ad-lab/kerberoasting.md](https://github.com/Siddique-12300983/purple-team-journey/blob/main/labs/ad-lab/kerberoasting.md).

## Supported formats

- Linux `auth.log` (OpenSSH lines)
- Windows Security log exported to CSV, with columns `TimeCreated`, `EventID`,
  `TargetUserName`, `IpAddress`, `ServiceName`, `TicketEncryptionType`. Handled
  event IDs: 4625 (failed logon), 4624 (logon), 4769 (Kerberos service ticket).

The format is auto-detected from the file, or set it with `--format`.

## Install

No third-party packages are needed to run it; it uses the Python standard
library. Python 3.9 or newer.

```bash
git clone https://github.com/Siddique-12300983/log-analyzer.git
cd log-analyzer
```

Optionally install it as a command:

```bash
pip install .
log-analyzer samples/auth.log --year 2026
```

## Usage

```bash
# Run straight from the source tree
python -m loganalyzer samples/auth.log --year 2026
python -m loganalyzer samples/windows-security-events.csv
```

```
usage: log-analyzer [-h] [--format {auth,winsec,auto}] [--year YEAR]
                    [--brute-threshold N] [--brute-window SECONDS]
                    [--spn-fanout N] [--version]
                    logfile
```

`auth.log` does not store the year, so pass `--year` for old logs; it defaults
to the current year. The command exits `1` when any high-severity finding turns
up, so you can use it in a script.

## Example output

```
============================================================
 log-analyzer summary
============================================================
 events parsed        : 13
   failed logins      : 6
   invalid users      : 0
   accepted logins    : 2
   kerberos tickets   : 5

 top source IPs by failed logins
   10.10.10.30        6

 findings             : 3
------------------------------------------------------------
 [HIGH] Brute-force from 10.10.10.30
        6 failed logins total, peaking at 6 within 60s (threshold 5).
 [HIGH] Kerberoasting indicator: RC4 service ticket (4769)
        jack.wilson requested a ticket for MSSQLSvc/sql01.purple.internal:1433 with encryption 0x17 (RC4).
 [MED ] Kerberoasting indicator: SPN fan-out by jack.wilson
        jack.wilson requested service tickets for 4 distinct SPNs (threshold 3): ...
============================================================
```

## Sample data

Two sample files are in `samples/` so the tool runs out of the box:

- `auth.log`: a brute force from `203.0.113.45` that ends in a successful login.
- `windows-security-events.csv`: a password-spray, one RC4 ticket request, and
  an SPN fan-out from a single account.

## Running the tests

```bash
pip install pytest
pytest
```

The tests cover the parsers, each detector (including the time-window and
threshold edges), and the shipped sample files.

## Layout

```
loganalyzer/
  model.py      normalised event and finding types
  parsers.py    auth.log and Windows CSV parsers
  analyzer.py   the detectors
  report.py     terminal summary
  cli.py        argument parsing and entry point
samples/        example logs
tests/          pytest suite
```

## Related repos

- [attack-coverage-map](https://github.com/Siddique-12300983/attack-coverage-map) reads this repo and reports which ATT&CK techniques my detections actually cover, and where the gaps are. [Live heatmap](https://siddique-12300983.github.io/attack-coverage-map/)
- [persistwatch](https://github.com/Siddique-12300983/persistwatch) hunts Linux persistence in systemd units and timers
- [sigma-detection-rules](https://github.com/Siddique-12300983/sigma-detection-rules) the Sigma rules, mapped to ATT&CK
- [purple-team-journey](https://github.com/Siddique-12300983/purple-team-journey) the AD lab all of this came out of

## License

MIT. See [LICENSE](LICENSE).

---

Built by **ruxchipher** (Md Abu Bakar Siddique), cyber security student working
toward a purple team role.
[ruxchipher.com](https://ruxchipher.com) ·
[GitHub](https://github.com/Siddique-12300983) ·
[LinkedIn](https://linkedin.com/in/siddiqueabu)
