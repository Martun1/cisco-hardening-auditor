#!/usr/bin/env python3
"""
cisco-hardening-auditor
=======================
Offline security auditor for Cisco IOS / IOS-XE running-configs.

* Parses a saved `show running-config` text file
* Runs 20+ hardening checks (management plane, passwords, services, logging...)
* Calculates a weighted security score (0-100) and letter grade
* Prints a coloured terminal report
* Generates a self-contained HTML report and a ready-to-paste remediation script

No network access, no device credentials needed — it only reads text files.
Author: Martin Ivanov (Martun1)
License: MIT
"""
from __future__ import annotations

import argparse
import html
import json
import re
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path

__version__ = "1.0.0"

# --------------------------------------------------------------------------- #
#  Terminal colours (no external dependencies)
# --------------------------------------------------------------------------- #
class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"

    @classmethod
    def disable(cls) -> None:
        for name in dir(cls):
            if name.isupper():
                setattr(cls, name, "")


SEVERITY_WEIGHT = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 2}
SEVERITY_COLOR = {"CRITICAL": "MAGENTA", "HIGH": "RED", "MEDIUM": "YELLOW", "LOW": "BLUE"}


# --------------------------------------------------------------------------- #
#  Cisco type 7 decoding (weak reversible "encryption" — used to PROVE the risk)
# --------------------------------------------------------------------------- #
_XLAT = "dsfd;kfoA,.iyewrkldJKDHSUBsgvca69834ncxv9873254k;fg87"


def decode_type7(enc: str) -> str | None:
    """Decode a Cisco type 7 password. Returns None if the string is malformed."""
    try:
        seed = int(enc[:2])
        out = []
        for i in range(2, len(enc), 2):
            out.append(chr(int(enc[i:i + 2], 16) ^ ord(_XLAT[(seed + (i // 2) - 1) % len(_XLAT)])))
        return "".join(out)
    except (ValueError, IndexError):
        return None


# --------------------------------------------------------------------------- #
#  Config model
# --------------------------------------------------------------------------- #
@dataclass
class IOSConfig:
    raw: str
    lines: list[str] = field(default_factory=list)
    blocks: dict[str, list[str]] = field(default_factory=dict)

    @classmethod
    def parse(cls, text: str) -> "IOSConfig":
        cfg = cls(raw=text)
        cfg.lines = [l.rstrip() for l in text.splitlines()]
        current = None
        for line in cfg.lines:
            if not line.strip() or line.strip() == "!":
                current = None
                continue
            if not line.startswith(" "):
                current = line.strip()
                cfg.blocks.setdefault(current, [])
            elif current is not None:
                cfg.blocks[current].append(line.strip())
        return cfg

    def has(self, pattern: str) -> bool:
        rx = re.compile(pattern, re.M)
        return bool(rx.search(self.raw))

    def find(self, pattern: str) -> list[re.Match]:
        return list(re.finditer(pattern, self.raw, re.M))

    def blocks_matching(self, header_rx: str) -> dict[str, list[str]]:
        rx = re.compile(header_rx)
        return {h: b for h, b in self.blocks.items() if rx.match(h)}

    @property
    def hostname(self) -> str:
        m = re.search(r"^hostname (\S+)", self.raw, re.M)
        return m.group(1) if m else "unknown"


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    category: str
    passed: bool
    detail: str
    fix: list[str]
    reference: str = ""


# --------------------------------------------------------------------------- #
#  Checks
# --------------------------------------------------------------------------- #
CHECKS = []


def check(cid: str, title: str, severity: str, category: str, reference: str = ""):
    def deco(fn):
        CHECKS.append((cid, title, severity, category, reference, fn))
        return fn
    return deco


@check("PWD-01", "Enable secret is configured (not 'enable password')", "CRITICAL", "Passwords",
       "CIS Cisco IOS 1.1.x")
def _(c: IOSConfig):
    if c.has(r"^enable password"):
        return False, "'enable password' found — stored with weak/no encryption.", [
            "no enable password", "enable algorithm-type scrypt secret <STRONG_PASSWORD>"]
    if not c.has(r"^enable (algorithm-type \S+ )?secret"):
        return False, "No enable secret configured — privileged mode is unprotected.", [
            "enable algorithm-type scrypt secret <STRONG_PASSWORD>"]
    if c.has(r"^enable secret 5 "):
        return True, "enable secret uses type 5 (MD5). Consider type 9 (scrypt).", []
    return True, "Enable secret is configured.", []


@check("PWD-02", "No reversible type 7 passwords", "HIGH", "Passwords")
def _(c: IOSConfig):
    hits = c.find(r"(?:password|key) 7 ([0-9A-Fa-f]+)")
    if not hits:
        return True, "No type 7 passwords found.", []
    decoded = []
    for m in hits:
        plain = decode_type7(m.group(1))
        if plain is not None:
            decoded.append(f"'{m.group(0)[:40]}' → decodes to '{plain[:2]}{'*' * max(len(plain) - 2, 0)}'")
    return False, (f"{len(hits)} type 7 password(s) found. Type 7 is trivially reversible: "
                   + "; ".join(decoded)), [
        "! Replace with type 9 secrets, e.g.",
        "username <user> privilege 15 algorithm-type scrypt secret <STRONG_PASSWORD>"]


@check("PWD-03", "service password-encryption enabled", "LOW", "Passwords")
def _(c: IOSConfig):
    if c.has(r"^service password-encryption"):
        return True, "Enabled (note: only obfuscation, use secrets wherever possible).", []
    return False, "Plain-text passwords will be visible in the config.", ["service password-encryption"]


@check("PWD-04", "Minimum password length enforced", "MEDIUM", "Passwords")
def _(c: IOSConfig):
    m = re.search(r"^security passwords min-length (\d+)", c.raw, re.M)
    if m and int(m.group(1)) >= 10:
        return True, f"Minimum length is {m.group(1)}.", []
    return False, "No (or short) minimum password length.", ["security passwords min-length 12"]


@check("MGMT-01", "Telnet disabled on VTY lines (SSH only)", "CRITICAL", "Management plane",
       "CIS Cisco IOS 1.2.x")
def _(c: IOSConfig):
    bad = []
    for header, body in c.blocks_matching(r"^line vty").items():
        transport = [l for l in body if l.startswith("transport input")]
        if not transport or "telnet" in transport[0] or "all" in transport[0]:
            bad.append(header)
    if bad:
        return False, f"Telnet (clear-text) allowed on: {', '.join(bad)}", [
            *[f"{h}\n transport input ssh" for h in bad]]
    return True, "All VTY lines restricted to SSH.", []


@check("MGMT-02", "SSH version 2 enforced", "HIGH", "Management plane")
def _(c: IOSConfig):
    if c.has(r"^ip ssh version 2"):
        return True, "SSH v2 enforced.", []
    return False, "SSH v1 may be negotiated (known weaknesses).", ["ip ssh version 2"]


@check("MGMT-03", "VTY access restricted with an ACL", "HIGH", "Management plane")
def _(c: IOSConfig):
    vty = c.blocks_matching(r"^line vty")
    if not vty:
        return False, "No VTY lines found in config.", []
    missing = [h for h, b in vty.items() if not any(l.startswith("access-class") for l in b)]
    if missing:
        return False, f"No access-class on: {', '.join(missing)} — anyone can reach the login prompt.", [
            "ip access-list standard MGMT-ONLY", " permit 10.0.99.0 0.0.0.255", " deny any log",
            *[f"{h}\n access-class MGMT-ONLY in" for h in missing]]
    return True, "VTY lines protected by access-class.", []


@check("MGMT-04", "Idle session timeout configured (<= 10 min)", "MEDIUM", "Management plane")
def _(c: IOSConfig):
    bad = []
    for header, body in c.blocks_matching(r"^line (vty|con)").items():
        t = [l for l in body if l.startswith("exec-timeout")]
        if not t:
            continue  # default is 10 min — acceptable
        parts = t[0].split()
        mins = int(parts[1]) if len(parts) > 1 else 10
        secs = int(parts[2]) if len(parts) > 2 else 0
        if mins == 0 and secs == 0 or mins > 10:
            bad.append(f"{header} ({t[0]})")
    if bad:
        return False, "Sessions never/too-late time out: " + "; ".join(bad), [
            "line vty 0 15\n exec-timeout 5 0", "line con 0\n exec-timeout 5 0"]
    return True, "Session timeouts are reasonable.", []


@check("MGMT-05", "Login brute-force protection (login block-for)", "MEDIUM", "Management plane")
def _(c: IOSConfig):
    if c.has(r"^login block-for"):
        return True, "Login blocking enabled.", []
    return False, "No protection against password guessing on the login prompt.", [
        "login block-for 120 attempts 5 within 60", "login on-failure log", "login on-success log"]


@check("MGMT-06", "HTTP server disabled", "HIGH", "Services")
def _(c: IOSConfig):
    if c.has(r"^ip http server") and not c.has(r"^no ip http server"):
        return False, "Unencrypted HTTP management server is enabled.", ["no ip http server"]
    return True, "HTTP server is disabled.", []


@check("MGMT-07", "Login banner configured", "LOW", "Management plane")
def _(c: IOSConfig):
    if c.has(r"^banner (login|motd)"):
        return True, "Banner present.", []
    return False, "No legal warning banner — weakens legal action against intruders.", [
        "banner login ^C Authorized access only. Activity is monitored. ^C"]


@check("AAA-01", "AAA new-model enabled", "MEDIUM", "AAA")
def _(c: IOSConfig):
    if c.has(r"^aaa new-model"):
        return True, "AAA enabled.", []
    return False, "AAA is not enabled — no centralised authentication/accounting.", [
        "aaa new-model", "aaa authentication login default local", "aaa authorization exec default local"]


@check("SNMP-01", "No default SNMP communities (public/private)", "CRITICAL", "SNMP")
def _(c: IOSConfig):
    hits = c.find(r"^snmp-server community (public|private)\b.*")
    if hits:
        return False, "Default community strings found: " + ", ".join(h.group(0) for h in hits), [
            *[f"no {h.group(0)}" for h in hits],
            "! Prefer SNMPv3 authPriv:",
            "snmp-server group SECURE v3 priv",
            "snmp-server user monitor SECURE v3 auth sha <AUTH_PASS> priv aes 128 <PRIV_PASS>"]
    return True, "No default communities.", []


@check("SNMP-02", "No SNMP read-write communities", "HIGH", "SNMP")
def _(c: IOSConfig):
    hits = c.find(r"^snmp-server community \S+ RW.*")
    if hits:
        return False, "RW community allows remote config changes: " + ", ".join(h.group(0) for h in hits), [
            *[f"no {h.group(0)}" for h in hits]]
    return True, "No RW communities.", []


@check("SVC-01", "CDP disabled globally or on edge ports", "LOW", "Services")
def _(c: IOSConfig):
    if c.has(r"^no cdp run"):
        return True, "CDP disabled globally.", []
    return False, "CDP leaks model, IOS version and IPs to anyone on the segment.", [
        "no cdp run", "! or per-interface: interface <edge-port>\n no cdp enable"]


@check("SVC-02", "Small/legacy services disabled", "MEDIUM", "Services")
def _(c: IOSConfig):
    bad = [s for s in ("service tcp-small-servers", "service udp-small-servers", "ip finger",
                       "service finger", "ip bootp server") if c.has(rf"^{s}")]
    if bad:
        return False, "Legacy services enabled: " + ", ".join(bad), [f"no {s}" for s in bad]
    return True, "No legacy services found.", []


@check("SVC-03", "Source routing disabled", "MEDIUM", "Services")
def _(c: IOSConfig):
    if c.has(r"^no ip source-route"):
        return True, "Source routing disabled.", []
    return False, "IP source routing lets attackers choose the packet path.", ["no ip source-route"]


@check("LOG-01", "Remote syslog server configured", "MEDIUM", "Logging")
def _(c: IOSConfig):
    if c.has(r"^logging (host )?\d+\.\d+\.\d+\.\d+"):
        return True, "Remote logging configured.", []
    return False, "Logs only exist on the device — lost on reboot/compromise.", [
        "logging host 10.0.99.10", "logging trap informational"]


@check("LOG-02", "Timestamps on logs", "LOW", "Logging")
def _(c: IOSConfig):
    if c.has(r"^service timestamps log datetime"):
        return True, "Log timestamps enabled.", []
    return False, "Logs lack precise timestamps — hard to correlate incidents.", [
        "service timestamps log datetime msec localtime show-timezone"]


@check("LOG-03", "NTP configured", "MEDIUM", "Logging")
def _(c: IOSConfig):
    if c.has(r"^ntp server"):
        return True, "NTP configured.", []
    return False, "No NTP — log times will drift.", ["ntp server 10.0.99.1"]


@check("L2-01", "Unused access ports shut down", "MEDIUM", "Layer 2")
def _(c: IOSConfig):
    bad = []
    for header, body in c.blocks_matching(r"^interface (Fast|Gigabit)Ethernet").items():
        is_access = "switchport mode access" in body
        has_desc = any(l.startswith("description") for l in body)
        if is_access and not has_desc and "shutdown" not in body:
            bad.append(header.replace("interface ", ""))
    if bad:
        return False, f"{len(bad)} access port(s) without description that are not shut: {', '.join(bad[:6])}", [
            f"interface range {bad[0]} - ...\n shutdown\n switchport access vlan 999"]
    return True, "No obviously unused open access ports.", []


@check("L2-02", "Port-security on access ports", "MEDIUM", "Layer 2")
def _(c: IOSConfig):
    access = {h: b for h, b in c.blocks_matching(r"^interface").items() if "switchport mode access" in b
              and "shutdown" not in b}
    if not access:
        return True, "No active access ports.", []
    missing = [h.replace("interface ", "") for h, b in access.items() if "switchport port-security" not in b]
    if missing:
        return False, f"Port-security missing on {len(missing)} active access port(s).", [
            f"interface {missing[0]}\n switchport port-security\n switchport port-security maximum 2\n"
            f" switchport port-security violation restrict"]
    return True, "Port-security enabled on access ports.", []


@check("L2-03", "Native VLAN is not VLAN 1 on trunks", "MEDIUM", "Layer 2")
def _(c: IOSConfig):
    trunks = {h: b for h, b in c.blocks_matching(r"^interface").items() if "switchport mode trunk" in b}
    bad = [h.replace("interface ", "") for h, b in trunks.items()
           if not any(l.startswith("switchport trunk native vlan") for l in b)]
    if bad:
        return False, f"Trunks using default native VLAN 1 (VLAN hopping risk): {', '.join(bad)}", [
            f"interface {bad[0]}\n switchport trunk native vlan 999\n switchport nonegotiate"]
    return True, "Trunks use a dedicated native VLAN.", []


@check("L2-04", "DHCP snooping enabled", "LOW", "Layer 2")
def _(c: IOSConfig):
    if not c.has(r"^ switchport"):
        return True, "Not a switch config (no switchports).", []
    if c.has(r"^ip dhcp snooping$") or c.has(r"^ip dhcp snooping\s*$"):
        return True, "DHCP snooping enabled.", []
    return False, "No DHCP snooping — rogue DHCP servers can MITM clients.", [
        "ip dhcp snooping", "ip dhcp snooping vlan 10,20", "interface <uplink>\n ip dhcp snooping trust"]


# --------------------------------------------------------------------------- #
#  Engine
# --------------------------------------------------------------------------- #
def audit(cfg: IOSConfig) -> list[Finding]:
    results = []
    for cid, title, sev, cat, ref, fn in CHECKS:
        passed, detail, fix = fn(cfg)
        results.append(Finding(cid, title, sev, cat, passed, detail, fix, ref))
    return results


def score(findings: list[Finding]) -> tuple[int, str]:
    total = sum(SEVERITY_WEIGHT[f.severity] for f in findings)
    got = sum(SEVERITY_WEIGHT[f.severity] for f in findings if f.passed)
    pct = round(100 * got / total) if total else 100
    grade = "A" if pct >= 90 else "B" if pct >= 80 else "C" if pct >= 65 else "D" if pct >= 50 else "F"
    return pct, grade


# --------------------------------------------------------------------------- #
#  Output
# --------------------------------------------------------------------------- #
def bar(pct: int, width: int = 30) -> str:
    filled = round(width * pct / 100)
    color = C.GREEN if pct >= 80 else C.YELLOW if pct >= 50 else C.RED
    return f"{color}{'█' * filled}{C.DIM}{'░' * (width - filled)}{C.RESET}"


def print_report(name: str, cfg: IOSConfig, findings: list[Finding], verbose: bool) -> None:
    pct, grade = score(findings)
    head = f"╔══ Cisco Hardening Auditor v{__version__} "
    print(f"\n{C.BOLD}{C.CYAN}{head}{'═' * (62 - len(head))}╗{C.RESET}")
    print(f"{C.BOLD}  Device:{C.RESET} {cfg.hostname}   {C.BOLD}File:{C.RESET} {name}")
    print(f"{C.BOLD}  Score :{C.RESET} {bar(pct)} {C.BOLD}{pct}/100  Grade {grade}{C.RESET}")
    print(f"{C.CYAN}╚{'═' * 61}╝{C.RESET}\n")
    for f in sorted(findings, key=lambda x: (x.passed, -SEVERITY_WEIGHT[x.severity])):
        if f.passed and not verbose:
            continue
        mark = f"{C.GREEN}✔ PASS{C.RESET}" if f.passed else f"{C.RED}✘ FAIL{C.RESET}"
        sc = getattr(C, SEVERITY_COLOR[f.severity])
        print(f" {mark}  {sc}{f.severity:<8}{C.RESET} {C.BOLD}{f.id:<8}{C.RESET} {f.title}")
        if not f.passed:
            print(f"        {C.DIM}↳ {f.detail}{C.RESET}")
    fails = [f for f in findings if not f.passed]
    print(f"\n {C.BOLD}Summary:{C.RESET} {len(findings) - len(fails)} passed, {len(fails)} failed "
          f"({sum(1 for f in fails if f.severity == 'CRITICAL')} critical)\n")


def write_fix_script(path: Path, cfg: IOSConfig, findings: list[Finding]) -> None:
    out = [f"! Remediation script for {cfg.hostname}",
           f"! Generated by cisco-hardening-auditor v{__version__} on {datetime.now():%Y-%m-%d %H:%M}",
           "! REVIEW BEFORE APPLYING. Replace <PLACEHOLDERS>. Test in a lab first.", "!",
           "configure terminal"]
    for f in findings:
        if not f.passed and f.fix:
            out.append(f"! --- {f.id}: {f.title}")
            out.extend(f.fix)
    out += ["end", "write memory"]
    path.write_text("\n".join(out) + "\n", encoding="utf-8")


def write_html(path: Path, name: str, cfg: IOSConfig, findings: list[Finding]) -> None:
    pct, grade = score(findings)
    color = "#22c55e" if pct >= 80 else "#eab308" if pct >= 50 else "#ef4444"
    sev_col = {"CRITICAL": "#a855f7", "HIGH": "#ef4444", "MEDIUM": "#eab308", "LOW": "#3b82f6"}
    cats: dict[str, list[Finding]] = {}
    for f in findings:
        cats.setdefault(f.category, []).append(f)
    cat_rows = "".join(
        f"<div class='cat'><span>{html.escape(k)}</span><div class='mini'><div style='width:"
        f"{round(100 * sum(1 for x in v if x.passed) / len(v))}%'></div></div>"
        f"<b>{sum(1 for x in v if x.passed)}/{len(v)}</b></div>" for k, v in cats.items())
    rows = ""
    for f in sorted(findings, key=lambda x: (x.passed, -SEVERITY_WEIGHT[x.severity])):
        fix = ("<pre>" + html.escape("\n".join(f.fix)) + "</pre>") if f.fix and not f.passed else ""
        rows += (f"<tr class='{'pass' if f.passed else 'fail'}'><td>{'✔' if f.passed else '✘'}</td>"
                 f"<td><span class='sev' style='background:{sev_col[f.severity]}'>{f.severity}</span></td>"
                 f"<td><code>{f.id}</code></td><td><b>{html.escape(f.title)}</b><br>"
                 f"<small>{html.escape(f.detail)}</small>{fix}</td></tr>")
    doc = f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<title>Hardening report – {html.escape(cfg.hostname)}</title><style>
body{{font-family:Inter,Segoe UI,system-ui,sans-serif;background:#0b1020;color:#e2e8f0;margin:0;padding:32px}}
.wrap{{max-width:1100px;margin:auto}} h1{{margin:0;font-size:28px}} .muted{{color:#94a3b8}}
.top{{display:grid;grid-template-columns:260px 1fr;gap:24px;margin:24px 0}}
.card{{background:#111833;border:1px solid #1e293b;border-radius:14px;padding:20px}}
.ring{{width:180px;height:180px;border-radius:50%;margin:auto;display:grid;place-items:center;
background:conic-gradient({color} {pct * 3.6}deg,#1e293b 0)}}
.ring div{{width:140px;height:140px;border-radius:50%;background:#111833;display:grid;place-items:center;text-align:center}}
.ring b{{font-size:44px}} .cat{{display:grid;grid-template-columns:170px 1fr 50px;gap:12px;align-items:center;margin:8px 0}}
.mini{{height:10px;background:#1e293b;border-radius:6px;overflow:hidden}} .mini div{{height:100%;background:{color}}}
table{{width:100%;border-collapse:collapse}} td{{padding:12px;border-bottom:1px solid #1e293b;vertical-align:top}}
tr.fail td:first-child{{color:#ef4444;font-size:20px}} tr.pass td:first-child{{color:#22c55e;font-size:20px}}
tr.pass{{opacity:.65}} .sev{{padding:3px 8px;border-radius:6px;font-size:11px;font-weight:700;color:#fff}}
pre{{background:#020617;border:1px solid #1e293b;padding:10px;border-radius:8px;color:#7dd3fc;white-space:pre-wrap}}
small{{color:#94a3b8}} code{{white-space:nowrap}}</style></head><body><div class="wrap">
<h1>🛡️ Cisco Hardening Report — {html.escape(cfg.hostname)}</h1>
<div class="muted">Source: {html.escape(name)} · Generated {datetime.now():%Y-%m-%d %H:%M} · cisco-hardening-auditor v{__version__}</div>
<div class="top"><div class="card"><div class="ring"><div><div><b>{pct}</b><br>Grade {grade}</div></div></div></div>
<div class="card"><h3 style="margin-top:0">Category breakdown</h3>{cat_rows}</div></div>
<div class="card"><table>{rows}</table></div></div></body></html>"""
    path.write_text(doc, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Audit Cisco IOS running-configs against security hardening best practices.")
    ap.add_argument("configs", nargs="+", type=Path, help="config file(s) (output of 'show running-config')")
    ap.add_argument("-v", "--verbose", action="store_true", help="also show passed checks")
    ap.add_argument("--html", type=Path, help="write HTML report (one file, or a directory for many configs)")
    ap.add_argument("--fix", type=Path, help="write remediation script(s) (file or directory)")
    ap.add_argument("--json", action="store_true", help="print machine-readable JSON instead of text")
    ap.add_argument("--min-score", type=int, default=0, help="exit code 2 if any score is below this (CI usage)")
    ap.add_argument("--no-color", action="store_true", help="disable ANSI colours")
    args = ap.parse_args(argv)
    if args.no_color:
        C.disable()

    many = len(args.configs) > 1
    worst = 100
    all_json = []
    for path in args.configs:
        if not path.is_file():
            print(f"[!] File not found: {path}", file=sys.stderr)
            return 1
        cfg = IOSConfig.parse(path.read_text(encoding="utf-8", errors="replace"))
        findings = audit(cfg)
        pct, grade = score(findings)
        worst = min(worst, pct)
        if args.json:
            all_json.append({"file": str(path), "hostname": cfg.hostname, "score": pct, "grade": grade,
                             "findings": [asdict(f) for f in findings]})
        else:
            print_report(path.name, cfg, findings, args.verbose)
        if args.html:
            out = (args.html / f"{cfg.hostname}.html") if (many or args.html.is_dir()) else args.html
            out.parent.mkdir(parents=True, exist_ok=True)
            write_html(out, path.name, cfg, findings)
            if not args.json:
                print(f" {C.GREEN}[+]{C.RESET} HTML report  → {out}")
        if args.fix:
            out = (args.fix / f"{cfg.hostname}-fix.txt") if (many or args.fix.is_dir()) else args.fix
            out.parent.mkdir(parents=True, exist_ok=True)
            write_fix_script(out, cfg, findings)
            if not args.json:
                print(f" {C.GREEN}[+]{C.RESET} Fix script   → {out}")
    if args.json:
        print(json.dumps(all_json if many else all_json[0], indent=2))
    return 2 if worst < args.min_score else 0


if __name__ == "__main__":
    sys.exit(main())
