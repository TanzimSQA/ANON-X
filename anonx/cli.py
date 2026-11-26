"""Command-line interface (`anonctl`) and terminal dashboard for ANON-X."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List

from .core import AnonXCore

RESET = "\033[0m"
BOLD = "\033[1m"
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
MUTED = "\033[90m"


def _badge(label: str) -> str:
    upper = label.upper()
    if upper in ("ACTIVE", "PROTECTED", "PASS", "ENABLED"):
        return f"{GREEN}[{upper}]{RESET}"
    if upper in ("WARNING", "PARTIAL"):
        return f"{YELLOW}[{upper}]{RESET}"
    if upper in ("FAILED", "DISABLED", "INACTIVE"):
        return f"{RED}[{upper}]{RESET}"
    return f"{MUTED}[{upper}]{RESET}"


def render_dashboard(status: Dict[str, Any], detailed: bool = False) -> str:
    """Render the ANON-X terminal dashboard."""
    tor = status["tor"]
    fw = status["firewall"]
    dns = status["dns"]
    v4 = status["ipv4"]
    v6 = status["ipv6"]
    net = status["network"]
    boot = status["startup"]
    rec = status["recovery"]

    lines = [
        f"{CYAN}{BOLD}============================================================{RESET}",
        f"{CYAN}{BOLD}                 ANON-X PRIVACY DASHBOARD                   {RESET}",
        f"{CYAN}{BOLD}============================================================{RESET}",
        f"  Application Version : {status['app_version']}",
        f"  Kali / OS Version   : {status['os_version']}",
        f"  Privacy Mode Status : {_badge(status['overall_state'])}",
        f"  Tor Service         : {_badge('ACTIVE' if tor['service_active'] else 'INACTIVE')}  (Bootstrap: {tor['bootstrap_percent']}%)",
        f"  IPv4 Protection     : {_badge('PROTECTED' if v4['protected'] else 'NOT VERIFIED')}",
        f"  IPv6 Protection     : {_badge('PROTECTED' if v6['protected'] else 'NOT VERIFIED')}",
        f"  DNS Protection      : {_badge('PROTECTED' if dns['protected'] else 'NOT VERIFIED')}",
        f"  Firewall Status     : {_badge('ACTIVE' if fw['filter_active'] else 'INACTIVE')}  ({fw['details']})",
        f"  Startup Protection  : {_badge('ENABLED' if boot['enabled'] else 'DISABLED')}",
        f"  Network Interface   : {net['primary_interface'] or 'none'}",
        f"  Last Boot Check     : {boot['last_boot_result'] or 'Not recorded'}",
        f"{MUTED}  Note: ACTIVE indicates local routing & firewall enforcement, not absolute anonymity.{RESET}",
    ]

    if detailed:
        lines.extend([
            f"{CYAN}------------------------------------------------------------{RESET}",
            f"  Tor Summary         : {tor['bootstrap_summary']}",
            f"  ControlPort Auth    : {tor['control_authenticated']}",
            f"  DNS Nameservers     : {', '.join(dns['nameservers']) or 'none'}",
            f"  LAN Access Policy   : {'ALLOWED (Reduced isolation)' if fw['allow_lan'] else 'BLOCKED (Strict)'}",
            f"  Recovery Snapshot   : {rec['captured_at'] or 'None'}",
            f"  Direct Connections  : {len(v4['direct_connections'])} non-Tor established socket(s)",
        ])
        if status.get("warnings"):
            lines.append(f"{YELLOW}  Advisories:{RESET}")
            for w in status["warnings"]:
                lines.append(f"    - {w}")

    lines.append(f"{CYAN}{BOLD}============================================================{RESET}")
    return "\n".join(lines)


def _require_root(action: str) -> bool:
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print(f"{RED}Error:{RESET} '{action}' requires root privileges. Run with sudo.", file=sys.stderr)
        return False
    return True


def _run_repo_script(script_name: str) -> int:
    script = Path(__file__).resolve().parent.parent / "scripts" / script_name
    if not script.exists():
        print(f"{RED}Error:{RESET} Script not found: {script}", file=sys.stderr)
        return 1
    proc = subprocess.run(["/bin/bash", str(script)], check=False)
    return proc.returncode


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="anonctl",
        description="ANON-X — Advanced Kali Linux Privacy & Tor Protection CLI",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("install", help="Install ANON-X system components")
    sub.add_parser("start", help="Activate fail-closed firewall and Tor privacy mode")
    sub.add_parser("stop", help="Stop privacy mode and restore ANON-X-changed settings")
    sub.add_parser("restart", help="Safely restart privacy protection")

    p_status = sub.add_parser("status", help="Display protection status dashboard")
    p_status.add_argument("--detailed", action="store_true", help="Show extended diagnostics")
    p_status.add_argument("--json", action="store_true", help="Output JSON")

    sub.add_parser("doctor", help="Run comprehensive 16-point system diagnostics")
    sub.add_parser("verify", help="Verify privacy configuration")
    sub.add_parser("new-identity", help="Request a new Tor circuit via authenticated ControlPort")

    p_boot = sub.add_parser("boot", help="Manage automatic startup protection")
    p_boot.add_argument("action", choices=["enable", "disable", "status"], help="Boot action")

    p_logs = sub.add_parser("logs", help="Show sanitized ANON-X logs")
    p_logs.add_argument("--lines", type=int, default=50, help="Number of lines")
    p_logs.add_argument("--category", default="ALL", help="Filter category (TOR, FIREWALL, RECOVERY, etc.)")

    p_rec = sub.add_parser("recover", help="Emergency network recovery (removes ANON-X rules)")
    p_rec.add_argument("--yes", action="store_true", help="Confirm disabling protection")

    sub.add_parser("update", help="Update ANON-X safely")
    sub.add_parser("uninstall", help="Safely uninstall ANON-X")
    return parser


def main(argv: List[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    core = AnonXCore()

    cmd = args.command
    if cmd == "install":
        return _run_repo_script("install.sh") if _require_root("install") else 1
    if cmd == "uninstall":
        return _run_repo_script("uninstall.sh") if _require_root("uninstall") else 1
    if cmd == "update":
        return _run_repo_script("setup.sh") if _require_root("update") else 1

    if cmd == "start":
        if not _require_root("start"):
            return 1
        ok, msg = core.start_protection()
        print(f"{GREEN if ok else RED}{msg}{RESET}")
        return 0 if ok else 2

    if cmd == "stop":
        if not _require_root("stop"):
            return 1
        ok, msg = core.stop_protection()
        print(f"{GREEN if ok else YELLOW}{msg}{RESET}")
        return 0 if ok else 2

    if cmd == "restart":
        if not _require_root("restart"):
            return 1
        ok, msg = core.restart_protection()
        print(f"{GREEN if ok else RED}{msg}{RESET}")
        return 0 if ok else 2

    if cmd == "status":
        st = core.get_status()
        if args.json:
            print(json.dumps(st, indent=2))
        else:
            print(render_dashboard(st, detailed=args.detailed))
        return 0

    if cmd in ("doctor", "verify"):
        report = core.verify()
        print(f"{CYAN}{BOLD}ANON-X DIAGNOSTICS REPORT{RESET}  ({report['timestamp']})")
        print(f"{MUTED}{report['note']}{RESET}\n")
        for item in report["checks"]:
            print(f"  {_badge(item['status']):22s} {BOLD}{item['check']:28s}{RESET} {item['details']}")
        s = report["summary"]
        print(f"\nSummary: PASS={s['PASS']} WARNING={s['WARNING']} FAILED={s['FAILED']} NOT_SUPPORTED={s['NOT SUPPORTED']}")
        return 0 if s["FAILED"] == 0 else 2

    if cmd == "new-identity":
        ok, msg = core.new_identity()
        print(f"{GREEN if ok else RED}{msg}{RESET}")
        return 0 if ok else 2

    if cmd == "boot":
        if args.action == "status":
            st = core.startup.get_status()
            print(f"Boot Protection : {_badge('ENABLED' if st.boot_protection_enabled else 'DISABLED')}")
            print(f"Firewall Unit   : {st.firewall_unit_enabled}")
            print(f"Service Unit    : {st.service_unit_enabled}")
            print(f"Recovery Unit   : {st.recovery_unit_enabled}")
            print(f"Last Verified   : {st.last_boot_verified_at or 'Never'} ({st.last_boot_result or 'N/A'})")
            return 0
        if not _require_root(f"boot {args.action}"):
            return 1
        ok, msg = core.startup.enable_boot() if args.action == "enable" else core.startup.disable_boot()
        print(f"{GREEN if ok else RED}{msg}{RESET}")
        return 0 if ok else 2

    if cmd == "logs":
        lines = core.get_logs(limit=args.lines, category=args.category)
        if not lines:
            print("No ANON-X log entries found.")
        else:
            print("\n".join(lines))
        return 0

    if cmd == "recover":
        if not _require_root("recover"):
            return 1
        if not args.yes:
            print(f"{YELLOW}WARNING:{RESET} Emergency recovery will remove ANON-X firewall rules and disable Tor routing.")
            print("Your system will return to direct network connectivity.")
            confirm = input("Proceed with emergency recovery? [y/N]: ").strip().lower()
            if confirm not in ("y", "yes"):
                print("Recovery cancelled.")
                return 0
        ok, msg = core.recovery.recover(reason="cli-emergency")
        print(f"{GREEN if ok else RED}{msg}{RESET}")
        return 0 if ok else 2

    return 1


if __name__ == "__main__":
    sys.exit(main())
