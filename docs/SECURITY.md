# Security Architecture & Hardening

## Mandatory Security Controls
- **Fail-Closed Design:** Before Tor starts (and whenever Tor fails or loses bootstrap), `anonx_filter` drops non-essential outbound IPv4 and IPv6 traffic rather than falling back to direct internet access.
- **Non-Destructive Firewall:** ANON-X creates only `ip anonx_nat` and `inet anonx_filter`. It never runs `nft flush ruleset` or `iptables -F`, preserving UFW, Docker, and NetworkManager rules.
- **Tor Loop Prevention:** Tor daemon traffic (`meta skuid "debian-tor"`) is explicitly exempted from NAT redirection and allowed in the output filter.
- **Authenticated Local ControlPort:** Tor `ControlPort` binds strictly to `127.0.0.1:9051` with `CookieAuthentication 1`.
- **Privilege Separation:** The PySide6 GUI runs unprivileged and invokes only allowlisted operations on `org.anonx.Manager` over system D-Bus, gated by Polkit (`org.anonx.Manager.manage`).
- **Safe Subprocess Execution:** All system commands use `subprocess.run(..., shell=False)` with an explicit binary allowlist and validated arguments.
- **Log Sanitization:** Control cookies, authentication tokens, and passwords are automatically redacted before writing or displaying logs.
- **No Anti-Forensics / No Unsolicited Changes:** ANON-X never wipes user files, browser history, or logs, and never spoofs MAC addresses automatically.
