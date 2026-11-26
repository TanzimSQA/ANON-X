# ANON-X Test & Verification Report

## Environment Summary
- **Development Host:** Windows (Python 3.15.0)
- **Target Kali Linux Environment:** Not directly accessible from this Windows host during build (WSL not installed; no VMware/VirtualBox CLI detected).

## Automated Unit Tests (Executed on Windows Host)
- **Test Runner:** `python -m unittest discover -s tests -t . -v`
- **Coverage:**
  - `tests/test_core.py`: Command allowlist enforcement, interface/CIDR validation, config schema validation, fail-closed behavior when Tor fails to start, CLI parser.
  - `tests/test_tor.py`: Tor drop-in config (local-only ControlPort + CookieAuthentication), bootstrap parsing, `SIGNAL NEWNYM`.
  - `tests/test_firewall.py`: Verification that global `nft flush ruleset` / `iptables -F` are never used, Tor `debian-tor` exemption, unsupported UDP drop, IPv6 drop, fail-closed mode, selective owned-table removal.
  - `tests/test_dns.py`: Non-destructive `resolv.conf` parsing, nftables DNSPort interception verification.
  - `tests/test_ipv4_ipv6.py`: IPv4 redirect verification, IPv6 `sysctl` capture and restore.
  - `tests/test_recovery.py`: Snapshot capture and selective recovery.
  - `tests/test_startup.py`: Boot unit enablement and verification recording.
  - `tests/test_backend.py`: D-Bus/Polkit API allowlist rejection and log secret redaction.

## Kali Linux Integration Tests (Pending Target VM/Hardware Execution)
The following tests require a live Kali Linux Rolling system (recommended inside an isolated VM snapshot or network namespace) and have **not** been executed on Windows:
1. `sudo ./scripts/install.sh` end-to-end package & systemd installation.
2. Live `nft -c -f -` and kernel `nftables` packet-flow verification (TCP -> `9040`, DNS -> `5353`, UDP drop, IPv6 drop).
3. Live Tor daemon bootstrap and `SIGNAL NEWNYM` against `/run/tor/control.authcookie`.
4. Reboot verification (`anonx-firewall.service` + `anonx.service` early-boot ordering).
5. Live PySide6 GUI launch, Polkit prompt, and system tray behavior under X11/Wayland.
6. Live Docker/UFW/NetworkManager coexistence verification.
