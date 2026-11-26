# ANON-X — Advanced Kali Linux Privacy & Tor Protection System

**ANON-X** is a modular, fail-closed Linux privacy-management system built for **Kali Linux Rolling** (and compatible Debian/systemd distributions). It provides both a **PySide6 desktop GUI (`anonx-gui`)** and a **command-line interface (`anonctl`)** backed by a unified Python engine, **nftables**, **Tor**, **systemd**, **D-Bus**, and **Polkit**.

> **Important Security Notice:** ANON-X reduces network exposure and enforces fail-closed Tor routing for supported TCP/DNS traffic, but **no tool can guarantee 100% anonymity**. Always review [Privacy Limitations](docs/PRIVACY_LIMITATIONS.md).

## Key Features

- **Fail-Closed nftables Firewall:** Uses dedicated `anonx_nat` and `anonx_filter` tables. Never flushes global rulesets (`nft flush ruleset` / `iptables -F`) and preserves existing UFW, Docker, and NetworkManager rules.
- **Tor Transparent Routing & Authenticated ControlPort:** Routes supported TCP traffic through Tor `TransPort` (`9040`), DNS through `DNSPort` (`5353`), and manages circuits via cookie-authenticated local `ControlPort` (`127.0.0.1:9051`).
- **DNS & IPv6 Leak Prevention:** Intercepts port 53 traffic to Tor `DNSPort`, drops direct external DNS (`53`/`853`), blocks IPv6 egress/DNS bypasses, and captures/restores IPv6 `sysctl` state without blindly overwriting `/etc/resolv.conf`.
- **Automatic Boot Protection:** Early-boot `anonx-firewall.service` activates fail-closed rules before normal user traffic, followed by `anonx.service` monitoring Tor health and bootstrap.
- **Privilege-Separated Desktop GUI:** `ANON-X Privacy Center` runs as a normal unprivileged user and communicates with `anonx-dbus.service` via D-Bus + Polkit. Closing the GUI **never** stops background protection.
- **Safe Recovery System:** Captures pre-change snapshots and removes only ANON-X-owned tables and settings.

## Quick Installation (on Kali Linux)

```bash
git clone <your-repo-or-copy-anonx-folder>
cd anonx
sudo chmod +x scripts/*.sh
sudo ./scripts/install.sh
```

## Quick Commands (`anonctl`)

| Command | Description |
|---|---|
| `sudo anonctl start` | Activate fail-closed firewall & Tor privacy mode |
| `sudo anonctl stop` | Stop protection & restore ANON-X-changed settings |
| `sudo anonctl restart` | Safely restart protection |
| `anonctl status` | Show terminal privacy dashboard |
| `anonctl status --detailed` | Show extended network & security advisories |
| `anonctl doctor` | Run 16-point system diagnostics |
| `anonctl verify` | Verify privacy configuration |
| `anonctl new-identity` | Request a new Tor circuit (`SIGNAL NEWNYM`) |
| `sudo anonctl boot enable` | Enable automatic protection on system boot |
| `sudo anonctl boot disable` | Disable automatic boot protection |
| `anonctl boot status` | Check boot protection status |
| `anonctl logs` | View sanitized ANON-X logs |
| `sudo anonctl recover` | Emergency recovery (restores direct network) |
| `sudo anonctl uninstall` | Safely uninstall ANON-X |

## Launching the GUI

- From the Kali Application Menu: **System / Security -> ANON-X Privacy Center**
- From terminal (as normal user): `anonx-gui`

## Documentation

- [Installation Guide](docs/INSTALLATION.md)
- [User Guide](docs/USER_GUIDE.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Security Design](docs/SECURITY.md)
- [Privacy Limitations](docs/PRIVACY_LIMITATIONS.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)
- [Test Report](docs/TEST_REPORT.md)
