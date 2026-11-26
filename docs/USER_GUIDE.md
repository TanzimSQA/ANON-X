# User Guide

## Using the Graphical Interface (`anonx-gui`)
Launch **ANON-X Privacy Center** from the Kali application menu or run `anonx-gui` as your regular desktop user.

### Pages
1. **Dashboard:** Overview of Tor, DNS, IPv4, IPv6, Firewall, Startup, Recovery, and Network status with a primary `ENABLE PRIVACY` / `DISABLE PRIVACY` toggle.
2. **Network Protection:** Interface details, DNS/NM integration, and unsupported protocol warnings.
3. **Privacy Diagnostics:** Click `RUN FULL DIAGNOSTIC` to run all 16 checks and export a sanitized JSON report.
4. **Tor & Identity:** Bootstrap progress, built circuits, `REQUEST NEW TOR CIRCUIT`, and Tor Browser guidance.
5. **Firewall Center:** Read-only inspection of ANON-X-owned `nftables` tables.
6. **Automatic Protection:** Enable/disable boot units and inspect last boot verification.
7. **Logs & Activity:** Search, filter, and export sanitized logs.
8. **Settings:** Configure fail-closed mode, UDP blocking, optional LAN access, tray minimization, notifications, and logging level.
9. **Recovery Center:** Snapshot status and emergency recovery trigger with explicit confirmation.

## System Tray Behavior
Closing the main window minimizes ANON-X to the system tray (when enabled). **Exiting the GUI never stops the background protection service.**

## Automatic Boot Protection
When enabled (`sudo anonctl boot enable`), `anonx-firewall.service` loads fail-closed `nftables` rules before normal network traffic, and `anonx.service` starts Tor, waits for 100% bootstrap, and enables transparent routing. If Tor fails, non-essential outbound traffic remains blocked.
