# Troubleshooting Guide

## 1. No Internet After Starting ANON-X (Fail-Closed Active)
- **Cause:** Tor has not reached 100% bootstrap or cannot reach Tor relays, so `anonx_filter` is intentionally blocking direct traffic.
- **Check:** Run `anonctl status --detailed` and `anonctl doctor`.
- **Fix:** Check `journalctl -u tor -n 50` or `anonctl logs --category TOR`. If on a restricted network, configure Tor bridges in `/etc/tor/torrc` and restart: `sudo anonctl restart`.

## 2. Emergency Network Recovery
If you are locked out of network access and need to restore direct connectivity immediately:
```bash
sudo anonctl recover
```
Or from a TTY without `anonctl`:
```bash
sudo nft delete table ip anonx_nat 2>/dev/null || true
sudo nft delete table inet anonx_filter 2>/dev/null || true
```
*(This removes only ANON-X tables and leaves UFW/Docker rules intact.)*

## 3. GUI Shows "Privileged D-Bus/Polkit service unavailable"
- Ensure `anonx-dbus.service` is running:
  ```bash
  sudo systemctl status anonx-dbus.service
  ```
- Start it if needed: `sudo systemctl enable --now anonx-dbus.service`.

## 4. Docker or VPN Conflicts
- `anonctl doctor` flags active VPN interfaces (`tun0`, `wg0`) and Docker bridges. Avoid chaining transparent Tor proxying over an unverified VPN tunnel without explicit routing rules.
