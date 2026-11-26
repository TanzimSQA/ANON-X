# Installation Manual

## Target Environment
- Kali Linux Rolling (Debian-based)
- `systemd` init system
- `nftables` (`nft`)
- `Tor` (`tor`)
- `NetworkManager`
- `Python >= 3.10`

## Deploying from Windows (`D:\tools\anon`) to Kali Linux

If you are developing on Windows (`D:\tools\anon`) and targeting a Kali Linux VM or physical machine:
1. Copy the `D:\tools\anon` directory to your Kali machine (e.g., via `scp -r` or shared folder):
   ```bash
   scp -r /mnt/d/tools/anon kali@<kali-ip>:~/anonx
   ```
2. On Kali Linux, run the idempotent installer:
   ```bash
   cd ~/anonx
   sudo chmod +x scripts/*.sh
   sudo ./scripts/install.sh
   ```

## What `install.sh` Does
1. Verifies OS and `systemd` availability.
2. Installs required packages via `apt-get` (`python3`, `python3-yaml`, `python3-pyside6.*`, `python3-dbus`, `python3-gi`, `tor`, `nftables`, `policykit-1`, `libnotify-bin`).
3. Creates protected directories (`/etc/anonx`, `/var/log/anonx`, `/var/lib/anonx/backups`).
4. Installs `/opt/anonx`, `/usr/local/bin/anonctl`, and `/usr/local/bin/anonx-gui`.
5. Installs Polkit policy (`org.anonx.Manager.policy`), D-Bus system bus config, and systemd units.
6. Installs desktop launcher (`/usr/share/applications/anonx.desktop`) and SVG icon.
7. Enables `anonx-dbus.service` and automatic boot protection (`anonctl boot enable`), then runs `anonctl doctor`.

## Uninstallation
```bash
sudo ./scripts/uninstall.sh
```
This safely restores ANON-X-modified network settings, removes ANON-X-owned nftables tables and systemd units, and preserves unrelated firewall rules.
