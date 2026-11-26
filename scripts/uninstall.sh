#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Error: Please run as root (sudo ./scripts/uninstall.sh)." >&2
  exit 1
fi

echo "Stopping ANON-X and restoring network settings..."
if command -v anonctl >/dev/null 2>&1; then
  anonctl recover --yes || true
  anonctl boot disable || true
fi

systemctl disable --now anonx-dbus.service anonx.service anonx-firewall.service anonx-recovery.service 2>/dev/null || true

rm -f /etc/systemd/system/anonx*.service
systemctl daemon-reload

rm -f /usr/local/bin/anonctl /usr/local/bin/anonx-gui
rm -f /usr/share/polkit-1/actions/org.anonx.Manager.policy
rm -f /etc/dbus-1/system.d/org.anonx.Manager.conf
rm -f /etc/polkit-1/rules.d/50-anonx.rules
rm -f /usr/share/applications/anonx.desktop
rm -f /usr/share/icons/hicolor/scalable/apps/anonx.svg
rm -f /etc/tor/torrc.d/99-anonx.conf
rm -rf /opt/anonx

echo "ANON-X uninstalled safely. Unrelated firewall rules and /etc/anonx backups were preserved."
