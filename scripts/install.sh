#!/usr/bin/env bash
set -euo pipefail

# ANON-X Idempotent Installer for Kali Linux / Debian-based systemd systems

if [[ "${EUID}" -ne 0 ]]; then
  echo "Error: Please run as root (sudo ./scripts/install.sh)." >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
INSTALL_DIR="/opt/anonx"

echo "=== [1/8] Inspecting Operating System & Prerequisites ==="
if [[ -f /etc/os-release ]]; then
  . /etc/os-release
  echo "Detected OS: ${PRETTY_NAME:-Unknown}"
fi

if ! command -v systemctl >/dev/null 2>&1; then
  echo "Error: systemd is required." >&2
  exit 1
fi

echo "=== [2/8] Installing System Dependencies ==="
apt-get update -qq
apt-get install -y --no-install-recommends \
  python3 python3-pip python3-yaml python3-pyside6.qtwidgets python3-pyside6.qtcore python3-pyside6.qtgui \
  python3-dbus python3-gi tor nftables polkitd pkexec libnotify-bin

echo "=== [3/8] Creating Protected Directories ==="
mkdir -p /etc/anonx /var/log/anonx /var/lib/anonx/backups /run/anonx "${INSTALL_DIR}"
chmod 750 /etc/anonx /var/log/anonx
chmod 700 /var/lib/anonx /var/lib/anonx/backups

echo "=== [4/8] Installing ANON-X Source & Executables ==="
cp -r "${PROJECT_ROOT}/anonx" "${PROJECT_ROOT}/gui" "${PROJECT_ROOT}/privileged" "${PROJECT_ROOT}/config" "${PROJECT_ROOT}/scripts" "${INSTALL_DIR}/"
cp "${PROJECT_ROOT}/pyproject.toml" "${INSTALL_DIR}/"

if [[ ! -f /etc/anonx/config.yaml ]]; then
  cp "${PROJECT_ROOT}/config/default.yaml" /etc/anonx/config.yaml
  chmod 640 /etc/anonx/config.yaml
fi

cat > /usr/local/bin/anonctl << 'EOF'
#!/usr/bin/env bash
PYTHONPATH=/opt/anonx exec /usr/bin/python3 -m anonx.cli "$@"
EOF
chmod 755 /usr/local/bin/anonctl

cat > /usr/local/bin/anonx-gui << 'EOF'
#!/usr/bin/env bash
PYTHONPATH=/opt/anonx exec /usr/bin/python3 -m gui.main "$@"
EOF
chmod 755 /usr/local/bin/anonx-gui

echo "=== [5/8] Installing Polkit & D-Bus Policies ==="
install -m 644 "${PROJECT_ROOT}/privileged/polkit_policy/org.anonx.Manager.policy" /usr/share/polkit-1/actions/
install -m 644 "${PROJECT_ROOT}/privileged/polkit_policy/org.anonx.Manager.conf" /etc/dbus-1/system.d/
if [[ -d /etc/polkit-1/rules.d ]]; then
  install -m 644 "${PROJECT_ROOT}/privileged/polkit_policy/50-anonx.rules" /etc/polkit-1/rules.d/
fi

echo "=== [6/8] Installing Desktop Launcher & Icon ==="
install -d /usr/share/icons/hicolor/scalable/apps /usr/share/applications
install -m 644 "${PROJECT_ROOT}/packaging/anonx.svg" /usr/share/icons/hicolor/scalable/apps/anonx.svg
install -m 644 "${PROJECT_ROOT}/packaging/anonx.desktop" /usr/share/applications/anonx.desktop

echo "=== [7/8] Installing Systemd Units ==="
for unit in anonx-firewall.service anonx.service anonx-recovery.service anonx-dbus.service; do
  sed "/^\[Service\]/a Environment=PYTHONPATH=${INSTALL_DIR}" \
    "${PROJECT_ROOT}/systemd/${unit}" > "/etc/systemd/system/${unit}"
  chmod 644 "/etc/systemd/system/${unit}"
done

systemctl daemon-reload
systemctl enable --now anonx-dbus.service

echo "=== [8/8] Verifying & Enabling Boot Protection ==="
anonctl boot enable
anonctl doctor || true

echo ""
echo "ANON-X installation complete."
echo "Run 'sudo anonctl start' to activate now, or launch 'ANON-X Privacy Center' from your Kali menu."
