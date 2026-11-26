# Architecture Overview

## Layered Design

```
+-------------------------------------------------------------+
|  User Interfaces                                            |
|  - anonctl (CLI & Terminal Dashboard)                       |
|  - anonx-gui (PySide6 Privacy Center + System Tray)         |
+------------------------------+------------------------------+
                               | D-Bus (org.anonx.Manager)
                               | + Polkit (auth_admin_keep)
+------------------------------v------------------------------+
|  Privileged Service API (privileged/service_api.py)         |
|  - Strict operation allowlist + JSON schema validation      |
+------------------------------+------------------------------+
                               |
+------------------------------v------------------------------+
|  Unified Backend Core (anonx/core.py)                       |
|  - TorManager (systemd + ControlPort cookie auth)           |
|  - FirewallManager (nftables anonx_nat & anonx_filter)      |
|  - DNSManager (DNSPort 5353 + resolver inspection)          |
|  - IPv4Manager / IPv6Manager (sysctl + egress drop)         |
|  - RecoveryManager (atomic state snapshots)                 |
|  - StartupManager (systemd boot units)                      |
|  - DiagnosticsEngine (16-point verification)                |
+-------------------------------------------------------------+
```

## Boot Sequence
1. `anonx-firewall.service` runs before `network-online.target` and `tor.service`, capturing a recovery snapshot and loading fail-closed `anonx_filter` rules.
2. `anonx.service` starts Tor, waits for 100% bootstrap via authenticated `ControlPort`, and applies `anonx_nat` transparent redirection.
3. `anonx.service` continuously monitors Tor health and `nftables` integrity, reverting to fail-closed mode if Tor drops.
