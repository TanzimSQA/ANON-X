"""Configuration management with schema validation and atomic persistence."""

from __future__ import annotations

import copy
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Dict

try:
    import yaml  # type: ignore
except ImportError:  # pragma: no cover
    yaml = None

DEFAULT_CONFIG_PATH = Path("/etc/anonx/config.yaml")
PACKAGE_DEFAULT_CONFIG = Path(__file__).resolve().parent.parent / "config" / "default.yaml"

BUILTIN_DEFAULTS: Dict[str, Any] = {
    "general": {
        "app_name": "ANON-X",
        "version": "1.0.0",
        "log_level": "INFO",
        "log_dir": "/var/log/anonx",
        "state_dir": "/var/lib/anonx",
        "backup_dir": "/var/lib/anonx/backups",
        "run_dir": "/run/anonx",
    },
    "tor": {
        "service_name": "tor",
        "user": "debian-tor",
        "torrc_path": "/etc/tor/torrc",
        "torrc_dropin": "/etc/tor/torrc.d/99-anonx.conf",
        "trans_port": 9040,
        "dns_port": 5353,
        "socks_port": 9050,
        "control_port": 9051,
        "cookie_auth_file": "/run/tor/control.authcookie",
        "virtual_addr_network": "10.192.0.0/10",
        "bootstrap_timeout_sec": 90,
        "health_check_interval_sec": 15,
    },
    "firewall": {
        "backend": "nftables",
        "table_name": "anonx_filter",
        "nat_table_name": "anonx_nat",
        "fail_closed": True,
        "block_unsupported_udp": True,
        "allow_dhcp": True,
        "allow_lan": False,
        "lan_cidrs": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
        "preserve_docker": True,
        "preserve_ufw": True,
    },
    "dns": {
        "intercept_port53": True,
        "block_external_dns": True,
        "manage_resolv_conf": False,
        "check_systemd_resolved": True,
        "check_network_manager": True,
    },
    "ipv6": {
        "policy": "block_egress",
        "disable_sysctl_ipv6": True,
        "block_ipv6_dns": True,
    },
    "startup": {
        "enable_boot_protection": True,
        "retry_interval_sec": 10,
        "max_bootstrap_retries": 6,
        "gui_autostart": False,
    },
    "gui": {
        "theme": "dark",
        "minimize_to_tray": True,
        "notifications_enabled": True,
        "refresh_interval_ms": 3000,
    },
    "hardening": {
        "warn_browser_fingerprinting": True,
        "warn_vpn_conflicts": True,
        "warn_torrent_over_tor": True,
        "auto_mac_spoof": False,
        "auto_wipe_logs": False,
    },
}

ALLOWED_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
ALLOWED_IPV6_POLICIES = {"block_egress"}


class ConfigValidationError(ValueError):
    """Raised when configuration values fail security or schema validation."""


def deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively merge override dictionary into a copy of base."""
    merged = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = deep_merge(merged[key], value)
        else:
            merged[key] = copy.deepcopy(value)
    return merged


def _validate_port(value: Any, name: str) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or not (1 <= value <= 65535):
        raise ConfigValidationError(f"Invalid port for {name}: {value!r}")


def validate_config(cfg: Dict[str, Any]) -> None:
    """Validate configuration structure and enforce security invariants."""
    if not isinstance(cfg, dict):
        raise ConfigValidationError("Configuration root must be a mapping.")

    log_level = str(cfg.get("general", {}).get("log_level", "INFO")).upper()
    if log_level not in ALLOWED_LOG_LEVELS:
        raise ConfigValidationError(f"Unsupported log_level: {log_level}")

    tor = cfg.get("tor", {})
    for port_key in ("trans_port", "dns_port", "socks_port", "control_port"):
        _validate_port(tor.get(port_key), f"tor.{port_key}")

    if not isinstance(tor.get("user"), str) or not tor["user"].strip():
        raise ConfigValidationError("tor.user must be a non-empty string.")

    fw = cfg.get("firewall", {})
    if fw.get("backend") not in ("nftables",):
        raise ConfigValidationError(f"Unsupported firewall backend: {fw.get('backend')!r}")
    if not isinstance(fw.get("fail_closed"), bool):
        raise ConfigValidationError("firewall.fail_closed must be a boolean.")
    if not isinstance(fw.get("allow_lan"), bool):
        raise ConfigValidationError("firewall.allow_lan must be a boolean.")

    ipv6_policy = cfg.get("ipv6", {}).get("policy")
    if ipv6_policy not in ALLOWED_IPV6_POLICIES:
        raise ConfigValidationError(f"Unsupported ipv6.policy: {ipv6_policy!r}")

    hardening = cfg.get("hardening", {})
    if hardening.get("auto_wipe_logs"):
        raise ConfigValidationError("auto_wipe_logs is prohibited by ANON-X security policy.")


class ConfigManager:
    """Loads, validates, and atomically saves ANON-X configuration."""

    def __init__(self, config_path: Path | str | None = None) -> None:
        self.config_path = Path(config_path) if config_path else DEFAULT_CONFIG_PATH
        self._config: Dict[str, Any] = copy.deepcopy(BUILTIN_DEFAULTS)
        self.load()

    def load(self) -> Dict[str, Any]:
        """Load configuration from package defaults and system override file."""
        base = copy.deepcopy(BUILTIN_DEFAULTS)
        if PACKAGE_DEFAULT_CONFIG.exists():
            parsed = self._read_file(PACKAGE_DEFAULT_CONFIG)
            if parsed:
                base = deep_merge(base, parsed)

        if self.config_path.exists():
            parsed_override = self._read_file(self.config_path)
            if parsed_override:
                base = deep_merge(base, parsed_override)

        validate_config(base)
        self._config = base
        return copy.deepcopy(self._config)

    def _read_file(self, path: Path) -> Dict[str, Any]:
        raw = path.read_text(encoding="utf-8")
        if not raw.strip():
            return {}
        if yaml is not None:
            data = yaml.safe_load(raw)
        elif raw.lstrip().startswith("{"):
            data = json.loads(raw)
        else:
            # PyYAML not installed and file is YAML; fall back to BUILTIN_DEFAULTS
            return {}
        if data is None:
            return {}
        if not isinstance(data, dict):
            raise ConfigValidationError(f"Config file {path} must contain a mapping.")
        return data

    @property
    def data(self) -> Dict[str, Any]:
        return copy.deepcopy(self._config)

    def get(self, dotted_key: str, default: Any = None) -> Any:
        node: Any = self._config
        for part in dotted_key.split("."):
            if isinstance(node, dict) and part in node:
                node = node[part]
            else:
                return default
        return copy.deepcopy(node)

    def update(self, updates: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and atomically persist updated configuration."""
        candidate = deep_merge(self._config, updates)
        validate_config(candidate)
        self._atomic_write(candidate)
        self._config = candidate
        return copy.deepcopy(self._config)

    def reset_defaults(self) -> Dict[str, Any]:
        """Restore built-in default configuration."""
        candidate = copy.deepcopy(BUILTIN_DEFAULTS)
        if PACKAGE_DEFAULT_CONFIG.exists():
            parsed = self._read_file(PACKAGE_DEFAULT_CONFIG)
            if parsed:
                candidate = deep_merge(candidate, parsed)
        validate_config(candidate)
        self._atomic_write(candidate)
        self._config = candidate
        return copy.deepcopy(self._config)

    def _atomic_write(self, data: Dict[str, Any]) -> None:
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        serialized = yaml.safe_dump(data, sort_keys=False) if yaml is not None else json.dumps(data, indent=2)
        fd, tmp_path = tempfile.mkstemp(prefix=".anonx_cfg_", dir=str(self.config_path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(serialized)
                handle.flush()
                os.fsync(handle.fileno())
            if os.name == "posix":
                os.chmod(tmp_path, 0o640)
            os.replace(tmp_path, self.config_path)
        except Exception:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            raise
