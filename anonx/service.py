"""Background systemd protection daemon for ANON-X."""

from __future__ import annotations

import signal
import sys
import time

from .core import AnonXCore


class AnonXDaemon:
    """Monitors Tor health and nftables fail-closed integrity independently of the GUI."""

    def __init__(self) -> None:
        self.core = AnonXCore()
        self.running = True
        self.interval = int(self.core.config_mgr.get("tor.health_check_interval_sec", 15))

    def _handle_signal(self, signum: int, _frame) -> None:
        self.core.logger.info("SERVICE: Received signal %d; stopping daemon loop", signum)
        self.running = False

    def run(self) -> int:
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)

        self.core.logger.info("SERVICE: Starting ANON-X background protection service")
        ok, msg = self.core.start_protection()
        if not ok:
            self.core.logger.error("SERVICE: Initial startup warning: %s", msg)

        while self.running:
            time.sleep(self.interval)
            if not self.running:
                break
            fw_st = self.core.firewall.get_status()
            tor_st = self.core.tor.get_status()

            if not fw_st.filter_table_present:
                self.core.logger.warning("SERVICE: Filter table missing; reapplying fail-closed protection")
                try:
                    self.core.firewall.apply(fail_closed_only=not (tor_st.service_active and tor_st.bootstrap_percent >= 100))
                except Exception as exc:
                    self.core.logger.error("SERVICE: Firewall recovery failed: %s", exc)

            if not tor_st.service_active or tor_st.bootstrap_percent < 100:
                self.core.logger.warning("SERVICE: Tor unhealthy (%s); maintaining fail-closed firewall and retrying", tor_st.bootstrap_summary)
                try:
                    self.core.firewall.apply(fail_closed_only=True)
                except Exception:
                    pass
                self.core.tor.start()
                boot_ok, _, _ = self.core.tor.wait_for_bootstrap(timeout_sec=30)
                if boot_ok:
                    try:
                        self.core.firewall.apply(fail_closed_only=False)
                        self.core.logger.info("SERVICE: Tor recovered; transparent routing restored")
                    except Exception as exc:
                        self.core.logger.error("SERVICE: Could not restore NAT rules after Tor recovery: %s", exc)

        return 0


def main() -> int:
    daemon = AnonXDaemon()
    return daemon.run()


if __name__ == "__main__":
    sys.exit(main())
