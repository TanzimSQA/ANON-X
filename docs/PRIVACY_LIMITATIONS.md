# Privacy Limitations & Threat Model

ANON-X is designed to reduce network exposure and prevent accidental direct leaks on Kali Linux. It **does not** provide perfect or guaranteed anonymity.

## Key Technical Limitations
1. **Tor Exit Visibility & ISP Observation:** Your local ISP or Wi-Fi operator can still see that you are connecting to the Tor network (unless bridges/pluggable transports are configured).
2. **Transparent Proxy vs. Tor Browser:** Routing all system traffic through a single transparent proxy shares circuits across background applications. For web browsing, **Tor Browser** is strongly recommended because it resists WebRTC leaks, canvas/font fingerprinting, and cross-site tracking.
3. **Unsupported UDP Protocols:** Tor transports TCP streams and DNS (via `DNSPort`). Arbitrary UDP applications (VoIP, BitTorrent, WebRTC media, gaming) are **blocked by default** and must not be routed outside Tor.
4. **Application & Account Metadata:** Logging into personal accounts, sending identifying documents, or running background telemetry daemons can deanonymize you regardless of network routing.
5. **New Circuit (`SIGNAL NEWNYM`):** Requesting a new Tor circuit applies to *new* connections and does not guarantee a different exit IP or clear existing browser state.
6. **LAN Access (`allow_lan: true`):** Enabling local network access allows direct communication with LAN devices outside Tor, which can expose local host metadata.
7. **Virtualization & Containers:** In a VM or Docker environment, the host OS or container bridge sits outside the guest's `nftables` rules.
8. **Verification Scope:** `ACTIVE` / `PROTECTED` indicators reflect verified local `nftables`, `sysctl`, and Tor ControlPort state — external exit-IP verification requires checking via Tor itself.
