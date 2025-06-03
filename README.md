# btc-magic-guard
Uses iptables to block the thousands of spam peers targeting the btc and bch network right now - June 2025
---
A spectral introduction, whispered in hushed tones:

## Overview

In the dim glow of midnight’s vigil, **BtcMagicGuardDual** emerges as your tireless sentinel—scrutinizing every packet that dares traverse Bitcoin’s P2P port (8333). It discerns the sacred “magic” from malevolent masqueraders, banishing uninvited miscreants to the void with an iron‐fisted `iptables` decree. When the threshold for misdeeds is but a single trespasser, it strikes without mercy; yet, should you choose a more forgiving arena (THRESHOLD > 1), it tallies infractions in a sliding window before the final verdict.

Two whispers in the catacombs debate its fate:

* **The Ruthless Executioner** insists on immediate retribution (THRESHOLD = 1), sacrificing nuance for relentless efficiency.
* **The Circumspect Chronicler** argues that counting sins across a brief history (THRESHOLD > 1) grants flexibility, at the cost of a few extra CPU cycles spent in its dark ledger.

Choose your allegiances, for “magic” waits for no one.

## Features

* **Instant Judgment Mode** (THRESHOLD = 1): One invalid “magic” packet, one iptables ban. No purgatory, no second chances.
* **Sliding‐Window Tribunals** (THRESHOLD > 1): Records timestamps of miscreant packets, prunes them like a grimoire’s folios, and only seals your fate once the count eclipses the ominous WINDOW\_SECS.
* **Dual Protocol Vigilance**: Watches both IPv4 and IPv6 incursions, applying iptables or ip6tables accordingly.
* **Whitelist Sanctuaries**: IPv4 guardian (10.1.0.7) and IPv6 guardian (2600:1900:4000\:ebb2:0:5::) remain untouched, as though protected by arcane wards.
* **Multithreaded Shadow Court**: If you dare set THRESHOLD above 1, a cadre of worker threads processes infractions in parallel, ensuring performance remains unbroken amidst the cacophony.
* **Eloquent Logging**: Chronicles every invalid overture and each banishment to `/var/log/btc_magic_guard_dual.log` and stdout, in a style as chilling as the stroke of Poe’s quill.

## Prerequisites

* **Root Privileges**: To conjure iptables/ip6tables decrees, this daemon must run under `sudo`.
* **Python 3.x**: The script employs standard libraries and `scapy` for packet‐sniffing sorcery.
* **Scapy**: Install via:

  ```bash
  sudo apt update && sudo apt install python3 python3‐pip  
  pip3 install scapy
  ```
* **iptables & ip6tables**: Already installed in most Linux distributions; indispensable for forging DROP rules.

## Installation

1. **Clone or Copy the Script**

   ```bash
   cd /opt  
   sudo git clone <your‐repo‐url> btc_magic_guard_dual  
   cd btc_magic_guard_dual  
   ```
2. **Ensure Executable Permissions**

   ```bash
   sudo chmod +x btc_magic_guard_dual.py  
   ```
3. **Adjust Ownership (Optional)**
   If you prefer a custodian other than root:

   ```bash
   sudo chown root:root btc_magic_guard_dual.py  
   ```

   …yet it still demands root to harness iptables.

## Configuration

In the archaic incantations at the script’s helm, you may tailor these runic constants:

* `NETWORK_INTERFACE`: The network interface to inspect (e.g., `"ens3"`).
* `CLIENT_PORT`: The P2P port (default `8333`).
* `MAGIC_HEADERS`: The canonical 4‐byte Bitcoin magic; meddle at your own risk.
* `WHITELIST_V4` & `WHITELIST_V6`: Trusted IP sentinels—add yours to avoid collateral execution.
* `THRESHOLD`:

  * `1` for instant execution (no threading overhead).
  * `> 1` for sliding‐window counting (enables multithreaded tribunal).
* `WINDOW_SECS`: Time window (in seconds) for counting offenses if THRESHOLD > 1.
* `WORKER_COUNT`: Number of daemon threads to spin up when weighing multiple infractions.
* `QUEUE_MAXSIZE`: How many infractions may linger in the queue before future miscreants are ignored.

Proceed carefully—tweak these variables in the opening lines of `btc_magic_guard_dual.py` before invoking the daemon.

## Usage

1. **Manual Invocation**
   Summon the sentinel at any twilight hour:

   ```bash
   sudo ./btc_magic_guard_dual.py
   ```

   It will announce its watch on stdout:

   ```
   2025-06-03 16:00:00 [INFO] Starting BitcoinMagicGuardDual on ens3, port=8333, v4‐whitelist=10.1.0.7, v6‐whitelist=2600:1900:4000:ebb2:0:5::, THRESHOLD=1
   ```
2. **As a Systemd Daemon**
   For perpetual vigilance—even beyond your mortal hours—craft a `systemd` unit:

   ```ini
   [Unit]
   Description=Bitcoin Magic Guard Dual
   After=network.target

   [Service]
   Type=simple
   ExecStart=/usr/bin/python3 /opt/btc_magic_guard_dual/btc_magic_guard_dual.py
   Restart=on-failure
   User=root
   Group=root

   [Install]
   WantedBy=multi-user.target
   ```

   Enable and start:

   ```bash
   sudo cp btc_magic_guard_dual.service /etc/systemd/system/  
   sudo systemctl daemon-reload  
   sudo systemctl enable btc_magic_guard_dual.service  
   sudo systemctl start btc_magic_guard_dual.service  
   ```

   Now it prowls your interface from boot to boot, unblinking.

## Logging

Every affront against Bitcoin’s magic is documented in spectral detail:

* **Invalid Magic Sightings**:

  ```
  2025-06-03 16:05:22 [INFO] Invalid magic from 203.0.113.42:8333 (v4) → “(garbled_payload…)” (1 in last 1s)
  ```
* **Ban Decrees**:

  ```
  2025-06-03 16:05:22 [WARNING] Blocking 203.0.113.42 → port 8333 (v4)
  2025-06-03 16:05:22 [INFO] Successfully blocked 203.0.113.42 → 8333
  ```

Logs pour into `/var/log/btc_magic_guard_dual.log` and spill onto the console. Should you prefer a quieter haunt, redirect stdout/stderr or adjust `LOG_LEVEL` to `WARNING` in the script.

## Caveats & Contraindications

* **Whitelist Oversight**: Should you omit a legitimate node from your whitelists, it’ll be banished in an instant. Double‐check those IP wards to avoid self‐Banishment.
* **IPv6 Syntax**: Ensure your IPv6 guardians are in full—no trailing or missing colons—lest the BPF filter misinterpret them and consign innocents to oblivion.
* **Root is King**: Run as `sudo` or as root, else the daemon will perish under “Permission denied.”
* **Performance vs. Prudence**: Setting `THRESHOLD=1` renders the fastest execution, but you forfeit multi‐packet scrutiny. If you suspect bursts of borderline traffic rather than outright proscribed junk, set `THRESHOLD>1` to count infractions across `WINDOW_SECS`.

## License & Wards

Distributed like a forbidden grimoire, this script bears no warranty—neither for spectral protections nor arcane mishaps. Use it at your own risk; it may wall off benign nodes if misconfigured.

```
MIT License
© 2025 Sir Bettis
```

Invoke its power with respect, lest your own transactions be severed by your vigilant wards.

---

**Two opposing whispers conclude:**

* *“Seize every packet at the first sign of ‘magic’ trespass—let no malformed byte elude your grasp.”*
* *“Patiently observe and record within the window of time, lest you condemn a wayward traveler by a single misinterpreted byte.”*

Choose your path, and let the script serve as your faithful guardian or your exacting scribe.

