#!/usr/bin/env python3
"""
btc_magic_guard_dual.py (Optimized)

Monitors BOTH IPv4 and IPv6 TCP traffic on Bitcoin’s P2P port (8333) for invalid‐magic
messages.  Whitelists one IPv4 (10.1.0.7) and one IPv6 (2600:1900:4000:ebb2:0:5::),
and drops/blocklists anything else that sends malformed payloads.

If THRESHOLD == 1, we immediately block on the first invalid packet (no worker queue).
If THRESHOLD > 1, we fall back to a deque + worker threads for sliding‐window counting.
"""

import subprocess
import threading
import time
import logging
import sys
import queue
from collections import defaultdict, deque

from scapy.all import sniff, IP, IPv6, TCP, Raw

# ────── CONFIG ────────────────────────────────────────────────────────────────

NETWORK_INTERFACE = "ens3"

#: Watch only Bitcoin’s P2P port:
CLIENT_PORT = 8333

#: Known Bitcoin “magic” (4 bytes)
MAGIC_HEADERS = { b"\xF9\xBE\xB4\xD9" }

#: Whitelist IP v4/v6
WHITELIST_V4 = "10.1.0.7"
WHITELIST_V6 = "2600:1900:4000:ebb2:0:5::"

#: How many invalid messages before blocking
THRESHOLD   = 1
WINDOW_SECS = 1

LOGFILE  = "/var/log/btc_magic_guard_dual.log"
LOG_LEVEL = logging.INFO

#: Only used if THRESHOLD > 1
WORKER_COUNT  = 4
QUEUE_MAXSIZE = 5000

# ── CORRECTED BPF FILTER ───────────────────────────────────────────────────────
#
#   - “tcp and dst port 8333 and not src host 10.1.0.5”      (IPv4 side)
#   - “ip6 and tcp and dst port 8333 and not src host 2600:1900:4000:ebb2:0:4::”  (IPv6 side)
#
BPF_FILTER = (
    f"(tcp and dst port {CLIENT_PORT} and not src host {WHITELIST_V4}) "
    f"or (ip6 and tcp and dst port {CLIENT_PORT} and not src host {WHITELIST_V6})"
)

# ────── GLOBAL STATE ───────────────────────────────────────────────────────────

#: Only used if THRESHOLD > 1: map “(src_addr, dst_port, is_ipv6)” → deque[timestamps]
recent_invalid = defaultdict(lambda: deque())

#: Set of (src_addr, dst_port, is_ipv6) already blocked
blocked = set()
state_lock = threading.Lock()

#: Only used if THRESHOLD > 1: worker queue: (src, dst_port, is_ipv6, snippet)
event_queue = queue.Queue(maxsize=QUEUE_MAXSIZE) if THRESHOLD > 1 else None

# ── LOGGER SETUP ──────────────────────────────────────────────────────────────

logger = logging.getLogger("BtcMagicGuardDual")
logger.setLevel(LOG_LEVEL)

fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S")

fh = logging.FileHandler(LOGFILE)
fh.setFormatter(fmt)
logger.addHandler(fh)

ch = logging.StreamHandler(sys.stdout)
ch.setLevel(LOG_LEVEL)
ch.setFormatter(fmt)
logger.addHandler(ch)

# ────── HELPERS ────────────────────────────────────────────────────────────────

def is_invalid_magic(payload: bytes) -> bool:
    """
    True if < 4 bytes or first 4 bytes not in MAGIC_HEADERS.
    """
    return len(payload) < 4 or payload[:4] not in MAGIC_HEADERS

def install_block(src_addr: str, dst_port: int, is_ipv6: bool):
    """
    Add a DROP rule (iptables for v4, ip6tables for v6), but only if not yet installed.
    Uses “-C” to check duplication first.
    """
    key = (src_addr, dst_port, is_ipv6)
    with state_lock:
        if key in blocked:
            return
        blocked.add(key)
        logger.warning(f"Blocking {src_addr} → port {dst_port} ({'v6' if is_ipv6 else 'v4'})")

    table_cmd = "ip6tables" if is_ipv6 else "iptables"
    base = [
        table_cmd,
        "-A", "INPUT",
        "-s", src_addr,
        "-p", "tcp",
        "--dport", str(dst_port),
        "-j", "DROP"
    ]

    # 1) Check for an existing identical rule
    check = base.copy()
    check[1] = "-C"
    try:
        subprocess.check_call(check, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        logger.info(f"Already blocked {src_addr} → {dst_port}. Skipping.")
        return
    except subprocess.CalledProcessError:
        # -C returned nonzero ⇒ rule not found ⇒ proceed to append
        pass

    # 2) Append the DROP rule
    try:
        subprocess.check_call(base, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        logger.info(f"Successfully blocked {src_addr} → {dst_port}")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to run {table_cmd} for {src_addr}:{dst_port}: {e}")

def process_event(src: str, dst_port: int, is_ipv6: bool, snippet: str):
    """
    Worker thread: update recent_invalid, prune old timestamps, log count,
    block if threshold exceeded. Only used if THRESHOLD > 1.
    """
    now = time.time()
    key = (src, dst_port, is_ipv6)

    with state_lock:
        if key in blocked:
            return

        dq = recent_invalid[key]
        dq.append(now)

        # Prune old timestamps outside WINDOW_SECS
        while dq and (now - dq[0] > WINDOW_SECS):
            dq.popleft()

        count = len(dq)
        if not dq:
            del recent_invalid[key]

    logger.info(
        f"Invalid magic from {src}:{dst_port} ({'v6' if is_ipv6 else 'v4'}) → “{snippet}” "
        f"({count} in last {WINDOW_SECS}s)"
    )
    if count >= THRESHOLD:
        install_block(src, dst_port, is_ipv6)

def worker_loop():
    """
    Continuously process events from the queue. Only used if THRESHOLD > 1.
    """
    while True:
        try:
            src, dport, ipv6_flag, snippet = event_queue.get()
            process_event(src, dport, ipv6_flag, snippet)
        except Exception as e:
            logger.error(f"Worker exception: {e}")
        finally:
            event_queue.task_done()

# ────── PACKET HANDLER / SNIFF LOOP ─────────────────────────────────────────────

def packet_callback(pkt):
    """
    Called for each sniffed packet (BPF ensures either v4‐TCP or v6‐TCP for our port).
    We check whether it’s IPv4 or IPv6, extract src→dst_port, then test Raw/magic.

    If THRESHOLD == 1: block inline (no queue).
    If THRESHOLD > 1: enqueue event for worker threads.
    """
    # IPv4 path:
    if pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw):
        src = pkt[IP].src
        dport = pkt[TCP].dport
        key = (src, dport, False)

        # ─── SKIP THE V4 WHITELIST ─────────────────────────────────────────────────
        if src == WHITELIST_V4:
            return

        with state_lock:
            if key in blocked:
                return

        payload = bytes(pkt[Raw].load)
        if is_invalid_magic(payload):
            snippet = payload[:32].decode("utf-8", "ignore").replace("\n", "\\n").replace("\r","\\r")
            # If THRESHOLD == 1, block immediately inline
            if THRESHOLD == 1:
                logger.info(f"Invalid magic from {src}:{dport} (v4) → “{snippet}”; auto‐blocking (THRESHOLD=1)")
                install_block(src, dport, False)
            else:
                try:
                    event_queue.put_nowait((src, dport, False, snippet))
                except queue.Full:
                    # If under extreme load, drop the event
                    pass
        return

    # IPv6 path:
    if pkt.haslayer(IPv6) and pkt.haslayer(TCP) and pkt.haslayer(Raw):
        src6 = pkt[IPv6].src
        dport = pkt[TCP].dport
        key6 = (src6, dport, True)

        # ─── SKIP THE V6 WHITELIST ─────────────────────────────────────────────────
        if src6 == WHITELIST_V6:
            return

        with state_lock:
            if key6 in blocked:
                return

        payload = bytes(pkt[Raw].load)
        if is_invalid_magic(payload):
            snippet = payload[:32].decode("utf-8", "ignore").replace("\n", "\\n").replace("\r","\\r")
            # If THRESHOLD == 1, block immediately inline
            if THRESHOLD == 1:
                logger.info(f"Invalid magic from {src6}:{dport} (v6) → “{snippet}”; auto‐blocking (THRESHOLD=1)")
                install_block(src6, dport, True)
            else:
                try:
                    event_queue.put_nowait((src6, dport, True, snippet))
                except queue.Full:
                    pass

def main():
    logger.info(
        f"Starting BitcoinMagicGuardDual on {NETWORK_INTERFACE}, port={CLIENT_PORT}, "
        f"v4‐whitelist={WHITELIST_V4}, v6‐whitelist={WHITELIST_V6}, "
        f"THRESHOLD={THRESHOLD}"
    )

    # Ensure SSH is allowed before blocking anything:
    #   sudo iptables  -I INPUT 1 -p tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
    #   sudo iptables  -I INPUT 2 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    #   sudo ip6tables -I INPUT 1 -p tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
    #   sudo ip6tables -I INPUT 2 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

    # If THRESHOLD > 1, spawn worker threads
    if THRESHOLD > 1:
        for _ in range(WORKER_COUNT):
            t = threading.Thread(target=worker_loop, daemon=True)
            t.start()

    # Launch sniff with the corrected BPF filter
    try:
        sniff(
            iface   = NETWORK_INTERFACE,
            prn     = packet_callback,
            store   = 0,
            filter  = BPF_FILTER
        )
    except PermissionError:
        logger.error("Permission denied: run as root (sudo).")
        sys.exit(1)
    except KeyboardInterrupt:
        logger.info("Interrupted by user. Exiting.")
        sys.exit(0)

if __name__ == "__main__":
    main()
