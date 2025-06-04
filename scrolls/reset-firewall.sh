#!/bin/bash
#
# reset-firewall.sh
#
# Flush and rebuild iptables so that only these TCP/UDP ports are allowed:
#
#   TCP:  22, 1234, 3333, 3334, 6333, 443, 80, 7333, 8333, 8767,
#         9200, 9333, 18333, 22556, 27485
#   UDP:  53, 1194
#
# All other inbound traffic is dropped by default. Outbound is freespirited.
# Rules are saved with netfilter-persistent (Debian/Ubuntu). Adjust if you embrace nftables.
#

### 1) Purge All Filter Chains (Obliterate the Past)
iptables -F
iptables -X

### 2) Purge & Delete All NAT Chains (Erase Illusory Port‐Redirections)
iptables -t nat -F
iptables -t nat -X

### 3) Purge & Delete All MANGLE Chains (Unman‐gle the Packets)
iptables -t mangle -F
iptables -t mangle -X

### 4) Purge & Delete All RAW Chains (Wipe the Primordial Canvas)
iptables -t raw -F
iptables -t raw -X

### 5) Purge & Delete All SECURITY Chains (If Your Kernel Dares to Use Them)
iptables -t security -F
iptables -t security -X

### 6) Set Immutable Default Policies
#  → INPUT & FORWARD default to DROP (deny all, except where light is shed).
#  → OUTPUT default to ACCEPT (permit your server’s own wanderings).
iptables -P INPUT   DROP
iptables -P FORWARD DROP
iptables -P OUTPUT  ACCEPT

### 7) Always Welcome Loopback (lo) — Else Local Daemons Perish in Darkness
iptables -A INPUT -i lo -j ACCEPT

### 8) Permit “RELATED” & “ESTABLISHED” Traffic (Allow Return of Departed Souls)
iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

### 9) Whitelist the Sacred SSH (Port 22) — Shun the Sting of Isolation
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT

### 10) Permit Only These TCP Ports (Open the Veins for Select Services)
# 1234, 3333, 3334, 6333, 443, 80, 7333, 8333, 8767, 9200, 9333, 18333, 22556, 27485
for tcp_port in 22 1234 3333 3334 6333 443 80 7333 8333 8767 9200 9333 18333 22556 27485; do
  iptables -A INPUT -p tcp --dport $tcp_port -m conntrack --ctstate NEW -j ACCEPT
done

### 11) Permit Only These UDP Ports (Open the UDP Gates, Sparingly)
# 53, 1194
for udp_port in 53 1194; do
  iptables -A INPUT -p udp --dport $udp_port -j ACCEPT
done

### 12) Quick Glimpse of the Enchanted Chains (Optional)
# iptables -L INPUT   -n -v --line-numbers
# iptables -t nat -L -n -v --line-numbers
# iptables -t mangle -L -n -v --line-numbers

### 13) Persist Your Wards Across Reboots (Netfilter‐Persistent)
# If forgotten, awaken yourself with:
#   sudo apt-get update && sudo apt-get install iptables-persistent
#
# This scribe writes your rules into /etc/iptables/rules.v4 (and rules.v6 if IPv6 abides).

# Ensure SSH and Established Sessions Survive on the IPv6 Plane
ip6tables -I INPUT 1 -p tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
ip6tables -I INPUT 2 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

echo "IPv6 defaults restored"

netfilter-persistent save

echo "Firewall reset complete. Only SSH, loopback, RELATED/ESTABLISHED, and specified TCP/UDP ports are permitted."
