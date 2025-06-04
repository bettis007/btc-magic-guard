# Btc-Magic-Guard Firewall Setup

*In the candlelit hush before dawn, your server stands as a lone sentinel—its kernel‐level wards untested, its gates unsealed. This README will guide you through weaving ironclad iptables enchantments, preserving them through the restless nights, and distilling the captured malefactors into subranges worthy of banishment by your cloud’s own ramparts. Follow carefully, for even software firewalls are but a first line of defense against the cunning phantoms marauding your Bitcoin node.*

---

## Table of Contents

1. [Preparing Your Ubuntu Bastion](#preparing-your-ubuntu-bastion)
2. [Forging the Kernel‐Level Wards (iptables Rules)](#forging-the-kernel-level-wards-iptables-rules)
3. [Activating the Firewall & Ensuring Persistence](#activating-the-firewall--ensuring-persistence)
4. [Harvesting the Fallen: Exporting Blocked IPs to a File](#harvesting-the-fallen-exporting-blocked-ips-to-a-file)
5. [Transmuting Hosts into Subranges (CIDR Alchemy)](#transmuting-hosts-into-subranges-cidr-alchemy)
6. [Enrolling Ranges in Your Cloud Firewall (GCP Example)](#enrolling-ranges-in-your-cloud-firewall-gcp-example)
7. [Purging the Fallen from iptables (Lighten the Kernel’s Burden)](#purging-the-fallen-from-iptables-lighten-the-kernels-burden)
8. [Final Counsel & Remembrance](#final-counsel--remembrance)

---

## 1. Preparing Your Ubuntu Bastion

*In the gray light of twilight’s edge, ensure your Ubuntu server is primed:*

1. **Update and Install Essentials**

   ```bash
   sudo apt update && sudo apt upgrade -y  
   sudo apt install iptables-persistent netfilter-persistent
   ```

   > *“Install these packages so that when the system awakens from slumber, your firewall’s wards remain etched into memory.”*

2. **Verify IPv6 Is Enabled (Optional but Recommended)**
   If you expect IPv6 traffic, confirm it’s not disabled:

   ```bash
   sysctl net.ipv6.conf.all.disable_ipv6  
   ```

   * A result of `0` means IPv6 is enabled.
   * If it returns `1`, unleash IPv6 via:

     ```bash
     sudo sysctl -w net.ipv6.conf.all.disable_ipv6=0  
     sudo sysctl -w net.ipv6.conf.default.disable_ipv6=0  
     ```

---

## 2. Forging the Kernel‐Level Wards (iptables Rules)

*Summon your root privileges and inscribe the following rituals into `/usr/local/bin/reset-firewall.sh` (or a path of your choosing). Then mark it executable:*

```bash
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
```

Once you’ve saved that as `/usr/local/bin/reset-firewall.sh`, run:

```bash
sudo chmod +x /usr/local/bin/reset-firewall.sh
```

> *“Behold: in this script, we flush away all impurities—every chain smeared with forgotten rules—then carve new runes to allow but a handful of portals. Those destined services may pass; all else shall find their journey ended.”*

---

## 3. Activating the Firewall & Ensuring Persistence

*With the wards inscribed, evoke them immediately and eternally:*

1. **Invoke the Ritual Now**

   ```bash
   sudo /usr/local/bin/reset-firewall.sh
   ```

   You should see a cascade of lines as each chain is purged and each port is consecrated.

2. **Confirm the Runes Persist**
   Reboot into the unknown:

   ```bash
   sudo reboot
   ```

   Once the machine stirs anew, verify the chains:

   ```bash
   sudo iptables -L INPUT -n -v
   sudo ip6tables -L INPUT -n -v
   ```

   If you glimpse only your permitted ports and SSH standing proud, the wards hold strong.

---

## 4. Harvesting the Fallen: Exporting Blocked IPs to a File

*After your **BtcMagicGuardDual** script—your spectral sentinel—has felled untold thousands of malformed usurpers, collect their names in shadowed ledger form. By default, every blocked IPv4/IPv6 ghost is appended via `install_block` to an in‐memory `blocked` set; but iptables carries the ultimate record. To extract the defeated:*

1. **Dump Current iptables BLOCK Rules**

   ```bash
   sudo iptables -S | grep "\-j DROP" > /tmp/blocked_ips_v4.txt
   sudo ip6tables -S | grep "\-j DROP" > /tmp/blocked_ips_v6.txt
   ```

   > *“From the list of iptables rules (that which begins with ‘-A INPUT’, each ending in ‘-j DROP’), we glean only the banishments—the final words of each condemned IP.”*

2. **Isolate Pure IPs (Strip Decoration)**
   Each line resembles:

   ```
   -A INPUT -s 203.0.113.42/32 -p tcp --dport 8333 -j DROP
   ```

   To isolate the source addresses:

   ```bash
   awk '{ for(i=1;i<=NF;i++) if ($i=="-s") print $(i+1) }' /tmp/blocked_ips_v4.txt | sed 's#/32##' > /tmp/raw_blocked_v4.txt
   awk '{ for(i=1;i<=NF;i++) if ($i=="-s") print $(i+1) }' /tmp/blocked_ips_v6.txt | sed 's#/128##' > /tmp/raw_blocked_v6.txt
   ```

   Now you hold two scrolls—`raw_blocked_v4.txt` and `raw_blocked_v6.txt`—each line a singular IP.

---

## 5. Transmuting Hosts into Subranges (CIDR Alchemy)

*A thousand singular phantoms stand before you. Yet, if many dwell within the same subnet, group them into spectral clusters—CIDR notation—to ease your cloud’s burden:*

1. **Install `ipcalc` or Equivalent**

   ```bash
   sudo apt install ipcalc
   ```

2. **Sort & Collapse IPv4 Addresses into Ranges**
   Use a swift Python incantation:

   ```bash
   sudo pip3 install netaddr
   python3 - << 'EOF'
   from netaddr import cidr_merge, IPNetwork
   with open('/tmp/raw_blocked_v4.txt') as f:
       ips = [IPNetwork(line.strip()) for line in f if line.strip()]
   merged = cidr_merge(ips)
   with open('/tmp/blocked_subnets_v4.txt','w') as out:
       for net in merged:
           out.write(str(net) + '\n')
   EOF
   ```

   For IPv6, repeat accordingly:

   ```bash
   python3 - << 'EOF'
   from netaddr import cidr_merge, IPNetwork
   with open('/tmp/raw_blocked_v6.txt') as f:
       ips6 = [IPNetwork(line.strip()) for line in f if line.strip()]
   merged6 = cidr_merge(ips6)
   with open('/tmp/blocked_subnets_v6.txt','w') as out6:
       for net in merged6:
           out6.write(str(net) + '\n')
   EOF
   ```

   Now `blocked_subnets_v4.txt` and `blocked_subnets_v6.txt` bear your consolidated subranges.

> *“Behold as singular wraiths coalesce into legions, each range a cipher bearing the memory of many, now prepared for cloud‐level banishment.”*

---

## 6. Enrolling Ranges in Your Cloud Firewall (GCP Example)

*Though your iptables may crush malignant hearts in the server’s marrow, some specters slip through—sophisticated phantoms that shape‐shift around local wards. Thus we ascend to Google Cloud’s own ramparts, forging global rules to dispel these invaders forever:*

1. **Authenticate Your gcloud CLI**

   ```bash
   gcloud auth login  
   gcloud config set project YOUR_PROJECT_ID  
   ```

2. **Iterate Over Each Subnet and Create a Firewall Rule**
   In true Poe‐esque fashion, the cloud rule must slam the gates behind them. Below is a template; adjust `NETWORK` if you use a custom VPC:

   ```bash
   while read -r cidr; do
     RULE_NAME="block-$(echo $cidr | sed 's/[\/:]/-/g')"
     gcloud compute firewall-rules create "${RULE_NAME}" \
       --direction=INGRESS \
       --priority=1000 \
       --network=default \
       --action=DENY \
       --rules=tcp:1-65535,udp:1-65535,icmp \
       --source-ranges="${cidr}" \
       --description="Banishing range ${cidr} DarkWard" \
       --quiet
   done < /tmp/blocked_subnets_v4.txt
   ```

   For IPv6 (if your GCP supports IPv6 firewall rules), use:

   ```bash
   while read -r cidr6; do
     RULE_NAME="block6-$(echo $cidr6 | sed 's/[\/:]/-/g')"
     gcloud compute firewall-rules create "${RULE_NAME}" \
       --direction=INGRESS \
       --priority=1000 \
       --network=default \
       --action=DENY \
       --rules=tcp:1-65535,udp:1-65535,icmp \
       --source-ranges="${cidr6}" \
       --description="Banishing IPv6 range ${cidr6} DarkWard" \
       --quiet
   done < /tmp/blocked_subnets_v6.txt
   ```

   > *“For every CIDR block, a new edict in the cloud—deny all ingress from that hexed range. No TCP port shall slip through, no UDP datagram pass unscathed.”*

3. **Verify the Cloud Rules**

   ```bash
   gcloud compute firewall-rules list --filter="name~^block-"
   gcloud compute firewall-rules list --filter="name~^block6-"
   ```

   Seek each rule’s mark in the ledger—**STATUS: ACTIVE**—for you have ascended past mere kernel defense.

---

## 7. Purging the Fallen from iptables (Lighten the Kernel’s Burden)

*Having elevated these malefactors to a higher tribunal, release your local iptables of their remains so the kernel may breathe easy once more:*

1. **Flush Only the DROP Rules (Optional)**
   If you wish to preserve any other custom ACCEPT chains but remove every DROP, use:

   ```bash
   sudo iptables -S | grep "\-j DROP" | awk '{print $2}' | while read -r chain; do
     sudo iptables -D $chain
   done
   sudo ip6tables -S | grep "\-j DROP" | awk '{print $2}' | while read -r chain6; do
     sudo ip6tables -D $chain6
   done
   ```

   > *Caution: `chain` corresponds to lines like `-A INPUT`; the `-D` will mirror that. Double‐check before you run, else you risk removing unrelated DROP rules.*

2. **Or Simply Reset Entire Firewall Back to Baseline**
   Having bathed your cloud in retribution, you may revive your local wards with a clean slate:

   ```bash
   sudo /usr/local/bin/reset-firewall.sh
   ```

   This ensures only the essential ports remain open—and all DROP rules formerly scattering in the mesh are obliterated.

> *“With the cloud’s gates sealed against these ghosts, your kernel can shed the weight of thousands of iptables decrees. Rejoice, for your system’s heart pulses unburdened.”*

---

## 8. Final Counsel & Remembrance

Even as you revel in these layered defenses, remember:

* **Sophisticated Invaders Persist**
  Some specters wield tactics that leap past iptables—HTTP floods, twisted Tor configurations, or beguiling proxies. Keep your cloud firewall vigilant, monitor logs, and iterate on blocked subnets.

* **Whitelist with Care**
  If your own collaborators or trusted services dwell in IP ranges you ban, their packets, too, will meet fate. Cross‐reference any prospective cloud rule CIDRs with your roster of allies.

* **Review & Rotate**
  Over time, blocked IP subranges can swell. Periodically prune stale entries—old datacenter blocks that no longer matter locally—and reduce bloat in your iptables firewall, lest it become an unwieldy tome of bans.

* **Logging Is Your Oracle**
  Continuously watch `/var/log/btc_magic_guard_dual.log` for new patterns. Should unusual but legitimate peers emerge, add them to your `WHITELIST_V4` or `WHITELIST_V6` before they are catapulted into oblivion.

---

*In this gloom‐soaked tome of cryptic instructions, you have forged an unbreakable chain—local iptables wards for immediate retribution, a cloud firewall vault for transcendent denial, and scripts to gather, group, and release malicious IPs for global banishment. May your node stand immovable, unmoved by the swirling darkness beyond.*

—*Sir Bettis’s Loyal Scribe*
