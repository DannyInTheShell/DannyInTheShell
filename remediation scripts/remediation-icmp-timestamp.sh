#!/usr/bin/env bash
# remediation-icmp-timestamp.sh
# Purpose: Filter out ICMP timestamp request (13) and timestamp reply (14)
#          on Ubuntu 22.04. Prefers nftables; falls back to iptables.
# Usage: sudo ./remediation-icmp-timestamp.sh

# Author        : Danny Cologero
# Date Created  : 10-14-2025
# Date Modified : 10-14-2025
# Version       : 1.0

# See after script notes

set -euo pipefail

# ----- Helpers -----
info()  { printf "\e[1;34m[INFO]\e[0m %s\n" "$*"; }
warn()  { printf "\e[1;33m[WARN]\e[0m %s\n" "$*"; }
error() { printf "\e[1;31m[ERROR]\e[0m %s\n" "$*"; exit 1; }

if [ "$EUID" -ne 0 ]; then
  error "Run this script as root (use sudo)."
fi

# ----- nftables path (preferred) -----
if command -v nft >/dev/null 2>&1; then
  info "nft detected — using nftables path."

  # Ensure table and chains exist (create only if missing)
  if ! nft list table inet filter >/dev/null 2>&1; then
    info "Creating inet filter table and default chains (input/output)."
    nft add table inet filter
  fi

  if ! nft list chain inet filter input >/dev/null 2>&1; then
    info "Creating chain inet filter input."
    nft add chain inet filter input { type filter hook input priority 0 \; policy accept \; }
  fi

  if ! nft list chain inet filter output >/dev/null 2>&1; then
    info "Creating chain inet filter output."
    nft add chain inet filter output { type filter hook output priority 0 \; policy accept \; }
  fi

  # Idempotent add of rules: check if present first
  if nft list chain inet filter input | grep -q -- 'icmp type timestamp-request'; then
    info "INPUT rule for icmp type timestamp-request already present; skipping."
  else
    info "Adding INPUT rule to drop ICMP type 13 (timestamp-request)."
    nft insert rule inet filter input ip protocol icmp icmp type timestamp-request counter drop
  fi

  if nft list chain inet filter output | grep -q -- 'icmp type timestamp-reply'; then
    info "OUTPUT rule for icmp type timestamp-reply already present; skipping."
  else
    info "Adding OUTPUT rule to drop ICMP type 14 (timestamp-reply)."
    nft insert rule inet filter output ip protocol icmp icmp type timestamp-reply counter drop
  fi

  # Persist nftables rules to /etc/nftables.conf and enable nftables service
  info "Saving nftables rules to /etc/nftables.conf."
  nft list ruleset > /etc/nftables.conf

  if systemctl is-enabled --quiet nftables; then
    info "nftables service already enabled."
  else
    info "Enabling nftables service so rules load at boot."
    apt-get update >/dev/null
    apt-get install -y nftables >/dev/null
    systemctl enable --now nftables
  fi

  info "nftables rules installed and persisted."
  info "Current relevant rules:"
  nft list table inet filter | sed -n '/chain input/,/chain output/p'

  exit 0
fi

# ----- iptables fallback -----
if command -v iptables >/dev/null 2>&1; then
  info "nft not found; falling back to iptables."

  # Add INPUT rule for type 13 (timestamp-request) if not present
  if iptables -C INPUT -p icmp --icmp-type 13 -j DROP >/dev/null 2>&1; then
    info "INPUT DROP rule for icmp type 13 already exists; skipping."
  else
    info "Inserting INPUT DROP rule for icmp type 13 (timestamp-request)."
    iptables -I INPUT -p icmp --icmp-type 13 -j DROP
  fi

  # Add OUTPUT rule for type 14 (timestamp-reply) if not present
  if iptables -C OUTPUT -p icmp --icmp-type 14 -j DROP >/dev/null 2>&1; then
    info "OUTPUT DROP rule for icmp type 14 already exists; skipping."
  else
    info "Inserting OUTPUT DROP rule for icmp type 14 (timestamp-reply)."
    iptables -I OUTPUT -p icmp --icmp-type 14 -j DROP
  fi

  # Make persistent using iptables-persistent / netfilter-persistent
  info "Installing iptables-persistent to make rules persistent across reboots."
  DEBIAN_FRONTEND=noninteractive apt-get update >/dev/null
  DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent netfilter-persistent >/dev/null

  info "Saving current iptables rules."
  netfilter-persistent save

  info "iptables rules installed and saved."
  info "Showing matching iptables lines:"
  iptables -L -v -n | grep --color=never -E 'icmp|13|14' || true

  exit 0
fi

error "Neither nft nor iptables found on this system; cannot apply remediation."

# Basic Instructions:

# Download the script:
# wget https://raw.githubusercontent.com/dcgrx45/Cybersecurity-Projects/refs/heads/main/remediation-icmp-timestamp.sh --no-check-certificate
  # To connect to raw.githubusercontent.com insecurely, use `--no-check-certificate'

# Make script executable:
# chmod +x remediation-icmp-timestamp.sh

# Execute the script:
# ./remediation-icmp-timestamp.sh

# Notes, safety, and verification:

# If UFW (Uncomplicated Firewall) or another firewall manager is active, this script still adds rules at the kernel netfilter level; however, you should review how UFW interacts with nft/iptables on your system. UFW on Ubuntu 22.04 uses iptables/nft under the hood — the script is compatible but test on staging first.

# After running, verify from another host:
  # Using Nmap (Windows or Linux): nmap -sO -p 13,14 <host-ip> (should show filtered)
    # Note: You may get error if FW or NSG is blocking Ping: "Host seems down. If it is really up, but blocking our ping probes, try -Pn"
      # nmap -sO -Pn -p 13,14 <host-ip>
  # Using hping3 on Linux: sudo hping3 -1 --icmptype 13 <host-ip> (no reply expected)

# To inspect the rules:
  # nft: sudo nft list ruleset or sudo nft list table inet filter
  # iptables: sudo iptables -L -v -n
