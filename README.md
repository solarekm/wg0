# WireGuard VPN Router Setup for Ubuntu

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-Ubuntu-orange.svg)](https://ubuntu.com/)
[![Shell](https://img.shields.io/badge/shell-bash-green.svg)](https://www.gnu.org/software/bash/)

Automated setup script for WireGuard VPN router with firewall, DHCP server, and security features on Ubuntu/Debian/Raspberry Pi OS systems.

## 🚀 Quick Start

**Prerequisites:** Make sure you have `wg_client.conf` in the current directory.

Run directly from GitHub without cloning:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/solarekm/wg0/master/wg0-setup.sh)
```

Or download and run locally:

```bash
curl -fsSL https://raw.githubusercontent.com/solarekm/wg0/master/wg0-setup.sh -o wg0-setup.sh
chmod +x wg0-setup.sh
./wg0-setup.sh
```

Or clone the repository:

```bash
git clone https://github.com/solarekm/wg0.git
cd wg0
./wg0-setup.sh
```

## 📋 Table of Contents

- [Prerequisites](#-prerequisites)
- [Architecture](#-architecture)
- [What the Script Does](#-what-the-script-does)
- [Manual Installation Steps](#-manual-installation-steps)
- [Post-Installation](#-post-installation)
- [Client Configuration](#-client-configuration)
- [Testing Connection](#-testing-connection)
- [Managing WireGuard Router](#-managing-wireguard-router)
- [Troubleshooting](#-troubleshooting)
- [Script Features](#-script-features)
- [Files Included](#-files-included)
- [Contributing](#-contributing)
- [License](#-license)
- [Useful Links](#-useful-links)
- [Support](#-support)

---

## ✅ Prerequisites

### 1. Ubuntu/Debian System

This script is designed for Ubuntu and Debian-based systems with kernel version >= 5.6.

To check your kernel version:

```bash
uname -r
```

### 2. WireGuard Configuration File

You must have a `wg_client.conf` file in the same directory as the script. This file should contain your WireGuard client configuration with:

- `[Interface]` section with PrivateKey, Address, DNS, and PostUp/PreDown hooks
- `[Peer]` section with PublicKey, Endpoint, AllowedIPs

Example structure:

```ini
[Interface]
PrivateKey = <YOUR_PRIVATE_KEY_HERE>
Address = <VPN_CLIENT_IP>/32
DNS = <DNS_SERVER_IP>

# Routing rule for LAN traffic through WireGuard
PostUp = ip rule add from 192.168.10.0/24 table 51820 priority 100
PreDown = ip rule del from 192.168.10.0/24 table 51820 priority 100

# Load firewall rules
PostUp = nft -f /etc/nftables/firewall.nft

# NAT configuration
PostUp = nft add table ip nat 2>/dev/null || true
PostUp = nft add chain ip nat postrouting { type nat hook postrouting priority 100 \; } 2>/dev/null || true
PostUp = nft add rule ip nat postrouting oifname "wg0" masquerade
PreDown = nft delete table ip nat 2>/dev/null || true

[Peer]
PublicKey = <SERVER_PUBLIC_KEY_HERE>
PresharedKey = <PRESHARED_KEY_HERE>
AllowedIPs = 0.0.0.0/0
Endpoint = <SERVER_IP>:<SERVER_PORT>
PersistentKeepalive = 25
```

**Note:** If your `wg_client.conf` doesn't include PostUp/PreDown hooks, the script will add them automatically.

### 3. Sudo Access

The script requires sudo privileges to:
- Install system packages
- Configure network interfaces
- Set up firewall rules
- Create and manage system services
- Copy configuration to `/etc/wireguard/`
- Configure dnsmasq

### 4. Hardware Requirements (for Router Mode)

For full router functionality:
- Ethernet interface (eth0) for LAN clients
- WiFi or another network interface for internet connection
- Sufficient resources to handle NAT and firewall operations

**Note:** Ethernet cable does NOT need to be connected during installation. The script will configure the interface, and DHCP will work automatically when you plug in a cable later.

---

## 📊 Architecture

This script configures your system as a VPN router:

```
Internet ←→ Router (WiFi/WAN) ←→ LAN Clients (Ethernet)
             wg0 (VPN)        │       eth0 (192.168.10.x)
         [WireGuard Tunnel]   │   [DHCP Server]
         [Firewall nftables]  │   [dnsmasq]
```

**Traffic Flow:**
1. Router connects to internet via WAN/WiFi
2. WireGuard (wg0) creates secure VPN tunnel
3. LAN clients connect via Ethernet (eth0)
4. dnsmasq provides DHCP (192.168.10.10-14, 5 addresses)
5. All LAN traffic routed through WireGuard VPN
6. nftables firewall protects against unauthorized access

---

## 🎯 What the Script Does

The `wg0-setup.sh` script automatically:

✅ **Checks system compatibility**
- Verifies OS is Ubuntu/Debian/Raspberry Pi OS
- Checks for sudo privileges
- Confirms `wg_client.conf` exists

✅ **Installs all required packages**
- WireGuard tools and dependencies
- nftables firewall
- dnsmasq (DHCP server)
- unattended-upgrades (automatic security updates)

✅ **Configures network**
- Enables IP forwarding
- Configures eth0 with static IP (192.168.10.1/24)
- Sets up DHCP range (192.168.10.10-14, 5 addresses)

✅ **Configures WireGuard with automation**
- Adds PostUp/PreDown hooks for firewall and NAT
- Sets up routing rules for LAN traffic
- Enables NAT masquerading
- Sets proper permissions (600, root:root)

✅ **Creates and loads firewall (nftables)**
- Blocks unauthorized access
- Allows LAN → VPN traffic
- Blocks VPN → WiFi traffic
- Rate limiting and logging

✅ **Configures DHCP server (dnsmasq)**
- Serves IP addresses to LAN clients (5 addresses)
- Provides DNS and gateway configuration
- Creates systemd service

✅ **Starts all services**
- WireGuard VPN
- dnsmasq DHCP
- Verifies installation

---

## 📦 Manual Installation Steps

If you prefer manual installation:

Quick summary:

```bash
# 1. Install packages
sudo apt-get update
sudo apt-get install -y wireguard-tools openresolv dnsmasq nftables unattended-upgrades

# 2. Configure WireGuard with PostUp/PreDown hooks
sudo nano /etc/wireguard/wg0.conf

# 3. Create firewall rules
sudo mkdir -p /etc/nftables
sudo nano /etc/nftables/firewall.nft

# 4. Configure eth0 with static IP (192.168.10.1/24)

# 5. Enable IP forwarding
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -w net.ipv4.ip_forward=1

# 6. Configure dnsmasq
sudo nano /etc/dnsmasq.conf

# 7. Start services
sudo systemctl enable --now wg-quick@wg0
sudo systemctl enable --now dnsmasq

# 8. Verify
sudo wg show
ip addr show wg0
sudo nft list ruleset
```

---

## 🔄 Post-Installation

After the script completes:

1. **Verify WireGuard interface is up**:
   ```bash
   ip addr show wg0
   sudo wg show
   ```

2. **Check firewall is loaded**:
   ```bash
   sudo nft list ruleset | head -30
   ```

3. **Verify services are running**:
   ```bash
   sudo systemctl status wg-quick@wg0
   sudo systemctl status dnsmasq
   ```

4. **Connect a client device**:
   - Connect via Ethernet to eth0
   - Device should auto-receive IP (192.168.10.x)
   - Test: `curl ifconfig.me` (should show VPN IP)

5. **Monitor traffic**:
   ```bash
   sudo nft list chain inet filter forward
   ```

---

## 💻 Client Configuration

### Connect Device to LAN

Connect your device to the router's Ethernet port (eth0).

**Option A: DHCP (Automatic - Recommended)**

Set network configuration to automatic (DHCP). Device will receive:
- **IP:** 192.168.10.10-14 (automatic, 5 addresses available)
- **Gateway:** 192.168.10.1
- **DNS:** Automatically extracted from your WireGuard config

**Option B: Static Configuration**

- **IP Address:** 192.168.10.2 (or any .2-.9 or .15-.254 outside DHCP range)
- **Subnet Mask:** 255.255.255.0
- **Gateway:** 192.168.10.1
- **DNS Server:** Use DNS from your WireGuard configuration

### Refresh Connection

**Windows:**
```cmd
ipconfig /release
ipconfig /renew
ipconfig /all
```

**Linux:**
```bash
sudo dhclient -r eth0
sudo dhclient eth0
ip addr show
```

**macOS:**
```
System Preferences → Network → Disconnect/Reconnect
```

---

## ✅ Testing Connection

### Test 1: Basic Connectivity

```bash
# Test connection to router
ping 192.168.10.1

# Test internet (direct IP)
ping 8.8.8.8

# Test DNS resolution
ping google.com

# Check route
traceroute google.com  # First hop should be 192.168.10.1
```

### Test 2: Verify VPN IP

Visit https://ifconfig.me or run:
```bash
curl ifconfig.me
```

**Should show your WireGuard VPN IP, NOT your ISP IP.**

### Test 3: Monitor Router Traffic

On the router, check traffic counters:
```bash
sudo nft list chain inet filter forward
```

You should see packet counts increasing.

---

## 🔧 Managing WireGuard Router

### WireGuard Service

```bash
# Check status
sudo systemctl status wg-quick@wg0

# Stop VPN (stops all routing)
sudo systemctl stop wg-quick@wg0

# Start VPN (loads firewall, NAT, and routing)
sudo systemctl start wg-quick@wg0

# Restart VPN
sudo systemctl restart wg-quick@wg0

# Disable autostart on boot
sudo systemctl disable wg-quick@wg0

# Enable autostart on boot
sudo systemctl enable wg-quick@wg0
```

### DHCP Server (dnsmasq)

```bash
# Check status
sudo systemctl status dnsmasq

# View active DHCP leases
cat /var/lib/misc/dnsmasq.leases

# View connected devices
ip neigh show dev eth0

# Restart DHCP server
sudo systemctl restart dnsmasq
```

### Firewall (nftables)

```bash
# View all firewall rules
sudo nft list ruleset

# View traffic counters
sudo nft list chain inet filter forward

# Reload firewall
sudo nft -f /etc/nftables/firewall.nft

# Check firewall logs
sudo journalctl -k | grep "DROP"
```

---

## 🐛 Troubleshooting

### eth0 Has No Address (DHCP Not Working)

**Symptom:** Clients don't receive IP addresses. dnsmasq logs show:
```
DHCP packet received on eth0 which has no address
```

**Cause:** eth0 lost its IP address (NetworkManager or systemd-networkd removed it).

**Solution:**
```bash
# Check current eth0 status
ip addr show eth0

# Manually assign IP
sudo ip addr add 192.168.10.1/24 dev eth0
sudo ip link set eth0 up

# Restart dnsmasq
sudo systemctl restart dnsmasq

# For permanent fix with systemd-networkd:
sudo tee /etc/systemd/network/10-eth0-static.network > /dev/null << EOF
[Match]
Name=eth0

[Network]
Address=192.168.10.1/24
EOF

sudo systemctl restart systemd-networkd
```

### Client Gets 169.254.x.x Address

**Cause:** DHCP server not working.

**Solution:**
```bash
# On router - check eth0
ip addr show eth0

# Check dnsmasq
sudo systemctl status dnsmasq
sudo journalctl -u dnsmasq -n 50

# Restart dnsmasq
sudo systemctl restart dnsmasq
```

### External IP Shows ISP, Not VPN

**Cause:** Routing or NAT not working.

**Solution:**
```bash
# Check routing rule
ip rule list | grep 192.168.10

# Check NAT
sudo nft list ruleset | grep masquerade

# Restart WireGuard (reloads everything)
sudo systemctl restart wg-quick@wg0
```

### Lost SSH/Remote Access After Installation

**Cause:** Firewall blocks SSH access from WiFi/WAN interface.

**Solution (requires physical access or serial console):**
```bash
# Temporarily disable firewall to regain SSH access
sudo nft flush ruleset

# Stop WireGuard to disable routing rules
sudo systemctl stop wg-quick@wg0

# Now you can SSH again from WiFi network
# After connecting via SSH, you can:

# Option 1: Add SSH rule to firewall (replace wlan0 with your WiFi interface)
sudo nft add rule inet filter input iifname "wlan0" tcp dport 22 accept

# Option 2: Permanently allow SSH on WiFi interface
# Edit /etc/nftables/firewall.nft and add under input chain:
# iifname "wlan0" tcp dport 22 accept

# Restart WireGuard
sudo systemctl start wg-quick@wg0
```

**Prevention:** If you need SSH access, configure it before installation or add firewall rules manually.

### Firewall Blocks Traffic

**Solution:**
```bash
# Check firewall logs
sudo journalctl -k | grep "FORWARD DROP"

# View firewall rules
sudo nft list ruleset

# Reload firewall
sudo nft -f /etc/nftables/firewall.nft

# Temporarily disable firewall for testing
sudo nft flush ruleset
```

### Interface Not Found

If `wg0` interface is not visible after installation:

```bash
# Check service status
sudo systemctl status wg-quick@wg0

# View recent errors
journalctl -u wg-quick@wg0 -n 50

# Try manual start
sudo wg-quick up wg0
```

### Connection Issues

```bash
# Check if packets are being sent/received
sudo wg show

# Verify routing
ip route

# Test DNS
nslookup google.com

# Check firewall
sudo iptables -L -n -v
```

### Configuration Errors

```bash
# Validate configuration syntax
sudo wg-quick up wg0 --dry-run

# Check configuration file
sudo cat /etc/wireguard/wg0.conf

# Restore backup if needed
sudo cp /etc/wireguard/wg0.conf.backup.* /etc/wireguard/wg0.conf
```

### Permission Denied

If you see permission errors:

```bash
# Verify file permissions
ls -l /etc/wireguard/wg0.conf

# Fix permissions
sudo chmod 600 /etc/wireguard/wg0.conf
sudo chown root:root /etc/wireguard/wg0.conf
```

---

## 🔍 Script Features

### Error Handling
- Strict error handling (`set -euo pipefail`)
- Clear error messages with color coding
- Graceful handling of existing installations

### Idempotency
- Safe to run multiple times
- Checks if WireGuard is already installed
- Backs up existing configurations

### Security
- **Firewall:** nftables with strict rules (drop by default)
- **Network isolation:** Prevents VPN → WiFi traffic
- **Rate limiting:** Protects against flooding attacks
- Sets proper file permissions (600 for WireGuard config)
- Validates configuration files before applying
- Requires sudo authentication

**Note:** SSH and fail2ban are NOT included - if you need SSH access, configure it manually with proper security.

### Logging
- Color-coded output:
  - 🟢 Green = Info
  - 🟡 Yellow = Warning
  - 🔴 Red = Error
  - 🔵 Blue = Success

---

## 📁 Files Included

- **`wg0-setup.sh`** - Comprehensive router installation script
- **`README.md`** - This documentation

### Auto-Generated Files:
- **`/etc/wireguard/wg0.conf`** - WireGuard config with PostUp/PreDown hooks
- **`/etc/nftables/firewall.nft`** - Firewall ruleset
- **`/etc/dnsmasq.conf`** - DHCP server configuration

---

## 🤝 Contributing

Feel free to submit issues or pull requests to improve this script.

---

## 📄 License

This project is open source and available under the MIT License.

---

## 🔗 Useful Links

### Official Documentation
- [WireGuard Official Site](https://www.wireguard.com/)
- [WireGuard Quick Start](https://www.wireguard.com/quickstart/)
- [Ubuntu WireGuard Guide](https://ubuntu.com/server/docs/wireguard-vpn)

### Tutorials
- [DigitalOcean WireGuard Tutorial](https://www.digitalocean.com/community/tutorials/how-to-set-up-wireguard-on-ubuntu-20-04)
- [Arch Wiki - WireGuard](https://wiki.archlinux.org/title/WireGuard)

---

## 📮 Support

For issues related to:
- WireGuard itself: Check [WireGuard Mailing List](https://lists.zx2c4.com/mailman/listinfo/wireguard)
- This script: Open an issue in this repository

---

**Made with ❤️ for secure VPN connections on Ubuntu**