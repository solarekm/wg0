#!/usr/bin/env bash

# WireGuard Router Setup Script for Ubuntu/Raspberry Pi
# Automatically configures WireGuard VPN router with firewall, DHCP, and security

# Strict error handling
set -euo pipefail

# Colors for messages
readonly RED="\e[31m"
readonly GREEN="\e[32m"
readonly YELLOW="\e[33m"
readonly BLUE="\e[34m"
readonly NC="\e[0m"

# Script constants
# Handle both local and piped execution (curl | bash)
SCRIPT_SOURCE="${BASH_SOURCE[0]:-$0}"
readonly SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_SOURCE")" 2>/dev/null && pwd || echo "$PWD")"
WG_CONF_SOURCE=""  # Will be set in check_config_file()
readonly WG_CONF_DEST="/etc/wireguard/wg0.conf"
readonly WG_INTERFACE="wg0"
readonly ETH_INTERFACE="eth0"
readonly ETH_IP="192.168.10.1/24"
readonly DHCP_RANGE_START="192.168.10.10"
readonly DHCP_RANGE_END="192.168.10.14"

# DNS server (will be extracted from wg_client.conf)
DNS_SERVER=""

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

log_success() {
    echo -e "${BLUE}[SUCCESS]${NC} $*"
}

# Check if running on Ubuntu/Debian
check_os() {
    if [[ ! -f /etc/os-release ]]; then
        log_error "Cannot detect OS. This script is designed for Ubuntu/Debian/Raspberry Pi OS."
        exit 1
    fi
    
    . /etc/os-release
    if [[ "$ID" != "ubuntu" && "$ID" != "debian" && "$ID" != "raspbian" ]]; then
        log_warn "This script is designed for Ubuntu/Debian/Raspberry Pi OS. Detected: $ID"
        read -p "Continue anyway? (y/N) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
    
    log_info "Operating system: $PRETTY_NAME"
}

# Verify sudo access is available
check_sudo() {
    if ! sudo -n true 2>/dev/null; then
        log_warn "This script requires sudo privileges"
        sudo -v || {
            log_error "Failed to obtain sudo privileges"
            exit 1
        }
    fi
}

# Check if WireGuard configuration file exists
check_config_file() {
    # Check in current directory first (for curl execution)
    if [[ -f "$PWD/wg_client.conf" ]]; then
        WG_CONF_SOURCE="$PWD/wg_client.conf"
        log_info "Found configuration file: $WG_CONF_SOURCE"
        return 0
    fi
    
    # Check in script directory (for local execution)
    if [[ -f "$SCRIPT_DIR/wg_client.conf" ]]; then
        WG_CONF_SOURCE="$SCRIPT_DIR/wg_client.conf"
        log_info "Found configuration file: $WG_CONF_SOURCE"
        return 0
    fi
    
    # Not found in either location
    log_error "Configuration file not found: wg_client.conf"
    log_error "Please ensure wg_client.conf exists in the current directory"
    log_error "Current directory: $PWD"
    exit 1
}

# Extract DNS server from wg_client.conf
extract_dns_from_config() {
    log_info "Extracting DNS server from configuration..."
    
    # Extract DNS line from wg_client.conf (format: DNS = x.x.x.x)
    DNS_SERVER=$(grep -E "^DNS[[:space:]]*=" "$WG_CONF_SOURCE" | sed -E 's/^DNS[[:space:]]*=[[:space:]]*([^[:space:]]+).*/\1/' | head -n 1)
    
    if [[ -z "$DNS_SERVER" ]]; then
        log_warn "No DNS entry found in $WG_CONF_SOURCE"
        log_warn "Using fallback DNS: 1.1.1.1 (Cloudflare)"
        DNS_SERVER="1.1.1.1"
    elif [[ "$DNS_SERVER" == "<"* ]]; then
        # DNS is still a placeholder
        log_warn "DNS is a placeholder in $WG_CONF_SOURCE: $DNS_SERVER"
        log_warn "Using fallback DNS: 1.1.1.1 (Cloudflare)"
        DNS_SERVER="1.1.1.1"
    else
        log_success "Extracted DNS server: $DNS_SERVER"
    fi
}

# Install required packages
install_packages() {
    log_info "Updating package lists and installing required packages..."
    
    sudo apt-get update
    sudo apt-get install -y \
        wireguard-tools \
        openresolv \
        dnsmasq \
        unattended-upgrades \
        apt-listchanges \
        nftables \
        net-tools \
        iptables
    
    log_success "All packages installed successfully"
}

# Enable IP forwarding
enable_ip_forwarding() {
    log_info "Enabling IP forwarding..."
    
    if grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf; then
        log_info "IP forwarding already enabled in sysctl.conf"
    else
        echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf > /dev/null
        log_success "IP forwarding enabled in sysctl.conf"
    fi
    
    sudo sysctl -w net.ipv4.ip_forward=1 > /dev/null
    log_success "IP forwarding activated"
}

# Configure eth0 with static IP (persistent configuration)
configure_eth0() {
    log_info "Configuring $ETH_INTERFACE with static IP..."
    
    # Check if interface exists (physical interface, cable not required)
    if ! ip link show "$ETH_INTERFACE" &> /dev/null; then
        log_warn "Interface $ETH_INTERFACE not found. Skipping eth0 configuration."
        log_warn "You may need to configure it manually for DHCP server functionality."
        return 0
    fi
    
    log_info "Found interface $ETH_INTERFACE (cable connection not required)"
    
    # Try NetworkManager first (Ubuntu Desktop)
    if command -v nmcli &> /dev/null && systemctl is-active --quiet NetworkManager 2>/dev/null; then
        log_info "Using NetworkManager for persistent configuration..."
        
        # Check if connection exists
        local connection_name=$(nmcli -t -f NAME,DEVICE connection show | grep ":$ETH_INTERFACE\$" | cut -d: -f1 | head -n1)
        
        if [[ -z "$connection_name" ]]; then
            # Create new connection
            log_info "Creating new NetworkManager connection for $ETH_INTERFACE"
            sudo nmcli connection add \
                type ethernet \
                ifname "$ETH_INTERFACE" \
                con-name "eth0-static" \
                ipv4.method manual \
                ipv4.addresses "$ETH_IP" || {
                log_warn "Failed to create NetworkManager connection"
                return 1
            }
            connection_name="eth0-static"
        else
            # Modify existing connection
            log_info "Modifying existing connection: $connection_name"
            sudo nmcli connection modify "$connection_name" \
                ipv4.method manual \
                ipv4.addresses "$ETH_IP" || {
                log_warn "Failed to modify NetworkManager connection"
                return 1
            }
        fi
        
        # Activate connection (will work even without cable)
        sudo nmcli connection up "$connection_name" 2>/dev/null || true
        log_success "NetworkManager configuration applied (persistent)"
        
    # Try systemd-networkd (Raspberry Pi, Ubuntu Server)
    elif command -v networkctl &> /dev/null; then
        log_info "Using systemd-networkd for persistent configuration..."
        
        # Create systemd-networkd configuration
        sudo mkdir -p /etc/systemd/network
        sudo tee /etc/systemd/network/10-eth0-static.network > /dev/null << EOF
[Match]
Name=$ETH_INTERFACE

[Network]
Address=$ETH_IP
EOF
        
        # Enable and restart systemd-networkd
        sudo systemctl enable systemd-networkd 2>/dev/null || true
        sudo systemctl restart systemd-networkd || {
            log_warn "Failed to restart systemd-networkd, trying to start..."
            sudo systemctl start systemd-networkd || true
        }
        
        log_success "systemd-networkd configuration applied (persistent)"
        
    # Fallback to /etc/network/interfaces (Classic Debian)
    elif [[ -d /etc/network ]]; then
        log_info "Using /etc/network/interfaces for persistent configuration..."
        
        # Backup existing configuration
        if [[ -f /etc/network/interfaces ]]; then
            sudo cp /etc/network/interfaces /etc/network/interfaces.backup.$(date +%Y%m%d_%H%M%S)
        fi
        
        # Remove existing eth0 configuration
        sudo sed -i "/iface $ETH_INTERFACE/,/^$/d" /etc/network/interfaces 2>/dev/null || true
        
        # Add static configuration
        sudo tee -a /etc/network/interfaces > /dev/null << EOF

# Static configuration for $ETH_INTERFACE (WireGuard Router)
auto $ETH_INTERFACE
iface $ETH_INTERFACE inet static
    address 192.168.10.1
    netmask 255.255.255.0
EOF
        
        # Bring interface up with new configuration
        sudo ifdown "$ETH_INTERFACE" 2>/dev/null || true
        sudo ifup "$ETH_INTERFACE" 2>/dev/null || true
        
        log_success "/etc/network/interfaces configuration applied (persistent)"
    else
        log_warn "No supported network manager found"
        log_warn "Falling back to temporary configuration with ip command..."
    fi
    
    # Always try to apply IP immediately (even if persistent config is set)
    sudo ip addr flush dev "$ETH_INTERFACE" 2>/dev/null || true
    sudo ip addr add "$ETH_IP" dev "$ETH_INTERFACE" 2>/dev/null || true
    sudo ip link set "$ETH_INTERFACE" up 2>/dev/null || true
    
    # Verify configuration (might show "no carrier" if cable not connected - that's OK)
    sleep 1
    local eth_status=$(ip -br addr show "$ETH_INTERFACE" 2>/dev/null || echo "unknown")
    if echo "$eth_status" | grep -q "192.168.10.1"; then
        log_success "Interface configured: $eth_status"
        if echo "$eth_status" | grep -qi "no-carrier\|down"; then
            log_info "Note: Cable not connected - DHCP will work when cable is plugged in"
        fi
    else
        log_warn "Could not verify IP assignment. Status: $eth_status"
        log_warn "Configuration saved but IP not active. Check after plugging cable."
    fi
}

# Create nftables firewall configuration
create_firewall() {
    log_info "Creating nftables firewall configuration..."
    
    sudo mkdir -p /etc/nftables
    
    sudo tee /etc/nftables/firewall.nft > /dev/null << 'EOF'
#!/usr/sbin/nft -f

# Flush all rules
flush ruleset

# ==========================================
# INPUT CHAIN - traffic TO router
# ==========================================
table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;

        # Accept established connections
        ct state established,related accept

        # Accept loopback
        iif lo accept

        # Accept ICMP (ping) - rate limited
        ip protocol icmp limit rate 5/second accept
        ip6 nexthdr icmpv6 limit rate 5/second accept

        # DHCP for clients on eth0
        iifname "eth0" udp dport 67 accept

        # DNS for clients on eth0
        iifname "eth0" tcp dport 53 accept
        iifname "eth0" udp dport 53 accept

        # Log and drop the rest
        limit rate 5/minute log prefix "INPUT DROP: "
        drop
    }

    # ==========================================
    # FORWARD CHAIN - traffic THROUGH router
    # ==========================================
    chain forward {
        type filter hook forward priority 0; policy drop;

        # Accept established connections
        ct state established,related accept

        # LAN → WireGuard: accept all
        iifname "eth0" oifname "wg0" accept

        # WireGuard → LAN: only established
        iifname "wg0" oifname "eth0" ct state established,related accept

        # Counters for monitoring
        iifname "eth0" oifname "wg0" counter
        iifname "wg0" oifname "eth0" counter

        # Log dropped packets
        limit rate 5/minute log prefix "FORWARD DROP: "
        drop
    }

    # ==========================================
    # OUTPUT CHAIN - traffic FROM router
    # ==========================================
    chain output {
        type filter hook output priority 0; policy accept;
        # Allow all outgoing traffic from router
    }
}
EOF
    
    sudo chmod 644 /etc/nftables/firewall.nft
    
    # Test firewall syntax
    if sudo nft -c -f /etc/nftables/firewall.nft; then
        log_success "Firewall configuration created and validated"
    else
        log_error "Firewall configuration has syntax errors"
        exit 1
    fi
}

# Configure WireGuard with PostUp/PreDown hooks
configure_wireguard() {
    log_info "Configuring WireGuard..."
    
    # Create wireguard directory if it doesn't exist
    sudo mkdir -p /etc/wireguard
    
    # Backup existing config if present
    if [[ -f "$WG_CONF_DEST" ]]; then
        local backup_file="${WG_CONF_DEST}.backup.$(date +%Y%m%d_%H%M%S)"
        log_warn "Existing configuration found. Creating backup: $backup_file"
        sudo cp "$WG_CONF_DEST" "$backup_file"
    fi
    
    # Read the source config
    local config_content
    config_content=$(cat "$WG_CONF_SOURCE")
    
    # Check if PostUp/PreDown already exist
    if echo "$config_content" | grep -q "PostUp"; then
        log_info "WireGuard config already contains PostUp/PreDown rules"
        sudo cp "$WG_CONF_SOURCE" "$WG_CONF_DEST"
    else
        log_info "Adding PostUp/PreDown rules to WireGuard configuration..."
        
        # Add PostUp/PreDown after [Interface] section
        echo "$config_content" | sudo tee "$WG_CONF_DEST" > /dev/null
        
        # Insert PostUp/PreDown rules after DNS line or Address line
        sudo sed -i '/^DNS\s*=/a \
\
# Routing rule for LAN traffic through WireGuard\
PostUp = ip rule add from 192.168.10.0/24 table 51820 priority 100\
PreDown = ip rule del from 192.168.10.0/24 table 51820 priority 100\
\
# Load firewall rules\
PostUp = nft -f /etc/nftables/firewall.nft\
\
# NAT configuration\
PostUp = nft add table ip nat 2>/dev/null || true\
PostUp = nft add chain ip nat postrouting { type nat hook postrouting priority 100 \\; } 2>/dev/null || true\
PostUp = nft add rule ip nat postrouting oifname "wg0" masquerade\
PreDown = nft delete table ip nat 2>/dev/null || true' "$WG_CONF_DEST"
    fi
    
    # Set proper permissions
    sudo chmod 600 "$WG_CONF_DEST"
    sudo chown root:root "$WG_CONF_DEST"
    
    log_success "WireGuard configuration completed"
}

# Configure dnsmasq DHCP server
configure_dnsmasq() {
    log_info "Configuring dnsmasq DHCP server..."
    
    # Backup existing config
    if [[ -f /etc/dnsmasq.conf ]]; then
        sudo cp /etc/dnsmasq.conf /etc/dnsmasq.conf.backup.$(date +%Y%m%d_%H%M%S)
    fi
    
    # Create dnsmasq configuration
    sudo tee /etc/dnsmasq.conf > /dev/null << EOF
# Interface to listen on
interface=$ETH_INTERFACE

# Bind to interface dynamically (works even if interface is down)
bind-dynamic

# DHCP range for LAN devices
dhcp-range=$DHCP_RANGE_START,$DHCP_RANGE_END,255.255.255.0,24h

# Gateway for clients
dhcp-option=3,192.168.10.1

# DNS server (from WireGuard config)
dhcp-option=6,$DNS_SERVER

# Disable DNS forwarding
no-resolv
no-poll
EOF
    
    # Create systemd service for dnsmasq
    sudo tee /etc/systemd/system/dnsmasq.service > /dev/null << 'EOF'
[Unit]
Description=dnsmasq - A lightweight DHCP and caching DNS server
After=network-online.target
Wants=network-online.target

[Service]
Type=forking
PIDFile=/var/run/dnsmasq.pid
ExecStartPre=/usr/sbin/dnsmasq --test
ExecStart=/usr/sbin/dnsmasq
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    
    sudo systemctl daemon-reload
    sudo systemctl enable dnsmasq
    
    log_success "dnsmasq configured"
}

# Enable unattended upgrades
configure_unattended_upgrades() {
    log_info "Enabling automatic security updates..."
    
    echo 'unattended-upgrades unattended-upgrades/enable_auto_updates boolean true' | \
        sudo debconf-set-selections
    sudo dpkg-reconfigure -f noninteractive unattended-upgrades
    
    log_success "Automatic security updates enabled"
}

# Start WireGuard service
start_wireguard() {
    log_info "Starting WireGuard service..."
    
    # Stop if already running
    if sudo systemctl is-active --quiet "wg-quick@${WG_INTERFACE}"; then
        log_info "Stopping existing WireGuard connection..."
        sudo systemctl stop "wg-quick@${WG_INTERFACE}"
    fi
    
    # Start WireGuard
    if sudo systemctl start "wg-quick@${WG_INTERFACE}"; then
        log_success "WireGuard started successfully"
    else
        log_error "Failed to start WireGuard"
        log_error "Check logs: sudo journalctl -u wg-quick@$WG_INTERFACE -n 50"
        exit 1
    fi
    
    # Enable on boot
    if sudo systemctl enable "wg-quick@${WG_INTERFACE}"; then
        log_success "WireGuard enabled to start on boot"
    else
        log_warn "Failed to enable WireGuard on boot"
    fi
}

# Start dnsmasq service
start_dnsmasq() {
    log_info "Starting dnsmasq service..."
    
    if sudo systemctl start dnsmasq; then
        log_success "dnsmasq started successfully"
    else
        log_warn "dnsmasq failed to start (may be normal if eth0 not available)"
        log_info "Check logs: sudo journalctl -u dnsmasq -n 50"
    fi
}

# Verify installation
verify_installation() {
    log_info "Verifying installation..."
    echo
    
    # Check WireGuard interface
    if ip link show "$WG_INTERFACE" &> /dev/null; then
        log_success "✓ WireGuard interface $WG_INTERFACE is up"
        echo "  $(ip -br addr show $WG_INTERFACE)"
    else
        log_error "✗ WireGuard interface $WG_INTERFACE not found"
        return 1
    fi
    
    # Check IP forwarding
    if [[ "$(cat /proc/sys/net/ipv4/ip_forward)" == "1" ]]; then
        log_success "✓ IP forwarding is enabled"
    else
        log_error "✗ IP forwarding is disabled"
    fi
    
    # Check firewall
    if sudo nft list ruleset | grep -q "inet filter"; then
        log_success "✓ Firewall (nftables) is loaded"
    else
        log_warn "⚠ Firewall may not be loaded"
    fi
    
    # Check NAT
    if sudo nft list ruleset | grep -q "nat postrouting"; then
        log_success "✓ NAT is configured"
    else
        log_warn "⚠ NAT may not be configured"
    fi
    
    # Check services
    if sudo systemctl is-active --quiet dnsmasq; then
        log_success "✓ dnsmasq is running"
    else
        log_warn "⚠ dnsmasq is not running"
    fi
    
    echo
}

# Display final information
show_final_info() {
    echo
    echo "========================================="
    echo "  WireGuard Router Setup Complete! 🎉"
    echo "========================================="
    echo
    echo "Network Configuration:"
    echo "  • WireGuard interface: $WG_INTERFACE"
    echo "  • LAN interface: $ETH_INTERFACE ($ETH_IP)"
    echo "  • DHCP range: $DHCP_RANGE_START - $DHCP_RANGE_END (5 addresses)"
    echo "  • Gateway: 192.168.10.1"
    echo
    echo "Security Features:"
    echo "  • Firewall: nftables (active)"
    echo "  • Automatic security updates: Enabled"
    echo
    echo "To manage WireGuard:"
    echo "  • Check status:  sudo systemctl status wg-quick@$WG_INTERFACE"
    echo "  • View details:  sudo wg show"
    echo "  • Restart:       sudo systemctl restart wg-quick@$WG_INTERFACE"
    echo
    echo "To manage dnsmasq:"
    echo "  • Check status:  sudo systemctl status dnsmasq"
    echo "  • View leases:   cat /var/lib/misc/dnsmasq.leases"
    echo "  • Restart:       sudo systemctl restart dnsmasq"
    echo
    echo "To check firewall:"
    echo "  • View rules:    sudo nft list ruleset"
    echo "  • View counters: sudo nft list chain inet filter forward"
    echo
    echo "To test connection:"
    echo "  • Connect device to eth0 via Ethernet"
    echo "  • Device should receive IP: 192.168.10.x"
    echo "  • Test: curl ifconfig.me (should show VPN IP)"
    echo
    echo "For troubleshooting:"
    echo "  • WireGuard logs: sudo journalctl -u wg-quick@$WG_INTERFACE"
    echo "  • dnsmasq logs:   sudo journalctl -u dnsmasq"
    echo
}

# Main execution flow
main() {
    echo
    log_info "Starting WireGuard Router Setup..."
    log_info "This will configure a complete VPN router with firewall and DHCP"
    echo
    
    check_os
    check_sudo
    check_config_file
    extract_dns_from_config
    install_packages
    enable_ip_forwarding
    configure_eth0
    create_firewall
    configure_wireguard
    configure_dnsmasq
    configure_unattended_upgrades
    start_wireguard
    start_dnsmasq
    verify_installation
    show_final_info
}

# Run main function
main "$@"
