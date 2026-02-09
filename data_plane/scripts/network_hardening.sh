#!/bin/bash
# =============================================================================
# Network Hardening Script for Cagent Data Plane
# =============================================================================
#
# This script adds iptables rules as defense-in-depth backup to Docker's
# internal network flag. Even if Envoy or CoreDNS crashes, the agent
# container cannot reach the internet directly.
#
# Run this script on the Docker host after starting the data plane.
# Requires root/sudo privileges.
#
# =============================================================================

set -e

# Configuration
AGENT_SUBNET="172.30.0.0/16"
AGENT_IP="172.30.0.20"
ENVOY_IP="172.30.0.10"
COREDNS_IP="172.30.0.5"
FRPC_IP="172.30.0.30"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   log_error "This script must be run as root (sudo)"
   exit 1
fi

# Check if iptables is available
if ! command -v iptables &> /dev/null; then
    log_error "iptables not found. Install with: apt-get install iptables"
    exit 1
fi

# =============================================================================
# Create custom chain for Cagent rules
# =============================================================================

CHAIN_NAME="CAGENT-AGENT"

# Remove existing chain if present (for idempotency)
iptables -D FORWARD -s "$AGENT_IP" -j "$CHAIN_NAME" 2>/dev/null || true
iptables -F "$CHAIN_NAME" 2>/dev/null || true
iptables -X "$CHAIN_NAME" 2>/dev/null || true

# Create new chain
iptables -N "$CHAIN_NAME"
log_info "Created iptables chain: $CHAIN_NAME"

# =============================================================================
# Agent egress rules (from agent container)
# =============================================================================

# Allow agent -> Envoy (proxy)
iptables -A "$CHAIN_NAME" -s "$AGENT_IP" -d "$ENVOY_IP" -p tcp --dport 8443 -j ACCEPT
log_info "Allow: Agent -> Envoy (TCP 8443)"

# Allow agent -> CoreDNS (DNS)
iptables -A "$CHAIN_NAME" -s "$AGENT_IP" -d "$COREDNS_IP" -p udp --dport 53 -j ACCEPT
iptables -A "$CHAIN_NAME" -s "$AGENT_IP" -d "$COREDNS_IP" -p tcp --dport 53 -j ACCEPT
log_info "Allow: Agent -> CoreDNS (UDP/TCP 53)"

# Allow agent -> frpc (for SSH tunnel, if running)
iptables -A "$CHAIN_NAME" -s "$AGENT_IP" -d "$FRPC_IP" -j ACCEPT
log_info "Allow: Agent -> frpc (all ports)"

# Allow established/related connections (for responses)
iptables -A "$CHAIN_NAME" -m state --state ESTABLISHED,RELATED -j ACCEPT
log_info "Allow: Established/related connections"

# Allow loopback
iptables -A "$CHAIN_NAME" -s "$AGENT_IP" -d "$AGENT_IP" -j ACCEPT
log_info "Allow: Loopback"

# DROP everything else from agent
iptables -A "$CHAIN_NAME" -s "$AGENT_IP" -j DROP
log_info "Drop: All other traffic from agent"

# =============================================================================
# Insert chain into FORWARD
# =============================================================================

iptables -I FORWARD -s "$AGENT_IP" -j "$CHAIN_NAME"
log_info "Inserted $CHAIN_NAME into FORWARD chain"

# =============================================================================
# Block agent from reaching host services
# =============================================================================

# Prevent agent from reaching Docker host (common attack vector)
HOST_IP=$(ip route | grep default | awk '{print $3}')
if [[ -n "$HOST_IP" ]]; then
    iptables -A INPUT -s "$AGENT_IP" -d "$HOST_IP" -j DROP 2>/dev/null || true
    log_info "Drop: Agent -> Docker host ($HOST_IP)"
fi

# =============================================================================
# Verification
# =============================================================================

echo ""
log_info "Network hardening applied. Current rules:"
echo ""
iptables -L "$CHAIN_NAME" -n -v --line-numbers
echo ""
log_info "To remove these rules, run: $0 --remove"

# =============================================================================
# Remove option
# =============================================================================

if [[ "$1" == "--remove" ]]; then
    log_warn "Removing Cagent iptables rules..."
    iptables -D FORWARD -s "$AGENT_IP" -j "$CHAIN_NAME" 2>/dev/null || true
    iptables -F "$CHAIN_NAME" 2>/dev/null || true
    iptables -X "$CHAIN_NAME" 2>/dev/null || true
    log_info "Removed iptables chain: $CHAIN_NAME"
    exit 0
fi
