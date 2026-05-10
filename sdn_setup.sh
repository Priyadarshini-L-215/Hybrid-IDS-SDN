#!/bin/bash
# sdn_setup.sh - Infrastructure setup for Sentinel SDN Layer
# Sets up OVS bridge, network namespaces for honeypot, and management links.

set -e

PROJECT_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
cd "$PROJECT_ROOT"
BRIDGE_NAME="br-sentinel"
HP_NS="honeypot"
HP_IP="10.99.0.2/24"
HP_PORT_NAME="hp0"

log_info() { echo -e "\e[34m[INFO]\e[0m $1"; }
log_success() { echo -e "\e[32m[SUCCESS]\e[0m $1"; }
log_error() { echo -e "\e[31m[ERROR]\e[0m $1"; }

# 1. Install OVS if not present
if ! command -v ovs-vsctl &> /dev/null; then
    log_info "Installing Open vSwitch..."
    sudo apt-get update && sudo apt-get install -y openvswitch-switch
fi

# 2. Setup OVS Bridge
if sudo ovs-vsctl br-exists "$BRIDGE_NAME"; then
    log_info "Bridge $BRIDGE_NAME already exists. Cleaning up..."
    sudo ovs-vsctl del-br "$BRIDGE_NAME"
fi

log_info "Creating OVS bridge: $BRIDGE_NAME"
sudo ovs-vsctl add-br "$BRIDGE_NAME"
sudo ovs-vsctl set bridge "$BRIDGE_NAME" protocols=OpenFlow13

# 3. Setup Honeypot Namespace
log_info "Setting up Honeypot network namespace..."
if ip netns list | grep -q "$HP_NS"; then
    sudo ip netns del "$HP_NS"
fi

sudo ip netns add "$HP_NS"
sudo ovs-vsctl add-port "$BRIDGE_NAME" "$HP_PORT_NAME" -- set Interface "$HP_PORT_NAME" type=internal
sudo ip link set "$HP_PORT_NAME" netns "$HP_NS"

sudo ip netns exec "$HP_NS" ip addr add "$HP_IP" dev "$HP_PORT_NAME"
sudo ip netns exec "$HP_NS" ip link set "$HP_PORT_NAME" up
sudo ip netns exec "$HP_NS" ip link set lo up

# 4. Set Controller to Ryu (Default port 6653)
log_info "Configuring controller for $BRIDGE_NAME"
sudo ovs-vsctl set-controller "$BRIDGE_NAME" tcp:127.0.0.1:6653

log_success "SDN Infrastructure Setup Complete!"
log_info "Bridge: $BRIDGE_NAME"
log_info "Honeypot IP: $HP_IP (Namespace: $HP_NS)"
log_info "Controller: 127.0.0.1:6653"
