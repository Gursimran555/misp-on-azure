#!/usr/bin/env bash
# Deploy a single-VM MISP 2.5 instance on Azure, reachable only from your own IP.
#
# The first time I built this I clicked through the portal. This script is the
# same build written down so it can be repeated (and torn down) in minutes.
#
# Usage:
#   az login
#   ./deploy/deploy.sh                 # defaults below
#   LOCATION=canadacentral DNS_LABEL=my-misp-123 ./deploy/deploy.sh
#
# Requirements: Azure CLI 2.60+, curl, an SSH key at ~/.ssh/id_ed25519.pub
# (or set SSH_PUBKEY).

set -euo pipefail

RG="${RG:-rg-misp}"
LOCATION="${LOCATION:-northcentralus}"
VM_NAME="${VM_NAME:-misp-01}"
VM_SIZE="${VM_SIZE:-Standard_B2as_v2}"          # 2 vCPU / 8 GiB - MISP is unhappy with less
IMAGE="${IMAGE:-Canonical:ubuntu-24_04-lts:server:latest}"
ADMIN_USER="${ADMIN_USER:-mispadmin}"
DISK_GB="${DISK_GB:-64}"
DNS_LABEL="${DNS_LABEL:-misp-$(LC_ALL=C tr -dc 'a-z0-9' </dev/urandom | head -c 6)}"
SSH_PUBKEY="${SSH_PUBKEY:-$HOME/.ssh/id_ed25519.pub}"
SHUTDOWN_UTC="${SHUTDOWN_UTC:-0300}"             # nightly auto-shutdown, saves credit
# Pinned commit of the official installer (MISP/MISP branch 2.5). Bump on purpose,
# after reading what changed - this script runs as root on the VM.
MISP_INSTALLER_REF="${MISP_INSTALLER_REF:-fc99c9e3fc85beddc6ef18835359f3c8b7f44608}"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NSG="${VM_NAME}-nsg"
FQDN="${DNS_LABEL}.${LOCATION}.cloudapp.azure.com"

log() { printf '\n==> %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

command -v az >/dev/null || die "Azure CLI (az) not found"
az account show >/dev/null 2>&1 || die "run 'az login' first"
[[ -f "$SSH_PUBKEY" ]] || die "SSH public key not found at $SSH_PUBKEY"

MY_IP="${MY_IP:-$(curl -fsS https://api.ipify.org)}"
[[ "$MY_IP" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || die "could not work out your public IP (set MY_IP)"

# Student and trial subscriptions often restrict regions and sizes. Checking
# first gives a clear error instead of a failed deployment 3 minutes in.
log "Checking $VM_SIZE is available in $LOCATION"
if ! az vm list-skus --location "$LOCATION" --size "$VM_SIZE" --resource-type virtualMachines \
      --query "[?length(restrictions)==\`0\`].name" -o tsv | grep -qx "$VM_SIZE"; then
  die "$VM_SIZE is not available to this subscription in $LOCATION - try another LOCATION or VM_SIZE"
fi

log "Rendering cloud-init for $FQDN"
CLOUD_INIT="$(mktemp)"
trap 'rm -f "$CLOUD_INIT"' EXIT
sed -e "s|__MISP_DOMAIN__|${FQDN}|g" \
    -e "s|__MISP_INSTALLER_REF__|${MISP_INSTALLER_REF}|g" \
    "$HERE/cloud-init.yaml" > "$CLOUD_INIT"

log "Resource group $RG ($LOCATION)"
az group create -n "$RG" -l "$LOCATION" -o none

# --nsg-rule NONE: the VM starts with no inbound rules at all. SSH and HTTPS
# are opened below, for one source IP only.
log "Creating VM $VM_NAME"
az vm create \
  -g "$RG" -n "$VM_NAME" -l "$LOCATION" \
  --image "$IMAGE" --size "$VM_SIZE" \
  --os-disk-size-gb "$DISK_GB" \
  --admin-username "$ADMIN_USER" --ssh-key-values "$SSH_PUBKEY" \
  --authentication-type ssh \
  --public-ip-sku Standard --public-ip-address-dns-name "$DNS_LABEL" \
  --nsg "$NSG" --nsg-rule NONE \
  --custom-data "$CLOUD_INIT" \
  -o none

log "Locking inbound access to $MY_IP"
az network nsg rule create -g "$RG" --nsg-name "$NSG" -n Allow-SSH-MyIP \
  --priority 1000 --direction Inbound --access Allow --protocol Tcp \
  --source-address-prefixes "${MY_IP}/32" --destination-port-ranges 22 -o none
az network nsg rule create -g "$RG" --nsg-name "$NSG" -n Allow-HTTPS-MyIP \
  --priority 1010 --direction Inbound --access Allow --protocol Tcp \
  --source-address-prefixes "${MY_IP}/32" --destination-port-ranges 443 -o none

log "Nightly auto-shutdown at ${SHUTDOWN_UTC} UTC"
az vm auto-shutdown -g "$RG" -n "$VM_NAME" --time "$SHUTDOWN_UTC" -o none

cat <<EOF

Done. MISP is installing in the background (about 20-30 minutes).

  Follow the install:   ssh ${ADMIN_USER}@${FQDN} 'sudo tail -f /root/misp-install.log'
  Admin password:       ssh ${ADMIN_USER}@${FQDN} 'sudo cat /root/misp_settings.txt'
  Web UI:               https://${FQDN}   (self-signed certificate)

  Your IP changed?      ./deploy/allow-my-ip.sh
  Stop paying for it:   ./deploy/teardown.sh stop
EOF
