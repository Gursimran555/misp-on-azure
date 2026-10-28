#!/usr/bin/env bash
# Home IPs change. Point both NSG rules at whatever your public IP is now.
set -euo pipefail

RG="${RG:-rg-misp}"
VM_NAME="${VM_NAME:-misp-01}"
NSG="${VM_NAME}-nsg"
MY_IP="${MY_IP:-$(curl -fsS https://api.ipify.org)}"

[[ "$MY_IP" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || { echo "could not work out your public IP" >&2; exit 1; }

for rule in Allow-SSH-MyIP Allow-HTTPS-MyIP; do
  az network nsg rule update -g "$RG" --nsg-name "$NSG" -n "$rule" \
    --source-address-prefixes "${MY_IP}/32" -o none
  echo "$rule -> ${MY_IP}/32"
done
