#!/usr/bin/env bash
# stop    - deallocate the VM. Compute billing stops, the disk and IP are kept.
# start   - bring it back.
# destroy - delete the whole resource group. Asks first.
set -euo pipefail

RG="${RG:-rg-misp}"
VM_NAME="${VM_NAME:-misp-01}"

case "${1:-}" in
  stop)
    az vm deallocate -g "$RG" -n "$VM_NAME"
    az vm get-instance-view -g "$RG" -n "$VM_NAME" \
      --query "instanceView.statuses[?starts_with(code,'PowerState')].displayStatus" -o tsv
    ;;
  start)
    az vm start -g "$RG" -n "$VM_NAME"
    ;;
  destroy)
    read -r -p "Delete resource group '$RG' and everything in it? Type the name to confirm: " answer
    [[ "$answer" == "$RG" ]] || { echo "aborted"; exit 1; }
    az group delete -n "$RG" --yes --no-wait
    echo "deletion started"
    ;;
  *)
    echo "usage: $0 stop|start|destroy" >&2
    exit 1
    ;;
esac
