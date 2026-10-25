# Testing Azureclaw on Proxmox VE

This guide walks you through setting up an isolated virtual test environment on Proxmox VE to validate Azureclaw as your home router before bare-metal or production deployment.

---

## 1. Proxmox Network Architecture

To test a router VM safely without creating DHCP conflicts or IP loops on your existing home network, create an isolated bridge for the LAN:

```
[ Your Physical LAN / Home Router ]
                 │
           [ vmbr0 ] (Proxmox WAN Bridge)
                 │  (DHCP or Static IP from your home network)
          ┌──────┴──────┐
          │  net0 (WAN) │
          │             │
          │  Azureclaw  │
          │  Router VM  │
          │             │
          │  net1 (LAN) │ (Static 192.168.1.1/24 + dnsmasq DHCP)
          └──────┬──────┘
                 │
           [ vmbr1 ] (Isolated Internal Bridge - No physical NIC)
                 │
      ┌──────────┴──────────┐
      │  Test Client VM     │ (Gets 192.168.1.5x via DHCP, tests DNS & NAT)
      └─────────────────────┘
```

### Step 1: Create the Isolated LAN Bridge (`vmbr1`)
On your Proxmox VE host:
1. Navigate to **Proxmox Node** -> **System** -> **Network**.
2. Click **Create** -> **Linux Bridge**.
   - **Name**: `vmbr1`
   - **IPv4 / CIDR**: Leave blank (unmanaged bridge)
   - **Bridge ports**: Leave blank (no physical NIC attached)
   - **Comment**: `Isolated LAN for Azureclaw test`
3. Click **Apply Configuration**.

*(Or via CLI in `/etc/network/interfaces`):*
```text
auto vmbr1
iface vmbr1 inet manual
	bridge-ports none
	bridge-stp off
	bridge-fd 0
```

---

## 2. Generate and Import the Disk Image

### Option A: Build `.qcow2` with `bootc-image-builder`
On your build machine or directly on a container-capable host:
```bash
# 1. Build and push container to registry (or build locally)
./scripts/build-container.sh

# 2. Export QCOW2 image
./scripts/build-disk.sh ghcr.io/<your-username>/azureclaw:latest
```

### Option B: Deploy Using Helper Script
Transfer `disk.qcow2` to your Proxmox host (e.g. using `scp`):
```bash
scp output/qcow2/disk.qcow2 root@proxmox:/tmp/azureclaw.qcow2
```

SSH into your Proxmox host and run:
```bash
chmod +x ./scripts/deploy-proxmox-vm.sh
./scripts/deploy-proxmox-vm.sh 900 local-lvm /tmp/azureclaw.qcow2
```

---

## 3. Manual VM Creation (CLI Reference)

If you prefer running the commands manually on Proxmox:

```bash
VMID=900
STORAGE="local-lvm"
DISK="/tmp/azureclaw.qcow2"

# 1. Create VM shell with UEFI and 2 VirtIO NICs
qm create $VMID \
    --name "azureclaw-router" \
    --memory 2048 \
    --cores 2 \
    --cpu host \
    --machine q35 \
    --bios ovmf \
    --scsihw virtio-scsi-single \
    --agent enabled=1 \
    --net0 virtio,bridge=vmbr0,firewall=0 \
    --net1 virtio,bridge=vmbr1,firewall=0 \
    --onboot 1

# 2. Add EFI disk
qm set $VMID --efidisk0 ${STORAGE}:0,efitype=4m,pre-enrolled-keys=0

# 3. Import disk image
qm disk import $VMID $DISK $STORAGE

# 4. Attach imported disk and configure boot order
qm set $VMID --scsi0 ${STORAGE}:vm-${VMID}-disk-1,discard=on,ssd=1
qm set $VMID --boot order=scsi0

# 5. Start the router
qm start $VMID
```

---

## 4. Testing & Verification Steps

### 1. Check Router Boot & Qemu Agent
In the Proxmox Web GUI:
- Open VM `900` -> **Summary**.
- Within 15–30 seconds, `qemu-guest-agent` will report both IP addresses:
  - `net0` (WAN): IP received from your existing home network.
  - `net1` (LAN): `192.168.1.1/24`.

### 2. Connect a Test Client to `vmbr1`
Create or reconfigure an existing client VM (e.g., Ubuntu Desktop, Alpine Linux, or Windows):
1. In the client VM's **Hardware** settings, change its Network Device bridge to **`vmbr1`**.
2. Boot the client VM.
3. Verify that the client receives an IP lease in the `192.168.1.50 - 192.168.1.200` pool:
   ```bash
   ip a
   # Expected: inet 192.168.1.5x/24
   ```
4. Verify DNS resolution:
   ```bash
   nslookup cloudflare.com 192.168.1.1
   ```
5. Verify NAT Masquerading and internet egress:
   ```bash
   ping -c 3 1.1.1.1
   curl -I https://www.google.com
   ```

### 3. Access Management Interfaces from Test Client
From the client VM connected to `vmbr1`:
- **SSH**: `ssh admin@192.168.1.1`
- **Cockpit Web UI**: Open browser to `https://192.168.1.1:9090` (Login with `admin` account).

---

## 5. Testing Atomic Updates & Rollback

### Testing Staged Updates:
On the router:
```bash
# Check current bootc deployment
bootc status

# Trigger upgrade check
bootc upgrade

# Or trigger immediate upgrade and reboot
bootc upgrade --apply
```

### Testing Rollback:
If an update is unsatisfactory or fails health checks:
```bash
# Roll back to the previous deployment layer
bootc rollback
systemctl reboot
```
You can also select the previous ostree deployment directly from the GRUB boot menu via the Proxmox NoVNC console during startup.
