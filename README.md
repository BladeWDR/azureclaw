# Azureclaw 🦀

> **Immutable, Container-Native Linux Router built with Fedora & bootc**

Azureclaw is a modern, lightweight, declarative alternative to traditional router appliances (like OPNsense and pfSense). Built on top of **Fedora bootc**, Azureclaw combines the atomic update capabilities of containers with production Linux networking primitives.

---

## Key Features

- 🛡️ **Immutable Operating System**: Read-only root filesystem via `bootc` and OSTree on **Fedora 44**. Immune to accidental drift or runtime corruption.
- 🚀 **Declarative Bootloader & DPS**: Native implementation of the Boot Loader Specification (BLS) and Discoverable Partitions Specification (DPS) with `bootupd` and automatic boot-assessment rollback.
- 🔄 **Autonomous Zero-Touch Updates**: Automatic image pulls and staged deployments with configurable maintenance windows and instant rollback.
- ⚡ **Modern High-Performance Networking**:
  - **Firewall & NAT**: Declarative, high-speed `nftables` ruleset.
  - **DHCP & DNS**: `dnsmasq` for ultra-lightweight DHCP leases and caching DNS resolver with DNSSEC support.
  - **Interface Management**: `NetworkManager` with declarative keyfiles.
  - **Kernel Tuning**: BBR congestion control, fq_codel queueing, and hardened sysctls.
  - **VPN & Remote Access**: `wireguard-tools` userspace utilities and `tailscale` (supports subnet routing and exit node modes).
- 📊 **Telemetry & Observability (Grafana Alloy)**: Built-in Grafana Alloy agent to collect router node metrics (CPU, RAM, conntrack, interface throughput) and forward systemd journal logs (dnsmasq, nftables drops, NetworkManager) to Prometheus/Mimir and Loki.
- ⚙️ **GitOps & Ansible Ready**:
  - **GitOps**: Base OS, firewall, and packages version-controlled in Git and built via CI.
  - **Ansible**: Post-deployment site customization for dynamic reservations, WireGuard keys, and secrets in persistent `/etc`.
- 🖥️ **Proxmox VE Native**: Pre-configured with `qemu-guest-agent` for instant IP detection, clean shutdown signaling, and snapshot freezing. Optional Cockpit Web UI on LAN.

---

## Repository Structure

```
azureclaw/
├── .github/
│   └── workflows/build.yml            # CI/CD: Builds container, QCOW2 (VM), and ISO (Baremetal)
├── AGENTS.md                          # Architectural decisions & agent guidelines
├── README.md                          # Project documentation
├── Containerfile                      # Fedora bootc container definition
├── config/
│   ├── alloy/                         # Grafana Alloy pipeline (metrics scraping & log forwarding)
│   ├── bootc/                         # Declarative bootc installer config (DPS & rootfs)
│   ├── ssh/                           # Hardened OpenSSH server configuration
│   ├── sysctl.d/99-router.conf        # Network forwarding & kernel tuning
│   ├── nftables/nftables.conf         # Stateful router firewall & NAT rules
│   ├── dnsmasq/dnsmasq.conf           # DHCP server & DNS caching resolver
│   ├── network/                       # Declarative NetworkManager profiles (WAN & LAN)
│   ├── systemd/                       # Auto-update timer and service definitions
│   └── motd                           # Custom console status banner
├── ansible/
│   ├── inventory.example.ini          # Sample inventory for router fleets
│   ├── playbook.yml                   # Post-deployment site-customization playbook
│   └── vars/main.yml                  # Configurable subnets, leases, and port forwards
├── scripts/
│   ├── build-container.sh             # Build local container image
│   ├── build-disk.sh                  # Generate QCOW2 image via bootc-image-builder
│   └── deploy-proxmox-vm.sh           # Automated Proxmox VM deployment script
└── docs/
    ├── proxmox-setup.md               # Step-by-step Proxmox VE testing guide
    ├── gitops-workflow.md             # Automated CI/CD pipeline and auto-updates
    ├── secure-boot-sbctl.md           # Bare-metal Secure Boot configuration with sbctl
    └── troubleshooting.md             # Diagnostics and rollback procedures
```

---

## Quickstart: Testing in Proxmox VE

### 1. Build the Container Image
```bash
./scripts/build-container.sh
```

### 2. Export QCOW2 Disk for Proxmox
```bash
./scripts/build-disk.sh azureclaw:latest
```
*(The output disk is saved to `output/qcow2/disk.qcow2`)*

### 3. Deploy to Proxmox VE
Copy the disk to your Proxmox host and run:
```bash
./scripts/deploy-proxmox-vm.sh <VMID> <STORAGE_POOL> /path/to/disk.qcow2
```
*For detailed Proxmox isolated network setup and test client validation, see [docs/proxmox-setup.md](docs/proxmox-setup.md).*

---

## Baremetal Appliance Installation

To build a bootable installer ISO for physical mini-PC appliances (e.g. Protectli, Intel N100):
```bash
DISK_TYPE=anaconda-iso ./scripts/build-disk.sh azureclaw:latest
```
Flash the generated installer to a USB drive:
```bash
sudo dd if=output/bootiso/install.iso of=/dev/sdX bs=4M status=progress oflag=sync
```
Boot the target appliance from the USB drive; the installer will automatically partition the internal NVMe/SSD drive and install the bootc deployment.

---

## Configuration Management

### Approach 1: GitOps (Recommended for Base OS)
1. Fork or clone this repository.
2. Set up GitHub Actions using [docs/gitops-workflow.md](docs/gitops-workflow.md).
3. The router automatically checks for new image versions and stages updates nightly at 04:00 AM.

### Approach 2: Ansible (Recommended for Site-Specific Settings)
To manage DHCP reservations, static leases, or port forwarding dynamically:
```bash
cd ansible
cp inventory.example.ini inventory.ini
# Edit vars/main.yml with your desired IP ranges and static leases
ansible-playbook -i inventory.ini playbook.yml
```

---

## Operational Commands

| Action | Command |
|---|---|
| View active OS deployment | `bootc status` |
| Manually trigger update check | `bootc upgrade` |
| Apply staged update and reboot | `bootc upgrade --apply` |
| Instant rollback to previous OS | `bootc rollback && systemctl reboot` |
| View active firewall ruleset | `nft list ruleset` |
| View active DHCP leases | `cat /var/lib/dnsmasq/dnsmasq.leases` |
| Grafana Alloy Web UI / Metrics | `http://192.168.1.1:12345` |
| Cockpit Web Console | `https://192.168.1.1:9090` |

---

## Documentation

- [Proxmox VE Setup Guide](docs/proxmox-setup.md)
- [GitOps Pipeline Guide](docs/gitops-workflow.md)
- [Bare-Metal Secure Boot with sbctl](docs/secure-boot-sbctl.md)
- [Troubleshooting & Rollback](docs/troubleshooting.md)
- [Developer & Agent Guide (AGENTS.md)](AGENTS.md)
