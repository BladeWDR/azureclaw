# Azureclaw

[![Build](https://github.com/BladeWDR/azureclaw/actions/workflows/build.yml/badge.svg)](https://github.com/BladeWDR/azureclaw/actions/workflows/build.yml)

Azureclaw is an immutable, container-native Linux router built on Fedora using **bootc**. It packages the operating system, kernel tunables, firewall, and routing services into an OCI container image. Updates are applied as atomic image deployments with rollback support, and site-specific configuration can be managed declaratively or via Ansible.

This project is not in any way affiliated with Microsoft or Microsoft Azure.

---

## Architecture & Components

| Component | Implementation | Description |
|---|---|---|
| **Base Operating System** | Fedora 44 (`bootc` / OSTree) | Read-only `/usr` filesystem with atomic image updates and rollback via GRUB/bootupd. |
| **Routing & Firewall** | Linux Kernel & `nftables` | Packet forwarding (`ip_forward=1`), NAT masquerading, and a zero-WAN-exposure stealth firewall. |
| **DHCP & DNS** | `dnsmasq` | Lightweight DHCP server and caching DNS resolver with modular snippet support (`/etc/dnsmasq.d/`). |
| **Network Management** | `NetworkManager` | Declarative connection keyfiles in `/etc/NetworkManager/system-connections/`. |
| **VPN Support** | WireGuard, Tailscale, IPsec | `wireguard-tools`, `tailscale`, `strongswan`, `NetworkManager-l2tp` (backed by `go-l2tp`) |
| **Telemetry & Metrics** | Grafana Alloy | Streams host node metrics and journald logs to Prometheus, Mimir, and Loki. |
| **Management** | SSH & Cockpit | Public-key OpenSSH, interactive login monitor, and Cockpit web console with native Azureclaw Router extension (port forwarding, DHCP reservations, DNS overrides). |

---

## Repository Layout

```
azureclaw/
├── .github/workflows/build.yml        # CI/CD: Container build, QCOW2 export, and ISO generation
├── AGENTS.md                          # Architectural decisions and developer guidelines
├── Containerfile                      # Bootc container image definition
├── config/
│   ├── alloy/                         # Grafana Alloy pipeline configuration
│   ├── bootc/                         # Bootc installer configuration
│   ├── dnsmasq/                       # DHCP server & DNS configuration and snippets
│   ├── network/                       # NetworkManager connection keyfiles
│   ├── nftables/                      # Stateful router firewall, NAT, and snippet include
│   ├── profile.d/                     # Interactive shell status display
│   ├── ssh/                           # Hardened OpenSSH daemon configuration
│   ├── sysctl.d/99-router.conf        # Network forwarding & kernel tunables
│   └── systemd/                       # Scheduled update timers and service drop-ins
├── ansible/
│   ├── inventory.example.ini          # Sample inventory for router deployment
│   ├── playbook.yml                   # Configuration playbook for day-2 site settings
│   └── vars/main.yml                  # Configurable parameters (IPs, DHCP pools, port forwards)
├── scripts/
│   ├── build-container.sh             # Local container build script
│   ├── build-disk.sh                  # Disk image generator using bootc-image-builder
│   ├── deploy-proxmox-vm.sh           # Proxmox VE VM creation helper
│   └── router-status.sh               # Live interface and routing status script
└── docs/
    ├── proxmox-setup.md               # Proxmox VE testing and deployment guide
    ├── vlan-configuration.md          # 802.1Q VLAN setup, DHCP/DNS, and isolation rules
    ├── gitops-workflow.md             # Automated CI/CD pipeline and registry configuration
    ├── secure-boot-sbctl.md           # Bare-metal Secure Boot configuration with sbctl
    └── troubleshooting.md             # Diagnostics, rollback, and recovery procedures
```

---

## Installation & Deployment

Pre-built images and installer media are published via GitHub Releases and GitHub Container Registry (`ghcr.io/bladewdr/azureclaw`).

### 1. Virtual Machine (Proxmox VE / KVM)
Download the latest compressed QCOW2 image (`azureclaw-proxmox-kvm-*.qcow2.zst`) from [Releases](https://github.com/BladeWDR/azureclaw/releases), uncompress it with `zstd -d`, and import it:

```bash
# Decompress image
zstd -d azureclaw-proxmox-kvm-<sha>.qcow2.zst

# Deploy to Proxmox VE
./scripts/deploy-proxmox-vm.sh <VMID> <STORAGE_POOL> azureclaw-proxmox-kvm-<sha>.qcow2
```
See [docs/proxmox-setup.md](docs/proxmox-setup.md) for details on setting up isolated test bridges and client testing.

### 2. Bare-Metal Appliance
Download the installer ISO (`azureclaw-baremetal-installer-*.iso`) from [Releases](https://github.com/BladeWDR/azureclaw/releases), write it to a USB drive:

```bash
sudo dd if=azureclaw-baremetal-installer-<sha>.iso of=/dev/sdX bs=4M status=progress oflag=sync
```
Boot the target appliance from the USB drive. The installer partitions the target storage drive and writes the initial deployment.

---

## Configuration

### Base Image (GitOps)
The base operating system, system packages, kernel parameters, and default firewall rules are defined in this repository. Pushing changes to `main` triggers GitHub Actions to rebuild and push the container image to the registry. 

Running routers check the registry on a scheduled timer, stage updates in the background, and boot into the new image during maintenance windows.

### Modular Snippets
To add local configuration without modifying base system files:
- **DHCP Pools & DNS**: Drop `.conf` files into `/etc/dnsmasq.d/` (e.g. `/etc/dnsmasq.d/10-vlan100.conf`).
- **Firewall & Port Forwards**: Drop `.nft` files into `/etc/nftables.d/` (e.g. `/etc/nftables.d/99-port-forwards.nft`).

### Ansible (Day-2 Automation)
Site-specific configuration (secrets, WireGuard keys, customized port forwards, and VLAN assignments) can be managed via Ansible:

```bash
cd ansible
cp inventory.example.ini inventory.ini
# Edit vars/main.yml or use ansible-vault for secrets
ansible-playbook -i inventory.ini playbook.yml
```

---

## Operational Commands

| Task | Command |
|---|---|
| Check active image & deployment status | `bootc status` |
| Check for available updates | `bootc upgrade --check` |
| Stage updates and reboot | `bootc upgrade --apply` |
| Roll back to previous deployment | `bootc rollback && systemctl reboot` |
| View active firewall ruleset | `nft list ruleset` |
| View active DHCP leases | `cat /var/lib/dnsmasq/dnsmasq.leases` |
| Check live interface and IP status | `/usr/libexec/azureclaw/router-status.sh` |
| Cockpit Web Console | `https://<lan-ip>:9090` |
| Grafana Alloy Metrics / UI | `http://<lan-ip>:12345` |

---

## Documentation

- [Proxmox VE Setup Guide](docs/proxmox-setup.md)
- [VLAN Configuration & Network Segmentation](docs/vlan-configuration.md)
- [GitOps Pipeline Guide](docs/gitops-workflow.md)
- [Bare-Metal Secure Boot with sbctl](docs/secure-boot-sbctl.md)
- [Troubleshooting & Rollback Procedures](docs/troubleshooting.md)
- [Developer & Architecture Guide](AGENTS.md)
