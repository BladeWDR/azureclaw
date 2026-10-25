# AGENTS.md - Developer and Agent Guide for Azureclaw (bootc Router)

This document provides system design, architectural decisions, and operational guidelines for AI agents and human contributors working on `azureclaw`.

---

## 1. System Overview

`azureclaw` is an immutable, container-native home router built on Fedora using **bootc** (bootable containers). It is designed as a modern, lightweight, declarative alternative to monolithic router appliances like OPNsense or pfSense.

### Core Architecture Principles

1. **Immutability by Default**:
   - The root filesystem (`/usr`, core binaries, kernel modules) is mounted read-only via ostree/bootc.
   - Updates are atomic container image deployments: the new image is pulled, staged in an ostree deployment, and activated on reboot.
   - Instant rollback is available via bootloader GRUB/systemd-boot entries or `bootc rollback`.

2. **GitOps as the Primary Configuration Engine**:
   - The container image is the source of truth for base packages, kernel sysctls, firewall rulesets, and default networking.
   - Changes committed to Git trigger an image build and push to an OCI registry.
   - The running router detects updates and automatically stages and applies them according to maintenance policies.

3. **Hybrid Stateful Configuration via Ansible**:
   - While the base OS is immutable, `/etc` supports 3-way merge across upgrades, and `/var` is persistent.
   - Site-specific configuration (secrets, WireGuard private keys, customized DHCP reservations, dynamic interfaces) can be configured post-deployment using Ansible or pushed directly into `/etc`.

4. **Production Linux Networking Primitives**:
   - **Routing Engine**: Linux kernel packet forwarding (`net.ipv4.ip_forward=1`, `net.ipv6.conf.all.forwarding=1`).
   - **Firewall & NAT**: Modern, declarative `nftables` (replaces legacy iptables).
   - **DHCPv4 / DHCPv6 & DNS**: `dnsmasq` for lightweight, ultra-reliable DHCP leases, local domain resolution, and DNS caching with DNSSEC/upstream forwarding.
   - **Interface Management**: `NetworkManager` with declarative keyfiles (`/etc/NetworkManager/system-connections/`).
   - **Virtualization & Telemetry**: `qemu-guest-agent` for native Proxmox VE integration (shutdowns, IP reporting, backup freezes).

---

## 2. Repository Layout

```
azureclaw/
├── AGENTS.md                          # This file: architectural & agent guidelines
├── README.md                          # Quickstart & user documentation
├── Containerfile                      # Bootc container definition based on Fedora 41
├── config/
│   ├── sysctl.d/
│   │   └── 99-router.conf             # Kernel network tuning (forwarding, conntrack, bbr)
│   ├── nftables/
│   │   └── nftables.conf              # Stateful router firewall (WAN NAT, LAN routing, drop rules)
│   ├── dnsmasq/
│   │   └── dnsmasq.conf               # DHCP server & DNS caching configuration
│   ├── network/
│   │   ├── 10-wan.nmconnection        # WAN connection profile (DHCP client)
│   │   └── 20-lan.nmconnection        # LAN connection profile (Static: 192.168.1.1/24)
│   ├── systemd/
│   │   ├── bootc-auto-update.service  # Systemd service for non-disruptive update staging
│   │   └── bootc-auto-update.timer    # Daily scheduled timer for upgrades & reboots
│   └── motd                           # Router login banner and status indicator
├── ansible/
│   ├── inventory.example.ini          # Example inventory for site management
│   ├── playbook.yml                   # Configuration playbook for day-2 customizations
│   └── vars/
│       └── main.yml                   # Configurable parameters (IPs, DHCP pools, DNS forwarders)
├── scripts/
│   ├── build-container.sh             # Build local container image
│   ├── build-disk.sh                  # Build qcow2/raw/iso via bootc-image-builder
│   └── deploy-proxmox-vm.sh           # Proxmox VE helper (qm commands)
└── docs/
    ├── proxmox-setup.md               # Step-by-step Proxmox VE testing & deployment guide
    ├── gitops-workflow.md             # Automated CI/CD updates & registry setup
    └── troubleshooting.md             # Diagnostics, rollback, and recovery procedures
```

---

## 3. Network Architecture & Interface Conventions

In a virtualized (Proxmox) or bare-metal environment, the router expects two primary network interfaces:

| Interface Name / Role | Default Mode | Typical Proxmox Bridge | Description |
|---|---|---|---|
| **WAN** (`eth0` / `enp1s0`) | DHCP Client | `vmbr0` (uplink) | Connected to ISP / Upstream Gateway. Masqueraded NAT applied. |
| **LAN** (`eth1` / `enp2s0`) | Static (`192.168.1.1/24`) | `vmbr1` (internal) | Serves internal clients. Runs `dnsmasq` DHCP & DNS resolver. |

### Firewall (nftables) Ruleset Architecture

The firewall ruleset uses standard nftables `inet` family:
- **`input` chain**:
  - Drops all unsolicited inbound traffic from WAN.
  - Allows established/related traffic.
  - Allows ICMP/ICMPv6 (with rate limiting) for MTU path discovery and connectivity checks.
  - Allows SSH (`22`) and Cockpit (`9090`) ONLY from LAN interfaces (rate-limited).
  - Allows DNS (`53`) and DHCP (`67/udp`) from LAN.
- **`forward` chain**:
  - Allows LAN -> WAN egress.
  - Allows established/related WAN -> LAN return traffic.
  - Blocks unsolicited WAN -> LAN incoming connections unless explicitly forwarded.
- **`postrouting` (NAT) chain**:
  - Applies `masquerade` on WAN egress for IPv4.

---

## 4. Updates & Immutability Lifecycle

### How Updates Work in bootc
1. A container image is built and pushed to an OCI registry (e.g., `quay.io/username/azureclaw:latest`).
2. The router's `bootc-auto-update.timer` triggers `bootc upgrade --apply` (or stages the update).
3. `bootc` downloads only the changed layers (OSTree chunked commits) to `/ostree/repo`.
4. A new OSTree deployment is staged without affecting running router processes.
5. During the designated maintenance window (default: 04:00 AM), the router reboots into the new deployment.
6. If the kernel fails to boot or systemd watchdog detects boot failure, GRUB/systemd-boot automatically rolls back to the previous deployment.

### Manual Rollback
```bash
# Roll back to previous deployment
bootc rollback
systemctl reboot
```

---

## 5. Agent Instructions for Modifying Configuration

When modifying or expanding azureclaw:
1. **Preserve Immutability**: Do not write instructions that rely on mutable `/usr` or runtime package installations (`dnf install` at runtime will fail in bootc). All packages must be installed in `Containerfile`.
2. **Keep Networking Deterministic**: Avoid interface name hardcoding when possible. Use NetworkManager connection match rules (e.g. matching `interface-name=enp*` or MAC address) or standard predictable names (`eth0`, `eth1`).
3. **Verify Security Invariants**:
   - Inbound SSH must **never** be opened to the WAN interface by default.
   - Forwarding between subnets must default to drop unless explicitly permitted.
   - `net.ipv4.ip_forward` must remain enabled.
4. **Document Proxmox Details**: Always maintain explicit Proxmox CLI (`qm`) commands alongside web GUI instructions.
