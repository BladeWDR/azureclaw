# AGENTS.md - Developer and Agent Guide for Azureclaw (bootc Router)

This document provides system design, architectural decisions, and operational guidelines for AI agents and human contributors working on `azureclaw`.

---

## 1. System Overview

`azureclaw` is an immutable, container-native router built on Fedora using **bootc** (bootable containers). It is designed as a modern, lightweight, declarative alternative to monolithic router appliances like OPNsense or pfSense.

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
   - **VPN Subsystem**:
     - `wireguard-tools` (`wg` / `wg-quick`) and `tailscale` (daemon + CLI for mesh networking, exit node, and subnet routing).
     - `strongswan` (IKEv1/IKEv2 IPsec for site-to-site) and `NetworkManager-l2tp` (L2TP/IPsec client backed by `go-l2tp`).
     - `openvpn` and `NetworkManager-openvpn` (OpenVPN client with Cockpit/NetworkManager import).
   - **Virtualization & Telemetry**:
     - `qemu-guest-agent` for native Proxmox VE integration (shutdowns, IP reporting, backup freezes).
     - `alloy` (Grafana Alloy) for streaming host metrics (`node_exporter` via `prometheus.exporter.unix`) and systemd journal logs (`loki.source.journal`) to Prometheus, Mimir, and Loki.

---

## 2. Repository Layout

```
azureclaw/
├── .github/
│   └── workflows/
│       └── build.yml                  # Automated CI/CD (Container, Proxmox QCOW2, Baremetal ISO)
├── AGENTS.md                          # This file: architectural & agent guidelines
├── README.md                          # Quickstart & user documentation
├── Containerfile                      # Bootc container definition based on Fedora 44
├── config/
│   ├── alloy/
│   │   ├── config.alloy               # Grafana Alloy pipeline (metrics scraping & log forwarding)
│   │   └── alloy.sysconfig            # Environment variables and listen port configuration
│   ├── bootc/
│   │   └── 10-systemd-boot.toml       # Declarative bootc installer config (DPS, ext4 rootfs)
│   ├── ssh/
│   │   └── 99-hardening.conf          # Hardened SSH daemon config (keys only, modern ciphers)
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
    ├── secure-boot-sbctl.md           # Bare-metal Secure Boot configuration with sbctl
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

The firewall ruleset uses standard nftables `inet` family with a strict **Zero-WAN-Exposure (Full Stealth)** posture:
- **`input` chain**:
  - **Zero Open WAN Ports**: **NO ports or protocols are EVER opened to the WAN by default.** All unsolicited inbound traffic from WAN is silently dropped.
  - WAN ping (`echo-request`) is dropped by default to prevent internet-wide scanning and fingerprinting.
  - Only essential ICMP/ICMPv6 network signaling (Path MTU discovery `packet-too-big` / `destination-unreachable`, IPv6 Neighbor Discovery) and stateful `established,related` return packets are accepted from WAN.
  - Outbound VPN clients (Tailscale, WireGuard, OpenVPN, StrongSwan IPsec, L2TP) rely strictly on stateful connection tracking (`ct state established,related accept`). Users must explicitly configure and open ports if they wish to host inbound server daemons.
  - Management services (SSH `22`, Cockpit `9090`, Grafana Alloy `12345`) are permitted ONLY from LAN and authenticated VPN interfaces (rate-limited).
  - Router services (DNS `53`, DHCP `67/udp`) are permitted ONLY from LAN interfaces.
- **`forward` chain**:
  - Allows LAN -> WAN egress.
  - Allows established/related WAN -> LAN return traffic.
  - Blocks unsolicited WAN -> LAN incoming connections unless explicitly forwarded by user rules.
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
   - **Zero WAN Exposure Rule**: **NO ports should EVER be opened to the WAN by default.** This includes SSH, Web consoles, monitoring endpoints, and all VPN ports (WireGuard `51820`, Tailscale `41641`, IPsec `500`/`4500`, L2TP `1701`, etc.). All VPNs must operate as clients via stateful conntrack unless the administrator explicitly configures an inbound listener.
   - Inbound SSH and management tools must **never** be exposed to the WAN interface.
   - Inbound WAN ping (`echo-request`) must remain dropped by default for total stealth.
   - Forwarding between subnets must default to drop unless explicitly permitted.
   - `net.ipv4.ip_forward` must remain enabled.
4. **Document Proxmox Details**: Always maintain explicit Proxmox CLI (`qm`) commands alongside web GUI instructions.

---

## 6. Security Hardening Specifications

Azureclaw enforces multi-layered defense-in-depth across the router stack:

1. **Kernel Sysctls (`/usr/lib/sysctl.d/99-router.conf`)**:
   - `net.ipv4.tcp_syncookies = 1` & `net.ipv4.tcp_rfc1337 = 1`: Defends against TCP SYN flooding and TIME-WAIT assassination attacks.
   - `kernel.kptr_restrict = 2` & `kernel.dmesg_restrict = 1`: Hides kernel pointer addresses and prevents unprivileged log snooping.
   - `kernel.unprivileged_bpf_disabled = 1` & `net.core.bpf_jit_harden = 2`: Closes unprivileged eBPF attack surface and hardens JIT compiler against spraying.
   - `fs.suid_dumpable = 0` & `kernel.yama.ptrace_scope = 2`: Restricts core dumping and cross-process ptrace debugging.

2. **Firewall Anomaly Protection (`/etc/nftables/nftables.conf`)**:
   - Zero WAN Exposure: Zero open ports or unsolicited protocols on WAN by default; WAN ping dropped for 100% stealth.
   - State-tracking drops: Drops `ct state invalid` packets immediately.
   - Port-scan mitigation: Automatically drops Xmas scans, Null scans, and illegal SYN combinations (`syn|fin`, `syn|rst`).
   - Brute-force rate limiting: Meters SSH and management connections to 15/minute burst 5.

3. **SSH Lockdown (`/etc/ssh/sshd_config.d/99-hardening.conf`)**:
   - Public-key only: `PasswordAuthentication no`, `PermitEmptyPasswords no`.
   - Root login disabled: `PermitRootLogin no` (root account password locked).
   - Modern cryptography: Strict Curve25519, ChaCha20-Poly1305, and AES-GCM suites only.

4. **DNS Rebinding Protection (`/etc/dnsmasq.conf`)**:
   - `stop-dns-rebind`: Drops upstream answers resolving to private RFC 1918 or loopback addresses, preventing malicious websites from targeting internal IoT devices.
