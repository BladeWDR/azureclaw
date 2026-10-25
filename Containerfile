FROM quay.io/fedora/fedora-bootc:44

# Labels for OCI image tracking
LABEL org.opencontainers.image.title="azureclaw" \
      org.opencontainers.image.description="Immutable Linux Home Router built with Fedora and bootc" \
      org.opencontainers.image.source="https://github.com/BladeWDR/azureclaw"

# 1. Add Third-Party Repositories (Grafana Alloy & Tailscale)
RUN rpm --import https://rpm.grafana.com/gpg.key && \
    printf "[grafana]\nname=grafana\nbaseurl=https://rpm.grafana.com\nrepo_gpgcheck=1\nenabled=1\ngpgcheck=1\ngpgkey=https://rpm.grafana.com/gpg.key\nsslverify=1\nsslcacert=/etc/pki/tls/certs/ca-bundle.crt\n" > /etc/yum.repos.d/grafana.repo && \
    curl -fsSL https://pkgs.tailscale.com/stable/fedora/tailscale.repo -o /etc/yum.repos.d/tailscale.repo

# 2. Install Router, Firewall, DNS/DHCP, VPN, Bootloader, Telemetry, and Management Packages
# We install systemd-boot-unsigned and sbctl for modern Secure Boot key management,
# cockpit for optional web GUI administration (similar to OPNsense),
# qemu-guest-agent for native Proxmox VE telemetry, alloy for metrics & logs,
# wireguard-tools & tailscale for VPN, and dnsmasq/nftables for core routing.
RUN dnf -y install --setopt=install_weak_deps=False \
        systemd-boot-unsigned \
        sbctl \
        sbsigntools \
        NetworkManager \
        NetworkManager-tui \
        nftables \
        dnsmasq \
        wireguard-tools \
        tailscale \
        qemu-guest-agent \
        cloud-init \
        alloy \
        openssh-server \
        cockpit-bridge \
        cockpit-system \
        cockpit-networkmanager \
        iproute \
        iptables-nft \
        conntrack-tools \
        ethtool \
        tcpdump \
        bind-utils \
        iputils \
        iperf3 \
        rsync \
        tmux \
        htop \
        vim-minimal \
        sudo && \
    dnf clean all && \
    rm -rf /var/cache/dnf /var/cache/yum /tmp/* /var/tmp/*

# 2. System and Service Configuration
# Disable systemd-resolved to prevent port 53 collision with dnsmasq
RUN systemctl disable systemd-resolved.service || true && \
    systemctl mask systemd-resolved.service && \
    rm -f /etc/resolv.conf && \
    echo "nameserver 127.0.0.1" > /etc/resolv.conf && \
    echo "nameserver 1.1.1.1" >> /etc/resolv.conf

# 3. Copy Custom Configuration Files
COPY config/sysctl.d/99-router.conf /usr/lib/sysctl.d/99-router.conf
COPY config/nftables/nftables.conf /etc/nftables/nftables.conf
COPY config/dnsmasq/dnsmasq.conf /etc/dnsmasq.conf
COPY config/motd /etc/motd
COPY config/network/10-wan.nmconnection /etc/NetworkManager/system-connections/10-wan.nmconnection
COPY config/network/20-lan.nmconnection /etc/NetworkManager/system-connections/20-lan.nmconnection
COPY config/systemd/bootc-auto-update.service /usr/lib/systemd/system/bootc-auto-update.service
COPY config/systemd/bootc-auto-update.timer /usr/lib/systemd/system/bootc-auto-update.timer
COPY config/alloy/config.alloy /etc/alloy/config.alloy
COPY config/alloy/alloy.sysconfig /etc/sysconfig/alloy
COPY config/bootc/10-systemd-boot.toml /usr/lib/bootc/install/10-systemd-boot.toml
COPY config/ssh/99-hardening.conf /etc/ssh/sshd_config.d/99-hardening.conf

# 4. Secure File Permissions & Group Memberships
# NetworkManager strictly requires 0600 on connection keyfiles
# Alloy needs systemd-journal group membership to tail host journal logs
RUN chmod 0600 /etc/NetworkManager/system-connections/*.nmconnection && \
    chmod 0600 /etc/ssh/sshd_config.d/99-hardening.conf && \
    chmod 0644 /etc/nftables/nftables.conf && \
    chmod 0644 /etc/dnsmasq.conf && \
    chmod 0644 /etc/alloy/config.alloy && \
    chmod 0644 /etc/sysconfig/alloy && \
    chmod 0644 /usr/lib/sysctl.d/99-router.conf && \
    chmod 0644 /usr/lib/systemd/system/bootc-auto-update.* && \
    chmod 0644 /usr/lib/bootc/install/10-systemd-boot.toml && \
    usermod -aG systemd-journal alloy || true && \
    passwd -l root

# 5. Enable Necessary System Services
RUN systemctl enable NetworkManager.service && \
    systemctl enable nftables.service && \
    systemctl enable dnsmasq.service && \
    systemctl enable qemu-guest-agent.service && \
    systemctl enable sshd.service && \
    systemctl enable cockpit.socket && \
    systemctl enable alloy.service && \
    systemctl enable tailscaled.service && \
    systemctl enable bootc-auto-update.timer

# 6. Admin User Provisioning
# - Initial console password is set to 'azureclaw' (forced to change on first login via chage)
# - Note: SSH password login is disabled by policy; this password only works on the physical/Proxmox console
# - If config/ssh/authorized_keys is provided at build time, it will be baked in automatically.
RUN useradd -m -s /bin/bash -G wheel admin && \
    echo "admin:azureclaw" | chpasswd && \
    chage -d 0 admin && \
    echo "%wheel ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/wheel-nopasswd && \
    chmod 0440 /etc/sudoers.d/wheel-nopasswd && \
    mkdir -p /home/admin/.ssh && \
    chmod 0700 /home/admin/.ssh && \
    chown -R admin:admin /home/admin/.ssh

COPY config/ssh/authorized_keys* /tmp/ssh_keys/
RUN if [ -f /tmp/ssh_keys/authorized_keys ]; then \
        cp /tmp/ssh_keys/authorized_keys /home/admin/.ssh/authorized_keys && \
        chmod 0600 /home/admin/.ssh/authorized_keys && \
        chown admin:admin /home/admin/.ssh/authorized_keys ; \
    fi && rm -rf /tmp/ssh_keys
