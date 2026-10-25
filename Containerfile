FROM quay.io/fedora/fedora-bootc:41

# Labels for OCI image tracking
LABEL org.opencontainers.image.title="azureclaw" \
      org.opencontainers.image.description="Immutable Linux Home Router built with Fedora and bootc" \
      org.opencontainers.image.source="https://github.com/BladeWDR/azureclaw"

# 1. Install Router, Firewall, DNS/DHCP, and Management Packages
# We install cockpit for optional web GUI administration (similar to OPNsense),
# qemu-guest-agent for native Proxmox VE telemetry, and dnsmasq/nftables for core routing.
RUN dnf -y install --setopt=install_weak_deps=False \
        NetworkManager \
        NetworkManager-tui \
        nftables \
        dnsmasq \
        wireguard-tools \
        qemu-guest-agent \
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

# 4. Secure File Permissions
# NetworkManager strictly requires 0600 on connection keyfiles
RUN chmod 0600 /etc/NetworkManager/system-connections/*.nmconnection && \
    chmod 0644 /etc/nftables/nftables.conf && \
    chmod 0644 /etc/dnsmasq.conf && \
    chmod 0644 /usr/lib/sysctl.d/99-router.conf && \
    chmod 0644 /usr/lib/systemd/system/bootc-auto-update.*

# 5. Enable Necessary System Services
RUN systemctl enable NetworkManager.service && \
    systemctl enable nftables.service && \
    systemctl enable dnsmasq.service && \
    systemctl enable qemu-guest-agent.service && \
    systemctl enable sshd.service && \
    systemctl enable cockpit.socket && \
    systemctl enable bootc-auto-update.timer

# Create placeholder admin user 'admin' (NOPASSWD sudo, user can set password/key via cloud-init/ansible)
# Default login via SSH keys or Proxmox console
RUN useradd -m -s /bin/bash -G wheel admin && \
    echo "%wheel ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/wheel-nopasswd && \
    chmod 0440 /etc/sudoers.d/wheel-nopasswd
