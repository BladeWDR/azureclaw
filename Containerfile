FROM quay.io/fedora/fedora-bootc:44

# Labels for OCI image tracking
LABEL org.opencontainers.image.title="azureclaw" \
      org.opencontainers.image.description="Immutable Linux Router built with Fedora and bootc" \
      org.opencontainers.image.source="https://github.com/BladeWDR/azureclaw"

# 1. Add Third-Party Repositories (Grafana Alloy & Tailscale)
RUN rpm --import https://rpm.grafana.com/gpg.key && \
    rpm --import https://pkgs.tailscale.com/stable/fedora/repo.gpg && \
    printf "[grafana]\nname=grafana\nbaseurl=https://rpm.grafana.com\nenabled=1\ngpgcheck=1\ngpgkey=https://rpm.grafana.com/gpg.key\nsslverify=1\n" > /etc/yum.repos.d/grafana.repo && \
    curl -fsSL https://pkgs.tailscale.com/stable/fedora/tailscale.repo -o /etc/yum.repos.d/tailscale.repo && \
    sed -i "s/repo_gpgcheck=1/repo_gpgcheck=0/g" /etc/yum.repos.d/tailscale.repo

# 2. Install Router, Firewall, DNS/DHCP, VPN, Telemetry, and Management Packages
# We install sbsigntools for EFI verification and signing,
# cockpit for optional web GUI administration (similar to OPNsense),
# qemu-guest-agent for native Proxmox VE telemetry, alloy for metrics & logs,
# VPN tools (wireguard, tailscale, openvpn, strongswan, NetworkManager-l2tp), and dnsmasq/nftables for core routing.
RUN dnf -y install --setopt=install_weak_deps=False \
        sbsigntools \
        NetworkManager \
        NetworkManager-tui \
        NetworkManager-libnm \
        NetworkManager-openvpn \
        NetworkManager-l2tp \
        NetworkManager-strongswan \
        python3-gobject-base \
        nftables \
        dnsmasq \
        wireguard-tools \
        tailscale \
        openvpn \
        strongswan \
        qemu-guest-agent \
        cloud-init \
        alloy \
        openssh-server \
        cockpit-bridge \
        cockpit-ws \
        cockpit-system \
        cockpit-networkmanager \
        iproute \
        iptables-nft \
        conntrack-tools \
        ethtool \
        tcpdump \
        bind-utils \
        iputils \
        ndisc6 \
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
# Set default system hostname to azureclaw
RUN systemctl disable systemd-resolved.service || true && \
    systemctl mask systemd-resolved.service && \
    rm -f /etc/resolv.conf && \
    echo "nameserver 127.0.0.1" > /etc/resolv.conf && \
    echo "nameserver 1.1.1.1" >> /etc/resolv.conf && \
    echo "azureclaw" > /etc/hostname

# 3. Copy Custom Configuration Files
COPY config/sysctl.d/99-router.conf /usr/lib/sysctl.d/99-router.conf
COPY config/nftables/nftables.conf /etc/nftables/nftables.conf
COPY config/nftables/nftables.conf /etc/sysconfig/nftables.conf
COPY config/nftables/nftables.d/ /etc/nftables.d/
COPY config/dnsmasq/dnsmasq.conf /etc/dnsmasq.conf
COPY config/dnsmasq/dnsmasq.d/ /etc/dnsmasq.d/
COPY config/motd /etc/motd
COPY config/network/10-wan.nmconnection /etc/NetworkManager/system-connections/10-wan.nmconnection
COPY config/network/20-lan.nmconnection /etc/NetworkManager/system-connections/20-lan.nmconnection
COPY config/systemd/bootc-auto-update.service /usr/lib/systemd/system/bootc-auto-update.service
COPY config/systemd/bootc-auto-update.timer /usr/lib/systemd/system/bootc-auto-update.timer
COPY config/alloy/config.alloy /etc/alloy/config.alloy
COPY config/alloy/alloy.sysconfig /etc/sysconfig/alloy
COPY config/bootc/10-systemd-boot.toml /usr/lib/bootc/install/10-systemd-boot.toml
COPY config/ssh/99-hardening.conf /etc/ssh/sshd_config.d/99-hardening.conf
COPY config/systemd/azureclaw-firstboot.service /usr/lib/systemd/system/azureclaw-firstboot.service
COPY config/systemd/alloy.service.d/10-permissions.conf /usr/lib/systemd/system/alloy.service.d/10-permissions.conf
COPY config/systemd/tmpfiles-alloy.conf /usr/lib/tmpfiles.d/alloy.conf
COPY scripts/firstboot-cleanup.sh /usr/libexec/azureclaw/firstboot-cleanup.sh
COPY scripts/firstboot.sh /usr/libexec/azureclaw/firstboot.sh
COPY scripts/router-status.sh /usr/libexec/azureclaw/router-status.sh
COPY config/profile.d/99-azureclaw-status.sh /etc/profile.d/99-azureclaw-status.sh
COPY config/network/99-azureclaw-issue.sh /etc/NetworkManager/dispatcher.d/99-azureclaw-issue.sh

# 4. Secure File Permissions & Group Memberships
# NetworkManager strictly requires 0600 on connection keyfiles
# Alloy needs systemd-journal group membership to tail host journal logs
RUN chmod 0600 /etc/NetworkManager/system-connections/*.nmconnection && \
    chmod 0600 /etc/ssh/sshd_config.d/99-hardening.conf && \
    chmod 0644 /etc/nftables/nftables.conf && \
    chmod 0644 /etc/sysconfig/nftables.conf && \
    mkdir -p /etc/nftables.d && \
    chmod 0755 /etc/nftables.d && \
    chmod 0644 /etc/nftables.d/* && \
    chmod 0644 /etc/dnsmasq.conf && \
    chmod 0755 /etc/dnsmasq.d && \
    chmod 0644 /etc/dnsmasq.d/* && \
    chmod 0644 /etc/alloy/config.alloy && \
    chmod 0644 /etc/sysconfig/alloy && \
    chmod 0644 /usr/lib/sysctl.d/99-router.conf && \
    chmod 0644 /usr/lib/systemd/system/bootc-auto-update.* && \
    chmod 0644 /usr/lib/systemd/system/azureclaw-firstboot.service && \
    chmod 0644 /usr/lib/systemd/system/alloy.service.d/10-permissions.conf && \
    chmod 0644 /usr/lib/tmpfiles.d/alloy.conf && \
    chmod 0755 /usr/libexec/azureclaw/firstboot.sh && \
    chmod 0755 /usr/libexec/azureclaw/firstboot-cleanup.sh && \
    chmod 0755 /usr/libexec/azureclaw/router-status.sh && \
    chmod 0644 /etc/profile.d/99-azureclaw-status.sh && \
    chmod 0755 /etc/NetworkManager/dispatcher.d/99-azureclaw-issue.sh && \
    chmod 0644 /usr/lib/bootc/install/10-systemd-boot.toml && \
    echo "session optional pam_exec.so seteuid /usr/libexec/azureclaw/firstboot-cleanup.sh" >> /etc/pam.d/postlogin && \
    mkdir -p /var/lib/alloy && \
    chown -R alloy:alloy /var/lib/alloy && \
    chown -R alloy:alloy /etc/alloy && \
    chmod 0755 /etc/alloy && \
    chmod 0644 /etc/alloy/config.alloy && \
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
    systemctl enable bootc-auto-update.timer && \
    systemctl enable azureclaw-firstboot.service

# 6. Admin User Provisioning
# - Zero hardcoded passwords exist in this image (admin password is locked by default)
# - Standard wheel group membership ensures admin can sudo using their password
# - If config/ssh/authorized_keys is provided at build time, it will be baked in automatically.
# - If no SSH key is detected on first boot, azureclaw-firstboot.service generates a unique
#   cryptographic random password on the fly, displays it on the console, and expires it.
RUN useradd -m -s /bin/bash -G wheel admin && \
    passwd -l admin && \
    mkdir -p /home/admin/.ssh && \
    chmod 0700 /home/admin/.ssh && \
    chown -R admin:admin /home/admin/.ssh

COPY config/ssh/authorized_keys* /tmp/ssh_keys/
RUN if [ -f /tmp/ssh_keys/authorized_keys ]; then \
        cp /tmp/ssh_keys/authorized_keys /home/admin/.ssh/authorized_keys && \
        chmod 0600 /home/admin/.ssh/authorized_keys && \
        chown admin:admin /home/admin/.ssh/authorized_keys ; \
    fi && rm -rf /tmp/ssh_keys
