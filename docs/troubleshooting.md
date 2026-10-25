# Troubleshooting & Diagnostics Guide

This document provides operational diagnostics and recovery procedures for Azureclaw.

---

## 1. Quick Diagnostics Cheat Sheet

| Task | Command |
|---|---|
| Check bootc OS version & staging status | `bootc status` |
| View active firewall rules | `nft list ruleset` |
| Inspect DHCP leases | `cat /var/lib/dnsmasq/dnsmasq.leases` |
| Check interface links & IPs | `ip -brief address` |
| Inspect NetworkManager connections | `nmcli connection show` |
| Monitor live firewall packet drops | `nft monitor trace` |
| Test DNS query resolution | `dig @127.0.0.1 cloudflare.com` |
| Check auto-update timer next run | `systemctl list-timers bootc-auto-update.timer` |

---

## 2. Boot & Image Deployment Diagnostics

### Viewing Current & Staged OS State:
```bash
bootc status
```
Output breakdown:
- **`image`**: The OCI image URI being tracked (e.g. `ghcr.io/user/azureclaw:latest`).
- **`booted`**: The active OSTree deployment hash.
- **`rollback`**: The previous working deployment available if the current one fails.
- **`staged`**: If a new image was downloaded during an update check, it will show up here awaiting reboot.

### Manually Testing an Update Without Rebooting:
```bash
# Check if a new version is available on the registry
bootc update
```

### Performing an Immediate Rollback:
```bash
bootc rollback
systemctl reboot
```

---

## 3. Network & Interface Troubleshooting

### Interfaces Not Receiving IPs:
1. Verify link carrier detection:
   ```bash
   ip link show
   ```
   Check that both interfaces (`ens18`, `ens19` or `eth0`, `eth1`) show `state UP` and `carrier detected`.
2. Inspect NetworkManager connection state:
   ```bash
   nmcli connection show --active
   nmcli device status
   ```
3. If an interface didn't auto-activate, manually bring it up:
   ```bash
   nmcli connection up WAN
   nmcli connection up LAN
   ```

### WAN DHCP Not Getting Gateway or DNS:
Check system logs for NetworkManager DHCP client:
```bash
journalctl -u NetworkManager -b -e --no-pager
```

---

## 4. Firewall & NAT Troubleshooting

### Verify Packet Forwarding is Enabled in Kernel:
```bash
sysctl net.ipv4.ip_forward
# Expected output: net.ipv4.ip_forward = 1
```

### Test NAT Masquerading:
From a test client on the LAN:
```bash
# Ping router LAN interface
ping 192.168.1.1

# Ping an external IP (tests NAT forward)
ping 1.1.1.1
```

If internal ping succeeds but external ping fails:
1. Check the NAT postrouting table:
   ```bash
   nft list chain ip nat postrouting
   ```
   Ensure the rule `oifname $WAN_IFACES masquerade` is present.
2. Check the Forward filter chain:
   ```bash
   nft list chain inet router forward
   ```
   Ensure `iifname $LAN_IFACES oifname $WAN_IFACES accept` is present.

---

## 5. Emergency Recovery via Proxmox Console

If a configuration change breaks network access:
1. Open the Proxmox VE Web GUI.
2. Select your router VM -> **Console** (NoVNC).
3. If the system fails to boot, reboot the VM and hold `Esc` / `Shift` or press the Down arrow to display the GRUB boot menu.
4. Select the second entry (`Deployment 1 (rollback)`) to boot into the previous known-good deployment.
5. Once logged in as `admin`, investigate `/etc` modifications or execute `bootc rollback` to make the rollback persistent.
