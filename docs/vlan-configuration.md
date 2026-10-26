# Configuring VLANs & Network Segmentation on Azureclaw

This guide explains how to create isolated 802.1Q VLANs (such as an untrusted IoT network or Guest Wi-Fi) on Azureclaw, configure DHCP and DNS resolution, and write secure `nftables` rules that permit internet access while strictly isolating the VLAN from your management services and private LAN.

---

## Architecture: The Zero-Trust VLAN Model

In Azureclaw, the firewall posture is **Zero-WAN-Exposure and Least Privilege**:

- **Default Deny**: New VLAN sub-interfaces are **not** automatically trusted. They cannot access router management services (SSH `22`, Cockpit `9090`, Alloy `12345`) and cannot route into the primary LAN.
- **Explicit Access Grants**: For each VLAN, you explicitly grant:
  1. Router service access (DHCP `67/udp` and DNS `53`).
  2. Internet egress (NAT masquerading through the WAN interface).
  3. Inter-VLAN isolation (preventing IoT/Guest devices from communicating with servers or workstations on your main LAN).

```
                      ┌───────────────────────────────────────┐
                      │          Azureclaw Router VM          │
                      │                                       │
                      │  WAN: DHCP (ISP Gateway / Internet)  │
                      │   │                                   │
                      │  LAN (ens19): 192.168.1.1/24 (Trusted)│
                      │   │                                   │
                      │  VLAN 100 (ens19.100): 10.0.100.1/24  │
                      └───────┬───────────────────────────────┘
                              │ (802.1Q Trunk)
                      ┌───────┴───────────────────────────────┐
                      │ Proxmox VE Bridge (vmbr1, VLAN Aware) │
                      └───────┬───────────────────────┬───────┘
                              │                       │
                     (VLAN Tag: None)           (VLAN Tag: 100)
                              │                       │
                    ┌─────────┴─────────┐   ┌─────────┴─────────┐
                    │ Trusted LAN Client│   │ Untrusted IoT /   │
                    │ 192.168.1.50      │   │ Guest Client      │
                    │                   │   │ 10.0.100.50       │
                    └───────────────────┘   └───────────────────┘
```

---

## 1. Hypervisor Setup (Proxmox VE)

If you are running Azureclaw on Proxmox VE, the Linux bridge must be configured to pass 802.1Q VLAN tags:

### Step 1: Enable "VLAN Aware" on the LAN Bridge (`vmbr1`)
1. In Proxmox VE Web GUI, navigate to **Node** -> **System** -> **Network**.
2. Select your internal LAN bridge (e.g., `vmbr1`) and click **Edit**.
3. Check the **VLAN aware** checkbox.
4. Click **OK**, then click **Apply Configuration**.

### Step 2: Configure Azureclaw VM Network Interface
- The Azureclaw VM interface on `vmbr1` (typically `net1`) must receive raw 802.1Q tagged frames so the router kernel can create tagged sub-interfaces:
- In the Proxmox GUI under **VM Hardware** -> **Network Device (net1)**, leave the **VLAN Tag** field **blank** (or untagged).

### Step 3: Configure Client VMs or Physical Switches
- **For a Proxmox Client VM**: Set the **VLAN Tag** to `100` in the client's network adapter hardware settings. Proxmox will automatically tag its traffic into VLAN 100.
- **For Physical Switches**: Configure the port connected to Azureclaw LAN as a **Trunk** (allowing tagged VLAN 100 and native LAN), and configure your client/AP ports as **Access (PVID: 100)**.

---

## 2. Step 1: Create the VLAN Interface in NetworkManager

Use `nmcli` or `nmtui` to create the persistent 802.1Q interface.

### Example: Create `vlan100` on parent device `ens19`
```bash
sudo nmcli connection add \
  type vlan \
  con-name "VLAN100" \
  dev ens19 \
  id 100 \
  ip4 10.0.100.1/24 \
  ipv6.method ignore
```

Verify the interface was created and received the IP address:
```bash
ip -br addr show dev ens19.100
```
*Expected output: `ens19.100 UP 10.0.100.1/24`*

---

## 3. Step 2: Configure DHCP and DNS in Dnsmasq

Edit `/etc/dnsmasq.conf`:

```bash
sudo nano /etc/dnsmasq.conf
```

### 1. Bind Dnsmasq to the VLAN IP
Add the new VLAN gateway IP to `listen-address`:
```ini
listen-address=127.0.0.1
listen-address=::1
listen-address=192.168.1.1
listen-address=10.0.100.1
```

### 2. Define the DHCP Pool & Gateway Options
Add the DHCP range and routing options for VLAN 100:
```ini
# DHCP Pool for VLAN 100 (IoT / Guest Network)
dhcp-range=set:vlan100,10.0.100.50,10.0.100.200,255.255.255.0,24h
dhcp-option=tag:vlan100,option:router,10.0.100.1
dhcp-option=tag:vlan100,option:dns-server,10.0.100.1
```

### 3. Restart Dnsmasq
```bash
sudo systemctl restart dnsmasq
```

Verify `dnsmasq` is running without syntax errors:
```bash
sudo systemctl status dnsmasq
```

---

## 4. Step 3: Configure the Firewall (`nftables`)

Edit `/etc/sysconfig/nftables.conf` (or `config/nftables/nftables.conf` in your GitOps repository):

```bash
sudo nano /etc/sysconfig/nftables.conf
```

### 1. Define the VLAN Interface Variable
Near the top of the file, define your VLAN interfaces:
```nftables
# VLAN Interfaces (Segmented networks)
define IOT_IFACES = { "ens19.100" }
```

### 2. Allow DHCP & DNS on the VLAN (Input Chain)
Inside `chain input`, allow devices on the VLAN to obtain an IP lease and query DNS from the router:
```nftables
        # Allow DHCP and DNS from VLAN 100
        iifname $IOT_IFACES udp dport { 53, 67 } accept
        iifname $IOT_IFACES tcp dport 53 accept
```
*(Notice that we do NOT add `$IOT_IFACES` to `$MGMT_PORTS`, which prevents VLAN devices from accessing SSH `22`, Cockpit `9090`, or Alloy `12345`)*.

### 3. Allow Internet Egress (Forward Chain)
Inside `chain forward`, allow VLAN devices to access the Internet through your WAN interface:
```nftables
        # Allow VLAN 100 to access the Internet
        iifname $IOT_IFACES oifname $WAN_IFACES accept
```

> [!NOTE]
> Because `chain forward` has a default `policy drop`, traffic from `$IOT_IFACES` heading to `$LAN_IFACES` is automatically dropped. Your private LAN is fully protected from any compromised devices on the VLAN.

### 4. Reload the Firewall Rules
```bash
sudo systemctl restart nftables
```

Inspect the active ruleset to verify the changes:
```bash
sudo nft list ruleset
```

---

## 5. Verification & Testing

### 1. Check Azureclaw Dynamic Status Display
Run the built-in status tool:
```bash
/usr/libexec/azureclaw/router-status.sh
```
You should see your new VLAN sub-interface listed with its role and assigned IP address:
```text
 INTERFACE    ROLE/NAME        STATUS   ADDRESS(ES)                     
 ---------    ---------        ------   -----------                     
 ens18        WAN              UP       10.13.37.36/24                  
 ens19        LAN              UP       192.168.1.1/24                  
 ens19.100    VLAN             UP       10.0.100.1/24
```

### 2. Verify Client Connectivity
From your test client attached to VLAN 100:
1. **Acquire DHCP Lease**:
   ```bash
   # On Linux:
   sudo dhclient -v
   ip -br addr
   # Should have an address like 10.0.100.5x/24
   ```
2. **Test DNS Resolution**:
   ```bash
   dig @10.0.100.1 google.com
   ```
3. **Test Internet Routing (NAT)**:
   ```bash
   ping -c 3 1.1.1.1
   ```
4. **Verify LAN Isolation**:
   Attempt to ping or SSH to your trusted LAN gateway from the VLAN client:
   ```bash
   ping -c 2 192.168.1.1
   curl -m 3 https://192.168.1.1:9090
   ```
   *Result: Should time out or drop immediately, confirming complete network segmentation.*
