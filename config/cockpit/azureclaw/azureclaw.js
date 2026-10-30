/**
 * Azureclaw Cockpit Extension
 * Declarative router management for NetworkManager, nftables, dnsmasq, and WireGuard.
 * Hardened with strict input validation and sanitization.
 */

let state = {
  interfaces: [],
  wan: { method: "auto", ip: "", prefix: 24, gateway: "", dns: "", device: "ens18" },
  lan: { ip: "192.168.1.1", prefix: 24, device: "ens19" },
  vlans: [],
  dhcpScope: {
    enabled: true,
    rangeStart: "192.168.1.50",
    rangeEnd: "192.168.1.200",
    netmask: "255.255.255.0",
    leaseTime: "24h",
    gateway: "192.168.1.1",
    dns: "192.168.1.1",
    domain: "home.arpa"
  },
  dhcpOptions: [],
  reservations: [],
  dnsOverrides: [],
  portForwards: [],
  leases: [],
  wireguard: {
    configured: false,
    active: false,
    privkey: "",
    pubkey: "",
    address: "",
    listenPort: "",
    peerPubkey: "",
    peerEndpoint: "",
    allowedIps: "0.0.0.0/0",
    keepalive: 25,
    dns: "",
    inboundWan: false
  }
};

// ============================================================================
// Security & Validation Helpers
// ============================================================================
const Validators = {
  isValidIPv4(ip) {
    if (!ip || typeof ip !== "string") return false;
    if (!/^([0-9]{1,3}\.){3}[0-9]{1,3}$/.test(ip.trim())) return false;
    const parts = ip.trim().split(".");
    return parts.every(part => {
      const num = parseInt(part, 10);
      return num >= 0 && num <= 255 && String(num) === part;
    });
  },

  isValidCIDR(prefix) {
    if (prefix === undefined || prefix === null) return false;
    const p = parseInt(String(prefix).trim(), 10);
    return Number.isInteger(p) && p >= 1 && p <= 32 && String(p) === String(prefix).trim();
  },

  isValidPort(port) {
    if (port === undefined || port === null) return false;
    const str = String(port).trim();
    if (!/^\d{1,5}$/.test(str)) return false;
    const p = parseInt(str, 10);
    return Number.isInteger(p) && p >= 1 && p <= 65535 && String(p) === str;
  },

  isValidProto(proto) {
    if (typeof proto !== "string") return false;
    return ["tcp", "udp", "both"].includes(proto.toLowerCase().trim());
  },

  isValidMAC(mac) {
    if (!mac || typeof mac !== "string") return false;
    return /^([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})$/.test(mac.trim());
  },

  isValidHostname(name) {
    if (!name || typeof name !== "string" || name.length > 253) return false;
    return /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/.test(name.trim());
  },

  isValidRuleName(name) {
    if (!name || typeof name !== "string") return false;
    return /^[a-zA-Z0-9 _.-]{1,32}$/.test(name.trim());
  },

  isValidVlanId(id) {
    if (id === undefined || id === null) return false;
    const p = parseInt(String(id).trim(), 10);
    return Number.isInteger(p) && p >= 1 && p <= 4094 && String(p) === String(id).trim();
  },

  isValidLeaseTime(time) {
    if (!time || typeof time !== "string") return false;
    return /^(infinite|[0-9]{1,4}[smhdw])$/i.test(time.trim());
  },

  isValidWireGuardKey(key) {
    if (!key || typeof key !== "string") return false;
    const trimmed = key.trim();
    return trimmed.length === 44 && /^[A-Za-z0-9+/]{43}=$/.test(trimmed);
  },

  isValidEndpoint(ep) {
    if (!ep || typeof ep !== "string") return false;
    const parts = ep.trim().split(":");
    if (parts.length !== 2) return false;
    const [host, port] = parts;
    const validHost = Validators.isValidIPv4(host) || Validators.isValidHostname(host);
    const validPort = Validators.isValidPort(port);
    return validHost && validPort;
  }
};

function sanitizeString(str, maxLen = 64) {
  if (!str) return "";
  return String(str)
    .replace(/[\r\n\t\0;'"$`\\{}()[\]]/g, "")
    .trim()
    .slice(0, maxLen);
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// ============================================================================
// Initialization & Refresh
// ============================================================================
document.addEventListener("DOMContentLoaded", () => {
  setupTabs();
  setupUIEvents();
  setupForms();
  refreshAll();
});

function refreshAll() {
  loadServiceStatus();
  loadInterfaces();
  loadWanConfig();
  loadLanConfig();
  loadVlans();
  loadDHCPScopeAndOptions();
  loadDHCPLeases();
  loadPortForwards();
  loadReservations();
  loadDNSOverrides();
  loadWireGuard();
  loadIPsecStatus();
}

function showAlert(message, isError = false) {
  const container = document.getElementById("alert-banner");
  const box = document.getElementById("alert-box");
  const msgEl = document.getElementById("alert-msg");

  msgEl.textContent = message;
  box.className = isError ? "pf-c-alert pf-m-danger" : "pf-c-alert pf-m-success";
  container.style.display = "block";

  setTimeout(() => {
    container.style.display = "none";
  }, 7000);
}

function setupTabs() {
  const tabs = document.querySelectorAll(".nav-tab");
  tabs.forEach(tab => {
    tab.addEventListener("click", () => {
      tabs.forEach(t => t.classList.remove("active"));
      document.querySelectorAll(".tab-content").forEach(c => c.style.display = "none");

      tab.classList.add("active");
      const targetId = tab.getAttribute("data-tab");
      const target = document.getElementById(targetId);
      if (target) target.style.display = "block";
    });
  });
}

function switchTab(tabId) {
  const btn = document.querySelector(`.nav-tab[data-tab="${tabId}"]`);
  if (btn) btn.click();
}

// ============================================================================
// Form Validation UI Helpers
// ============================================================================
function setFieldError(fieldId, errorMsg) {
  const inputEl = document.getElementById(fieldId);
  const errEl = document.getElementById(fieldId + "-err");
  if (inputEl) {
    if (errorMsg) {
      inputEl.classList.add("is-invalid");
      inputEl.setAttribute("aria-invalid", "true");
    } else {
      inputEl.classList.remove("is-invalid");
      inputEl.removeAttribute("aria-invalid");
    }
  }
  if (errEl) {
    if (errorMsg) {
      errEl.innerHTML = `<span style="color: #c9190b !important; font-weight: 600; font-size: 12px; display: inline-block;">⚠ ${escapeHtml(errorMsg)}</span>`;
      errEl.style.setProperty("color", "#c9190b", "important");
      errEl.classList.add("visible");
    } else {
      errEl.innerHTML = "";
      errEl.classList.remove("visible");
    }
  }
}

function clearFormErrors(formId) {
  const form = document.getElementById(formId);
  if (!form) return;
  form.querySelectorAll(".is-invalid").forEach(el => {
    el.classList.remove("is-invalid");
    el.removeAttribute("aria-invalid");
  });
  form.querySelectorAll(".form-error-msg").forEach(el => {
    el.textContent = "";
    el.classList.remove("visible");
  });
}

function setupUIEvents() {
  document.getElementById("btn-refresh").addEventListener("click", refreshAll);

  // Toggle WAN mode fields
  const wanMethodSelect = document.getElementById("wan-method");
  if (wanMethodSelect) {
    wanMethodSelect.addEventListener("change", (e) => {
      const isManual = e.target.value === "manual";
      document.querySelectorAll(".wan-static-input").forEach(el => {
        el.style.display = isManual ? "flex" : "none";
      });
    });
  }

  // Toggle VLAN DHCP fields
  const vlanDhcpCheck = document.getElementById("vlan-opt-dhcp");
  if (vlanDhcpCheck) {
    vlanDhcpCheck.addEventListener("change", (e) => {
      const fields = document.getElementById("vlan-dhcp-fields");
      if (fields) fields.style.display = e.target.checked ? "flex" : "none";
    });
  }

  // WireGuard Keypair Generation
  const btnGenKeys = document.getElementById("btn-wg-genkeys");
  if (btnGenKeys) {
    btnGenKeys.addEventListener("click", () => {
      cockpit.spawn(["wg", "genkey"])
        .then(privKey => {
          privKey = privKey.trim();
          document.getElementById("wg-privkey").value = privKey;
          return cockpit.spawn(["wg", "pubkey"], { input: privKey });
        })
        .then(pubKey => {
          document.getElementById("wg-pubkey").value = pubKey.trim();
          showAlert("Generated new WireGuard cryptographic keypair.");
        })
        .catch(err => {
          showAlert("Failed to generate keys via wg: " + (err.message || err), true);
        });
    });
  }

  // WireGuard Private key change calculates public key
  const privKeyInput = document.getElementById("wg-privkey");
  if (privKeyInput) {
    privKeyInput.addEventListener("input", (e) => {
      const key = e.target.value.trim();
      if (Validators.isValidWireGuardKey(key)) {
        cockpit.spawn(["wg", "pubkey"], { input: key })
          .then(pub => {
            document.getElementById("wg-pubkey").value = pub.trim();
          })
          .catch(() => {
            document.getElementById("wg-pubkey").value = "";
          });
      } else {
        document.getElementById("wg-pubkey").value = "";
      }
    });
  }

  // WireGuard Start / Stop button
  const btnWgToggle = document.getElementById("btn-wg-toggle");
  if (btnWgToggle) {
    btnWgToggle.addEventListener("click", () => {
      toggleWireGuardService();
    });
  }

  // WireGuard Delete button
  const btnWgDelete = document.getElementById("btn-wg-delete");
  if (btnWgDelete) {
    btnWgDelete.addEventListener("click", () => {
      deleteWireGuardConfig();
    });
  }

  // IPsec refresh button
  const btnIpsecRefresh = document.getElementById("btn-ipsec-refresh");
  if (btnIpsecRefresh) {
    btnIpsecRefresh.addEventListener("click", loadIPsecStatus);
  }
}

// ============================================================================
// Service Status
// ============================================================================
function loadServiceStatus() {
  cockpit.spawn(["systemctl", "is-active", "nftables"])
    .then(out => updateStatusPill("stat-nft-status", out.trim() === "active"))
    .catch(() => updateStatusPill("stat-nft-status", false));

  cockpit.spawn(["systemctl", "is-active", "dnsmasq"])
    .then(out => updateStatusPill("stat-dns-status", out.trim() === "active"))
    .catch(() => updateStatusPill("stat-dns-status", false));
}

function updateStatusPill(elementId, isActive, textOverride = null) {
  const el = document.getElementById(elementId);
  if (!el) return;
  if (textOverride) {
    el.textContent = textOverride;
  } else {
    el.textContent = isActive ? "Active" : "Inactive";
  }
  el.className = "status-pill " + (isActive ? "status-active" : "status-inactive");
}

// ============================================================================
// Network Interfaces
// ============================================================================
function loadInterfaces() {
  const ipPromise = cockpit.spawn(["ip", "-j", "addr"])
    .then(jsonText => {
      try { return JSON.parse(jsonText); } catch(e) { return []; }
    })
    .catch(() => []);

  const nmPromise = cockpit.spawn(["nmcli", "-t", "-f", "DEVICE,CONNECTION", "device"])
    .then(text => {
      const map = {};
      text.split("\n").forEach(line => {
        const parts = line.split(":");
        if (parts.length >= 2 && parts[0] && parts[1] && parts[1] !== "--") {
          map[parts[0].trim()] = parts[1].trim();
        }
      });
      return map;
    })
    .catch(() => ({}));

  Promise.all([ipPromise, nmPromise])
    .then(([data, nmMap]) => {
      const tbody = document.getElementById("table-interfaces-body");
      tbody.innerHTML = "";

      state.interfaces = [];
      const physicalDevs = [];

      if (!data || data.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" class="empty-state">No network interfaces found.</td></tr>`;
        document.getElementById("stat-iface-count").textContent = "0";
        return;
      }

      data.forEach(iface => {
        if (!iface.ifname || iface.ifname === "lo" || iface.ifname.startsWith("veth") || iface.ifname.startsWith("br-")) {
          return;
        }

        const cleanDev = iface.ifname.split("@")[0];
        let role = nmMap[cleanDev] || nmMap[iface.ifname];

        if (!role || role === "--") {
          const lower = cleanDev.toLowerCase();
          if (["eth0", "ens18", "enp1s0"].includes(cleanDev)) role = "WAN";
          else if (["eth1", "ens19", "enp2s0"].includes(cleanDev)) role = "LAN";
          else if (lower.includes("vlan") || cleanDev.includes(".")) role = "VLAN";
          else if (lower.startsWith("tailscale")) role = "Tailscale";
          else if (lower.startsWith("wg")) role = "WireGuard";
          else if (lower.startsWith("tun") || lower.startsWith("tap")) role = "OpenVPN";
          else if (lower.startsWith("ppp") || lower.startsWith("ipsec") || lower.startsWith("xfrm")) role = "IPsec/L2TP";
          else role = "Other";
        }

        // Collect physical devices for parent selection
        if (!cleanDev.includes(".") && !cleanDev.startsWith("wg") && !cleanDev.startsWith("tailscale") && !cleanDev.startsWith("tun")) {
          physicalDevs.push(cleanDev);
          if (role === "WAN" || ["eth0", "ens18", "enp1s0"].includes(cleanDev)) {
            state.wan.device = cleanDev;
          }
          if (role === "LAN" || ["eth1", "ens19", "enp2s0"].includes(cleanDev)) {
            state.lan.device = cleanDev;
          }
        }

        const ips = (iface.addr_info || [])
          .map(a => `${escapeHtml(a.local)}/${escapeHtml(String(a.prefixlen))}`)
          .join("<br>") || "No IP";

        const mac = iface.address || "--";
        const stateClass = iface.operstate === "UP" ? "status-active" : "status-inactive";

        state.interfaces.push({ dev: cleanDev, role, state: iface.operstate, ips, mac });

        const row = document.createElement("tr");
        row.innerHTML = `
          <td><strong>${escapeHtml(cleanDev)}</strong></td>
          <td>${escapeHtml(role)}</td>
          <td><span class="status-pill ${stateClass}">${escapeHtml(iface.operstate || "UNKNOWN")}</span></td>
          <td><code>${ips}</code></td>
          <td><code>${escapeHtml(mac)}</code></td>
        `;
        tbody.appendChild(row);
      });

      document.getElementById("stat-iface-count").textContent = state.interfaces.length;
      updateParentDevDropdown(physicalDevs);
      updateDeviceBadges();
    })
    .catch(err => {
      console.warn("Failed to load interfaces:", err);
    });
}

function updateParentDevDropdown(physicalDevs) {
  const select = document.getElementById("vlan-parent");
  if (!select) return;
  const currentVal = select.value;
  select.innerHTML = "";
  const devs = physicalDevs.length > 0 ? physicalDevs : ["ens19", "eth1"];
  devs.forEach(dev => {
    const opt = document.createElement("option");
    opt.value = dev;
    opt.textContent = `${dev} (${dev === state.lan.device ? "LAN" : "Interface"})`;
    select.appendChild(opt);
  });
  if (devs.includes(currentVal)) {
    select.value = currentVal;
  } else if (devs.includes(state.lan.device)) {
    select.value = state.lan.device;
  }
}

function updateDeviceBadges() {
  const wanBadge = document.getElementById("wan-dev-badge");
  if (wanBadge) wanBadge.textContent = `Device: ${state.wan.device}`;
  const lanBadge = document.getElementById("lan-dev-badge");
  if (lanBadge) lanBadge.textContent = `Device: ${state.lan.device}`;
}

// ============================================================================
// WAN Configuration
// ============================================================================
function loadWanConfig() {
  cockpit.spawn(["nmcli", "-t", "-f", "ipv4.method,ipv4.addresses,ipv4.gateway,ipv4.dns", "connection", "show", "WAN"])
    .then(text => {
      const lines = text.trim().split("\n");
      const map = {};
      lines.forEach(l => {
        const parts = l.split(":");
        if (parts.length >= 2) map[parts[0].trim()] = parts.slice(1).join(":").trim();
      });

      const method = map["ipv4.method"] || "auto";
      state.wan.method = method;

      const methodSelect = document.getElementById("wan-method");
      if (methodSelect) {
        methodSelect.value = method === "manual" ? "manual" : "auto";
        document.querySelectorAll(".wan-static-input").forEach(el => {
          el.style.display = method === "manual" ? "flex" : "none";
        });
      }

      if (map["ipv4.addresses"]) {
        const [ip, prefix] = map["ipv4.addresses"].split("/");
        document.getElementById("wan-ip").value = ip || "";
        document.getElementById("wan-prefix").value = prefix || "24";
      }
      if (map["ipv4.gateway"]) {
        document.getElementById("wan-gw").value = map["ipv4.gateway"];
      }
      if (map["ipv4.dns"]) {
        document.getElementById("wan-dns").value = map["ipv4.dns"];
      }
    })
    .catch(() => {
      // WAN connection profile might not exist or defaults to auto
      document.getElementById("wan-method").value = "auto";
      document.querySelectorAll(".wan-static-input").forEach(el => el.style.display = "none");
    });
}

function saveWanConfig(e) {
  e.preventDefault();
  clearFormErrors("form-wan");

  const method = document.getElementById("wan-method").value;
  if (method === "auto") {
    // Revert to DHCP
    cockpit.spawn(["nmcli", "connection", "modify", "WAN", "ipv4.method", "auto", "ipv4.addresses", "", "ipv4.gateway", ""], { superuser: "require" })
      .then(() => cockpit.spawn(["nmcli", "connection", "up", "WAN"], { superuser: "require" }))
      .then(() => {
        showAlert("WAN set to DHCP client (Automatic) and reloaded.");
        loadWanConfig();
        loadInterfaces();
      })
      .catch(err => {
        showAlert("Failed to update WAN: " + (err.message || err), true);
      });
    return;
  }

  // Static WAN
  const ip = document.getElementById("wan-ip").value.trim();
  const prefix = document.getElementById("wan-prefix").value.trim();
  const gw = document.getElementById("wan-gw").value.trim();
  const dns = document.getElementById("wan-dns").value.trim();

  let hasError = false;
  if (!Validators.isValidIPv4(ip)) {
    setFieldError("wan-ip", "Valid IPv4 address is required.");
    hasError = true;
  }
  if (!Validators.isValidCIDR(prefix)) {
    setFieldError("wan-prefix", "CIDR prefix must be between 1 and 32.");
    hasError = true;
  }
  if (!Validators.isValidIPv4(gw)) {
    setFieldError("wan-gw", "Valid IPv4 default gateway is required.");
    hasError = true;
  }
  if (dns) {
    const dnsList = dns.split(",").map(d => d.trim());
    if (!dnsList.every(d => Validators.isValidIPv4(d))) {
      setFieldError("wan-dns", "DNS servers must be comma-separated valid IPv4 addresses.");
      hasError = true;
    }
  }

  if (hasError) {
    showAlert("Please correct the errors in the WAN form.", true);
    return;
  }

  const dnsArg = dns ? dns.split(",").map(d => d.trim()).join(" ") : "1.1.1.1 9.9.9.9";
  const cmd = ["nmcli", "connection", "modify", "WAN", "ipv4.method", "manual", "ipv4.addresses", `${ip}/${prefix}`, "ipv4.gateway", gw, "ipv4.dns", dnsArg];

  cockpit.spawn(cmd, { superuser: "require" })
    .then(() => cockpit.spawn(["nmcli", "connection", "up", "WAN"], { superuser: "require" }))
    .then(() => {
      showAlert("Static WAN configuration saved and connection activated.");
      loadWanConfig();
      loadInterfaces();
    })
    .catch(err => {
      showAlert("Failed to apply static WAN: " + (err.message || err), true);
    });
}

// ============================================================================
// LAN Configuration
// ============================================================================
function loadLanConfig() {
  cockpit.spawn(["nmcli", "-t", "-f", "ipv4.addresses", "connection", "show", "LAN"])
    .then(text => {
      const line = text.trim();
      if (line && line.includes("/")) {
        const [ip, prefix] = line.split("/");
        state.lan.ip = ip;
        state.lan.prefix = parseInt(prefix, 10) || 24;
        document.getElementById("lan-ip").value = ip;
        document.getElementById("lan-prefix").value = state.lan.prefix;
      }
    })
    .catch(() => {
      document.getElementById("lan-ip").value = "192.168.1.1";
      document.getElementById("lan-prefix").value = "24";
    });
}

function saveLanConfig(e) {
  e.preventDefault();
  clearFormErrors("form-lan");

  const ip = document.getElementById("lan-ip").value.trim();
  const prefix = document.getElementById("lan-prefix").value.trim();

  let hasError = false;
  if (!Validators.isValidIPv4(ip)) {
    setFieldError("lan-ip", "Valid IPv4 address is required (e.g. 192.168.1.1).");
    hasError = true;
  }
  if (!Validators.isValidCIDR(prefix)) {
    setFieldError("lan-prefix", "CIDR prefix must be between 8 and 30.");
    hasError = true;
  }

  if (hasError) {
    showAlert("Please correct the LAN configuration errors.", true);
    return;
  }

  const confirmMsg = `Are you sure you want to change the router LAN IP to ${ip}/${prefix}?\n\nWARNING: Your current browser session will disconnect. You must reconnect at https://${ip}:9090.`;
  if (!confirm(confirmMsg)) return;

  cockpit.spawn(["nmcli", "connection", "modify", "LAN", "ipv4.addresses", `${ip}/${prefix}`], { superuser: "require" })
    .then(() => cockpit.spawn(["nmcli", "connection", "up", "LAN"], { superuser: "require" }))
    .then(() => {
      showAlert(`LAN updated to ${ip}/${prefix}. Please reconnect at https://${ip}:9090.`);
      state.lan.ip = ip;
      state.lan.prefix = parseInt(prefix, 10);
    })
    .catch(err => {
      showAlert("Failed to update LAN connection: " + (err.message || err), true);
    });
}

// ============================================================================
// 802.1Q VLAN Management
// ============================================================================
const VLAN_NFT_FILE = "/etc/nftables.d/40-vlans.nft";
const VLAN_DNS_FILE = "/etc/dnsmasq.d/40-vlans.conf";

function loadVlans() {
  const file = cockpit.file(VLAN_NFT_FILE);
  file.read()
    .then(content => {
      state.vlans = [];
      if (content) {
        const match = content.match(/# JSON_VLANS:\s*(.+)$/m);
        if (match) {
          try {
            const rawVlans = JSON.parse(match[1]);
            state.vlans = rawVlans.filter(v =>
              Validators.isValidVlanId(v.id) &&
              Validators.isValidIPv4(v.ip) &&
              Validators.isValidCIDR(v.prefix)
            );
          } catch(e) {}
        }
      }
      renderVlans();
    })
    .catch(() => {
      state.vlans = [];
      renderVlans();
    });
}

function renderVlans() {
  const tbody = document.getElementById("table-vlans-body");
  tbody.innerHTML = "";

  if (state.vlans.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" class="empty-state">No 802.1Q VLANs configured.</td></tr>`;
    return;
  }

  state.vlans.forEach((v, idx) => {
    const row = document.createElement("tr");
    const subDev = `${v.parent}.${v.id}`;
    const dhcpInfo = v.dhcp ? `${escapeHtml(v.dhcpStart)} - ${escapeHtml(v.dhcpEnd)}` : `<span style="color: #6a6e73;">Disabled</span>`;

    row.innerHTML = `
      <td><strong>${escapeHtml(String(v.id))}</strong></td>
      <td>${escapeHtml(v.name)}</td>
      <td><code>${escapeHtml(subDev)}</code></td>
      <td><code>${escapeHtml(v.ip)}/${escapeHtml(String(v.prefix))}</code></td>
      <td><span class="status-pill ${v.wanAccess ? "status-active" : "status-neutral"}">${v.wanAccess ? "Allowed" : "Blocked"}</span></td>
      <td><span class="status-pill ${v.isolate ? "status-active" : "status-neutral"}">${v.isolate ? "Isolated" : "Bridged"}</span></td>
      <td>${dhcpInfo}</td>
      <td>
        <button class="btn btn-danger btn-del-vlan" data-idx="${idx}" data-con="VLAN${v.id}">Delete</button>
      </td>
    `;
    tbody.appendChild(row);
  });

  tbody.querySelectorAll(".btn-del-vlan").forEach(btn => {
    btn.addEventListener("click", () => {
      const idx = parseInt(btn.getAttribute("data-idx"), 10);
      const conName = btn.getAttribute("data-con");
      deleteVlan(idx, conName);
    });
  });
}

function addVlan(e) {
  e.preventDefault();
  clearFormErrors("form-add-vlan");

  const idVal = document.getElementById("vlan-id").value.trim();
  const nameVal = document.getElementById("vlan-name").value.trim();
  const parentVal = document.getElementById("vlan-parent").value.trim();
  const ipVal = document.getElementById("vlan-ip").value.trim();
  const prefixVal = document.getElementById("vlan-prefix").value.trim();

  const wanAccess = document.getElementById("vlan-opt-wan").checked;
  const isolate = document.getElementById("vlan-opt-isolate").checked;
  const dhcp = document.getElementById("vlan-opt-dhcp").checked;

  const dhcpStart = document.getElementById("vlan-dhcp-start").value.trim();
  const dhcpEnd = document.getElementById("vlan-dhcp-end").value.trim();
  const dhcpLease = document.getElementById("vlan-dhcp-lease").value.trim() || "24h";

  let hasError = false;
  if (!Validators.isValidVlanId(idVal)) {
    setFieldError("vlan-id", "VLAN ID must be an integer between 1 and 4094.");
    hasError = true;
  }
  if (!Validators.isValidRuleName(nameVal)) {
    setFieldError("vlan-name", "Name must be alphanumeric (max 32 chars).");
    hasError = true;
  }
  if (!Validators.isValidIPv4(ipVal)) {
    setFieldError("vlan-ip", "Must be a valid IPv4 address.");
    hasError = true;
  }
  if (!Validators.isValidCIDR(prefixVal)) {
    setFieldError("vlan-prefix", "CIDR prefix must be between 8 and 30.");
    hasError = true;
  }

  const vlanId = parseInt(idVal, 10);
  if (state.vlans.some(v => v.id === vlanId)) {
    setFieldError("vlan-id", `VLAN ID ${vlanId} already exists.`);
    hasError = true;
  }

  if (dhcp) {
    if (!Validators.isValidIPv4(dhcpStart)) {
      setFieldError("vlan-dhcp-start", "Valid start IPv4 required.");
      hasError = true;
    }
    if (!Validators.isValidIPv4(dhcpEnd)) {
      setFieldError("vlan-dhcp-end", "Valid end IPv4 required.");
      hasError = true;
    }
    if (!Validators.isValidLeaseTime(dhcpLease)) {
      setFieldError("vlan-dhcp-lease", "Valid lease duration (e.g. 24h) required.");
      hasError = true;
    }
  }

  if (hasError) {
    showAlert("Please correct the VLAN form errors.", true);
    return;
  }

  const newVlan = {
    id: vlanId,
    name: sanitizeString(nameVal, 32),
    parent: sanitizeString(parentVal, 16),
    ip: ipVal,
    prefix: parseInt(prefixVal, 10),
    wanAccess,
    isolate,
    dhcp,
    dhcpStart,
    dhcpEnd,
    dhcpLease
  };

  const conName = `VLAN${vlanId}`;
  const subDev = `${newVlan.parent}.${vlanId}`;

  // 1. Add NetworkManager connection
  cockpit.spawn([
    "nmcli", "connection", "add",
    "type", "vlan",
    "con-name", conName,
    "ifname", subDev,
    "dev", newVlan.parent,
    "id", String(vlanId),
    "ip4", `${newVlan.ip}/${newVlan.prefix}`,
    "ipv6.method", "ignore"
  ], { superuser: "require" })
    .then(() => cockpit.spawn(["nmcli", "connection", "up", conName], { superuser: "require" }))
    .then(() => {
      state.vlans.push(newVlan);
      return saveVlanFirewallAndDns();
    })
    .then(() => {
      showAlert(`VLAN ${vlanId} (${newVlan.name}) created and activated.`);
      document.getElementById("form-add-vlan").reset();
      document.getElementById("vlan-opt-wan").checked = true;
      document.getElementById("vlan-opt-isolate").checked = true;
      document.getElementById("vlan-opt-dhcp").checked = true;
      document.getElementById("vlan-dhcp-fields").style.display = "flex";
      renderVlans();
      loadInterfaces();
    })
    .catch(err => {
      showAlert("Failed to create VLAN: " + (err.message || err), true);
    });
}

function deleteVlan(idx, conName) {
  if (!confirm(`Delete ${conName}? This will remove the interface, firewall rules, and DHCP pool.`)) return;

  state.vlans.splice(idx, 1);

  // Delete from NetworkManager and update config files
  cockpit.spawn(["nmcli", "connection", "delete", conName], { superuser: "require" })
    .catch(() => {})
    .then(() => saveVlanFirewallAndDns())
    .then(() => {
      showAlert(`${conName} removed.`);
      renderVlans();
      loadInterfaces();
    })
    .catch(err => {
      showAlert("Failed to remove VLAN: " + (err.message || err), true);
      renderVlans();
    });
}

function saveVlanFirewallAndDns() {
  // Generate nftables rules for VLANs
  const inputRules = [];
  const forwardRules = [];

  state.vlans.forEach(v => {
    const subDev = `${v.parent}.${v.id}`;
    // Allow DHCP and DNS on VLAN sub-interface
    inputRules.push(`        iifname "${subDev}" udp dport { 53, 67 } accept comment "VLAN ${v.id} DHCP/DNS"`);
    inputRules.push(`        iifname "${subDev}" tcp dport 53 accept comment "VLAN ${v.id} DNS"`);

    if (!v.isolate) {
      // If not isolated from router management, allow management ports
      inputRules.push(`        iifname "${subDev}" tcp dport $MGMT_PORTS accept comment "VLAN ${v.id} Management"`);
    }

    if (v.wanAccess) {
      // Allow internet egress
      forwardRules.push(`        iifname "${subDev}" oifname $WAN_IFACES accept comment "VLAN ${v.id} Internet Egress"`);
    }
  });

  const nftContent = `# Azureclaw VLAN Firewall Ruleset
# Managed by Cockpit Azureclaw
# JSON_VLANS: ${JSON.stringify(state.vlans)}

table inet router {
    chain input {
${inputRules.join("\n")}
    }

    chain forward {
${forwardRules.join("\n")}
    }
}
`;

  // Generate Dnsmasq config for VLANs
  const dnsLines = [
    "# Azureclaw VLAN DHCP & DNS Pools (Managed by Cockpit)",
    "# DO NOT EDIT DIRECTLY IF USING COCKPIT GUI",
    ""
  ];

  state.vlans.filter(v => v.dhcp).forEach(v => {
    dnsLines.push(`# VLAN ${v.id} (${v.name})`);
    dnsLines.push(`listen-address=${v.ip}`);
    dnsLines.push(`dhcp-range=set:vlan${v.id},${v.dhcpStart},${v.dhcpEnd},255.255.255.0,${v.dhcpLease}`);
    dnsLines.push(`dhcp-option=tag:vlan${v.id},option:router,${v.ip}`);
    dnsLines.push(`dhcp-option=tag:vlan${v.id},option:dns-server,${v.ip}`);
    dnsLines.push("");
  });

  const nftFile = cockpit.file(VLAN_NFT_FILE, { superuser: "try" });
  const dnsFile = cockpit.file(VLAN_DNS_FILE, { superuser: "try" });

  return Promise.all([
    nftFile.replace(nftContent),
    dnsFile.replace(dnsLines.join("\n"))
  ])
  .then(() => cockpit.spawn(["nft", "-c", "-f", "/etc/nftables/nftables.conf"], { superuser: "require" }))
  .then(() => cockpit.spawn(["dnsmasq", "--test"], { superuser: "require" }))
  .then(() => cockpit.spawn(["systemctl", "reload", "nftables"], { superuser: "require" }))
  .then(() => cockpit.spawn(["systemctl", "reload", "dnsmasq"], { superuser: "require" }));
}

// ============================================================================
// DHCP Scopes & Custom Options
// ============================================================================
const DHCP_FILE = "/etc/dnsmasq.d/30-dhcp.conf";

function loadDHCPScopeAndOptions() {
  const file = cockpit.file(DHCP_FILE);
  file.read()
    .then(content => {
      state.dhcpOptions = [];
      if (content) {
        const match = content.match(/# JSON_DHCP:\s*(.+)$/m);
        if (match) {
          try {
            const parsed = JSON.parse(match[1]);
            if (parsed.lanScope) {
              state.dhcpScope = Object.assign({}, state.dhcpScope, parsed.lanScope);
            }
            if (Array.isArray(parsed.customOptions)) {
              state.dhcpOptions = parsed.customOptions;
            }
          } catch(e) {}
        }
      }
      populateDHCPScopeForm();
      renderDHCPOptions();
    })
    .catch(() => {
      populateDHCPScopeForm();
      renderDHCPOptions();
    });
}

function populateDHCPScopeForm() {
  const s = state.dhcpScope;
  document.getElementById("dhcp-scope-enabled").checked = s.enabled !== false;
  document.getElementById("dhcp-range-start").value = s.rangeStart || "192.168.1.50";
  document.getElementById("dhcp-range-end").value = s.rangeEnd || "192.168.1.200";
  document.getElementById("dhcp-netmask").value = s.netmask || "255.255.255.0";
  document.getElementById("dhcp-lease-time").value = s.leaseTime || "24h";
  document.getElementById("dhcp-opt-gw").value = s.gateway || "192.168.1.1";
  document.getElementById("dhcp-opt-dns").value = s.dns || "192.168.1.1";
  document.getElementById("dhcp-opt-domain").value = s.domain || "home.arpa";
}

function saveDHCPScope(e) {
  e.preventDefault();
  clearFormErrors("form-dhcp-scope");

  const enabled = document.getElementById("dhcp-scope-enabled").checked;
  const rangeStart = document.getElementById("dhcp-range-start").value.trim();
  const rangeEnd = document.getElementById("dhcp-range-end").value.trim();
  const netmask = document.getElementById("dhcp-netmask").value.trim();
  const leaseTime = document.getElementById("dhcp-lease-time").value.trim() || "24h";
  const gateway = document.getElementById("dhcp-opt-gw").value.trim() || state.lan.ip;
  const dns = document.getElementById("dhcp-opt-dns").value.trim() || state.lan.ip;
  const domain = document.getElementById("dhcp-opt-domain").value.trim() || "home.arpa";

  let hasError = false;
  if (!Validators.isValidIPv4(rangeStart)) {
    setFieldError("dhcp-range-start", "Valid IPv4 start required.");
    hasError = true;
  }
  if (!Validators.isValidIPv4(rangeEnd)) {
    setFieldError("dhcp-range-end", "Valid IPv4 end required.");
    hasError = true;
  }
  if (!Validators.isValidIPv4(netmask)) {
    setFieldError("dhcp-netmask", "Valid subnet mask required.");
    hasError = true;
  }
  if (!Validators.isValidLeaseTime(leaseTime)) {
    setFieldError("dhcp-lease-time", "Valid lease duration (e.g. 24h, 12h) required.");
    hasError = true;
  }
  if (gateway && !Validators.isValidIPv4(gateway)) {
    setFieldError("dhcp-opt-gw", "Default gateway must be a valid IPv4 address.");
    hasError = true;
  }
  if (domain && !Validators.isValidHostname(domain)) {
    setFieldError("dhcp-opt-domain", "Domain name must be RFC 1123 format.");
    hasError = true;
  }

  if (hasError) {
    showAlert("Please correct the DHCP scope form errors.", true);
    return;
  }

  state.dhcpScope = {
    enabled,
    rangeStart,
    rangeEnd,
    netmask,
    leaseTime,
    gateway,
    dns,
    domain
  };

  writeAndApplyDHCPSettings();
}

function renderDHCPOptions() {
  const tbody = document.getElementById("table-dhcp-opts-body");
  tbody.innerHTML = "";

  if (state.dhcpOptions.length === 0) {
    tbody.innerHTML = `<tr><td colspan="4" class="empty-state">No custom DHCP options configured.</td></tr>`;
    return;
  }

  state.dhcpOptions.forEach((opt, idx) => {
    const scopeLabel = opt.scope ? `Tag: ${escapeHtml(opt.scope)}` : "Global (All)";
    const row = document.createElement("tr");
    row.innerHTML = `
      <td><span class="badge-tag">${scopeLabel}</span></td>
      <td><code>${escapeHtml(opt.code)}</code></td>
      <td><code>${escapeHtml(opt.val)}</code></td>
      <td>
        <button class="btn btn-danger btn-del-dhcp-opt" data-idx="${idx}">Delete</button>
      </td>
    `;
    tbody.appendChild(row);
  });

  tbody.querySelectorAll(".btn-del-dhcp-opt").forEach(btn => {
    btn.addEventListener("click", () => {
      const idx = parseInt(btn.getAttribute("data-idx"), 10);
      state.dhcpOptions.splice(idx, 1);
      writeAndApplyDHCPSettings();
    });
  });
}

function addDHCPOption(e) {
  e.preventDefault();
  clearFormErrors("form-add-dhcp-opt");

  const scopeVal = document.getElementById("opt-scope").value.trim();
  const codeVal = document.getElementById("opt-code").value.trim();
  const valVal = document.getElementById("opt-val").value.trim();

  let hasError = false;
  if (!codeVal || !/^[a-zA-Z0-9_-]{1,32}$/.test(codeVal)) {
    setFieldError("opt-code", "Valid option code (e.g. 42 or ntp-server) required.");
    hasError = true;
  }
  if (!valVal || !/^[a-zA-Z0-9_.,:-]{1,128}$/.test(valVal)) {
    setFieldError("opt-val", "Valid option value required.");
    hasError = true;
  }

  if (hasError) return;

  state.dhcpOptions.push({
    scope: sanitizeString(scopeVal, 32),
    code: sanitizeString(codeVal, 32),
    val: sanitizeString(valVal, 128)
  });

  document.getElementById("form-add-dhcp-opt").reset();
  writeAndApplyDHCPSettings();
}

function writeAndApplyDHCPSettings() {
  const jsonMetadata = {
    lanScope: state.dhcpScope,
    customOptions: state.dhcpOptions
  };

  const lines = [
    "# Azureclaw DHCP Scopes and Options (Managed by Cockpit)",
    `# JSON_DHCP: ${JSON.stringify(jsonMetadata)}`,
    ""
  ];

  if (state.dhcpScope.enabled) {
    const s = state.dhcpScope;
    lines.push("# Primary LAN DHCP Scope");
    lines.push(`dhcp-range=${s.rangeStart},${s.rangeEnd},${s.netmask},${s.leaseTime}`);
    if (s.gateway) lines.push(`dhcp-option=option:router,${s.gateway}`);
    if (s.dns) lines.push(`dhcp-option=option:dns-server,${s.dns}`);
    if (s.domain) lines.push(`dhcp-option=option:domain-name,${s.domain}`);
    lines.push("");
  }

  if (state.dhcpOptions.length > 0) {
    lines.push("# Custom DHCP Options");
    state.dhcpOptions.forEach(opt => {
      const tagPrefix = opt.scope ? `tag:${opt.scope},` : "";
      lines.push(`dhcp-option=${tagPrefix}option:${opt.code},${opt.val}`);
    });
    lines.push("");
  }

  const file = cockpit.file(DHCP_FILE, { superuser: "try" });
  file.replace(lines.join("\n"))
    .then(() => cockpit.spawn(["dnsmasq", "--test"], { superuser: "require" }))
    .then(() => cockpit.spawn(["systemctl", "reload", "dnsmasq"], { superuser: "require" }))
    .then(() => {
      showAlert("DHCP scope and options applied successfully.");
      renderDHCPOptions();
    })
    .catch(err => {
      showAlert("Failed to apply DHCP configuration: " + (err.message || err), true);
      renderDHCPOptions();
    });
}

// ============================================================================
// WireGuard VPN
// ============================================================================
const WG_CONF_FILE = "/etc/wireguard/wg0.conf";
const WG_NFT_FILE = "/etc/nftables.d/60-vpn.nft";

function loadWireGuard() {
  cockpit.spawn(["systemctl", "is-active", "wg-quick@wg0"])
    .then(out => {
      const active = out.trim() === "active";
      state.wireguard.active = active;
      updateStatusPill("stat-vpn-status", active);
      updateStatusPill("wg-tunnel-status", active);
      document.getElementById("btn-wg-toggle").textContent = active ? "Stop Tunnel" : "Start Tunnel";
      document.getElementById("btn-wg-toggle").className = active ? "btn btn-danger" : "btn btn-secondary";
      if (active) {
        loadWireGuardLiveStats();
      } else {
        document.getElementById("wg-active-info").style.display = "none";
      }
    })
    .catch(() => {
      state.wireguard.active = false;
      updateStatusPill("stat-vpn-status", false);
      updateStatusPill("wg-tunnel-status", false);
      document.getElementById("btn-wg-toggle").textContent = "Start Tunnel";
      document.getElementById("btn-wg-toggle").className = "btn btn-secondary";
      document.getElementById("wg-active-info").style.display = "none";
    });

  const file = cockpit.file(WG_CONF_FILE);
  file.read()
    .then(content => {
      if (content) {
        state.wireguard.configured = true;
        document.getElementById("btn-wg-delete").style.display = "inline-flex";

        const match = content.match(/# JSON_WG:\s*(.+)$/m);
        if (match) {
          try {
            const data = JSON.parse(match[1]);
            document.getElementById("wg-privkey").value = data.privkey || "";
            document.getElementById("wg-pubkey").value = data.pubkey || "";
            document.getElementById("wg-addr").value = data.address || "";
            document.getElementById("wg-listen-port").value = data.listenPort || "";
            document.getElementById("wg-peer-pubkey").value = data.peerPubkey || "";
            document.getElementById("wg-peer-endpoint").value = data.peerEndpoint || "";
            document.getElementById("wg-allowed-ips").value = data.allowedIps || "0.0.0.0/0";
            document.getElementById("wg-keepalive").value = data.keepalive || "25";
            document.getElementById("wg-inbound-wan").checked = !!data.inboundWan;
          } catch(e) {}
        }
      } else {
        state.wireguard.configured = false;
        document.getElementById("btn-wg-delete").style.display = "none";
      }
    })
    .catch(() => {
      state.wireguard.configured = false;
      document.getElementById("btn-wg-delete").style.display = "none";
    });
}

function loadWireGuardLiveStats() {
  cockpit.spawn(["wg", "show", "wg0"])
    .then(out => {
      const container = document.getElementById("wg-active-info");
      const textEl = document.getElementById("wg-active-text");
      if (out && out.trim()) {
        container.style.display = "block";
        textEl.textContent = out.trim();
      } else {
        container.style.display = "none";
      }
    })
    .catch(() => {
      document.getElementById("wg-active-info").style.display = "none";
    });
}

function saveWireGuardConfig(e) {
  e.preventDefault();
  clearFormErrors("form-wg-config");

  const privkey = document.getElementById("wg-privkey").value.trim();
  const pubkey = document.getElementById("wg-pubkey").value.trim();
  const address = document.getElementById("wg-addr").value.trim();
  const listenPort = document.getElementById("wg-listen-port").value.trim();
  const peerPubkey = document.getElementById("wg-peer-pubkey").value.trim();
  const peerEndpoint = document.getElementById("wg-peer-endpoint").value.trim();
  const allowedIps = document.getElementById("wg-allowed-ips").value.trim() || "0.0.0.0/0";
  const keepalive = document.getElementById("wg-keepalive").value.trim() || "25";
  const inboundWan = document.getElementById("wg-inbound-wan").checked;

  let hasError = false;
  if (!Validators.isValidWireGuardKey(privkey)) {
    setFieldError("wg-privkey", "Valid 44-character base64 private key required.");
    hasError = true;
  }
  if (!address || !address.includes("/")) {
    setFieldError("wg-addr", "Valid tunnel CIDR address required (e.g. 10.2.0.2/24).");
    hasError = true;
  }
  if (listenPort && !Validators.isValidPort(listenPort)) {
    setFieldError("wg-listen-port", "Port must be 1-65535.");
    hasError = true;
  }
  if (!Validators.isValidWireGuardKey(peerPubkey)) {
    setFieldError("wg-peer-pubkey", "Valid 44-character base64 peer public key required.");
    hasError = true;
  }
  if (peerEndpoint && !Validators.isValidEndpoint(peerEndpoint)) {
    setFieldError("wg-peer-endpoint", "Valid endpoint required (host:port or ip:port).");
    hasError = true;
  }

  if (hasError) {
    showAlert("Please correct the WireGuard form errors.", true);
    return;
  }

  const wgData = {
    privkey,
    pubkey,
    address,
    listenPort,
    peerPubkey,
    peerEndpoint,
    allowedIps,
    keepalive,
    inboundWan
  };

  const lines = [
    "# Azureclaw WireGuard Interface Configuration (Managed by Cockpit)",
    `# JSON_WG: ${JSON.stringify(wgData)}`,
    "",
    "[Interface]",
    `PrivateKey = ${privkey}`,
    `Address = ${address}`
  ];

  if (listenPort) lines.push(`ListenPort = ${listenPort}`);
  lines.push("");
  lines.push("[Peer]");
  lines.push(`PublicKey = ${peerPubkey}`);
  if (peerEndpoint) lines.push(`Endpoint = ${peerEndpoint}`);
  lines.push(`AllowedIPs = ${allowedIps}`);
  if (keepalive) lines.push(`PersistentKeepalive = ${keepalive}`);
  lines.push("");

  // Inbound firewall rule
  let nftVpnContent = "";
  if (inboundWan && listenPort) {
    nftVpnContent = `# Azureclaw WireGuard Inbound Rule
table inet router {
    chain input {
        udp dport ${listenPort} accept comment "WireGuard Inbound Listener"
    }
}
`;
  }

  const file = cockpit.file(WG_CONF_FILE, { superuser: "try" });
  const nftFile = cockpit.file(WG_NFT_FILE, { superuser: "try" });

  file.replace(lines.join("\n"))
    .then(() => nftFile.replace(nftVpnContent))
    .then(() => cockpit.spawn(["chmod", "0600", WG_CONF_FILE], { superuser: "require" }))
    .then(() => cockpit.spawn(["systemctl", "reload", "nftables"], { superuser: "require" }))
    .then(() => {
      showAlert("WireGuard configuration saved.");
      document.getElementById("btn-wg-delete").style.display = "inline-flex";
      state.wireguard.configured = true;
      loadWireGuard();
    })
    .catch(err => {
      showAlert("Failed to save WireGuard configuration: " + (err.message || err), true);
    });
}

function toggleWireGuardService() {
  const willStart = !state.wireguard.active;
  const action = willStart ? "start" : "stop";

  cockpit.spawn(["systemctl", action, "wg-quick@wg0"], { superuser: "require" })
    .then(() => {
      showAlert(`WireGuard tunnel ${willStart ? "started" : "stopped"}.`);
      loadWireGuard();
      loadInterfaces();
    })
    .catch(err => {
      showAlert(`Failed to ${action} WireGuard tunnel: ` + (err.message || err), true);
    });
}

function deleteWireGuardConfig() {
  if (!confirm("Delete WireGuard configuration file and stop tunnel?")) return;

  cockpit.spawn(["systemctl", "stop", "wg-quick@wg0"], { superuser: "require" })
    .catch(() => {})
    .then(() => cockpit.spawn(["rm", "-f", WG_CONF_FILE], { superuser: "require" }))
    .then(() => cockpit.spawn(["rm", "-f", WG_NFT_FILE], { superuser: "require" }))
    .then(() => cockpit.spawn(["systemctl", "reload", "nftables"], { superuser: "require" }))
    .then(() => {
      showAlert("WireGuard configuration removed.");
      document.getElementById("form-wg-config").reset();
      document.getElementById("btn-wg-delete").style.display = "none";
      loadWireGuard();
      loadInterfaces();
    })
    .catch(err => {
      showAlert("Failed to remove WireGuard config: " + (err.message || err), true);
    });
}

// ============================================================================
// IPsec (StrongSwan) Status
// ============================================================================
function loadIPsecStatus() {
  const terminal = document.getElementById("ipsec-output");
  terminal.textContent = "Querying StrongSwan status...";

  cockpit.spawn(["systemctl", "is-active", "strongswan"])
    .then(out => {
      const active = out.trim() === "active";
      updateStatusPill("ipsec-service-status", active);
      return cockpit.spawn(["swanctl", "--stats"]).catch(() => cockpit.spawn(["ipsec", "status"]).catch(() => "StrongSwan service running."));
    })
    .then(output => {
      terminal.textContent = output ? output.trim() : "No active Security Associations (SAs). Ready for connections.";
    })
    .catch(() => {
      updateStatusPill("ipsec-service-status", false);
      terminal.textContent = "StrongSwan service is inactive or not running.\nTo enable site-to-site IPsec: systemctl enable --now strongswan";
    });
}

// ============================================================================
// DHCP Leases
// ============================================================================
function loadDHCPLeases() {
  const file = cockpit.file("/var/lib/dnsmasq/dnsmasq.leases");
  file.read()
    .then(content => {
      state.leases = [];
      const tbody = document.getElementById("table-leases-body");
      tbody.innerHTML = "";

      if (!content || !content.trim()) {
        tbody.innerHTML = `<tr><td colspan="5" class="empty-state">No active DHCP leases found.</td></tr>`;
        updateDHCPStatCount();
        return;
      }

      const lines = content.trim().split("\n");
      lines.forEach(line => {
        const parts = line.trim().split(/\s+/);
        if (parts.length >= 4) {
          const epoch = parseInt(parts[0], 10);
          const mac = parts[1].toLowerCase();
          const ip = parts[2];
          const hostname = parts[3] === "*" ? "Unknown Client" : parts[3];

          if (Validators.isValidMAC(mac) && Validators.isValidIPv4(ip)) {
            let expiresStr = "Expired";
            const now = Math.floor(Date.now() / 1000);
            if (epoch > now) {
              const hours = Math.round((epoch - now) / 3600);
              expiresStr = `in ${hours} hr(s)`;
            }

            state.leases.push({ epoch, mac, ip, hostname });

            const row = document.createElement("tr");
            row.innerHTML = `
              <td><strong>${escapeHtml(hostname)}</strong></td>
              <td><code>${escapeHtml(ip)}</code></td>
              <td><code>${escapeHtml(mac)}</code></td>
              <td>${escapeHtml(expiresStr)}</td>
              <td>
                <button class="btn btn-secondary btn-reserve" data-mac="${escapeHtml(mac)}" data-ip="${escapeHtml(ip)}" data-name="${escapeHtml(hostname)}">
                  + Reserve IP
                </button>
              </td>
            `;
            tbody.appendChild(row);
          }
        }
      });

      tbody.querySelectorAll(".btn-reserve").forEach(btn => {
        btn.addEventListener("click", () => {
          const mac = btn.getAttribute("data-mac");
          const ip = btn.getAttribute("data-ip");
          const name = btn.getAttribute("data-name");

          switchTab("tab-dhcp");
          clearFormErrors("form-add-res");
          document.getElementById("res-mac").value = mac;
          document.getElementById("res-ip").value = ip;
          document.getElementById("res-name").value = (name && name !== "Unknown Client") ? name : "";
          document.getElementById("res-name").focus();
        });
      });

      updateDHCPStatCount();
    })
    .catch(() => {
      document.getElementById("table-leases-body").innerHTML =
        `<tr><td colspan="5" class="empty-state">dnsmasq.leases is empty or not yet created.</td></tr>`;
      updateDHCPStatCount();
    });
}

function updateDHCPStatCount() {
  const el = document.getElementById("stat-dhcp-count");
  if (el) el.textContent = `${state.leases.length} / ${state.reservations.length}`;
}

// ============================================================================
// Port Forwarding (DNAT)
// ============================================================================
const NFT_FILE = "/etc/nftables.d/50-port-forwards.nft";

function loadPortForwards() {
  const file = cockpit.file(NFT_FILE);
  file.read()
    .then(content => {
      state.portForwards = [];
      if (content) {
        const match = content.match(/# JSON_RULES:\s*(.+)$/m);
        if (match) {
          try {
            const rawRules = JSON.parse(match[1]);
            state.portForwards = rawRules.filter(r =>
              Validators.isValidRuleName(r.name) &&
              Validators.isValidProto(r.proto) &&
              Validators.isValidPort(r.wanPort) &&
              Validators.isValidIPv4(r.lanIp) &&
              Validators.isValidPort(r.lanPort)
            );
          } catch(e) {}
        }
      }
      renderPortForwards();
    })
    .catch(() => {
      state.portForwards = [];
      renderPortForwards();
    });
}

function renderPortForwards() {
  const tbody = document.getElementById("table-pf-body");
  tbody.innerHTML = "";

  document.getElementById("stat-pf-count").textContent = state.portForwards.length;

  if (state.portForwards.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" class="empty-state">No port forwarding rules configured.</td></tr>`;
    return;
  }

  state.portForwards.forEach((rule, idx) => {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td><strong>${escapeHtml(rule.name)}</strong></td>
      <td><span class="badge-proto">${escapeHtml(rule.proto.toUpperCase())}</span></td>
      <td><code>${escapeHtml(String(rule.wanPort))}</code></td>
      <td><code>${escapeHtml(rule.lanIp)}</code></td>
      <td><code>${escapeHtml(String(rule.lanPort))}</code></td>
      <td>
        <button class="btn btn-danger btn-del-pf" data-idx="${idx}">Delete</button>
      </td>
    `;
    tbody.appendChild(row);
  });

  tbody.querySelectorAll(".btn-del-pf").forEach(btn => {
    btn.addEventListener("click", () => {
      const idx = parseInt(btn.getAttribute("data-idx"), 10);
      state.portForwards.splice(idx, 1);
      savePortForwards();
    });
  });
}

function savePortForwards() {
  let preroutingRules = [];
  let forwardRules = [];

  for (const r of state.portForwards) {
    if (!Validators.isValidRuleName(r.name) ||
        !Validators.isValidProto(r.proto) ||
        !Validators.isValidPort(r.wanPort) ||
        !Validators.isValidIPv4(r.lanIp) ||
        !Validators.isValidPort(r.lanPort)) {
      showAlert("Invalid port forward rule rejected during serialization.", true);
      return;
    }

    const safeName = sanitizeString(r.name, 32);
    const wanPort = parseInt(r.wanPort, 10);
    const lanPort = parseInt(r.lanPort, 10);
    const lanIp = r.lanIp.trim();

    const protocols = r.proto === "both" ? ["tcp", "udp"] : [r.proto];
    protocols.forEach(p => {
      preroutingRules.push(`        iifname $WAN_IFACES ${p} dport ${wanPort} dnat to ${lanIp}:${lanPort} comment "${safeName}"`);
      forwardRules.push(`        oifname $LAN_IFACES ip daddr ${lanIp} ${p} dport ${lanPort} ct state new accept comment "${safeName}"`);
    });
  }

  const content = `# Azureclaw Port Forwarding Ruleset
# DO NOT EDIT THIS FILE DIRECTLY IF USING COCKPIT GUI
# JSON_RULES: ${JSON.stringify(state.portForwards)}

table ip nat {
    chain prerouting {
${preroutingRules.join("\n")}
    }
}

table inet router {
    chain forward {
${forwardRules.join("\n")}
    }
}
`;

  const file = cockpit.file(NFT_FILE, { superuser: "try" });
  file.replace(content)
    .then(() => cockpit.spawn(["nft", "-c", "-f", "/etc/nftables/nftables.conf"], { superuser: "require" }))
    .then(() => cockpit.spawn(["systemctl", "reload", "nftables"], { superuser: "require" }))
    .then(() => {
      showAlert("Port forwarding rules applied successfully.");
      renderPortForwards();
    })
    .catch(err => {
      showAlert("Failed to apply port forwards: " + (err.message || err), true);
      renderPortForwards();
    });
}

// ============================================================================
// DHCP Reservations
// ============================================================================
const RES_FILE = "/etc/dnsmasq.d/50-reservations.conf";

function loadReservations() {
  const file = cockpit.file(RES_FILE);
  file.read()
    .then(content => {
      state.reservations = [];
      if (content) {
        const lines = content.split("\n");
        lines.forEach(line => {
          line = line.trim();
          if (line.startsWith("dhcp-host=")) {
            const raw = line.substring("dhcp-host=".length);
            const parts = raw.split(",");
            if (parts.length >= 3) {
              const mac = parts[0].trim().toLowerCase();
              const ip = parts[1].trim();
              const name = parts[2].trim();

              if (Validators.isValidMAC(mac) && Validators.isValidIPv4(ip) && Validators.isValidHostname(name)) {
                state.reservations.push({ name, mac, ip });
              }
            }
          }
        });
      }
      renderReservations();
    })
    .catch(() => {
      state.reservations = [];
      renderReservations();
    });
}

function renderReservations() {
  const tbody = document.getElementById("table-res-body");
  tbody.innerHTML = "";

  updateDHCPStatCount();

  if (state.reservations.length === 0) {
    tbody.innerHTML = `<tr><td colspan="4" class="empty-state">No static reservations configured.</td></tr>`;
    return;
  }

  state.reservations.forEach((res, idx) => {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td><strong>${escapeHtml(res.name)}</strong></td>
      <td><code>${escapeHtml(res.mac)}</code></td>
      <td><code>${escapeHtml(res.ip)}</code></td>
      <td>
        <button class="btn btn-danger btn-del-res" data-idx="${idx}">Delete</button>
      </td>
    `;
    tbody.appendChild(row);
  });

  tbody.querySelectorAll(".btn-del-res").forEach(btn => {
    btn.addEventListener("click", () => {
      const idx = parseInt(btn.getAttribute("data-idx"), 10);
      state.reservations.splice(idx, 1);
      saveReservations();
    });
  });
}

function saveReservations() {
  for (const r of state.reservations) {
    if (!Validators.isValidMAC(r.mac) || !Validators.isValidIPv4(r.ip) || !Validators.isValidHostname(r.name)) {
      showAlert("Invalid reservation data rejected.", true);
      return;
    }
  }

  const lines = [
    "# Azureclaw Static DHCP Reservations (Managed by Cockpit)",
    ...state.reservations.map(r => `dhcp-host=${r.mac.toLowerCase()},${r.ip.trim()},${sanitizeString(r.name, 63)}`),
    ""
  ];

  const file = cockpit.file(RES_FILE, { superuser: "try" });
  file.replace(lines.join("\n"))
    .then(() => cockpit.spawn(["dnsmasq", "--test"], { superuser: "require" }))
    .then(() => cockpit.spawn(["systemctl", "reload", "dnsmasq"], { superuser: "require" }))
    .then(() => {
      showAlert("DHCP reservations updated and dnsmasq reloaded.");
      renderReservations();
    })
    .catch(err => {
      showAlert("Failed to update DHCP reservations: " + (err.message || err), true);
      renderReservations();
    });
}

// ============================================================================
// DNS Overrides
// ============================================================================
const DNS_FILE = "/etc/dnsmasq.d/50-dns-hosts.conf";

function loadDNSOverrides() {
  const file = cockpit.file(DNS_FILE);
  file.read()
    .then(content => {
      state.dnsOverrides = [];
      if (content) {
        const lines = content.split("\n");
        lines.forEach(line => {
          line = line.trim();
          const match = line.match(/^address=\/([^\/]+)\/([^\s]+)$/);
          if (match) {
            const domain = match[1].trim();
            const ip = match[2].trim();
            if (Validators.isValidHostname(domain) && Validators.isValidIPv4(ip)) {
              state.dnsOverrides.push({ domain, ip });
            }
          }
        });
      }
      renderDNSOverrides();
    })
    .catch(() => {
      state.dnsOverrides = [];
      renderDNSOverrides();
    });
}

function renderDNSOverrides() {
  const tbody = document.getElementById("table-dns-body");
  tbody.innerHTML = "";

  if (state.dnsOverrides.length === 0) {
    tbody.innerHTML = `<tr><td colspan="3" class="empty-state">No DNS host overrides configured.</td></tr>`;
    return;
  }

  state.dnsOverrides.forEach((d, idx) => {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td><strong>${escapeHtml(d.domain)}</strong></td>
      <td><code>${escapeHtml(d.ip)}</code></td>
      <td>
        <button class="btn btn-danger btn-del-dns" data-idx="${idx}">Delete</button>
      </td>
    `;
    tbody.appendChild(row);
  });

  tbody.querySelectorAll(".btn-del-dns").forEach(btn => {
    btn.addEventListener("click", () => {
      const idx = parseInt(btn.getAttribute("data-idx"), 10);
      state.dnsOverrides.splice(idx, 1);
      saveDNSOverrides();
    });
  });
}

function saveDNSOverrides() {
  for (const d of state.dnsOverrides) {
    if (!Validators.isValidHostname(d.domain) || !Validators.isValidIPv4(d.ip)) {
      showAlert("Invalid DNS override rejected.", true);
      return;
    }
  }

  const lines = [
    "# Azureclaw DNS Host Overrides (Managed by Cockpit)",
    ...state.dnsOverrides.map(d => `address=/${sanitizeString(d.domain, 253)}/${d.ip.trim()}`),
    ""
  ];

  const file = cockpit.file(DNS_FILE, { superuser: "try" });
  file.replace(lines.join("\n"))
    .then(() => cockpit.spawn(["dnsmasq", "--test"], { superuser: "require" }))
    .then(() => cockpit.spawn(["systemctl", "reload", "dnsmasq"], { superuser: "require" }))
    .then(() => {
      showAlert("DNS overrides updated and dnsmasq reloaded.");
      renderDNSOverrides();
    })
    .catch(err => {
      showAlert("Failed to update DNS overrides: " + (err.message || err), true);
      renderDNSOverrides();
    });
}

// ============================================================================
// Forms Setup & Event Listeners
// ============================================================================
function setupForms() {
  // WAN Form
  const formWan = document.getElementById("form-wan");
  if (formWan) formWan.addEventListener("submit", saveWanConfig);

  // LAN Form
  const formLan = document.getElementById("form-lan");
  if (formLan) formLan.addEventListener("submit", saveLanConfig);

  // VLAN Form
  const formVlan = document.getElementById("form-add-vlan");
  if (formVlan) formVlan.addEventListener("submit", addVlan);

  // DHCP Scope Form
  const formScope = document.getElementById("form-dhcp-scope");
  if (formScope) formScope.addEventListener("submit", saveDHCPScope);

  // Custom DHCP Option Form
  const formOpt = document.getElementById("form-add-dhcp-opt");
  if (formOpt) formOpt.addEventListener("submit", addDHCPOption);

  // WireGuard Form
  const formWg = document.getElementById("form-wg-config");
  if (formWg) formWg.addEventListener("submit", saveWireGuardConfig);

  // Port Forward Form
  const formPf = document.getElementById("form-add-pf");
  if (formPf) {
    formPf.addEventListener("submit", (e) => {
      e.preventDefault();
      clearFormErrors("form-add-pf");

      const name = document.getElementById("pf-name").value.trim();
      const proto = document.getElementById("pf-proto").value.trim().toLowerCase();
      const wanPort = document.getElementById("pf-wan-port").value.trim();
      const lanIp = document.getElementById("pf-lan-ip").value.trim();
      const lanPort = document.getElementById("pf-lan-port").value.trim() || wanPort;

      let hasError = false;
      if (!Validators.isValidRuleName(name)) {
        setFieldError("pf-name", "Name required (alphanumeric, max 32 chars).");
        hasError = true;
      }
      if (!Validators.isValidPort(wanPort)) {
        setFieldError("pf-wan-port", "Valid port 1-65535 required.");
        hasError = true;
      }
      if (!Validators.isValidIPv4(lanIp)) {
        setFieldError("pf-lan-ip", "Valid IPv4 address required.");
        hasError = true;
      }
      if (!Validators.isValidPort(lanPort)) {
        setFieldError("pf-lan-port", "Valid port 1-65535 required.");
        hasError = true;
      }

      if (hasError) return;

      state.portForwards.push({
        name: sanitizeString(name, 32),
        proto,
        wanPort: parseInt(wanPort, 10),
        lanIp,
        lanPort: parseInt(lanPort, 10)
      });

      savePortForwards();
      formPf.reset();
    });
  }

  // Reservation Form
  const formRes = document.getElementById("form-add-res");
  if (formRes) {
    formRes.addEventListener("submit", (e) => {
      e.preventDefault();
      clearFormErrors("form-add-res");

      const name = document.getElementById("res-name").value.trim();
      const mac = document.getElementById("res-mac").value.trim().toLowerCase().replace(/-/g, ":");
      const ip = document.getElementById("res-ip").value.trim();

      let hasError = false;
      if (!Validators.isValidHostname(name)) {
        setFieldError("res-name", "Valid hostname required.");
        hasError = true;
      }
      if (!Validators.isValidMAC(mac)) {
        setFieldError("res-mac", "Valid MAC format (00:11:22:33:44:55) required.");
        hasError = true;
      }
      if (!Validators.isValidIPv4(ip)) {
        setFieldError("res-ip", "Valid IPv4 address required.");
        hasError = true;
      }

      if (hasError) return;

      state.reservations.push({
        name: sanitizeString(name, 63),
        mac,
        ip
      });

      saveReservations();
      formRes.reset();
    });
  }

  // DNS Host Override Form
  const formDns = document.getElementById("form-add-dns");
  if (formDns) {
    formDns.addEventListener("submit", (e) => {
      e.preventDefault();
      clearFormErrors("form-add-dns");

      const domain = document.getElementById("dns-domain").value.trim().toLowerCase();
      const ip = document.getElementById("dns-ip").value.trim();

      let hasError = false;
      if (!Validators.isValidHostname(domain)) {
        setFieldError("dns-domain", "Valid domain or hostname required.");
        hasError = true;
      }
      if (!Validators.isValidIPv4(ip)) {
        setFieldError("dns-ip", "Valid IPv4 address required.");
        hasError = true;
      }

      if (hasError) return;

      state.dnsOverrides.push({
        domain: sanitizeString(domain, 253),
        ip
      });

      saveDNSOverrides();
      formDns.reset();
    });
  }
}
