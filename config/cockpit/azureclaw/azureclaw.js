/**
 * Azureclaw Cockpit Extension
 * Declarative router management for NetworkManager, nftables, dnsmasq, and WireGuard.
 * Hardened with strict input validation and sanitization.
 */

let state = {
  interfaces: [],
  physicalIfaces: [],
  vlans: [],
  dhcpScopes: [
    {
      iface: "ens19",
      enabled: true,
      rangeStart: "192.168.1.50",
      rangeEnd: "192.168.1.200",
      netmask: "255.255.255.0",
      leaseTime: "24h",
      gateway: "192.168.1.1",
      dns: "192.168.1.1",
      domain: "home.arpa"
    }
  ],
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
  },

  isValidIfname(name) {
    if (!name || typeof name !== "string") return false;
    return /^[a-zA-Z][a-zA-Z0-9_-]{0,14}$/.test(name.trim());
  },

  isValidRole(role) {
    if (typeof role !== "string") return false;
    return ["wan", "lan", "isolated", "unassigned"].includes(role.trim());
  },

  isValidMethod(method) {
    if (typeof method !== "string") return false;
    return ["auto", "manual"].includes(method.trim());
  },

  isValidIPv4CIDR(cidr, allowZeroPrefix = false) {
    if (!cidr || typeof cidr !== "string") return false;
    const parts = cidr.trim().split("/");
    if (parts.length !== 2) return false;
    if (!Validators.isValidIPv4(parts[0])) return false;
    const pStr = String(parts[1]).trim();
    if (!/^\d{1,2}$/.test(pStr)) return false;
    const p = parseInt(pStr, 10);
    const min = allowZeroPrefix ? 0 : 1;
    return Number.isInteger(p) && p >= min && p <= 32 && String(p) === pStr;
  },

  isValidAllowedIPs(allowedIps) {
    if (!allowedIps || typeof allowedIps !== "string") return false;
    const list = allowedIps.split(",").map(s => s.trim()).filter(Boolean);
    if (list.length === 0 || list.length > 32) return false;
    return list.every(item => Validators.isValidIPv4CIDR(item, true));
  },

  isValidKeepalive(val) {
    if (val === undefined || val === null || val === "") return true;
    const str = String(val).trim();
    if (!/^\d{1,4}$/.test(str)) return false;
    const num = parseInt(str, 10);
    return Number.isInteger(num) && num >= 0 && num <= 3600 && String(num) === str;
  },

  isValidDNSList(dns) {
    if (!dns || typeof dns !== "string") return false;
    const list = dns.split(",").map(d => d.trim()).filter(Boolean);
    if (list.length === 0 || list.length > 8) return false;
    return list.every(d => Validators.isValidIPv4(d));
  },

  isValidDHCPOptionCode(code) {
    if (!code || typeof code !== "string") return false;
    return /^[a-zA-Z0-9_-]{1,32}$/.test(code.trim());
  },

  isValidDHCPOptionVal(val) {
    if (!val || typeof val !== "string") return false;
    return /^[a-zA-Z0-9_.,:/-]{1,128}$/.test(val.trim());
  },

  isValidDHCPScopeTag(tag) {
    if (tag === undefined || tag === null || tag === "") return true;
    if (typeof tag !== "string") return false;
    return /^[a-zA-Z0-9_-]{1,32}$/.test(tag.trim());
  }
};

function sanitizeString(str, maxLen = 64) {
  if (!str) return "";
  return String(str)
    .replace(/[\r\n\t\0;'"$`\\{}()[\]#]/g, "")
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

function prefixToNetmask(prefix) {
  const p = parseInt(prefix, 10);
  if (!Number.isInteger(p) || p < 1 || p > 32) return "255.255.255.0";
  const mask = (0xffffffff << (32 - p)) >>> 0;
  return [
    (mask >>> 24) & 255,
    (mask >>> 16) & 255,
    (mask >>> 8) & 255,
    mask & 255
  ].join(".");
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

function updatePhysFormVisibility() {
  const roleEl = document.getElementById("phys-role");
  const methodEl = document.getElementById("phys-method");
  const methodGroup = document.getElementById("phys-method-group");
  if (!roleEl || !methodEl) return;

  const role = roleEl.value;
  if (role === "unassigned") {
    if (methodGroup) methodGroup.style.display = "none";
    document.querySelectorAll(".phys-static-field, .phys-wan-static-field").forEach(el => {
      el.style.display = "none";
    });
    return;
  }

  if (role === "lan" || role === "isolated") {
    methodEl.value = "manual";
    if (methodGroup) methodGroup.style.display = "none";
  } else {
    if (methodGroup) methodGroup.style.display = "flex";
  }

  const isManual = methodEl.value === "manual" || role === "lan" || role === "isolated";
  document.querySelectorAll(".phys-static-field").forEach(el => {
    el.style.display = isManual ? "flex" : "none";
  });
  document.querySelectorAll(".phys-wan-static-field").forEach(el => {
    el.style.display = (role === "wan" && isManual) ? "flex" : "none";
  });
}

function populatePhysFormForDevice(devName) {
  clearFormErrors("form-phys-iface");
  const devSelect = document.getElementById("phys-dev");
  if (devSelect && devName) {
    devSelect.value = devName;
  }
  const selectedDev = devName || (devSelect ? devSelect.value : "");
  const info = state.physicalIfaces.find(p => p.dev === selectedDev);

  const roleEl = document.getElementById("phys-role");
  const methodEl = document.getElementById("phys-method");
  const ipEl = document.getElementById("phys-ip");
  const prefixEl = document.getElementById("phys-prefix");
  const gwEl = document.getElementById("phys-gw");
  const dnsEl = document.getElementById("phys-dns");

  if (!info) {
    if (roleEl) roleEl.value = "unassigned";
    if (methodEl) methodEl.value = "auto";
    if (ipEl) ipEl.value = "";
    if (prefixEl) prefixEl.value = "24";
    if (gwEl) gwEl.value = "";
    if (dnsEl) dnsEl.value = "";
    updatePhysFormVisibility();
    return;
  }

  if (roleEl) roleEl.value = info.role || "unassigned";
  if (methodEl) methodEl.value = info.method || (info.role === "wan" ? "auto" : "manual");
  if (ipEl) ipEl.value = info.ip || "";
  if (prefixEl) prefixEl.value = info.prefix || 24;
  if (gwEl) gwEl.value = info.gateway || "";
  if (dnsEl) dnsEl.value = info.dns || "";

  updatePhysFormVisibility();
}

function setupUIEvents() {
  document.getElementById("btn-refresh").addEventListener("click", refreshAll);

  // Physical interface selector & role/method toggles
  const physDevSelect = document.getElementById("phys-dev");
  if (physDevSelect) {
    physDevSelect.addEventListener("change", (e) => {
      populatePhysFormForDevice(e.target.value);
    });
  }

  const physRoleSelect = document.getElementById("phys-role");
  if (physRoleSelect) {
    physRoleSelect.addEventListener("change", () => {
      const role = physRoleSelect.value;
      const methodEl = document.getElementById("phys-method");
      if (role === "lan" || role === "isolated") {
        if (methodEl) methodEl.value = "manual";
      }
      updatePhysFormVisibility();
    });
  }

  const physMethodSelect = document.getElementById("phys-method");
  if (physMethodSelect) {
    physMethodSelect.addEventListener("change", updatePhysFormVisibility);
  }

  // DHCP scope interface selector
  const dhcpScopeIfaceSelect = document.getElementById("dhcp-scope-iface");
  if (dhcpScopeIfaceSelect) {
    dhcpScopeIfaceSelect.addEventListener("change", (e) => {
      populateDHCPScopeFormForIface(e.target.value);
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
// Physical Network Interfaces (Multi-NIC Role & Subnet Management)
// ============================================================================
const IFACES_NFT_FILE = "/etc/nftables/interfaces.nft";
const ISOLATED_NFT_FILE = "/etc/nftables.d/20-isolated-ifaces.nft";
const IFACES_DNS_FILE = "/etc/dnsmasq.d/10-interfaces.conf";

function isValidPhysIfaceObject(p) {
  if (!p || typeof p !== "object") return false;
  if (!Validators.isValidIfname(p.dev)) return false;
  if (!Validators.isValidRole(p.role)) return false;
  if (!Validators.isValidMethod(p.method)) return false;
  if (p.role !== "unassigned" && (p.method === "manual" || p.role === "lan" || p.role === "isolated")) {
    if (!Validators.isValidIPv4(p.ip)) return false;
    if (!Validators.isValidCIDR(p.prefix)) return false;
    if (p.role === "wan" && p.gateway && !Validators.isValidIPv4(p.gateway)) return false;
    if (p.role === "wan" && p.dns && !Validators.isValidDNSList(p.dns)) return false;
  }
  return true;
}

function isVirtualOrVpnDev(devName) {
  if (!devName) return true;
  const lower = devName.toLowerCase();
  return (
    lower === "lo" ||
    lower.includes(".") ||
    lower.includes("vlan") ||
    lower.startsWith("veth") ||
    lower.startsWith("br-") ||
    lower.startsWith("virbr") ||
    lower.startsWith("docker") ||
    lower.startsWith("podman") ||
    lower.startsWith("wg") ||
    lower.startsWith("tailscale") ||
    lower.startsWith("tun") ||
    lower.startsWith("tap") ||
    lower.startsWith("ppp") ||
    lower.startsWith("ipsec") ||
    lower.startsWith("xfrm") ||
    lower.startsWith("sit") ||
    lower.startsWith("gre") ||
    lower.startsWith("dummy")
  );
}

function loadInterfaces() {
  const ipPromise = cockpit.spawn(["ip", "-j", "addr"])
    .then(jsonText => {
      try { return JSON.parse(jsonText); } catch(e) { return []; }
    })
    .catch(() => []);

  const nmPromise = cockpit.spawn(["nmcli", "-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "device"])
    .then(text => {
      const map = {};
      text.split("\n").forEach(line => {
        const parts = line.split(":");
        if (parts.length >= 4 && parts[0]) {
          const dev = parts[0].trim();
          const type = parts[1].trim();
          const devState = parts[2].trim();
          const conn = parts.slice(3).join(":").trim();
          map[dev] = {
            type,
            state: devState,
            connection: conn !== "--" ? conn : ""
          };
        }
      });
      return map;
    })
    .catch(() => ({}));

  const savedIfacesPromise = cockpit.file(IFACES_NFT_FILE).read()
    .then(content => {
      if (!content) return null;
      const match = content.match(/# JSON_IFACES:\s*(.+)$/m);
      if (match) {
        try {
          const parsed = JSON.parse(match[1]);
          if (Array.isArray(parsed)) {
            return parsed.filter(isValidPhysIfaceObject);
          }
        } catch(e) {}
      }
      return null;
    })
    .catch(() => null);

  Promise.all([ipPromise, nmPromise, savedIfacesPromise])
    .then(([ipData, nmMap, savedIfaces]) => {
      const tbody = document.getElementById("table-interfaces-body");
      if (tbody) tbody.innerHTML = "";

      state.interfaces = [];
      const savedMap = {};
      if (savedIfaces) {
        savedIfaces.forEach(item => {
          savedMap[item.dev] = item;
        });
      }

      // Collect all known interfaces from ip -j addr and nmcli device
      const seenDevs = new Set();
      const rawIfaces = [];

      if (Array.isArray(ipData)) {
        ipData.forEach(iface => {
          if (!iface.ifname) return;
          const cleanDev = iface.ifname.split("@")[0];
          seenDevs.add(cleanDev);
          rawIfaces.push({
            dev: cleanDev,
            operstate: iface.operstate || "UNKNOWN",
            mac: iface.address || "--",
            addr_info: iface.addr_info || []
          });
        });
      }

      Object.keys(nmMap).forEach(dev => {
        const cleanDev = dev.split("@")[0];
        if (!seenDevs.has(cleanDev) && nmMap[dev].type === "ethernet") {
          seenDevs.add(cleanDev);
          rawIfaces.push({
            dev: cleanDev,
            operstate: nmMap[dev].state === "connected" ? "UP" : "DOWN",
            mac: "--",
            addr_info: []
          });
        }
      });

      const newPhysicalIfaces = [];

      if (rawIfaces.length === 0) {
        if (tbody) {
          tbody.innerHTML = `<tr><td colspan="5" class="empty-state">No network interfaces found.</td></tr>`;
        }
        const countEl = document.getElementById("stat-iface-count");
        if (countEl) countEl.textContent = "0";
        return;
      }

      rawIfaces.forEach(iface => {
        const cleanDev = iface.dev;
        if (cleanDev === "lo" || cleanDev.startsWith("veth") || cleanDev.startsWith("br-")) {
          return;
        }

        const nmInfo = nmMap[cleanDev] || {};
        const connName = nmInfo.connection || "";
        const ipv4Entry = (iface.addr_info || []).find(a => a.family === "inet");
        const liveIp = ipv4Entry ? ipv4Entry.local : "";
        const livePrefix = ipv4Entry ? ipv4Entry.prefixlen : 24;

        let displayRole = connName;
        if (!displayRole) {
          const lower = cleanDev.toLowerCase();
          if (savedMap[cleanDev]) {
            const r = savedMap[cleanDev].role;
            displayRole = r === "wan" ? "WAN" : r === "lan" ? "LAN" : r === "isolated" ? "Isolated / DMZ" : "Unassigned";
          } else if (["eth0", "ens18", "enp1s0"].includes(cleanDev)) {
            displayRole = "WAN";
          } else if (["eth1", "ens19", "enp2s0"].includes(cleanDev)) {
            displayRole = "LAN";
          } else if (lower.includes("vlan") || cleanDev.includes(".")) {
            displayRole = "VLAN";
          } else if (lower.startsWith("tailscale")) {
            displayRole = "Tailscale";
          } else if (lower.startsWith("wg")) {
            displayRole = "WireGuard";
          } else if (lower.startsWith("tun") || lower.startsWith("tap")) {
            displayRole = "OpenVPN";
          } else if (lower.startsWith("ppp") || lower.startsWith("ipsec") || lower.startsWith("xfrm")) {
            displayRole = "IPsec/L2TP";
          } else {
            displayRole = "Unassigned";
          }
        }

        // Determine if this is a physical Ethernet NIC
        if (!isVirtualOrVpnDev(cleanDev)) {
          let role = "unassigned";
          let method = "auto";
          let ip = liveIp;
          let prefix = livePrefix || 24;
          let gateway = "";
          let dns = "";

          if (savedMap[cleanDev]) {
            role = savedMap[cleanDev].role;
            method = savedMap[cleanDev].method;
            ip = savedMap[cleanDev].ip || liveIp;
            prefix = savedMap[cleanDev].prefix || livePrefix || 24;
            gateway = savedMap[cleanDev].gateway || "";
            dns = savedMap[cleanDev].dns || "";
          } else if (connName.startsWith("WAN") || (!connName && ["eth0", "ens18", "enp1s0"].includes(cleanDev))) {
            role = "wan";
            method = "auto";
          } else if (connName.startsWith("LAN") || (!connName && ["eth1", "ens19", "enp2s0"].includes(cleanDev))) {
            role = "lan";
            method = "manual";
            ip = liveIp || "192.168.1.1";
            prefix = livePrefix || 24;
          } else if (connName.startsWith("DMZ")) {
            role = "isolated";
            method = "manual";
            ip = liveIp || "";
            prefix = livePrefix || 24;
          }

          newPhysicalIfaces.push({
            dev: cleanDev,
            role,
            method,
            ip,
            prefix,
            gateway,
            dns,
            liveIp,
            livePrefix,
            operstate: iface.operstate || "UNKNOWN",
            mac: iface.mac
          });
        }

        const ips = (iface.addr_info || [])
          .map(a => `${escapeHtml(a.local)}/${escapeHtml(String(a.prefixlen))}`)
          .join("<br>") || "No IP";

        const mac = iface.mac || "--";
        const stateClass = iface.operstate === "UP" ? "status-active" : "status-inactive";

        state.interfaces.push({ dev: cleanDev, role: displayRole, state: iface.operstate, ips, mac });

        if (tbody) {
          const row = document.createElement("tr");
          row.innerHTML = `
            <td><strong>${escapeHtml(cleanDev)}</strong></td>
            <td>${escapeHtml(displayRole)}</td>
            <td><span class="status-pill ${stateClass}">${escapeHtml(iface.operstate || "UNKNOWN")}</span></td>
            <td><code>${ips}</code></td>
            <td><code>${escapeHtml(mac)}</code></td>
          `;
          tbody.appendChild(row);
        }
      });

      state.physicalIfaces = newPhysicalIfaces;

      const countEl = document.getElementById("stat-iface-count");
      if (countEl) countEl.textContent = String(state.interfaces.length);

      renderPhysicalInterfacesTable();
      updatePhysicalDropdowns();
    })
    .catch(err => {
      console.warn("Failed to load interfaces:", err);
    });
}

function renderPhysicalInterfacesTable() {
  const tbody = document.getElementById("table-phys-ifaces-body");
  if (!tbody) return;
  tbody.innerHTML = "";

  if (state.physicalIfaces.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" class="empty-state">No physical Ethernet interfaces detected.</td></tr>`;
    return;
  }

  state.physicalIfaces.forEach(p => {
    const roleBadgeMap = {
      wan: `<span class="status-pill status-active">WAN (Uplink)</span>`,
      lan: `<span class="status-pill status-active">LAN (Trusted)</span>`,
      isolated: `<span class="status-pill status-neutral">Isolated / DMZ</span>`,
      unassigned: `<span class="status-pill status-inactive">Unassigned</span>`
    };
    const roleBadge = roleBadgeMap[p.role] || roleBadgeMap.unassigned;

    let modeStr = "--";
    if (p.role !== "unassigned") {
      modeStr = p.method === "manual" ? "Static IPv4" : "DHCP Client";
    }

    const displayIp = p.ip
      ? `${escapeHtml(p.ip)}/${escapeHtml(String(p.prefix || 24))}`
      : (p.liveIp ? `${escapeHtml(p.liveIp)}/${escapeHtml(String(p.livePrefix || 24))} (DHCP)` : "No IPv4");

    const gwStr = p.gateway ? `<code>${escapeHtml(p.gateway)}</code>` : "--";
    const stateClass = p.operstate === "UP" ? "status-active" : "status-inactive";

    const row = document.createElement("tr");
    row.innerHTML = `
      <td><strong>${escapeHtml(p.dev)}</strong><br><small style="color: #6a6e73;">${escapeHtml(p.mac || "")}</small></td>
      <td>${roleBadge}</td>
      <td>${escapeHtml(modeStr)}</td>
      <td><code>${displayIp}</code></td>
      <td>${gwStr}</td>
      <td><span class="status-pill ${stateClass}">${escapeHtml(p.operstate || "UNKNOWN")}</span></td>
      <td>
        <button type="button" class="btn btn-secondary btn-cfg-phys" data-dev="${escapeHtml(p.dev)}">Configure</button>
      </td>
    `;
    tbody.appendChild(row);
  });

  tbody.querySelectorAll(".btn-cfg-phys").forEach(btn => {
    btn.addEventListener("click", () => {
      const dev = btn.getAttribute("data-dev");
      populatePhysFormForDevice(dev);
      const formEl = document.getElementById("form-phys-iface");
      if (formEl) formEl.scrollIntoView({ behavior: "smooth", block: "nearest" });
    });
  });
}

function updatePhysicalDropdowns() {
  const devs = state.physicalIfaces.length > 0
    ? state.physicalIfaces
    : [
        { dev: "ens18", role: "wan", method: "auto", ip: "", prefix: 24 },
        { dev: "ens19", role: "lan", method: "manual", ip: "192.168.1.1", prefix: 24 }
      ];

  // 1. Physical NIC selector (#phys-dev)
  const physSelect = document.getElementById("phys-dev");
  if (physSelect) {
    const prevVal = physSelect.value;
    physSelect.innerHTML = "";
    devs.forEach(p => {
      const roleLabel = p.role === "wan" ? "WAN" : p.role === "lan" ? "LAN" : p.role === "isolated" ? "Isolated/DMZ" : "Unassigned";
      const opt = document.createElement("option");
      opt.value = p.dev;
      opt.textContent = `${p.dev} — ${roleLabel}${p.ip ? " (" + p.ip + "/" + p.prefix + ")" : ""}`;
      physSelect.appendChild(opt);
    });
    if (devs.some(p => p.dev === prevVal)) {
      physSelect.value = prevVal;
    } else if (devs.length > 0) {
      physSelect.value = devs[0].dev;
    }
    populatePhysFormForDevice(physSelect.value);
  }

  // 2. VLAN parent interface selector (#vlan-parent)
  const vlanParentSelect = document.getElementById("vlan-parent");
  if (vlanParentSelect) {
    const prevParent = vlanParentSelect.value;
    vlanParentSelect.innerHTML = "";
    devs.forEach(p => {
      const roleLabel = p.role === "wan" ? "WAN" : p.role === "lan" ? "LAN" : p.role === "isolated" ? "Isolated/DMZ" : "Unassigned";
      const opt = document.createElement("option");
      opt.value = p.dev;
      opt.textContent = `${p.dev} (${roleLabel})`;
      vlanParentSelect.appendChild(opt);
    });
    const firstLan = devs.find(p => p.role === "lan");
    if (devs.some(p => p.dev === prevParent)) {
      vlanParentSelect.value = prevParent;
    } else if (firstLan) {
      vlanParentSelect.value = firstLan.dev;
    }
  }

  // 3. DHCP Scope Target Interface selector (#dhcp-scope-iface)
  const dhcpIfaceSelect = document.getElementById("dhcp-scope-iface");
  if (dhcpIfaceSelect) {
    const prevScopeIface = dhcpIfaceSelect.value;
    dhcpIfaceSelect.innerHTML = "";
    const lanOrIsoDevs = devs.filter(p => p.role === "lan" || p.role === "isolated");
    const targetDevs = lanOrIsoDevs.length > 0 ? lanOrIsoDevs : devs;
    targetDevs.forEach(p => {
      const roleLabel = p.role === "lan" ? "LAN" : p.role === "isolated" ? "Isolated/DMZ" : p.role.toUpperCase();
      const opt = document.createElement("option");
      opt.value = p.dev;
      opt.textContent = `${p.dev} (${roleLabel}${p.ip ? " — " + p.ip + "/" + p.prefix : ""})`;
      dhcpIfaceSelect.appendChild(opt);
    });
    if (targetDevs.some(p => p.dev === prevScopeIface)) {
      dhcpIfaceSelect.value = prevScopeIface;
    } else if (targetDevs.length > 0) {
      dhcpIfaceSelect.value = targetDevs[0].dev;
    }
    populateDHCPScopeFormForIface(dhcpIfaceSelect.value);
  }

  // 4. Custom DHCP Option Target Scope selector (#opt-scope)
  updateDHCPOptionScopeSelect();
}

function updateDHCPOptionScopeSelect() {
  const optScopeSelect = document.getElementById("opt-scope");
  if (!optScopeSelect) return;
  const prevVal = optScopeSelect.value;
  optScopeSelect.innerHTML = `<option value="">Global (All LAN &amp; VLAN Scopes)</option>`;

  state.dhcpScopes.forEach(s => {
    if (s.iface && Validators.isValidIfname(s.iface)) {
      const opt = document.createElement("option");
      opt.value = s.iface;
      opt.textContent = `Interface Scope (${s.iface})`;
      optScopeSelect.appendChild(opt);
    }
  });

  state.vlans.forEach(v => {
    if (Validators.isValidVlanId(v.id)) {
      const tag = `vlan${v.id}`;
      const opt = document.createElement("option");
      opt.value = tag;
      opt.textContent = `VLAN ${v.id} (${v.name})`;
      optScopeSelect.appendChild(opt);
    }
  });

  if (Array.from(optScopeSelect.options).some(o => o.value === prevVal)) {
    optScopeSelect.value = prevVal;
  }
}

function savePhysicalInterface(e) {
  e.preventDefault();
  clearFormErrors("form-phys-iface");

  const dev = document.getElementById("phys-dev").value.trim();
  const role = document.getElementById("phys-role").value.trim();
  const rawMethod = document.getElementById("phys-method").value.trim();
  const method = (role === "lan" || role === "isolated") ? "manual" : rawMethod;

  const ip = document.getElementById("phys-ip").value.trim();
  const prefix = document.getElementById("phys-prefix").value.trim();
  const gateway = document.getElementById("phys-gw").value.trim();
  const dns = document.getElementById("phys-dns").value.trim();

  let hasError = false;
  if (!Validators.isValidIfname(dev)) {
    setFieldError("phys-dev", "Please select a valid network interface.");
    hasError = true;
  }
  if (!Validators.isValidRole(role)) {
    setFieldError("phys-role", "Invalid interface role.");
    hasError = true;
  }
  if (!Validators.isValidMethod(method)) {
    setFieldError("phys-method", "Invalid IPv4 configuration mode.");
    hasError = true;
  }

  if (role !== "unassigned" && method === "manual") {
    if (!Validators.isValidIPv4(ip)) {
      setFieldError("phys-ip", "Valid IPv4 address is required.");
      hasError = true;
    }
    if (!Validators.isValidCIDR(prefix)) {
      setFieldError("phys-prefix", "CIDR prefix must be between 8 and 30.");
      hasError = true;
    }
    if (role === "wan") {
      if (!Validators.isValidIPv4(gateway)) {
        setFieldError("phys-gw", "Valid IPv4 default gateway is required for static WAN.");
        hasError = true;
      }
      if (dns && !Validators.isValidDNSList(dns)) {
        setFieldError("phys-dns", "DNS servers must be comma-separated valid IPv4 addresses.");
        hasError = true;
      }
    }
  }

  if (hasError) {
    showAlert("Please correct the errors in the Physical Interface form.", true);
    return;
  }

  const existing = state.physicalIfaces.find(p => p.dev === dev);
  if ((existing && existing.role === "lan") || role === "lan") {
    const newTarget = role === "lan" ? `https://${ip}:9090` : "another LAN interface";
    const confirmMsg = `Applying changes to ${dev} (${role.toUpperCase()}). If you are currently connected via ${dev}, your browser session may disconnect and you may need to reconnect at ${newTarget}.\n\nProceed?`;
    if (!confirm(confirmMsg)) return;
  }

  const updatedEntry = {
    dev,
    role,
    method: role === "unassigned" ? "auto" : method,
    ip: (role !== "unassigned" && method === "manual") ? ip : "",
    prefix: (role !== "unassigned" && method === "manual") ? parseInt(prefix, 10) : 24,
    gateway: (role === "wan" && method === "manual") ? gateway : "",
    dns: (role === "wan" && method === "manual" && dns)
      ? dns.split(",").map(d => d.trim()).filter(Boolean).join(",")
      : "",
    liveIp: existing ? existing.liveIp : "",
    livePrefix: existing ? existing.livePrefix : 24,
    operstate: existing ? existing.operstate : "UP",
    mac: existing ? existing.mac : "--"
  };

  if (!isValidPhysIfaceObject(updatedEntry)) {
    showAlert("Interface configuration failed security validation.", true);
    return;
  }

  const idx = state.physicalIfaces.findIndex(p => p.dev === dev);
  if (idx >= 0) {
    state.physicalIfaces[idx] = updatedEntry;
  } else {
    state.physicalIfaces.push(updatedEntry);
  }

  applyPhysicalInterfaceConfig(updatedEntry)
    .then(() => savePhysicalFirewallAndDns())
    .then(() => {
      showAlert(`Interface ${dev} configured as ${role.toUpperCase()} and firewall/DNS rules updated.`);
      loadInterfaces();
    })
    .catch(err => {
      showAlert(`Failed to apply configuration for ${dev}: ` + (err.message || err), true);
      loadInterfaces();
    });
}

function applyPhysicalInterfaceConfig(entry) {
  const dev = entry.dev;
  const conName = entry.role === "wan"
    ? `WAN-${dev}`
    : entry.role === "lan"
    ? `LAN-${dev}`
    : `DMZ-${dev}`;

  // Clean up any legacy wildcard match or previous per-device connections on this NIC
  const cleanupCmds = [
    ["nmcli", "connection", "delete", `WAN-${dev}`],
    ["nmcli", "connection", "delete", `LAN-${dev}`],
    ["nmcli", "connection", "delete", `DMZ-${dev}`]
  ];

  // Clear wildcard match.interface-name on stock WAN / LAN profiles if we are reassigning default NICs
  let chain = Promise.resolve();
  if (["ens18", "eth0", "enp1s0"].includes(dev) && entry.role !== "wan") {
    chain = chain.then(() =>
      cockpit.spawn(["nmcli", "connection", "delete", "WAN"], { superuser: "require" }).catch(() => {})
    );
  }
  if (["ens19", "eth1", "enp2s0"].includes(dev) && entry.role !== "lan") {
    chain = chain.then(() =>
      cockpit.spawn(["nmcli", "connection", "delete", "LAN"], { superuser: "require" }).catch(() => {})
    );
  }

  cleanupCmds.forEach(cmd => {
    chain = chain.then(() => cockpit.spawn(cmd, { superuser: "require" }).catch(() => {}));
  });

  if (entry.role === "unassigned") {
    return chain.then(() =>
      cockpit.spawn(["nmcli", "device", "disconnect", dev], { superuser: "require" }).catch(() => {})
    );
  }

  if (entry.role === "wan" && entry.method === "auto") {
    return chain
      .then(() =>
        cockpit.spawn([
          "nmcli", "connection", "add",
          "type", "ethernet",
          "con-name", conName,
          "ifname", dev,
          "ipv4.method", "auto",
          "ipv6.method", "auto"
        ], { superuser: "require" })
      )
      .then(() => cockpit.spawn(["nmcli", "connection", "up", conName], { superuser: "require" }));
  }

  if (entry.role === "wan" && entry.method === "manual") {
    const dnsArg = entry.dns ? entry.dns.split(",").map(d => d.trim()).join(" ") : "1.1.1.1 9.9.9.9";
    return chain
      .then(() =>
        cockpit.spawn([
          "nmcli", "connection", "add",
          "type", "ethernet",
          "con-name", conName,
          "ifname", dev,
          "ipv4.method", "manual",
          "ipv4.addresses", `${entry.ip}/${entry.prefix}`,
          "ipv4.gateway", entry.gateway,
          "ipv4.dns", dnsArg,
          "ipv6.method", "auto"
        ], { superuser: "require" })
      )
      .then(() => cockpit.spawn(["nmcli", "connection", "up", conName], { superuser: "require" }));
  }

  // LAN or Isolated / DMZ (Static IPv4)
  return chain
    .then(() =>
      cockpit.spawn([
        "nmcli", "connection", "add",
        "type", "ethernet",
        "con-name", conName,
        "ifname", dev,
        "ipv4.method", "manual",
        "ipv4.addresses", `${entry.ip}/${entry.prefix}`,
        "ipv6.method", "ignore"
      ], { superuser: "require" })
    )
    .then(() => cockpit.spawn(["nmcli", "connection", "up", conName], { superuser: "require" }));
}

function savePhysicalFirewallAndDns() {
  for (const p of state.physicalIfaces) {
    if (!isValidPhysIfaceObject(p)) {
      return Promise.reject(new Error("Invalid physical interface object rejected during serialization."));
    }
  }

  const wanDevs = state.physicalIfaces
    .filter(p => p.role === "wan")
    .map(p => sanitizeString(p.dev, 15));
  const lanDevs = state.physicalIfaces
    .filter(p => p.role === "lan")
    .map(p => sanitizeString(p.dev, 15));
  const isolatedDevs = state.physicalIfaces
    .filter(p => p.role === "isolated");

  // nftables sets cannot be empty; fall back to default names if none assigned
  const wanSetItems = (wanDevs.length > 0 ? wanDevs : ["eth0", "ens18", "enp1s0"])
    .map(d => `"${d}"`)
    .join(", ");
  const lanSetItems = (lanDevs.length > 0 ? lanDevs : ["eth1", "ens19", "enp2s0"])
    .map(d => `"${d}"`)
    .join(", ");

  const serializedMeta = state.physicalIfaces.map(p => ({
    dev: p.dev,
    role: p.role,
    method: p.method,
    ip: p.ip || "",
    prefix: p.prefix || 24,
    gateway: p.gateway || "",
    dns: p.dns || ""
  }));

  const ifacesNftContent = `# Azureclaw Dynamic Interface Definitions
# Managed by Cockpit Azureclaw
# JSON_IFACES: ${JSON.stringify(serializedMeta)}

define WAN_IFACES = { ${wanSetItems} }
define LAN_IFACES = { ${lanSetItems} }
`;

  // Isolated / DMZ physical interfaces: allow DNS (53) & DHCP (67) and WAN egress, block LAN & Router Mgmt
  const isoInputRules = [];
  const isoForwardRules = [];
  isolatedDevs.forEach(p => {
    const safeDev = sanitizeString(p.dev, 15);
    isoInputRules.push(`        iifname "${safeDev}" udp dport { 53, 67 } accept comment "Isolated ${safeDev} DHCP/DNS"`);
    isoInputRules.push(`        iifname "${safeDev}" tcp dport 53 accept comment "Isolated ${safeDev} DNS"`);
    isoForwardRules.push(`        iifname "${safeDev}" oifname $WAN_IFACES accept comment "Isolated ${safeDev} WAN Egress"`);
  });

  const isolatedNftContent = `# Azureclaw Isolated Physical Interfaces Ruleset
# Managed by Cockpit Azureclaw

table inet router {
    chain input {
${isoInputRules.join("\n")}
    }

    chain forward {
${isoForwardRules.join("\n")}
    }
}
`;

  // Dnsmasq interface bindings (/etc/dnsmasq.d/10-interfaces.conf)
  const dnsLines = [
    "# Azureclaw Dynamic Interface Bindings (Managed by Cockpit)",
    "# DO NOT EDIT DIRECTLY IF USING COCKPIT GUI",
    ""
  ];
  (wanDevs.length > 0 ? wanDevs : ["eth0", "ens18", "enp1s0"]).forEach(d => {
    dnsLines.push(`except-interface=${d}`);
  });
  state.physicalIfaces
    .filter(p => (p.role === "lan" || p.role === "isolated") && Validators.isValidIPv4(p.ip))
    .forEach(p => {
      dnsLines.push(`listen-address=${p.ip.trim()}`);
    });
  dnsLines.push("");

  const nftIfacesFile = cockpit.file(IFACES_NFT_FILE, { superuser: "try" });
  const nftIsoFile = cockpit.file(ISOLATED_NFT_FILE, { superuser: "try" });
  const dnsIfacesFile = cockpit.file(IFACES_DNS_FILE, { superuser: "try" });

  return Promise.all([
    nftIfacesFile.replace(ifacesNftContent),
    nftIsoFile.replace(isolatedNftContent),
    dnsIfacesFile.replace(dnsLines.join("\n"))
  ])
    .then(() => cockpit.spawn(["nft", "-c", "-f", "/etc/nftables/nftables.conf"], { superuser: "require" }))
    .then(() => cockpit.spawn(["dnsmasq", "--test"], { superuser: "require" }))
    .then(() => cockpit.spawn(["systemctl", "reload", "nftables"], { superuser: "require" }))
    .then(() => cockpit.spawn(["systemctl", "reload", "dnsmasq"], { superuser: "require" }));
}

// ============================================================================
// 802.1Q VLAN Management
// ============================================================================
const VLAN_NFT_FILE = "/etc/nftables.d/40-vlans.nft";
const VLAN_DNS_FILE = "/etc/dnsmasq.d/40-vlans.conf";

function isValidVlanObject(v) {
  if (!v || typeof v !== "object") return false;
  if (!Validators.isValidVlanId(v.id)) return false;
  if (!Validators.isValidRuleName(v.name)) return false;
  if (!Validators.isValidIfname(v.parent)) return false;
  if (!Validators.isValidIPv4(v.ip)) return false;
  if (!Validators.isValidCIDR(v.prefix)) return false;
  if (v.dhcp) {
    if (!Validators.isValidIPv4(v.dhcpStart)) return false;
    if (!Validators.isValidIPv4(v.dhcpEnd)) return false;
    if (!Validators.isValidLeaseTime(v.dhcpLease)) return false;
  }
  return true;
}

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
            if (Array.isArray(rawVlans)) {
              state.vlans = rawVlans.filter(isValidVlanObject);
            }
          } catch(e) {}
        }
      }
      renderVlans();
      updateDHCPOptionScopeSelect();
    })
    .catch(() => {
      state.vlans = [];
      renderVlans();
      updateDHCPOptionScopeSelect();
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
        <button class="btn btn-danger btn-del-vlan" data-idx="${idx}" data-vlan-id="${escapeHtml(String(v.id))}">Delete</button>
      </td>
    `;
    tbody.appendChild(row);
  });

  tbody.querySelectorAll(".btn-del-vlan").forEach(btn => {
    btn.addEventListener("click", () => {
      const idx = parseInt(btn.getAttribute("data-idx"), 10);
      const vlanId = btn.getAttribute("data-vlan-id");
      if (Validators.isValidVlanId(vlanId)) {
        deleteVlan(idx, `VLAN${parseInt(vlanId, 10)}`);
      }
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
  if (!Validators.isValidIfname(parentVal)) {
    setFieldError("vlan-parent", "Parent interface must be a valid device name.");
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
    parent: sanitizeString(parentVal, 15),
    ip: ipVal,
    prefix: parseInt(prefixVal, 10),
    wanAccess: Boolean(wanAccess),
    isolate: Boolean(isolate),
    dhcp: Boolean(dhcp),
    dhcpStart: dhcp ? dhcpStart : "",
    dhcpEnd: dhcp ? dhcpEnd : "",
    dhcpLease: dhcp ? dhcpLease : "24h"
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
      updateDHCPOptionScopeSelect();
      loadInterfaces();
    })
    .catch(err => {
      showAlert("Failed to create VLAN: " + (err.message || err), true);
    });
}

function deleteVlan(idx, conName) {
  if (!/^VLAN[0-9]{1,4}$/.test(conName)) {
    showAlert("Invalid VLAN connection identifier.", true);
    return;
  }
  if (!confirm(`Delete ${conName}? This will remove the interface, firewall rules, and DHCP pool.`)) return;

  state.vlans.splice(idx, 1);

  // Delete from NetworkManager and update config files
  cockpit.spawn(["nmcli", "connection", "delete", conName], { superuser: "require" })
    .catch(() => {})
    .then(() => saveVlanFirewallAndDns())
    .then(() => {
      showAlert(`${conName} removed.`);
      renderVlans();
      updateDHCPOptionScopeSelect();
      loadInterfaces();
    })
    .catch(err => {
      showAlert("Failed to remove VLAN: " + (err.message || err), true);
      renderVlans();
    });
}

function saveVlanFirewallAndDns() {
  // Deep-validate every VLAN object before serializing to nftables and dnsmasq
  for (const v of state.vlans) {
    if (!isValidVlanObject(v)) {
      return Promise.reject(new Error("Invalid VLAN definition rejected during serialization."));
    }
  }

  // Generate nftables rules for VLANs
  const inputRules = [];
  const forwardRules = [];

  state.vlans.forEach(v => {
    const safeParent = sanitizeString(v.parent, 15);
    const safeId = parseInt(v.id, 10);
    const subDev = `${safeParent}.${safeId}`;
    // Allow DHCP and DNS on VLAN sub-interface
    inputRules.push(`        iifname "${subDev}" udp dport { 53, 67 } accept comment "VLAN ${safeId} DHCP/DNS"`);
    inputRules.push(`        iifname "${subDev}" tcp dport 53 accept comment "VLAN ${safeId} DNS"`);

    if (!v.isolate) {
      // If not isolated from router management, allow management ports
      inputRules.push(`        iifname "${subDev}" tcp dport $MGMT_PORTS accept comment "VLAN ${safeId} Management"`);
    }

    if (v.wanAccess) {
      // Allow internet egress
      forwardRules.push(`        iifname "${subDev}" oifname $WAN_IFACES accept comment "VLAN ${safeId} Internet Egress"`);
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
    const safeId = parseInt(v.id, 10);
    const safeName = sanitizeString(v.name, 32);
    dnsLines.push(`# VLAN ${safeId} (${safeName})`);
    dnsLines.push(`listen-address=${v.ip.trim()}`);
    dnsLines.push(`dhcp-range=set:vlan${safeId},${v.dhcpStart.trim()},${v.dhcpEnd.trim()},255.255.255.0,${v.dhcpLease.trim()}`);
    dnsLines.push(`dhcp-option=tag:vlan${safeId},option:router,${v.ip.trim()}`);
    dnsLines.push(`dhcp-option=tag:vlan${safeId},option:dns-server,${v.ip.trim()}`);
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
// DHCP Scopes & Custom Options (Multi-Scope Support)
// ============================================================================
const DHCP_FILE = "/etc/dnsmasq.d/30-dhcp.conf";

function isValidDHCPScopeObject(s) {
  if (!s || typeof s !== "object") return false;
  if (s.iface && !Validators.isValidIfname(s.iface)) return false;
  if (!Validators.isValidIPv4(s.rangeStart)) return false;
  if (!Validators.isValidIPv4(s.rangeEnd)) return false;
  if (!Validators.isValidIPv4(s.netmask)) return false;
  if (!Validators.isValidLeaseTime(s.leaseTime)) return false;
  if (s.gateway && !Validators.isValidIPv4(s.gateway)) return false;
  if (s.dns && !Validators.isValidDNSList(s.dns)) return false;
  if (s.domain && !Validators.isValidHostname(s.domain)) return false;
  return true;
}

function isValidDHCPOptionObject(opt) {
  if (!opt || typeof opt !== "object") return false;
  if (!Validators.isValidDHCPScopeTag(opt.scope)) return false;
  if (!Validators.isValidDHCPOptionCode(opt.code)) return false;
  if (!Validators.isValidDHCPOptionVal(opt.val)) return false;
  return true;
}

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
            if (Array.isArray(parsed.scopes)) {
              const validScopes = parsed.scopes.filter(isValidDHCPScopeObject);
              if (validScopes.length > 0) {
                state.dhcpScopes = validScopes;
              }
            } else if (parsed.lanScope && isValidDHCPScopeObject(parsed.lanScope)) {
              state.dhcpScopes = [
                Object.assign({ iface: "ens19" }, parsed.lanScope)
              ];
            }
            if (Array.isArray(parsed.customOptions)) {
              state.dhcpOptions = parsed.customOptions.filter(isValidDHCPOptionObject);
            }
          } catch(e) {}
        }
      }
      renderDHCPScopesTable();
      const ifaceSelect = document.getElementById("dhcp-scope-iface");
      populateDHCPScopeFormForIface(ifaceSelect ? ifaceSelect.value : "ens19");
      updateDHCPOptionScopeSelect();
      renderDHCPOptions();
    })
    .catch(() => {
      renderDHCPScopesTable();
      const ifaceSelect = document.getElementById("dhcp-scope-iface");
      populateDHCPScopeFormForIface(ifaceSelect ? ifaceSelect.value : "ens19");
      updateDHCPOptionScopeSelect();
      renderDHCPOptions();
    });
}

function populateDHCPScopeFormForIface(ifaceName) {
  const targetIface = ifaceName || "ens19";
  const existing = state.dhcpScopes.find(s => s.iface === targetIface) ||
                   (state.dhcpScopes.length === 1 && !state.dhcpScopes[0].iface ? state.dhcpScopes[0] : null);

  if (existing) {
    document.getElementById("dhcp-scope-enabled").checked = existing.enabled !== false;
    document.getElementById("dhcp-range-start").value = existing.rangeStart || "192.168.1.50";
    document.getElementById("dhcp-range-end").value = existing.rangeEnd || "192.168.1.200";
    document.getElementById("dhcp-netmask").value = existing.netmask || "255.255.255.0";
    document.getElementById("dhcp-lease-time").value = existing.leaseTime || "24h";
    document.getElementById("dhcp-opt-gw").value = existing.gateway || "192.168.1.1";
    document.getElementById("dhcp-opt-dns").value = existing.dns || "192.168.1.1";
    document.getElementById("dhcp-opt-domain").value = existing.domain || "home.arpa";
    return;
  }

  // Suggest subnet defaults from the selected physical interface's IP address
  const phys = state.physicalIfaces.find(p => p.dev === targetIface);
  const baseIp = (phys && Validators.isValidIPv4(phys.ip)) ? phys.ip : "192.168.1.1";
  const octets = baseIp.split(".");
  const prefixOctets = `${octets[0]}.${octets[1]}.${octets[2]}`;
  const netmask = phys && phys.prefix ? prefixToNetmask(phys.prefix) : "255.255.255.0";

  document.getElementById("dhcp-scope-enabled").checked = true;
  document.getElementById("dhcp-range-start").value = `${prefixOctets}.50`;
  document.getElementById("dhcp-range-end").value = `${prefixOctets}.200`;
  document.getElementById("dhcp-netmask").value = netmask;
  document.getElementById("dhcp-lease-time").value = "24h";
  document.getElementById("dhcp-opt-gw").value = baseIp;
  document.getElementById("dhcp-opt-dns").value = baseIp;
  document.getElementById("dhcp-opt-domain").value = "home.arpa";
}

function renderDHCPScopesTable() {
  const tbody = document.getElementById("table-dhcp-scopes-body");
  if (!tbody) return;
  tbody.innerHTML = "";

  if (state.dhcpScopes.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" class="empty-state">No DHCP scopes configured.</td></tr>`;
    return;
  }

  state.dhcpScopes.forEach((s, idx) => {
    const ifaceLabel = s.iface || "ens19";
    const statusClass = s.enabled !== false ? "status-active" : "status-inactive";
    const statusText = s.enabled !== false ? "Enabled" : "Disabled";

    const row = document.createElement("tr");
    row.innerHTML = `
      <td><strong>${escapeHtml(ifaceLabel)}</strong></td>
      <td><code>${escapeHtml(s.rangeStart)} - ${escapeHtml(s.rangeEnd)}</code><br><small style="color: #6a6e73;">Mask: ${escapeHtml(s.netmask)}</small></td>
      <td><code>${escapeHtml(s.gateway || "--")}</code></td>
      <td><code>${escapeHtml(s.dns || "--")}</code></td>
      <td>${escapeHtml(s.leaseTime)}</td>
      <td><span class="status-pill ${statusClass}">${statusText}</span></td>
      <td style="display: flex; gap: 6px;">
        <button type="button" class="btn btn-secondary btn-edit-scope" data-iface="${escapeHtml(ifaceLabel)}">Edit</button>
        <button type="button" class="btn btn-danger btn-del-scope" data-idx="${idx}">Delete</button>
      </td>
    `;
    tbody.appendChild(row);
  });

  tbody.querySelectorAll(".btn-edit-scope").forEach(btn => {
    btn.addEventListener("click", () => {
      const iface = btn.getAttribute("data-iface");
      const select = document.getElementById("dhcp-scope-iface");
      if (select) {
        if (!Array.from(select.options).some(o => o.value === iface)) {
          const opt = document.createElement("option");
          opt.value = iface;
          opt.textContent = iface;
          select.appendChild(opt);
        }
        select.value = iface;
      }
      populateDHCPScopeFormForIface(iface);
    });
  });

  tbody.querySelectorAll(".btn-del-scope").forEach(btn => {
    btn.addEventListener("click", () => {
      const idx = parseInt(btn.getAttribute("data-idx"), 10);
      state.dhcpScopes.splice(idx, 1);
      writeAndApplyDHCPSettings();
    });
  });
}

function saveDHCPScope(e) {
  e.preventDefault();
  clearFormErrors("form-dhcp-scope");

  const ifaceSelect = document.getElementById("dhcp-scope-iface");
  const iface = ifaceSelect ? ifaceSelect.value.trim() : "ens19";
  const enabled = document.getElementById("dhcp-scope-enabled").checked;
  const rangeStart = document.getElementById("dhcp-range-start").value.trim();
  const rangeEnd = document.getElementById("dhcp-range-end").value.trim();
  const netmask = document.getElementById("dhcp-netmask").value.trim();
  const leaseTime = document.getElementById("dhcp-lease-time").value.trim() || "24h";
  const gateway = document.getElementById("dhcp-opt-gw").value.trim();
  const dns = document.getElementById("dhcp-opt-dns").value.trim();
  const domain = document.getElementById("dhcp-opt-domain").value.trim() || "home.arpa";

  let hasError = false;
  if (!Validators.isValidIfname(iface)) {
    showAlert("Invalid target interface for DHCP scope.", true);
    hasError = true;
  }
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
  if (dns && !Validators.isValidDNSList(dns)) {
    setFieldError("dhcp-opt-dns", "DNS server(s) must be comma-separated valid IPv4 addresses.");
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

  const normalizedDns = dns ? dns.split(",").map(d => d.trim()).filter(Boolean).join(",") : "";

  const newScope = {
    iface,
    enabled: Boolean(enabled),
    rangeStart,
    rangeEnd,
    netmask,
    leaseTime,
    gateway,
    dns: normalizedDns,
    domain
  };

  const existingIdx = state.dhcpScopes.findIndex(s => s.iface === iface);
  if (existingIdx >= 0) {
    state.dhcpScopes[existingIdx] = newScope;
  } else {
    state.dhcpScopes.push(newScope);
  }

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
  if (!Validators.isValidDHCPScopeTag(scopeVal)) {
    showAlert("Invalid DHCP option scope tag.", true);
    hasError = true;
  }
  if (!Validators.isValidDHCPOptionCode(codeVal)) {
    setFieldError("opt-code", "Valid option code (e.g. 42 or ntp-server) required.");
    hasError = true;
  }
  if (!Validators.isValidDHCPOptionVal(valVal)) {
    setFieldError("opt-val", "Valid option value required (no spaces or special characters).");
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
  // Deep-validate before writing to dnsmasq configuration
  for (const s of state.dhcpScopes) {
    if (!isValidDHCPScopeObject(s)) {
      showAlert("Invalid DHCP scope parameters rejected during serialization.", true);
      return;
    }
  }
  for (const opt of state.dhcpOptions) {
    if (!isValidDHCPOptionObject(opt)) {
      showAlert("Invalid custom DHCP option rejected during serialization.", true);
      return;
    }
  }

  const jsonMetadata = {
    scopes: state.dhcpScopes,
    lanScope: state.dhcpScopes[0] || null,
    customOptions: state.dhcpOptions
  };

  const lines = [
    "# Azureclaw DHCP Scopes and Options (Managed by Cockpit)",
    `# JSON_DHCP: ${JSON.stringify(jsonMetadata)}`,
    ""
  ];

  state.dhcpScopes.forEach(s => {
    if (!s.enabled) return;
    const safeTag = sanitizeString(s.iface || "lan", 15);
    const safeDns = s.dns ? s.dns.split(",").map(d => d.trim()).filter(Boolean).join(",") : "";
    lines.push(`# DHCP Scope for ${safeTag}`);
    lines.push(`dhcp-range=set:${safeTag},${s.rangeStart.trim()},${s.rangeEnd.trim()},${s.netmask.trim()},${s.leaseTime.trim()}`);
    if (s.gateway) lines.push(`dhcp-option=tag:${safeTag},option:router,${s.gateway.trim()}`);
    if (safeDns) lines.push(`dhcp-option=tag:${safeTag},option:dns-server,${safeDns}`);
    if (s.domain) lines.push(`dhcp-option=tag:${safeTag},option:domain-name,${sanitizeString(s.domain, 253)}`);
    lines.push("");
  });

  if (state.dhcpOptions.length > 0) {
    lines.push("# Custom DHCP Options");
    state.dhcpOptions.forEach(opt => {
      const safeScope = opt.scope ? sanitizeString(opt.scope, 32) : "";
      const tagPrefix = safeScope ? `tag:${safeScope},` : "";
      lines.push(`dhcp-option=${tagPrefix}option:${sanitizeString(opt.code, 32)},${sanitizeString(opt.val, 128)}`);
    });
    lines.push("");
  }

  const file = cockpit.file(DHCP_FILE, { superuser: "try" });
  file.replace(lines.join("\n"))
    .then(() => cockpit.spawn(["dnsmasq", "--test"], { superuser: "require" }))
    .then(() => cockpit.spawn(["systemctl", "reload", "dnsmasq"], { superuser: "require" }))
    .then(() => {
      showAlert("DHCP scopes and options applied successfully.");
      renderDHCPScopesTable();
      updateDHCPOptionScopeSelect();
      renderDHCPOptions();
    })
    .catch(err => {
      showAlert("Failed to apply DHCP configuration: " + (err.message || err), true);
      renderDHCPScopesTable();
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
            document.getElementById("wg-privkey").value = Validators.isValidWireGuardKey(data.privkey) ? data.privkey.trim() : "";
            document.getElementById("wg-pubkey").value = Validators.isValidWireGuardKey(data.pubkey) ? data.pubkey.trim() : "";
            document.getElementById("wg-addr").value = Validators.isValidIPv4CIDR(data.address) ? data.address.trim() : "";
            document.getElementById("wg-listen-port").value = Validators.isValidPort(data.listenPort) ? String(data.listenPort).trim() : "";
            document.getElementById("wg-peer-pubkey").value = Validators.isValidWireGuardKey(data.peerPubkey) ? data.peerPubkey.trim() : "";
            document.getElementById("wg-peer-endpoint").value = Validators.isValidEndpoint(data.peerEndpoint) ? data.peerEndpoint.trim() : "";
            document.getElementById("wg-allowed-ips").value = Validators.isValidAllowedIPs(data.allowedIps) ? data.allowedIps.trim() : "0.0.0.0/0";
            document.getElementById("wg-keepalive").value = Validators.isValidKeepalive(data.keepalive) ? String(data.keepalive).trim() : "25";
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
  const rawPubkey = document.getElementById("wg-pubkey").value.trim();
  const pubkey = Validators.isValidWireGuardKey(rawPubkey) ? rawPubkey : "";
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
  if (!Validators.isValidIPv4CIDR(address)) {
    setFieldError("wg-addr", "Valid IPv4 CIDR address required (e.g. 10.2.0.2/24).");
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
  if (!Validators.isValidAllowedIPs(allowedIps)) {
    setFieldError("wg-allowed-ips", "Allowed IPs must be comma-separated IPv4 CIDRs (e.g. 0.0.0.0/0 or 10.2.0.0/24).");
    hasError = true;
  }
  if (!Validators.isValidKeepalive(keepalive)) {
    setFieldError("wg-keepalive", "Keepalive must be an integer between 0 and 3600.");
    hasError = true;
  }

  if (hasError) {
    showAlert("Please correct the WireGuard form errors.", true);
    return;
  }

  const normalizedAllowedIps = allowedIps.split(",").map(s => s.trim()).filter(Boolean).join(", ");
  const safePort = listenPort ? String(parseInt(listenPort, 10)) : "";
  const safeKeepalive = keepalive !== "" ? String(parseInt(keepalive, 10)) : "";

  const wgData = {
    privkey,
    pubkey,
    address,
    listenPort: safePort,
    peerPubkey,
    peerEndpoint,
    allowedIps: normalizedAllowedIps,
    keepalive: safeKeepalive,
    inboundWan: Boolean(inboundWan)
  };

  const lines = [
    "# Azureclaw WireGuard Interface Configuration (Managed by Cockpit)",
    `# JSON_WG: ${JSON.stringify(wgData)}`,
    "",
    "[Interface]",
    `PrivateKey = ${privkey}`,
    `Address = ${address}`
  ];

  if (safePort) lines.push(`ListenPort = ${safePort}`);
  lines.push("");
  lines.push("[Peer]");
  lines.push(`PublicKey = ${peerPubkey}`);
  if (peerEndpoint) lines.push(`Endpoint = ${peerEndpoint}`);
  lines.push(`AllowedIPs = ${normalizedAllowedIps}`);
  if (safeKeepalive) lines.push(`PersistentKeepalive = ${safeKeepalive}`);
  lines.push("");

  // Inbound firewall rule
  let nftVpnContent = "";
  if (inboundWan && safePort) {
    nftVpnContent = `# Azureclaw WireGuard Inbound Rule
table inet router {
    chain input {
        udp dport ${safePort} accept comment "WireGuard Inbound Listener"
    }
}
`;
  }

  const file = cockpit.file(WG_CONF_FILE, { superuser: "try" });
  const nftFile = cockpit.file(WG_NFT_FILE, { superuser: "try" });

  cockpit.spawn(["mkdir", "-p", "-m", "0700", "/etc/wireguard"], { superuser: "require" })
    .then(() => file.replace(lines.join("\n")))
    .then(() => cockpit.spawn(["chmod", "0600", WG_CONF_FILE], { superuser: "require" }))
    .then(() => nftFile.replace(nftVpnContent))
    .then(() => cockpit.spawn(["nft", "-c", "-f", "/etc/nftables/nftables.conf"], { superuser: "require" }))
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
  // Physical Interface Form
  const formPhys = document.getElementById("form-phys-iface");
  if (formPhys) formPhys.addEventListener("submit", savePhysicalInterface);

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
      if (!Validators.isValidProto(proto)) {
        setFieldError("pf-proto", "Select TCP, UDP, or Both.");
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
      } else if (state.reservations.some(r => r.mac === mac)) {
        setFieldError("res-mac", "A reservation for this MAC address already exists.");
        hasError = true;
      }
      if (!Validators.isValidIPv4(ip)) {
        setFieldError("res-ip", "Valid IPv4 address required.");
        hasError = true;
      } else if (state.reservations.some(r => r.ip === ip)) {
        setFieldError("res-ip", "A reservation for this IP address already exists.");
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
      } else if (state.dnsOverrides.some(d => d.domain.toLowerCase() === domain)) {
        setFieldError("dns-domain", "A DNS override for this domain already exists.");
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
