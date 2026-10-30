/**
 * Azureclaw Cockpit Extension
 * Declarative router management for nftables port forwards and dnsmasq DHCP/DNS
 * Hardened with strict input validation and sanitization to prevent injection vulnerabilities.
 */

let state = {
  portForwards: [],
  reservations: [],
  dnsOverrides: [],
  leases: []
};

// ============================================================================
// Security & Validation Helpers
// ============================================================================
const Validators = {
  /**
   * Strictly validates IPv4 address (4 octets, 0-255 each, no leading zeroes unless 0).
   * Prevents octal interpretations, spaces, control chars, and newlines.
   */
  isValidIPv4(ip) {
    if (!ip || typeof ip !== "string") return false;
    if (!/^([0-9]{1,3}\.){3}[0-9]{1,3}$/.test(ip)) return false;
    const parts = ip.split(".");
    return parts.every(part => {
      const num = parseInt(part, 10);
      return num >= 0 && num <= 255 && String(num) === part;
    });
  },

  /**
   * Strictly validates TCP/UDP port number (integer 1-65535).
   */
  isValidPort(port) {
    if (port === undefined || port === null) return false;
    const str = String(port);
    if (!/^\d{1,5}$/.test(str)) return false;
    const p = parseInt(str, 10);
    return Number.isInteger(p) && p >= 1 && p <= 65535 && String(p) === str;
  },

  /**
   * Whitelist validation for network protocols.
   */
  isValidProto(proto) {
    if (typeof proto !== "string") return false;
    return ["tcp", "udp", "both"].includes(proto.toLowerCase());
  },

  /**
   * Strictly validates 48-bit MAC address (e.g. 00:11:22:33:44:55 or 00-11-22-33-44-55).
   */
  isValidMAC(mac) {
    if (!mac || typeof mac !== "string") return false;
    return /^([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})$/.test(mac);
  },

  /**
   * Strictly validates RFC 1123 Hostnames and FQDNs.
   * Disallows spaces, newlines, quotes, slashes, or shell control characters.
   */
  isValidHostname(name) {
    if (!name || typeof name !== "string" || name.length > 253) return false;
    return /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/.test(name);
  },

  /**
   * Validates rule names / labels for nftables comments.
   * Strictly alphanumeric, underscores, hyphens, and spaces only. Max 32 chars.
   */
  isValidRuleName(name) {
    if (!name || typeof name !== "string") return false;
    return /^[a-zA-Z0-9 _.-]{1,32}$/.test(name);
  }
};

/**
 * Strips any potential control characters, newlines, and quotes from string values.
 */
function sanitizeString(str, maxLen = 64) {
  if (!str) return "";
  return String(str)
    .replace(/[\r\n\t\0;'"$`\\{}()[\]]/g, "")
    .trim()
    .slice(0, maxLen);
}

// ============================================================================
// Initialization
// ============================================================================
document.addEventListener("DOMContentLoaded", () => {
  setupTabs();
  setupForms();
  document.getElementById("btn-refresh").addEventListener("click", refreshAll);
  refreshAll();
});

function refreshAll() {
  loadServiceStatus();
  loadInterfaces();
  loadDHCPLeases();
  loadPortForwards();
  loadReservations();
  loadDNSOverrides();
}

// ============================================================================
// Alert & Notification System
// ============================================================================
function showAlert(message, isError = false) {
  const container = document.getElementById("alert-banner");
  const box = document.getElementById("alert-box");
  const msgEl = document.getElementById("alert-msg");

  msgEl.textContent = message;
  box.className = isError ? "pf-c-alert pf-m-danger" : "pf-c-alert pf-m-success";
  container.style.display = "block";

  setTimeout(() => {
    container.style.display = "none";
  }, 6000);
}

// ============================================================================
// Tab Navigation
// ============================================================================
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

const FieldValidators = {
  // Port Forward fields
  "pf-name"(val) {
    if (!val || !val.trim()) return "Rule name is required.";
    if (!Validators.isValidRuleName(val.trim())) {
      return "Rule name must be alphanumeric (spaces, - and _ allowed, max 32 characters).";
    }
    return null;
  },
  "pf-proto"(val) {
    if (!Validators.isValidProto(val)) {
      return "Select TCP, UDP, or Both.";
    }
    return null;
  },
  "pf-wan-port"(val) {
    if (!val || !String(val).trim()) return "WAN port is required.";
    if (!Validators.isValidPort(String(val).trim())) {
      return "Port must be an integer between 1 and 65535.";
    }
    return null;
  },
  "pf-lan-ip"(val) {
    if (!val || !val.trim()) return "Target LAN IP is required.";
    if (!Validators.isValidIPv4(val.trim())) {
      return "Must be a valid IPv4 address (e.g. 192.168.1.100).";
    }
    return null;
  },
  "pf-lan-port"(val) {
    if (val && String(val).trim() && !Validators.isValidPort(String(val).trim())) {
      return "Port must be an integer between 1 and 65535.";
    }
    return null;
  },

  // DHCP Reservation fields
  "res-name"(val) {
    if (!val || !val.trim()) return "Hostname is required.";
    if (!Validators.isValidHostname(val.trim())) {
      return "Hostname must be RFC 1123 format (alphanumeric, hyphens, dots, max 63 chars).";
    }
    return null;
  },
  "res-mac"(val) {
    if (!val || !val.trim()) return "MAC address is required.";
    if (!Validators.isValidMAC(val.trim())) {
      return "Invalid MAC format. Use 00:11:22:33:44:55 or 00-11-22-33-44-55.";
    }
    const mac = val.trim().toLowerCase().replace(/-/g, ":");
    if (state.reservations.some(r => r.mac === mac)) {
      return "A reservation for this MAC address already exists.";
    }
    return null;
  },
  "res-ip"(val) {
    if (!val || !val.trim()) return "Reserved IP is required.";
    if (!Validators.isValidIPv4(val.trim())) {
      return "Must be a valid IPv4 address (e.g. 192.168.1.50).";
    }
    if (state.reservations.some(r => r.ip === val.trim())) {
      return "A reservation for this IP address already exists.";
    }
    return null;
  },

  // DNS Override fields
  "dns-domain"(val) {
    if (!val || !val.trim()) return "Domain/hostname is required.";
    if (!Validators.isValidHostname(val.trim())) {
      return "Must be a valid hostname or domain (e.g. vault.home.arpa).";
    }
    const domain = val.trim().toLowerCase();
    if (state.dnsOverrides.some(d => d.domain.toLowerCase() === domain)) {
      return "A DNS override for this domain already exists.";
    }
    return null;
  },
  "dns-ip"(val) {
    if (!val || !val.trim()) return "Target IP is required.";
    if (!Validators.isValidIPv4(val.trim())) {
      return "Must be a valid IPv4 address (e.g. 192.168.1.100).";
    }
    return null;
  }
};

function validateField(fieldId) {
  const el = document.getElementById(fieldId);
  if (!el || !FieldValidators[fieldId]) return true;
  const errorMsg = FieldValidators[fieldId](el.value);
  setFieldError(fieldId, errorMsg);
  return errorMsg === null;
}

function attachValidationListeners(formId, fieldIds) {
  const form = document.getElementById(formId);
  if (!form) return;

  fieldIds.forEach(fieldId => {
    const el = document.getElementById(fieldId);
    if (!el) return;

    el.addEventListener("blur", () => {
      if (el.value.trim().length > 0) {
        validateField(fieldId);
      }
    });

    el.addEventListener("input", () => {
      if (el.classList.contains("is-invalid")) {
        validateField(fieldId);
      }
    });
  });
}

// ============================================================================
// Form Event Handlers with Strict Validation
// ============================================================================
function setupForms() {
  const pfFields = ["pf-name", "pf-proto", "pf-wan-port", "pf-lan-ip", "pf-lan-port"];
  const resFields = ["res-name", "res-mac", "res-ip"];
  const dnsFields = ["dns-domain", "dns-ip"];

  attachValidationListeners("form-add-pf", pfFields);
  attachValidationListeners("form-add-res", resFields);
  attachValidationListeners("form-add-dns", dnsFields);

  // Add Port Forward
  document.getElementById("form-add-pf").addEventListener("submit", (e) => {
    e.preventDefault();

    let allValid = true;
    let firstInvalid = null;
    pfFields.forEach(fieldId => {
      if (!validateField(fieldId)) {
        allValid = false;
        if (!firstInvalid) firstInvalid = document.getElementById(fieldId);
      }
    });

    if (!allValid) {
      if (firstInvalid) firstInvalid.focus();
      showAlert("Please correct the invalid field(s) highlighted in red.", true);
      return;
    }

    const rawName = document.getElementById("pf-name").value;
    const rawProto = document.getElementById("pf-proto").value;
    const rawWanPort = document.getElementById("pf-wan-port").value;
    const rawLanIp = document.getElementById("pf-lan-ip").value;
    const rawLanPort = document.getElementById("pf-lan-port").value || rawWanPort;

    const name = sanitizeString(rawName, 32);
    const proto = rawProto.trim().toLowerCase();
    const wanPort = parseInt(rawWanPort, 10);
    const lanIp = rawLanIp.trim();
    const lanPort = parseInt(rawLanPort, 10);

    state.portForwards.push({ name, proto, wanPort, lanIp, lanPort });
    savePortForwards();
    e.target.reset();
    clearFormErrors("form-add-pf");
  });

  // Add DHCP Reservation
  document.getElementById("form-add-res").addEventListener("submit", (e) => {
    e.preventDefault();

    let allValid = true;
    let firstInvalid = null;
    resFields.forEach(fieldId => {
      if (!validateField(fieldId)) {
        allValid = false;
        if (!firstInvalid) firstInvalid = document.getElementById(fieldId);
      }
    });

    if (!allValid) {
      if (firstInvalid) firstInvalid.focus();
      showAlert("Please correct the invalid field(s) highlighted in red.", true);
      return;
    }

    const rawName = document.getElementById("res-name").value;
    const rawMac = document.getElementById("res-mac").value;
    const rawIp = document.getElementById("res-ip").value;

    const name = sanitizeString(rawName, 63);
    const mac = rawMac.trim().toLowerCase().replace(/-/g, ":");
    const ip = rawIp.trim();

    state.reservations.push({ name, mac, ip });
    saveReservations();
    e.target.reset();
    clearFormErrors("form-add-res");
  });

  // Add DNS Override
  document.getElementById("form-add-dns").addEventListener("submit", (e) => {
    e.preventDefault();

    let allValid = true;
    let firstInvalid = null;
    dnsFields.forEach(fieldId => {
      if (!validateField(fieldId)) {
        allValid = false;
        if (!firstInvalid) firstInvalid = document.getElementById(fieldId);
      }
    });

    if (!allValid) {
      if (firstInvalid) firstInvalid.focus();
      showAlert("Please correct the invalid field(s) highlighted in red.", true);
      return;
    }

    const rawDomain = document.getElementById("dns-domain").value;
    const rawIp = document.getElementById("dns-ip").value;

    const domain = sanitizeString(rawDomain, 253);
    const ip = rawIp.trim();

    state.dnsOverrides.push({ domain, ip });
    saveDNSOverrides();
    e.target.reset();
    clearFormErrors("form-add-dns");
  });
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

function updateStatusPill(elementId, isActive) {
  const el = document.getElementById(elementId);
  if (!el) return;
  el.textContent = isActive ? "Active" : "Inactive";
  el.className = "status-pill " + (isActive ? "status-active" : "status-inactive");
}

// ============================================================================
// Network Interfaces
// ============================================================================
function loadInterfaces() {
  cockpit.spawn(["ip", "-j", "addr"])
    .then(jsonText => {
      let data = [];
      try { data = JSON.parse(jsonText); } catch(e) { return; }

      const tbody = document.getElementById("table-interfaces-body");
      tbody.innerHTML = "";

      data.forEach(iface => {
        if (!iface.ifname || iface.ifname === "lo" || iface.ifname.startsWith("veth") || iface.ifname.startsWith("br-")) {
          return;
        }

        let role = "Other";
        if (["eth0", "ens18", "enp1s0"].includes(iface.ifname)) role = "WAN (Uplink)";
        else if (["eth1", "ens19", "enp2s0"].includes(iface.ifname)) role = "LAN (Primary)";
        else if (iface.ifname.includes(".")) role = "VLAN Subnet";
        else if (iface.ifname.startsWith("tailscale") || iface.ifname.startsWith("wg")) role = "VPN Overlay";

        const ips = (iface.addr_info || [])
          .map(a => `${escapeHtml(a.local)}/${escapeHtml(String(a.prefixlen))}`)
          .join("<br>") || "No IP";

        const mac = iface.address || "--";
        const stateClass = iface.operstate === "UP" ? "status-active" : "status-inactive";

        const row = document.createElement("tr");
        row.innerHTML = `
          <td><strong>${escapeHtml(iface.ifname)}</strong></td>
          <td>${escapeHtml(role)}</td>
          <td><span class="status-pill ${stateClass}">${escapeHtml(iface.operstate || "UNKNOWN")}</span></td>
          <td><code>${ips}</code></td>
          <td><code>${escapeHtml(mac)}</code></td>
        `;
        tbody.appendChild(row);
      });
    })
    .catch(err => {
      console.warn("Failed to load interfaces:", err);
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

          // Validate fields read from file before presenting
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

          switchTab("tab-dhcp-reservations");
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
// Port Forwarding (DNAT with Syntax Safety)
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
            // Re-validate all loaded rules against strict schema
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

  // Deep validation of all rules before constructing nftables output
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
    .then(() => {
      // Validate configuration before reloading nftables
      return cockpit.spawn(["nft", "-c", "-f", "/etc/nftables/nftables.conf"], { superuser: "require" });
    })
    .then(() => {
      return cockpit.spawn(["systemctl", "reload", "nftables"], { superuser: "require" });
    })
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
  // Validate all entries before writing
  for (const r of state.reservations) {
    if (!Validators.isValidMAC(r.mac) || !Validators.isValidIPv4(r.ip) || !Validators.isValidHostname(r.name)) {
      showAlert("Invalid reservation data rejected. Cannot contain newlines or special characters.", true);
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
    .then(() => {
      return cockpit.spawn(["systemctl", "reload", "dnsmasq"], { superuser: "require" });
    })
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
  // Validate all entries before writing
  for (const d of state.dnsOverrides) {
    if (!Validators.isValidHostname(d.domain) || !Validators.isValidIPv4(d.ip)) {
      showAlert("Invalid DNS override rejected. Domain must be a valid hostname without spaces or newlines.", true);
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
    .then(() => {
      return cockpit.spawn(["systemctl", "reload", "dnsmasq"], { superuser: "require" });
    })
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
// Utility / HTML Escaping
// ============================================================================
function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
