/**
 * Azureclaw Cockpit Extension
 * Declarative router management for nftables port forwards and dnsmasq DHCP/DNS
 */

let state = {
  portForwards: [],
  reservations: [],
  dnsOverrides: [],
  leases: []
};

// --- Initialization ---
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

// --- Alerts ---
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

// --- Tabs ---
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

// --- Forms ---
function setupForms() {
  // Add Port Forward
  document.getElementById("form-add-pf").addEventListener("submit", (e) => {
    e.preventDefault();
    const name = document.getElementById("pf-name").value.trim();
    const proto = document.getElementById("pf-proto").value;
    const wanPort = document.getElementById("pf-wan-port").value.trim();
    const lanIp = document.getElementById("pf-lan-ip").value.trim();
    const lanPort = document.getElementById("pf-lan-port").value.trim() || wanPort;

    state.portForwards.push({ name, proto, wanPort, lanIp, lanPort });
    savePortForwards();
    e.target.reset();
  });

  // Add DHCP Reservation
  document.getElementById("form-add-res").addEventListener("submit", (e) => {
    e.preventDefault();
    const name = document.getElementById("res-name").value.trim();
    const mac = document.getElementById("res-mac").value.trim().toLowerCase();
    const ip = document.getElementById("res-ip").value.trim();

    state.reservations.push({ name, mac, ip });
    saveReservations();
    e.target.reset();
  });

  // Add DNS Override
  document.getElementById("form-add-dns").addEventListener("submit", (e) => {
    e.preventDefault();
    const domain = document.getElementById("dns-domain").value.trim();
    const ip = document.getElementById("dns-ip").value.trim();

    state.dnsOverrides.push({ domain, ip });
    saveDNSOverrides();
    e.target.reset();
  });
}

// --- Service Status ---
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

// --- Network Interfaces ---
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
          .map(a => `${a.local}/${a.prefixlen}`)
          .join("<br>") || "No IP";

        const mac = iface.address || "--";
        const stateClass = iface.operstate === "UP" ? "status-active" : "status-inactive";

        const row = document.createElement("tr");
        row.innerHTML = `
          <td><strong>${escapeHtml(iface.ifname)}</strong></td>
          <td>${role}</td>
          <td><span class="status-pill ${stateClass}">${iface.operstate || "UNKNOWN"}</span></td>
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

// --- DHCP Leases ---
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
          const mac = parts[1];
          const ip = parts[2];
          const hostname = parts[3] === "*" ? "Unknown Client" : parts[3];

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
            <td>${expiresStr}</td>
            <td>
              <button class="btn btn-secondary btn-reserve" data-mac="${escapeHtml(mac)}" data-ip="${escapeHtml(ip)}" data-name="${escapeHtml(hostname)}">
                + Reserve IP
              </button>
            </td>
          `;
          tbody.appendChild(row);
        }
      });

      tbody.querySelectorAll(".btn-reserve").forEach(btn => {
        btn.addEventListener("click", () => {
          const mac = btn.getAttribute("data-mac");
          const ip = btn.getAttribute("data-ip");
          const name = btn.getAttribute("data-name");

          switchTab("tab-dhcp-reservations");
          document.getElementById("res-mac").value = mac;
          document.getElementById("res-ip").value = ip;
          document.getElementById("res-name").value = name !== "Unknown Client" ? name : "";
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

// --- Port Forwarding ---
const NFT_FILE = "/etc/nftables.d/50-port-forwards.nft";

function loadPortForwards() {
  const file = cockpit.file(NFT_FILE);
  file.read()
    .then(content => {
      state.portForwards = [];
      if (content) {
        const match = content.match(/# JSON_RULES:\s*(.+)$/m);
        if (match) {
          try { state.portForwards = JSON.parse(match[1]); } catch(e) {}
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
      <td><code>${escapeHtml(rule.wanPort)}</code></td>
      <td><code>${escapeHtml(rule.lanIp)}</code></td>
      <td><code>${escapeHtml(rule.lanPort)}</code></td>
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

  state.portForwards.forEach(r => {
    const protocols = r.proto === "both" ? ["tcp", "udp"] : [r.proto];
    protocols.forEach(p => {
      preroutingRules.push(`        iifname $WAN_IFACES ${p} dport ${r.wanPort} dnat to ${r.lanIp}:${r.lanPort} comment "${r.name}"`);
      forwardRules.push(`        oifname $LAN_IFACES ip daddr ${r.lanIp} ${p} dport ${r.lanPort} ct state new accept comment "${r.name}"`);
    });
  });

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
      // Validate configuration before reloading
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

// --- DHCP Reservations ---
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
              const mac = parts[0].trim();
              const ip = parts[1].trim();
              const name = parts[2].trim();
              state.reservations.push({ name, mac, ip });
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
  const lines = [
    "# Azureclaw Static DHCP Reservations (Managed by Cockpit)",
    ...state.reservations.map(r => `dhcp-host=${r.mac},${r.ip},${r.name}`),
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

// --- DNS Overrides ---
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
            state.dnsOverrides.push({ domain: match[1], ip: match[2] });
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
  const lines = [
    "# Azureclaw DNS Host Overrides (Managed by Cockpit)",
    ...state.dnsOverrides.map(d => `address=/${d.domain}/${d.ip}`),
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

// --- Utility Functions ---
function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
