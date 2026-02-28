const state = {
  token: localStorage.getItem("nicepanel_token") || "",
  user: null,
  domains: [],
  dns: [],
  modules: [],
  settings: null,
};

const loginView = document.querySelector("#login-view");
const appView = document.querySelector("#app-view");
const loginForm = document.querySelector("#login-form");
const loginError = document.querySelector("#login-error");
const globalMessage = document.querySelector("#global-message");
const sessionUser = document.querySelector("#session-user");

function showGlobalMessage(text, type = "success") {
  globalMessage.textContent = text;
  globalMessage.className = `global-message ${type}`;
  globalMessage.hidden = false;
}

function hideGlobalMessage() {
  globalMessage.hidden = true;
}

function setToken(token) {
  state.token = token || "";
  if (state.token) {
    localStorage.setItem("nicepanel_token", state.token);
  } else {
    localStorage.removeItem("nicepanel_token");
  }
}

async function apiFetch(path, options = {}) {
  const headers = {
    "Content-Type": "application/json",
    ...(options.headers || {}),
  };
  if (state.token) {
    headers.Authorization = `Bearer ${state.token}`;
  }
  const response = await fetch(path, { ...options, headers });
  let payload = {};
  try {
    payload = await response.json();
  } catch (error) {
    payload = {};
  }
  if (response.status === 401) {
    logout(false);
    throw new Error("Sesion vencida o invalida.");
  }
  if (!response.ok || payload.ok === false) {
    throw new Error(payload.error || "Error de API");
  }
  return payload;
}

function switchView(loggedIn) {
  loginView.hidden = loggedIn;
  appView.hidden = !loggedIn;
}

function resetDomainForm() {
  document.querySelector("#domain-id").value = "";
  document.querySelector("#domain-name").value = "";
  document.querySelector("#domain-ns1-hostname").value = "";
  document.querySelector("#domain-ns1-ipv4").value = "";
  document.querySelector("#domain-ns2-hostname").value = "";
  document.querySelector("#domain-ns2-ipv4").value = "";
}

function resetDnsForm() {
  document.querySelector("#dns-id").value = "";
  document.querySelector("#dns-zone").value = "";
  document.querySelector("#dns-name").value = "";
  document.querySelector("#dns-type").value = "A";
  document.querySelector("#dns-value").value = "";
  document.querySelector("#dns-ttl").value = 300;
}

function renderDomains() {
  const body = document.querySelector("#domains-table");
  body.innerHTML = "";
  document.querySelector("#domains-count").textContent = String(state.domains.length);
  for (const item of state.domains) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${item.id}</td>
      <td>${item.domain}</td>
      <td>${item.ns1_hostname || "(global)"}${item.ns2_hostname ? ` / ${item.ns2_hostname}` : ""}</td>
      <td>
        <button class="button small ghost" data-action="edit-domain" data-id="${item.id}" type="button">Editar</button>
        <button class="button small danger" data-action="delete-domain" data-id="${item.id}" type="button">Borrar</button>
      </td>
    `;
    body.appendChild(tr);
  }
}

function renderDns() {
  const body = document.querySelector("#dns-table");
  body.innerHTML = "";
  document.querySelector("#dns-count").textContent = String(state.dns.length);
  for (const item of state.dns) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${item.id}</td>
      <td>${item.zone}</td>
      <td>${item.name}</td>
      <td>${item.type}</td>
      <td>${item.value}</td>
      <td>${item.ttl}</td>
      <td>
        <button class="button small ghost" data-action="edit-dns" data-id="${item.id}" type="button">Editar</button>
        <button class="button small danger" data-action="delete-dns" data-id="${item.id}" type="button">Borrar</button>
      </td>
    `;
    body.appendChild(tr);
  }
}

function renderModules() {
  const body = document.querySelector("#modules-table");
  body.innerHTML = "";
  document.querySelector("#modules-count").textContent = String(state.modules.length);
  for (const item of state.modules) {
    const tr = document.createElement("tr");
    const enabled = Boolean(item.enabled);
    tr.innerHTML = `
      <td>${item.name}</td>
      <td><span class="${enabled ? "state-on" : "state-off"}">${enabled ? "ON" : "OFF"}</span></td>
    `;
    body.appendChild(tr);
  }
}

function renderSettings() {
  if (!state.settings) {
    return;
  }
  const dns = state.settings.dns || {};
  document.querySelector("#settings-ns1-hostname").value = dns.ns1_hostname || "";
  document.querySelector("#settings-ns1-ipv4").value = dns.ns1_ipv4 || "";
  document.querySelector("#settings-ns2-hostname").value = dns.ns2_hostname || "";
  document.querySelector("#settings-ns2-ipv4").value = dns.ns2_ipv4 || "";
  document.querySelector("#settings-listen-on").value = dns.listen_on || "";
  document.querySelector("#settings-forwarders").value = dns.forwarders || "";
  document.querySelector("#settings-allow-recursion").checked = Boolean(dns.allow_recursion);
  document.querySelector("#settings-recovery-email").value = state.settings.recovery_email || "";
  document.querySelector("#settings-recovery-whatsapp").value = state.settings.recovery_whatsapp || "";
}

async function loadAll() {
  hideGlobalMessage();
  const [me, domains, dns, modules, settings] = await Promise.all([
    apiFetch("/api/me"),
    apiFetch("/api/domains"),
    apiFetch("/api/dns"),
    apiFetch("/api/apache/modules"),
    apiFetch("/api/settings"),
  ]);
  state.user = me.user;
  state.domains = domains.items || [];
  state.dns = dns.items || [];
  state.modules = modules.items || [];
  state.settings = settings.settings || null;
  sessionUser.textContent = state.user ? `${state.user.username} (${state.user.role})` : "";
  renderDomains();
  renderDns();
  renderModules();
  renderSettings();
}

async function login(username, password) {
  const payload = await apiFetch("/api/login", {
    method: "POST",
    body: JSON.stringify({ username, password }),
  });
  setToken(payload.token);
  switchView(true);
  await loadAll();
}

async function logout(callApi = true) {
  try {
    if (callApi && state.token) {
      await apiFetch("/api/logout", { method: "POST", body: "{}" });
    }
  } catch (error) {
  }
  setToken("");
  state.user = null;
  switchView(false);
}

document.querySelectorAll(".tab").forEach((button) => {
  button.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((item) => item.classList.toggle("active", item === button));
    document.querySelectorAll(".tab-panel").forEach((panel) => {
      panel.classList.toggle("active", panel.id === `tab-${button.dataset.tab}`);
    });
  });
});

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  loginError.hidden = true;
  try {
    await login(
      document.querySelector("#login-username").value.trim(),
      document.querySelector("#login-password").value
    );
  } catch (error) {
    loginError.textContent = error.message;
    loginError.hidden = false;
  }
});

document.querySelector("#logout-button").addEventListener("click", () => logout(true));
document.querySelector("#refresh-all").addEventListener("click", async () => {
  try {
    await loadAll();
    showGlobalMessage("Datos actualizados.");
  } catch (error) {
    showGlobalMessage(error.message, "error");
  }
});

document.querySelector("#domain-reset").addEventListener("click", resetDomainForm);
document.querySelector("#dns-reset").addEventListener("click", resetDnsForm);

document.querySelector("#domain-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const itemId = document.querySelector("#domain-id").value;
  const payload = {
    domain: document.querySelector("#domain-name").value.trim(),
    ns1_hostname: document.querySelector("#domain-ns1-hostname").value.trim(),
    ns1_ipv4: document.querySelector("#domain-ns1-ipv4").value.trim(),
    ns2_hostname: document.querySelector("#domain-ns2-hostname").value.trim(),
    ns2_ipv4: document.querySelector("#domain-ns2-ipv4").value.trim(),
  };
  try {
    await apiFetch(itemId ? `/api/domains/${itemId}` : "/api/domains", {
      method: itemId ? "PUT" : "POST",
      body: JSON.stringify(payload),
    });
    resetDomainForm();
    await loadAll();
    showGlobalMessage(itemId ? "Dominio actualizado." : "Dominio creado.");
  } catch (error) {
    showGlobalMessage(error.message, "error");
  }
});

document.querySelector("#dns-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const itemId = document.querySelector("#dns-id").value;
  const payload = {
    zone: document.querySelector("#dns-zone").value.trim(),
    name: document.querySelector("#dns-name").value.trim(),
    type: document.querySelector("#dns-type").value,
    value: document.querySelector("#dns-value").value.trim(),
    ttl: Number(document.querySelector("#dns-ttl").value || 300),
  };
  try {
    await apiFetch(itemId ? `/api/dns/${itemId}` : "/api/dns", {
      method: itemId ? "PUT" : "POST",
      body: JSON.stringify(payload),
    });
    resetDnsForm();
    await loadAll();
    showGlobalMessage(itemId ? "Record actualizado." : "Record creado.");
  } catch (error) {
    showGlobalMessage(error.message, "error");
  }
});

document.querySelector("#settings-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const payload = {
    dns: {
      ns1_hostname: document.querySelector("#settings-ns1-hostname").value.trim(),
      ns1_ipv4: document.querySelector("#settings-ns1-ipv4").value.trim(),
      ns2_hostname: document.querySelector("#settings-ns2-hostname").value.trim(),
      ns2_ipv4: document.querySelector("#settings-ns2-ipv4").value.trim(),
      listen_on: document.querySelector("#settings-listen-on").value.trim(),
      forwarders: document.querySelector("#settings-forwarders").value.trim(),
      allow_recursion: document.querySelector("#settings-allow-recursion").checked,
    },
    recovery_email: document.querySelector("#settings-recovery-email").value.trim(),
    recovery_whatsapp: document.querySelector("#settings-recovery-whatsapp").value.trim(),
  };
  try {
    await apiFetch("/api/settings", {
      method: "PUT",
      body: JSON.stringify(payload),
    });
    await loadAll();
    showGlobalMessage("Settings actualizados.");
  } catch (error) {
    showGlobalMessage(error.message, "error");
  }
});

document.addEventListener("click", async (event) => {
  const target = event.target;
  if (!(target instanceof HTMLElement)) {
    return;
  }
  const action = target.dataset.action;
  const itemId = Number(target.dataset.id || "0");
  if (!action || !itemId) {
    return;
  }
  if (action === "edit-domain") {
    const item = state.domains.find((entry) => entry.id === itemId);
    if (!item) {
      return;
    }
    document.querySelector("#domain-id").value = String(item.id);
    document.querySelector("#domain-name").value = item.domain || "";
    document.querySelector("#domain-ns1-hostname").value = item.ns1_hostname || "";
    document.querySelector("#domain-ns1-ipv4").value = item.ns1_ipv4 || "";
    document.querySelector("#domain-ns2-hostname").value = item.ns2_hostname || "";
    document.querySelector("#domain-ns2-ipv4").value = item.ns2_ipv4 || "";
    showGlobalMessage(`Editando dominio ${item.domain}.`);
    return;
  }
  if (action === "delete-domain") {
    if (!window.confirm("Borrar dominio y sus records DNS?")) {
      return;
    }
    try {
      await apiFetch(`/api/domains/${itemId}`, { method: "DELETE" });
      await loadAll();
      showGlobalMessage("Dominio eliminado.");
    } catch (error) {
      showGlobalMessage(error.message, "error");
    }
    return;
  }
  if (action === "edit-dns") {
    const item = state.dns.find((entry) => entry.id === itemId);
    if (!item) {
      return;
    }
    document.querySelector("#dns-id").value = String(item.id);
    document.querySelector("#dns-zone").value = item.zone || "";
    document.querySelector("#dns-name").value = item.name || "";
    document.querySelector("#dns-type").value = item.type || "A";
    document.querySelector("#dns-value").value = item.value || "";
    document.querySelector("#dns-ttl").value = item.ttl || 300;
    showGlobalMessage(`Editando record ${item.zone} ${item.name}.`);
    return;
  }
  if (action === "delete-dns") {
    if (!window.confirm("Borrar este record DNS?")) {
      return;
    }
    try {
      await apiFetch(`/api/dns/${itemId}`, { method: "DELETE" });
      await loadAll();
      showGlobalMessage("Record DNS eliminado.");
    } catch (error) {
      showGlobalMessage(error.message, "error");
    }
  }
});

(async function init() {
  if (!state.token) {
    switchView(false);
    return;
  }
  try {
    switchView(true);
    await loadAll();
  } catch (error) {
    logout(false);
  }
})();
