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
const recoveryForm = document.querySelector("#recovery-form");
const recoveryMessage = document.querySelector("#recovery-message");
const globalMessage = document.querySelector("#global-message");
const sessionUser = document.querySelector("#session-user");
const forcePasswordView = document.querySelector("#force-password-view");
const forcePasswordForm = document.querySelector("#force-password-form");
const forcePasswordMessage = document.querySelector("#force-password-message");
const tabs = Array.from(document.querySelectorAll(".tab"));
const panels = Array.from(document.querySelectorAll(".tab-panel"));

const rolePermissions = {
  superadmin: new Set([
    "accounts.read",
    "accounts.write",
    "domains.read",
    "domains.write",
    "dns.read",
    "dns.write",
    "settings.read",
    "settings.write",
    "apache.read",
    "apache.write",
    "ops.preview",
    "ops.execute",
    "security.read",
    "security.write",
    "web.read",
    "web.write",
  ]),
  operator: new Set([
    "domains.read",
    "domains.write",
    "dns.read",
    "dns.write",
    "settings.read",
    "settings.write",
    "apache.read",
    "ops.preview",
    "security.read",
    "web.read",
  ]),
};

function showGlobalMessage(text, type = "success") {
  globalMessage.textContent = text;
  globalMessage.className = `global-message ${type}`;
  globalMessage.hidden = false;
}

function hideGlobalMessage() {
  globalMessage.hidden = true;
}

function roleHas(permission) {
  const role = state.user?.role || "superadmin";
  return (rolePermissions[role] || rolePermissions.superadmin).has(permission);
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

function showRecoveryForm(visible) {
  recoveryForm.hidden = !visible;
  loginForm.hidden = visible;
  if (!visible) {
    recoveryForm.reset();
    recoveryMessage.hidden = true;
  }
}

function showForcePassword(required) {
  forcePasswordView.hidden = !required;
}

function activateTab(name) {
  tabs.forEach((button) => {
    button.classList.toggle("active", button.dataset.tab === name);
  });
  panels.forEach((panel) => {
    panel.classList.toggle("active", panel.id === `tab-${name}`);
  });
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
      <td>${item.module}</td>
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

function applyRoleVisibility() {
  const settingsTab = document.querySelector("#tab-button-settings");
  const apacheTab = document.querySelector("#tab-button-apache");
  const settingsPanel = document.querySelector("#tab-settings");
  const apachePanel = document.querySelector("#tab-apache");
  const domainForm = document.querySelector("#domain-form");
  const dnsForm = document.querySelector("#dns-form");
  const settingsForm = document.querySelector("#settings-form");

  settingsTab.hidden = !roleHas("settings.read");
  settingsPanel.hidden = !roleHas("settings.read");
  apacheTab.hidden = !roleHas("apache.read");
  apachePanel.hidden = !roleHas("apache.read");
  domainForm.hidden = !roleHas("domains.write");
  dnsForm.hidden = !roleHas("dns.write");

  settingsForm.querySelectorAll("input, button").forEach((element) => {
    element.disabled = !roleHas("settings.write");
  });

  if ((!roleHas("settings.read") && settingsTab.classList.contains("active")) || (!roleHas("apache.read") && apacheTab.classList.contains("active"))) {
    activateTab("domains");
  }
}

async function loadAll() {
  hideGlobalMessage();
  const me = await apiFetch("/api/me");
  state.user = me.user;
  sessionUser.textContent = state.user ? `${state.user.username} (${state.user.role})` : "";
  if (state.user?.force_password_change) {
    state.domains = [];
    state.dns = [];
    state.modules = [];
    state.settings = null;
    showForcePassword(true);
    return;
  }
  const [domains, dns, modules, settings] = await Promise.all([
    apiFetch("/api/domains"),
    apiFetch("/api/dns"),
    apiFetch("/api/apache/modules"),
    apiFetch("/api/settings"),
  ]);
  state.domains = domains.items || [];
  state.dns = dns.items || [];
  state.modules = modules.items || [];
  state.settings = settings.settings || null;
  applyRoleVisibility();
  showForcePassword(Boolean(state.user?.force_password_change));
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
  try {
    await loadAll();
    loginForm.reset();
    hideGlobalMessage();
    showRecoveryForm(false);
    switchView(true);
  } catch (error) {
    setToken("");
    switchView(false);
    throw error;
  }
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
  state.domains = [];
  state.dns = [];
  state.modules = [];
  state.settings = null;
  sessionUser.textContent = "";
  loginForm.reset();
  showRecoveryForm(false);
  resetDomainForm();
  resetDnsForm();
  showForcePassword(false);
  hideGlobalMessage();
  activateTab("domains");
  switchView(false);
}

tabs.forEach((button) => {
  button.addEventListener("click", () => {
    activateTab(button.dataset.tab);
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

document.querySelector("#show-recovery").addEventListener("click", () => {
  showRecoveryForm(true);
  recoveryMessage.hidden = true;
});

document.querySelector("#hide-recovery").addEventListener("click", () => {
  showRecoveryForm(false);
});

recoveryForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  recoveryMessage.hidden = true;
  try {
    await apiFetch("/api/recover/start", {
      method: "POST",
      body: JSON.stringify({
        username: document.querySelector("#recovery-username").value.trim(),
        whatsapp: document.querySelector("#recovery-whatsapp").value.trim(),
      }),
    });
    recoveryMessage.textContent = "Se envio una clave temporal al canal configurado.";
    recoveryMessage.className = "global-message success";
    recoveryMessage.hidden = false;
  } catch (error) {
    recoveryMessage.textContent = error.message;
    recoveryMessage.className = "form-error";
    recoveryMessage.hidden = false;
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

forcePasswordForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  forcePasswordMessage.hidden = true;
  try {
    const result = await apiFetch("/api/change-password", {
      method: "POST",
      body: JSON.stringify({
        new_password: document.querySelector("#force-password-new").value,
        confirm_password: document.querySelector("#force-password-confirm").value,
      }),
    });
    setToken(result.token);
    forcePasswordForm.reset();
    await loadAll();
    showGlobalMessage("Password actualizada.");
  } catch (error) {
    forcePasswordMessage.textContent = error.message;
    forcePasswordMessage.hidden = false;
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
    activateTab("domains");
    switchView(false);
    return;
  }
  try {
    await loadAll();
    switchView(true);
  } catch (error) {
    logout(false);
  }
})();
