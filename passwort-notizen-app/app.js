const STORAGE_KEY = "passwort-notizen-tresor-v1";
const THEME_KEY = "passwort-notizen-theme";
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

const state = {
  key: null,
  salt: null,
  vault: { entries: [] },
  accountName: "",
  activeId: null,
  filter: "all",
  search: "",
  pendingConfirm: null,
};

const $ = (id) => document.getElementById(id);

const els = {
  lockScreen: $("lockScreen"),
  vaultScreen: $("vaultScreen"),
  lockHint: $("lockHint"),
  lockMessage: $("lockMessage"),
  unlockForm: $("unlockForm"),
  accountName: $("accountName"),
  masterPassword: $("masterPassword"),
  toggleMaster: $("toggleMaster"),
  unlockButton: $("unlockButton"),
  accountLabel: $("accountLabel"),
  themeButton: $("themeButton"),
  exportButton: $("exportButton"),
  importFile: $("importFile"),
  lockButton: $("lockButton"),
  searchInput: $("searchInput"),
  entryCount: $("entryCount"),
  entryList: $("entryList"),
  entryForm: $("entryForm"),
  emptyState: $("emptyState"),
  formType: $("formType"),
  formTitle: $("formTitle"),
  deleteButton: $("deleteButton"),
  titleInput: $("titleInput"),
  usernameInput: $("usernameInput"),
  urlInput: $("urlInput"),
  passwordInput: $("passwordInput"),
  passwordFields: $("passwordFields"),
  notesInput: $("notesInput"),
  saveState: $("saveState"),
  lengthInput: $("lengthInput"),
  lengthOutput: $("lengthOutput"),
  symbolsInput: $("symbolsInput"),
  generateButton: $("generateButton"),
  togglePassword: $("togglePassword"),
  copyPassword: $("copyPassword"),
  newPasswordButton: $("newPasswordButton"),
  newNoteButton: $("newNoteButton"),
  confirmOverlay: $("confirmOverlay"),
  confirmTitle: $("confirmTitle"),
  confirmText: $("confirmText"),
  confirmCancel: $("confirmCancel"),
  confirmOk: $("confirmOk"),
};

function getStoredVault() {
  const raw = localStorage.getItem(STORAGE_KEY);
  return raw ? JSON.parse(raw) : null;
}

function bytesToBase64(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)));
}

function base64ToBytes(value) {
  return Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
}

async function deriveKey(password, salt) {
  const material = await crypto.subtle.importKey(
    "raw",
    textEncoder.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 260000, hash: "SHA-256" },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptVault() {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    state.key,
    textEncoder.encode(JSON.stringify(state.vault))
  );

  localStorage.setItem(STORAGE_KEY, JSON.stringify({
    version: 1,
    accountName: state.accountName,
    salt: bytesToBase64(state.salt),
    iv: bytesToBase64(iv),
    data: bytesToBase64(encrypted),
    updatedAt: new Date().toISOString(),
  }));
}

async function decryptVault(password, stored) {
  const salt = base64ToBytes(stored.salt);
  const key = await deriveKey(password, salt);
  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64ToBytes(stored.iv) },
    key,
    base64ToBytes(stored.data)
  );
  return { key, salt, vault: JSON.parse(textDecoder.decode(decrypted)) };
}

function uid() {
  return crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random()}`;
}

function now() {
  return new Date().toISOString();
}

function activeEntry() {
  return state.vault.entries.find((entry) => entry.id === state.activeId) || null;
}

function filteredEntries() {
  const needle = state.search.trim().toLowerCase();
  return state.vault.entries
    .filter((entry) => state.filter === "all" || entry.type === state.filter)
    .filter((entry) => {
      if (!needle) return true;
      return [entry.title, entry.username, entry.url, entry.notes]
        .join(" ")
        .toLowerCase()
        .includes(needle);
    })
    .sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
}

function renderList() {
  const entries = filteredEntries();
  els.entryCount.textContent = String(entries.length);
  els.entryList.innerHTML = "";

  if (!entries.length) {
    const empty = document.createElement("p");
    empty.className = "message";
    empty.textContent = "Keine passenden Einträge.";
    els.entryList.append(empty);
    return;
  }

  const sections = state.filter === "all"
    ? [
        { title: "Passwörter", type: "password" },
        { title: "Notizen", type: "note" },
      ]
    : [
        { title: state.filter === "password" ? "Passwörter" : "Notizen", type: state.filter },
      ];

  for (const section of sections) {
    const sectionEntries = entries.filter((entry) => entry.type === section.type);
    if (!sectionEntries.length) continue;

    const wrap = document.createElement("section");
    wrap.className = "entry-section";
    const heading = document.createElement("h4");
    heading.textContent = section.title;
    wrap.append(heading);

    for (const entry of sectionEntries) {
      wrap.append(createEntryCard(entry));
    }

    els.entryList.append(wrap);
  }
}

function createEntryCard(entry) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = `entry-card ${entry.id === state.activeId ? "active" : ""}`;
    button.dataset.id = entry.id;
    button.innerHTML = `
      <span class="type-pill ${entry.type === "note" ? "note" : ""}">${entry.type === "note" ? "Notiz" : "Passwort"}</span>
      <strong></strong>
      <span></span>
    `;
    button.querySelector("strong").textContent = entry.title || "Ohne Titel";
    button.querySelector("span:last-child").textContent = entry.type === "note"
      ? (entry.notes || "Leere Notiz").slice(0, 90)
      : (entry.username || entry.url || "Kein Login hinterlegt");
    button.addEventListener("click", () => selectEntry(entry.id));
    return button;
}

function renderEditor() {
  const entry = activeEntry();
  if (!entry) {
    els.entryForm.classList.add("hidden");
    els.emptyState.classList.remove("hidden");
    return;
  }

  els.emptyState.classList.add("hidden");
  els.entryForm.classList.remove("hidden");
  els.formType.textContent = entry.type === "note" ? "Notiz" : "Passwort";
  els.formTitle.textContent = entry.title || "Neuer Eintrag";
  els.passwordFields.classList.toggle("hidden", entry.type === "note");
  els.titleInput.value = entry.title || "";
  els.usernameInput.value = entry.username || "";
  els.urlInput.value = entry.url || "";
  els.passwordInput.value = entry.password || "";
  els.notesInput.value = entry.notes || "";
  els.saveState.textContent = "";
}

function render() {
  renderList();
  renderEditor();
}

function selectEntry(id) {
  state.activeId = id;
  render();
}

function createEntry(type) {
  const entry = {
    id: uid(),
    type,
    title: type === "note" ? "Neue Notiz" : "Neues Passwort",
    username: "",
    url: "",
    password: "",
    notes: "",
    createdAt: now(),
    updatedAt: now(),
  };
  state.vault.entries.push(entry);
  state.activeId = entry.id;
  saveAndRender("Angelegt.");
}

async function saveAndRender(message = "Gespeichert.") {
  await encryptVault();
  render();
  els.saveState.textContent = message;
  window.setTimeout(() => {
    if (els.saveState.textContent === message) els.saveState.textContent = "";
  }, 1800);
}

function fillActiveEntryFromForm() {
  const entry = activeEntry();
  if (!entry) return null;
  entry.title = els.titleInput.value.trim() || "Ohne Titel";
  entry.username = els.usernameInput.value.trim();
  entry.url = els.urlInput.value.trim();
  entry.password = els.passwordInput.value;
  entry.notes = els.notesInput.value.trim();
  entry.updatedAt = now();
  return entry;
}

function generatePassword(length, symbolsEnabled) {
  const letters = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  const digits = "23456789";
  const symbols = "!@#$%&*?-_+=";
  const pool = letters + digits + (symbolsEnabled ? symbols : "");
  const bytes = crypto.getRandomValues(new Uint32Array(length));
  return Array.from(bytes, (value) => pool[value % pool.length]).join("");
}

function download(filename, text) {
  const blob = new Blob([text], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

function setUnlocked() {
  els.lockScreen.classList.add("hidden");
  els.vaultScreen.classList.remove("hidden");
  els.accountLabel.textContent = state.accountName ? `Angemeldet als ${state.accountName}` : "";
  els.accountName.value = "";
  els.masterPassword.value = "";
  render();
}

function lock() {
  state.key = null;
  state.salt = null;
  state.vault = { entries: [] };
  state.accountName = "";
  state.activeId = null;
  els.vaultScreen.classList.add("hidden");
  els.lockScreen.classList.remove("hidden");
  els.lockMessage.textContent = "";
  updateLockCopy();
  els.masterPassword.focus();
}

function updateLockCopy() {
  const stored = getStoredVault();
  const hasVault = Boolean(stored);
  els.lockHint.textContent = hasVault
    ? "Gib deinen Account-Namen und dein Master-Passwort ein, um den Tresor zu entsperren."
    : "Erstelle einen Account mit Master-Passwort. Deine Daten bleiben verschlüsselt in diesem Browser.";
  els.accountName.placeholder = stored?.accountName || "z. B. Paul";
  els.unlockButton.textContent = hasVault ? "Entsperren" : "Tresor erstellen";
}

els.unlockForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const accountName = els.accountName.value.trim();
  const password = els.masterPassword.value;
  els.lockMessage.textContent = "Einen Moment...";

  try {
    if (!accountName) {
      els.lockMessage.textContent = "Bitte gib einen Account-Namen ein.";
      return;
    }

    const stored = getStoredVault();
    if (stored) {
      if (stored.accountName && stored.accountName.toLowerCase() !== accountName.toLowerCase()) {
        els.lockMessage.textContent = "Dieser Account-Name passt nicht zu diesem Tresor.";
        return;
      }
      const result = await decryptVault(password, stored);
      state.key = result.key;
      state.salt = result.salt;
      state.vault = result.vault;
      state.accountName = stored.accountName || accountName;
      if (!stored.accountName) await encryptVault();
    } else {
      state.salt = crypto.getRandomValues(new Uint8Array(16));
      state.key = await deriveKey(password, state.salt);
      state.vault = { entries: [] };
      state.accountName = accountName;
      await encryptVault();
    }
    setUnlocked();
  } catch (error) {
    els.lockMessage.textContent = "Master-Passwort stimmt nicht oder Backup ist beschädigt.";
  }
});

els.toggleMaster.addEventListener("click", () => {
  els.masterPassword.type = els.masterPassword.type === "password" ? "text" : "password";
});

els.togglePassword.addEventListener("click", () => {
  els.passwordInput.type = els.passwordInput.type === "password" ? "text" : "password";
});

els.copyPassword.addEventListener("click", async () => {
  if (!els.passwordInput.value) return;
  await navigator.clipboard.writeText(els.passwordInput.value);
  els.saveState.textContent = "Passwort kopiert.";
});

els.entryForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  fillActiveEntryFromForm();
  await saveAndRender();
});

for (const input of [els.titleInput, els.usernameInput, els.urlInput, els.passwordInput, els.notesInput]) {
  input.addEventListener("change", async () => {
    fillActiveEntryFromForm();
    await saveAndRender();
  });
}

els.deleteButton.addEventListener("click", async () => {
  const entry = activeEntry();
  if (!entry) return;
  const ok = await openConfirm({
    title: "Bist du dir sicher?",
    text: `"${entry.title || "Eintrag"}" wirklich löschen? Diese Aktion kann nicht rückgängig gemacht werden.`,
  });
  if (!ok) return;
  state.vault.entries = state.vault.entries.filter((item) => item.id !== entry.id);
  state.activeId = state.vault.entries[0]?.id || null;
  await saveAndRender("Gelöscht.");
});

els.newPasswordButton.addEventListener("click", () => createEntry("password"));
els.newNoteButton.addEventListener("click", () => createEntry("note"));

document.querySelectorAll("[data-create]").forEach((button) => {
  button.addEventListener("click", () => createEntry(button.dataset.create));
});

document.querySelectorAll(".segment").forEach((button) => {
  button.addEventListener("click", () => {
    document.querySelectorAll(".segment").forEach((item) => item.classList.remove("active"));
    button.classList.add("active");
    state.filter = button.dataset.filter;
    renderList();
  });
});

els.searchInput.addEventListener("input", () => {
  state.search = els.searchInput.value;
  renderList();
});

els.lengthInput.addEventListener("input", () => {
  els.lengthOutput.textContent = els.lengthInput.value;
});

els.generateButton.addEventListener("click", () => {
  els.passwordInput.value = generatePassword(Number(els.lengthInput.value), els.symbolsInput.checked);
  fillActiveEntryFromForm();
  saveAndRender("Passwort generiert.");
});

els.exportButton.addEventListener("click", () => {
  const stored = localStorage.getItem(STORAGE_KEY);
  if (!stored) return;
  download(`tresor-backup-${new Date().toISOString().slice(0, 10)}.json`, stored);
});

els.importFile.addEventListener("change", async () => {
  const file = els.importFile.files[0];
  if (!file) return;
  const text = await file.text();
  try {
    const parsed = JSON.parse(text);
    if (!parsed.salt || !parsed.iv || !parsed.data) throw new Error("Invalid backup");
    localStorage.setItem(STORAGE_KEY, JSON.stringify(parsed));
    alert("Backup importiert. Bitte mit dem passenden Master-Passwort neu entsperren.");
    lock();
  } catch (error) {
    alert("Diese Datei ist kein gültiges Tresor-Backup.");
  } finally {
    els.importFile.value = "";
  }
});

els.lockButton.addEventListener("click", lock);

function openConfirm({ title, text }) {
  els.confirmTitle.textContent = title;
  els.confirmText.textContent = text;
  els.confirmOverlay.classList.remove("hidden");
  els.confirmOverlay.setAttribute("aria-hidden", "false");
  els.confirmCancel.focus();

  return new Promise((resolve) => {
    state.pendingConfirm = resolve;
  });
}

function closeConfirm(result) {
  els.confirmOverlay.classList.add("hidden");
  els.confirmOverlay.setAttribute("aria-hidden", "true");
  if (state.pendingConfirm) state.pendingConfirm(result);
  state.pendingConfirm = null;
}

els.confirmCancel.addEventListener("click", () => closeConfirm(false));
els.confirmOk.addEventListener("click", () => closeConfirm(true));
els.confirmOverlay.addEventListener("click", (event) => {
  if (event.target === els.confirmOverlay) closeConfirm(false);
});

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && state.pendingConfirm) closeConfirm(false);
});

function applyTheme(theme) {
  const nextTheme = theme === "dark" ? "dark" : "light";
  document.body.dataset.theme = nextTheme;
  localStorage.setItem(THEME_KEY, nextTheme);
  els.themeButton.textContent = nextTheme === "dark" ? "Hell" : "Dunkel";
}

els.themeButton.addEventListener("click", () => {
  applyTheme(document.body.dataset.theme === "dark" ? "light" : "dark");
});

applyTheme(localStorage.getItem(THEME_KEY) || "light");
updateLockCopy();
