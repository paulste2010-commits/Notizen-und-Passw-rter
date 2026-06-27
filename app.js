// ── CONSTANTS ──
const STORAGE_KEY   = "passwort-notizen-tresor-v1";
const THEME_KEY     = "passwort-notizen-theme";
const LAST_ID_KEY   = "passwort-notizen-last-id";
const AUTO_LOCK_SEC = 10 * 60; // 10 minutes
const ENC = new TextEncoder();
const DEC = new TextDecoder();

// ── STATE ──
const state = {
  key: null, salt: null,
  vault: { entries: [] },
  accountName: "",
  activeId: null,
  filter: "all",
  search: "",
  sort: "updated",
  pendingConfirm: null,
  pendingTag: null,
  autoLockTimer: null,
  autoLockRemaining: AUTO_LOCK_SEC,
  clipboardTimer: null,
  pwRevealTimers: {},
};

const $ = (id) => document.getElementById(id);
const els = {
  lockScreen:       $("lockScreen"),
  vaultScreen:      $("vaultScreen"),
  lockHint:         $("lockHint"),
  lockMessage:      $("lockMessage"),
  unlockForm:       $("unlockForm"),
  accountName:      $("accountName"),
  masterPassword:   $("masterPassword"),
  toggleMaster:     $("toggleMaster"),
  unlockButton:     $("unlockButton"),
  accountLabel:     $("accountLabel"),
  themeButton:      $("themeButton"),
  exportButton:     $("exportButton"),
  importFile:       $("importFile"),
  lockButton:       $("lockButton"),
  searchInput:      $("searchInput"),
  sortSelect:       $("sortSelect"),
  entryCount:       $("entryCount"),
  entryList:        $("entryList"),
  entryForm:        $("entryForm"),
  emptyState:       $("emptyState"),
  formType:         $("formType"),
  formTitle:        $("formTitle"),
  formMeta:         $("formMeta"),
  deleteButton:     $("deleteButton"),
  duplicateButton:  $("duplicateButton"),
  favoriteButton:   $("favoriteButton"),
  titleInput:       $("titleInput"),
  usernameInput:    $("usernameInput"),
  urlInput:         $("urlInput"),
  passwordInput:    $("passwordInput"),
  passwordFields:   $("passwordFields"),
  notesInput:       $("notesInput"),
  saveState:        $("saveState"),
  lengthInput:      $("lengthInput"),
  lengthOutput:     $("lengthOutput"),
  symbolsInput:     $("symbolsInput"),
  generateButton:   $("generateButton"),
  togglePassword:   $("togglePassword"),
  copyPassword:     $("copyPassword"),
  breachCheckButton:$("breachCheckButton"),
  newPasswordButton:$("newPasswordButton"),
  newNoteButton:    $("newNoteButton"),
  confirmOverlay:   $("confirmOverlay"),
  confirmTitle:     $("confirmTitle"),
  confirmText:      $("confirmText"),
  confirmCancel:    $("confirmCancel"),
  confirmOk:        $("confirmOk"),
  strengthMeter:    $("strengthMeter"),
  strengthLabel:    $("strengthLabel"),
  sb1: $("sb1"), sb2: $("sb2"), sb3: $("sb3"), sb4: $("sb4"),
  tagRow:           $("tagRow"),
  tagList:          $("tagList"),
  addTagButton:     $("addTagButton"),
  tagOverlay:       $("tagOverlay"),
  tagInput:         $("tagInput"),
  tagCancel:        $("tagCancel"),
  tagOk:            $("tagOk"),
  pwHistoryRow:     $("pwHistoryRow"),
  pwHistoryList:    $("pwHistoryList"),
  expiryEnabled:    $("expiryEnabled"),
  expiryDate:       $("expiryDate"),
  toastContainer:   $("toastContainer"),
  offlineBanner:    $("offlineBanner"),
  autoLockTimer:    $("autoLockTimer"),
  autoLockLabel:    $("autoLockLabel"),
};

// ── SVG ICONS ──
const EYE_OPEN = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`;
const EYE_CLOSED = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/><path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/><line x1="1" y1="1" x2="23" y2="23"/></svg>`;
const STAR_FILLED = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>`;
const STAR_EMPTY  = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>`;

// ── CRYPTO ──
function getStoredVault() {
  const raw = localStorage.getItem(STORAGE_KEY);
  return raw ? JSON.parse(raw) : null;
}
function b64(bytes) { return btoa(String.fromCharCode(...new Uint8Array(bytes))); }
function unb64(s)   { return Uint8Array.from(atob(s), c => c.charCodeAt(0)); }

async function deriveKey(password, salt) {
  const mat = await crypto.subtle.importKey("raw", ENC.encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 260000, hash: "SHA-256" },
    mat, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
  );
}
async function encryptVault() {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, state.key, ENC.encode(JSON.stringify(state.vault)));
  localStorage.setItem(STORAGE_KEY, JSON.stringify({
    version: 1, accountName: state.accountName,
    salt: b64(state.salt), iv: b64(iv), data: b64(enc),
    updatedAt: new Date().toISOString(),
  }));
}
async function decryptVault(password, stored) {
  const salt = unb64(stored.salt);
  const key  = await deriveKey(password, salt);
  const dec  = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(stored.iv) }, key, unb64(stored.data));
  return { key, salt, vault: JSON.parse(DEC.decode(dec)) };
}

// ── UTILS ──
function uid()  { return crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random()}`; }
function now()  { return new Date().toISOString(); }
function fmtDate(iso) {
  if (!iso) return "";
  return new Date(iso).toLocaleDateString("de-DE", { day: "2-digit", month: "2-digit", year: "numeric" });
}
function activeEntry() { return state.vault.entries.find(e => e.id === state.activeId) || null; }

function filteredEntries() {
  const needle = state.search.trim().toLowerCase();
  return state.vault.entries
    .filter(e => {
      if (state.filter === "favorite") return e.favorite;
      if (state.filter === "all") return true;
      return e.type === state.filter;
    })
    .filter(e => !needle || [e.title, e.username, e.url, e.notes, ...(e.tags||[])].join(" ").toLowerCase().includes(needle))
    .sort((a, b) => {
      if (state.sort === "alpha")   return (a.title||"").localeCompare(b.title||"", "de");
      if (state.sort === "created") return b.createdAt.localeCompare(a.createdAt);
      return b.updatedAt.localeCompare(a.updatedAt);
    });
}

// ── TOAST ──
function toast(msg, type = "info", duration = 3000) {
  const el = document.createElement("div");
  el.className = `toast toast-${type}`;
  const icons = {
    success: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>`,
    error:   `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>`,
    warning: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`,
    info:    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`,
  };
  el.innerHTML = `${icons[type]||""}<span></span>`;
  el.querySelector("span").textContent = msg;
  els.toastContainer.append(el);
  requestAnimationFrame(() => el.classList.add("visible"));
  setTimeout(() => {
    el.classList.remove("visible");
    setTimeout(() => el.remove(), 300);
  }, duration);
}

// ── PASSWORD STRENGTH ──
function passwordStrength(pw) {
  if (!pw) return 0;
  let s = 0;
  if (pw.length >= 10) s++;
  if (pw.length >= 16) s++;
  if (/[A-Z]/.test(pw) && /[a-z]/.test(pw)) s++;
  if (/[0-9]/.test(pw)) s++;
  if (/[^A-Za-z0-9]/.test(pw)) s++;
  return Math.min(4, Math.round(s * 4 / 5));
}
function updateStrengthMeter(pw) {
  if (!pw) { els.strengthMeter.style.display = "none"; return; }
  els.strengthMeter.style.display = "";
  const level = passwordStrength(pw);
  const labels = ["", "Schwach", "Mäßig", "Gut", "Stark"];
  const cls = `filled-${level}`;
  [els.sb1,els.sb2,els.sb3,els.sb4].forEach((b,i) => { b.className = "strength-bar " + (i < level ? cls : ""); });
  els.strengthLabel.textContent = labels[level] || "";
  els.strengthLabel.style.color = level <= 1 ? "var(--danger)" : level === 2 ? "#F59E0B" : "var(--success)";
}

// ── SHA-1 for HIBP ──
async function sha1hex(str) {
  const buf = await crypto.subtle.digest("SHA-1", ENC.encode(str));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,"0")).join("").toUpperCase();
}

// ── BREACH CHECK ──
async function checkBreach(password) {
  if (!password) { toast("Kein Passwort eingegeben.", "warning"); return; }
  toast("Prüfe Datenleck…", "info", 2000);
  try {
    const hash   = await sha1hex(password);
    const prefix = hash.slice(0, 5);
    const suffix = hash.slice(5);
    const res    = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, { headers: { "Add-Padding": "true" } });
    if (!res.ok) throw new Error("API nicht erreichbar");
    const text   = await res.text();
    const match  = text.split("\r\n").find(line => line.startsWith(suffix));
    if (match) {
      const count = parseInt(match.split(":")[1], 10);
      toast(`⚠️ Dieses Passwort wurde ${count.toLocaleString("de-DE")}× in Datenlecks gefunden!`, "error", 6000);
    } else {
      toast("✓ Passwort nicht in bekannten Datenlecks gefunden.", "success", 4000);
    }
  } catch {
    toast("Breach-Check fehlgeschlagen. Bist du online?", "warning");
  }
}

// ── AUTO-LOCK ──
function resetAutoLock() {
  state.autoLockRemaining = AUTO_LOCK_SEC;
}
function startAutoLock() {
  stopAutoLock();
  state.autoLockRemaining = AUTO_LOCK_SEC;
  els.autoLockTimer.classList.remove("hidden");
  state.autoLockTimer = setInterval(() => {
    state.autoLockRemaining--;
    const m = String(Math.floor(state.autoLockRemaining / 60)).padStart(2,"0");
    const s = String(state.autoLockRemaining % 60).padStart(2,"0");
    els.autoLockLabel.textContent = `${m}:${s}`;
    if (state.autoLockRemaining <= 0) { lock(); toast("Tresor automatisch gesperrt.", "info"); }
  }, 1000);
}
function stopAutoLock() {
  clearInterval(state.autoLockTimer);
  state.autoLockTimer = null;
  els.autoLockTimer.classList.add("hidden");
}
["click","keydown","mousemove","touchstart"].forEach(ev => {
  document.addEventListener(ev, () => { if (state.key) resetAutoLock(); }, { passive: true });
});

// ── OFFLINE BANNER ──
function updateOnlineStatus() {
  els.offlineBanner.classList.toggle("hidden", navigator.onLine);
}
window.addEventListener("online",  updateOnlineStatus);
window.addEventListener("offline", updateOnlineStatus);

// ── URL AUTO-FORMAT ──
function autoFormatUrl(val) {
  if (!val) return val;
  if (/^https?:\/\//i.test(val)) return val;
  if (val.includes(".")) return "https://" + val;
  return val;
}

// ── RENDER ──
function renderList() {
  const entries = filteredEntries();
  els.entryCount.textContent = String(entries.length);
  els.entryList.innerHTML = "";
  if (!entries.length) {
    const p = document.createElement("p");
    p.className = "message";
    p.textContent = "Keine passenden Einträge.";
    els.entryList.append(p);
    return;
  }

  // Check duplicates
  const pwMap = {};
  entries.forEach(e => { if (e.password) { pwMap[e.password] = (pwMap[e.password]||0)+1; } });

  const sections = state.filter === "all"
    ? [{ title:"Passwörter",type:"password"},{title:"Notizen",type:"note"}]
    : state.filter === "favorite"
    ? [{ title:"Passwörter",type:"password"},{title:"Notizen",type:"note"}]
    : [{title: state.filter==="password"?"Passwörter":"Notizen", type:state.filter}];

  for (const sec of sections) {
    const grp = entries.filter(e => e.type === sec.type);
    if (!grp.length) continue;
    const wrap = document.createElement("section");
    wrap.className = "entry-section";
    const h = document.createElement("h4");
    h.textContent = sec.title;
    wrap.append(h);
    for (const entry of grp) wrap.append(createEntryCard(entry, pwMap));
    els.entryList.append(wrap);
  }
}

function createEntryCard(entry, pwMap) {
  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = `entry-card ${entry.id === state.activeId ? "active" : ""} entry-card-new`;
  btn.dataset.id = entry.id;

  const isNote = entry.type === "note";
  const isDuplicate = entry.password && pwMap && (pwMap[entry.password]||0) > 1;
  const isExpired = entry.expiryDate && new Date(entry.expiryDate) < new Date();

  const pillIcon = isNote
    ? `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>`
    : `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>`;

  const sub = isNote
    ? (entry.notes||"Leere Notiz").slice(0,80)
    : (entry.username || entry.url || "Kein Login hinterlegt");

  const warnings = [];
  if (isDuplicate) warnings.push(`<span class="card-warn">Doppeltes Passwort</span>`);
  if (isExpired)   warnings.push(`<span class="card-warn">Abgelaufen</span>`);

  btn.innerHTML = `
    <div class="card-header">
      <span class="type-pill ${isNote?"note":""}">${pillIcon}${isNote?"Notiz":"Passwort"}</span>
      ${entry.favorite ? `<span class="card-star">★</span>` : ""}
      ${warnings.join("")}
    </div>
    <strong></strong>
    <span class="card-sub"></span>
    <span class="card-date"></span>
  `;
  btn.querySelector("strong").textContent = entry.title || "Ohne Titel";
  btn.querySelector(".card-sub").textContent = sub;
  btn.querySelector(".card-date").textContent = fmtDate(entry.updatedAt);
  btn.addEventListener("click", () => selectEntry(entry.id));

  requestAnimationFrame(() => btn.classList.remove("entry-card-new"));
  return btn;
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
  els.formMeta.textContent = `Erstellt ${fmtDate(entry.createdAt)} · Bearbeitet ${fmtDate(entry.updatedAt)}`;
  els.passwordFields.classList.toggle("hidden", entry.type === "note");
  els.titleInput.value    = entry.title    || "";
  els.usernameInput.value = entry.username || "";
  els.urlInput.value      = entry.url      || "";
  els.passwordInput.value = entry.password || "";
  els.notesInput.value    = entry.notes    || "";
  els.saveState.textContent = "";

  // Favorite button
  els.favoriteButton.innerHTML = entry.favorite ? STAR_FILLED : STAR_EMPTY;
  els.favoriteButton.style.color = entry.favorite ? "var(--gold)" : "";

  // Tags
  renderTags(entry.tags || []);

  // Expiry
  const hasExpiry = Boolean(entry.expiryDate);
  els.expiryEnabled.checked = hasExpiry;
  els.expiryDate.classList.toggle("hidden", !hasExpiry);
  els.expiryDate.value = entry.expiryDate || "";

  // Password history
  const hist = entry.passwordHistory || [];
  if (hist.length) {
    els.pwHistoryRow.classList.remove("hidden");
    els.pwHistoryList.innerHTML = "";
    hist.slice().reverse().forEach(pw => {
      const span = document.createElement("span");
      span.className = "pw-history-item";
      span.textContent = "•".repeat(Math.min(pw.length, 12));
      span.title = "Klicken zum Wiederherstellen";
      span.addEventListener("click", () => {
        els.passwordInput.value = pw;
        updateStrengthMeter(pw);
        toast("Altes Passwort wiederhergestellt.", "info");
      });
      els.pwHistoryList.append(span);
    });
  } else {
    els.pwHistoryRow.classList.add("hidden");
  }

  updateStrengthMeter(entry.password || "");
}

function renderTags(tags) {
  els.tagList.innerHTML = "";
  tags.forEach(tag => {
    const pill = document.createElement("span");
    pill.className = "tag-pill";
    pill.innerHTML = `${tag}<button type="button" class="tag-remove" data-tag="${tag}">×</button>`;
    pill.querySelector(".tag-remove").addEventListener("click", () => removeTag(tag));
    els.tagList.append(pill);
  });
}

function render() { renderList(); renderEditor(); }
function selectEntry(id) {
  state.activeId = id;
  localStorage.setItem(LAST_ID_KEY, id);
  render();
}

function createEntry(type) {
  const entry = {
    id: uid(), type,
    title: type==="note" ? "Neue Notiz" : "Neues Passwort",
    username:"", url:"", password:"", notes:"",
    tags: [], favorite: false,
    passwordHistory: [],
    expiryDate: "",
    createdAt: now(), updatedAt: now(),
  };
  state.vault.entries.push(entry);
  state.activeId = entry.id;
  saveAndRender("Angelegt.");
}

async function saveAndRender(message="Gespeichert.") {
  await encryptVault();
  render();
  els.saveState.textContent = message;
  setTimeout(() => { if (els.saveState.textContent===message) els.saveState.textContent=""; }, 1800);
}

function fillActiveEntryFromForm() {
  const entry = activeEntry();
  if (!entry) return null;
  // Password history: save old pw if changed
  const newPw = els.passwordInput.value;
  if (newPw && newPw !== entry.password && entry.password) {
    const hist = entry.passwordHistory || [];
    hist.push(entry.password);
    entry.passwordHistory = hist.slice(-3);
  }
  entry.title    = els.titleInput.value.trim() || "Ohne Titel";
  entry.username = els.usernameInput.value.trim();
  entry.url      = autoFormatUrl(els.urlInput.value.trim());
  entry.password = newPw;
  entry.notes    = els.notesInput.value.trim();
  entry.expiryDate = els.expiryEnabled.checked ? els.expiryDate.value : "";
  entry.updatedAt  = now();
  return entry;
}

// ── TAGS ──
function removeTag(tag) {
  const entry = activeEntry();
  if (!entry) return;
  entry.tags = (entry.tags||[]).filter(t => t !== tag);
  entry.updatedAt = now();
  saveAndRender();
}

function openTagModal() {
  els.tagInput.value = "";
  els.tagOverlay.classList.remove("hidden");
  els.tagOverlay.setAttribute("aria-hidden","false");
  setTimeout(() => els.tagInput.focus(), 50);
  return new Promise(res => { state.pendingTag = res; });
}
function closeTagModal(val) {
  els.tagOverlay.classList.add("hidden");
  els.tagOverlay.setAttribute("aria-hidden","true");
  if (state.pendingTag) state.pendingTag(val);
  state.pendingTag = null;
}

els.tagCancel.addEventListener("click", () => closeTagModal(null));
els.tagOk.addEventListener("click", () => closeTagModal(els.tagInput.value.trim()));
els.tagInput.addEventListener("keydown", e => { if (e.key==="Enter") { e.preventDefault(); closeTagModal(els.tagInput.value.trim()); } });

els.addTagButton.addEventListener("click", async () => {
  const tag = await openTagModal();
  if (!tag) return;
  const entry = activeEntry();
  if (!entry) return;
  entry.tags = [...new Set([...(entry.tags||[]), tag])];
  entry.updatedAt = now();
  saveAndRender();
});

// ── GENERATE ──
function generatePassword(length, symbolsEnabled) {
  const letters = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  const digits  = "23456789";
  const symbols = "!@#$%&*?-_+=";
  const pool    = letters + digits + (symbolsEnabled ? symbols : "");
  const bytes   = crypto.getRandomValues(new Uint32Array(length));
  return Array.from(bytes, v => pool[v % pool.length]).join("");
}

function download(filename, text) {
  const url  = URL.createObjectURL(new Blob([text], {type:"application/json"}));
  const link = document.createElement("a");
  link.href  = url; link.download = filename; link.click();
  URL.revokeObjectURL(url);
}

// ── LOCK / UNLOCK ──
function setUnlocked() {
  els.lockScreen.classList.add("hidden");
  els.vaultScreen.classList.remove("hidden");
  els.accountLabel.textContent = state.accountName ? `Angemeldet als ${state.accountName}` : "";
  els.accountName.value = ""; els.masterPassword.value = "";
  updateOnlineStatus();
  startAutoLock();
  // restore last active entry
  const lastId = localStorage.getItem(LAST_ID_KEY);
  if (lastId && state.vault.entries.find(e => e.id === lastId)) state.activeId = lastId;
  render();
}

function lock() {
  stopAutoLock();
  clearInterval(state.clipboardTimer);
  state.key=null; state.salt=null; state.vault={entries:[]}; state.accountName=""; state.activeId=null;
  els.vaultScreen.classList.add("hidden");
  els.lockScreen.classList.remove("hidden");
  els.lockMessage.textContent = "";
  updateLockCopy();
  els.masterPassword.focus();
}

function updateLockCopy() {
  const stored   = getStoredVault();
  const hasVault = Boolean(stored);
  els.lockHint.textContent = hasVault
    ? "Gib deinen Account-Namen und dein Master-Passwort ein, um den Tresor zu entsperren."
    : "Erstelle einen Account mit Master-Passwort. Deine Daten bleiben verschlüsselt in diesem Browser.";
  els.accountName.placeholder = stored?.accountName || "z. B. Paul";
  els.unlockButton.innerHTML  = hasVault
    ? `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" style="width:16px;height:16px"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 9.9-1"/></svg> Entsperren`
    : `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" style="width:16px;height:16px"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg> Tresor erstellen`;
}

// ── EVENTS ──
els.unlockForm.addEventListener("submit", async e => {
  e.preventDefault();
  const accountName = els.accountName.value.trim();
  const password    = els.masterPassword.value;
  els.lockMessage.textContent = "Einen Moment…";
  els.unlockButton.disabled = true;
  try {
    if (!accountName) { els.lockMessage.textContent = "Bitte gib einen Account-Namen ein."; return; }
    const stored = getStoredVault();
    if (stored) {
      if (stored.accountName && stored.accountName.toLowerCase() !== accountName.toLowerCase()) {
        els.lockMessage.textContent = "Dieser Account-Name passt nicht zu diesem Tresor."; return;
      }
      const r = await decryptVault(password, stored);
      state.key=r.key; state.salt=r.salt; state.vault=r.vault;
      state.accountName = stored.accountName || accountName;
      if (!stored.accountName) await encryptVault();
    } else {
      state.salt = crypto.getRandomValues(new Uint8Array(16));
      state.key  = await deriveKey(password, state.salt);
      state.vault = {entries:[]}; state.accountName = accountName;
      await encryptVault();
    }
    setUnlocked();
  } catch { els.lockMessage.textContent = "Master-Passwort stimmt nicht oder Backup ist beschädigt."; }
  finally  { els.unlockButton.disabled = false; }
});

function toggleVisibility(input, btn) {
  const show = input.type === "password";
  input.type = show ? "text" : "password";
  btn.innerHTML = show ? EYE_CLOSED : EYE_OPEN;
  // Auto-hide after 10s
  if (show) {
    const key = btn.id;
    clearTimeout(state.pwRevealTimers[key]);
    state.pwRevealTimers[key] = setTimeout(() => {
      input.type = "password";
      btn.innerHTML = EYE_OPEN;
    }, 10000);
  }
}

els.toggleMaster.addEventListener("click",   () => toggleVisibility(els.masterPassword, els.toggleMaster));
els.togglePassword.addEventListener("click", () => toggleVisibility(els.passwordInput, els.togglePassword));

els.copyPassword.addEventListener("click", async () => {
  if (!els.passwordInput.value) return;
  await navigator.clipboard.writeText(els.passwordInput.value);
  toast("Passwort kopiert — wird in 30 Sek. gelöscht.", "success", 3000);
  clearInterval(state.clipboardTimer);
  let remaining = 30;
  state.clipboardTimer = setInterval(async () => {
    remaining--;
    if (remaining <= 0) {
      clearInterval(state.clipboardTimer);
      try { await navigator.clipboard.writeText(""); } catch {}
    }
  }, 1000);
});

els.breachCheckButton.addEventListener("click", () => checkBreach(els.passwordInput.value));

els.passwordInput.addEventListener("input", () => updateStrengthMeter(els.passwordInput.value));

els.entryForm.addEventListener("submit", async e => {
  e.preventDefault();
  fillActiveEntryFromForm();
  await saveAndRender();
  toast("Gespeichert.", "success");
});

for (const input of [els.titleInput, els.usernameInput, els.urlInput, els.passwordInput, els.notesInput]) {
  input.addEventListener("change", async () => { fillActiveEntryFromForm(); await saveAndRender(); });
}

els.urlInput.addEventListener("blur", () => {
  const formatted = autoFormatUrl(els.urlInput.value.trim());
  if (formatted !== els.urlInput.value) els.urlInput.value = formatted;
});

els.deleteButton.addEventListener("click", async () => {
  const entry = activeEntry();
  if (!entry) return;
  const ok = await openConfirm({ title:"Eintrag löschen?", text:`"${entry.title||"Eintrag"}" wirklich löschen?` });
  if (!ok) return;

  // Undo buffer
  const deleted = { ...entry };
  const idx = state.vault.entries.findIndex(e => e.id === entry.id);
  state.vault.entries.splice(idx, 1);
  state.activeId = state.vault.entries[0]?.id || null;
  await saveAndRender("Gelöscht.");

  // Show undo toast
  const undoToast = document.createElement("div");
  undoToast.className = "toast toast-warning visible toast-undo";
  undoToast.innerHTML = `<span>"${deleted.title}" gelöscht.</span><button class="toast-undo-btn">Rückgängig</button>`;
  let undone = false;
  undoToast.querySelector(".toast-undo-btn").addEventListener("click", async () => {
    undone = true;
    state.vault.entries.splice(idx, 0, deleted);
    state.activeId = deleted.id;
    await saveAndRender("Wiederhergestellt.");
    toast("Eintrag wiederhergestellt.", "success");
    undoToast.classList.remove("visible");
    setTimeout(() => undoToast.remove(), 300);
  });
  els.toastContainer.append(undoToast);
  setTimeout(() => {
    if (!undone) {
      undoToast.classList.remove("visible");
      setTimeout(() => undoToast.remove(), 300);
    }
  }, 6000);
});

els.duplicateButton.addEventListener("click", async () => {
  const entry = activeEntry();
  if (!entry) return;
  const copy = { ...JSON.parse(JSON.stringify(entry)), id: uid(), title: entry.title + " (Kopie)", createdAt: now(), updatedAt: now() };
  state.vault.entries.push(copy);
  state.activeId = copy.id;
  await saveAndRender("Dupliziert.");
  toast("Eintrag dupliziert.", "success");
});

els.favoriteButton.addEventListener("click", async () => {
  const entry = activeEntry();
  if (!entry) return;
  entry.favorite = !entry.favorite;
  entry.updatedAt = now();
  await saveAndRender();
  els.favoriteButton.innerHTML = entry.favorite ? STAR_FILLED : STAR_EMPTY;
  els.favoriteButton.style.color = entry.favorite ? "var(--gold)" : "";
  toast(entry.favorite ? "Als Favorit markiert." : "Favorit entfernt.", "info");
});

els.expiryEnabled.addEventListener("change", () => {
  els.expiryDate.classList.toggle("hidden", !els.expiryEnabled.checked);
  if (els.expiryEnabled.checked) els.expiryDate.focus();
});

els.newPasswordButton.addEventListener("click", () => createEntry("password"));
els.newNoteButton.addEventListener("click",     () => createEntry("note"));
document.querySelectorAll("[data-create]").forEach(btn => btn.addEventListener("click", () => createEntry(btn.dataset.create)));

document.querySelectorAll(".segment").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".segment").forEach(s => s.classList.remove("active"));
    btn.classList.add("active");
    state.filter = btn.dataset.filter;
    renderList();
  });
});

els.searchInput.addEventListener("input", () => { state.search = els.searchInput.value; renderList(); });
els.sortSelect.addEventListener("change", () => { state.sort = els.sortSelect.value; renderList(); });
els.lengthInput.addEventListener("input", () => { els.lengthOutput.textContent = els.lengthInput.value; });

els.generateButton.addEventListener("click", () => {
  const pw = generatePassword(Number(els.lengthInput.value), els.symbolsInput.checked);
  els.passwordInput.value = pw;
  updateStrengthMeter(pw);
  fillActiveEntryFromForm();
  saveAndRender("Passwort generiert.");
  toast("Neues Passwort generiert.", "success");
});

els.exportButton.addEventListener("click", () => {
  const stored = localStorage.getItem(STORAGE_KEY);
  if (!stored) return;
  download(`tresor-backup-${new Date().toISOString().slice(0,10)}.json`, stored);
  toast("Backup exportiert.", "success");
});

els.importFile.addEventListener("change", async () => {
  const file = els.importFile.files[0];
  if (!file) return;
  try {
    const parsed = JSON.parse(await file.text());
    if (!parsed.salt||!parsed.iv||!parsed.data) throw new Error();
    localStorage.setItem(STORAGE_KEY, JSON.stringify(parsed));
    toast("Backup importiert. Bitte neu entsperren.", "success", 4000);
    lock();
  } catch { toast("Ungültiges Backup.", "error"); }
  finally { els.importFile.value = ""; }
});

els.lockButton.addEventListener("click", lock);

// ── CONFIRM ──
function openConfirm({title, text}) {
  els.confirmTitle.textContent = title;
  els.confirmText.textContent  = text;
  els.confirmOverlay.classList.remove("hidden");
  els.confirmOverlay.setAttribute("aria-hidden","false");
  els.confirmCancel.focus();
  return new Promise(res => { state.pendingConfirm = res; });
}
function closeConfirm(result) {
  els.confirmOverlay.classList.add("hidden");
  els.confirmOverlay.setAttribute("aria-hidden","true");
  if (state.pendingConfirm) state.pendingConfirm(result);
  state.pendingConfirm = null;
}
els.confirmCancel.addEventListener("click", () => closeConfirm(false));
els.confirmOk.addEventListener("click",     () => closeConfirm(true));
els.confirmOverlay.addEventListener("click", e => { if (e.target===els.confirmOverlay) closeConfirm(false); });

// ── KEYBOARD SHORTCUTS ──
document.addEventListener("keydown", e => {
  if (e.key === "Escape") {
    if (state.pendingConfirm) closeConfirm(false);
    if (state.pendingTag) closeTagModal(null);
    return;
  }
  if (!state.key) return;
  const ctrl = e.ctrlKey || e.metaKey;
  if (ctrl && e.key === "n") { e.preventDefault(); createEntry("password"); }
  if (ctrl && e.key === "f") { e.preventDefault(); els.searchInput.focus(); els.searchInput.select(); }
  if (ctrl && e.key === "l") { e.preventDefault(); lock(); }
});

// ── THEME ──
function applyTheme(theme) {
  const t = theme==="dark" ? "dark" : "light";
  document.body.dataset.theme = t;
  localStorage.setItem(THEME_KEY, t);
  const dark = t==="dark";
  els.themeButton.innerHTML = dark
    ? `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width:15px;height:15px"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg> Hell`
    : `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width:15px;height:15px"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg> Dunkel`;
}
els.themeButton.addEventListener("click", () => applyTheme(document.body.dataset.theme==="dark"?"light":"dark"));

// ── INIT ──
applyTheme(localStorage.getItem(THEME_KEY) || "light");
updateLockCopy();
updateOnlineStatus();
