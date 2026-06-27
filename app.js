// ══════════════════════════════════════════════
//  TRESOR — app.js
//  XSS-safe: user data only via .textContent
//            never via innerHTML
// ══════════════════════════════════════════════

const STORAGE_KEY   = "passwort-notizen-tresor-v2";
const THEME_KEY     = "passwort-notizen-theme";
const LAST_ID_KEY   = "passwort-notizen-last-id";
const LOG_KEY       = "passwort-notizen-log";
const AUTO_LOCK_SEC = 10 * 60;

const ENC = new TextEncoder();
const DEC = new TextDecoder();

// ── STATE ──
const S = {
  key: null, salt: null,
  vault: { entries: [], files: [], bookmarks: [], codes: [], aliases: [] },
  accountName: "", alertEmail: "",
  activeId: null,
  filter: "all", search: "", sort: "updated",
  activeTab: "vault",
  pendingConfirm: null, pendingTag: null, pendingQA: null,
  autoLockTimer: null, autoLockRemaining: AUTO_LOCK_SEC,
  clipboardTimer: null, pwRevealTimers: {},
};

const $ = id => document.getElementById(id);

const els = {
  lockScreen:$("lockScreen"), vaultScreen:$("vaultScreen"),
  lockHint:$("lockHint"), lockMessage:$("lockMessage"),
  unlockForm:$("unlockForm"), accountName:$("accountName"),
  masterPassword:$("masterPassword"), toggleMaster:$("toggleMaster"),
  unlockButton:$("unlockButton"), alertEmailLabel:$("alertEmailLabel"),
  alertEmail:$("alertEmail"), accountLabel:$("accountLabel"),
  themeButton:$("themeButton"), exportButton:$("exportButton"),
  importFile:$("importFile"), lockButton:$("lockButton"),
  searchInput:$("searchInput"), sortSelect:$("sortSelect"),
  entryCount:$("entryCount"), entryList:$("entryList"),
  entryForm:$("entryForm"), emptyState:$("emptyState"),
  formType:$("formType"), formTitle:$("formTitle"), formMeta:$("formMeta"),
  deleteButton:$("deleteButton"), duplicateButton:$("duplicateButton"),
  favoriteButton:$("favoriteButton"),
  titleInput:$("titleInput"), usernameInput:$("usernameInput"),
  urlInput:$("urlInput"), passwordInput:$("passwordInput"),
  passwordFields:$("passwordFields"), notesInput:$("notesInput"),
  saveState:$("saveState"), lengthInput:$("lengthInput"),
  lengthOutput:$("lengthOutput"), symbolsInput:$("symbolsInput"),
  generateButton:$("generateButton"), togglePassword:$("togglePassword"),
  copyPassword:$("copyPassword"), breachCheckButton:$("breachCheckButton"),
  newPasswordButton:$("newPasswordButton"), newNoteButton:$("newNoteButton"),
  strengthMeter:$("strengthMeter"), strengthLabel:$("strengthLabel"),
  sb1:$("sb1"),sb2:$("sb2"),sb3:$("sb3"),sb4:$("sb4"),
  tagRow:$("tagRow"),tagList:$("tagList"),addTagButton:$("addTagButton"),
  tagOverlay:$("tagOverlay"),tagInput:$("tagInput"),
  tagCancel:$("tagCancel"),tagOk:$("tagOk"),
  pwHistoryRow:$("pwHistoryRow"),pwHistoryList:$("pwHistoryList"),
  expiryEnabled:$("expiryEnabled"),expiryDate:$("expiryDate"),
  toastContainer:$("toastContainer"),
  offlineBanner:$("offlineBanner"),
  autoLockTimer:$("autoLockTimer"),autoLockLabel:$("autoLockLabel"),
  confirmOverlay:$("confirmOverlay"),confirmTitle:$("confirmTitle"),
  confirmText:$("confirmText"),confirmCancel:$("confirmCancel"),confirmOk:$("confirmOk"),
  // tabs
  fileUploadInput:$("fileUploadInput"),fileList:$("fileList"),fileEmpty:$("fileEmpty"),
  bookmarkList:$("bookmarkList"),bookmarkEmpty:$("bookmarkEmpty"),newBookmarkButton:$("newBookmarkButton"),
  codeList:$("codeList"),codeEmpty:$("codeEmpty"),newCodeButton:$("newCodeButton"),
  aliasList:$("aliasList"),aliasEmpty:$("aliasEmpty"),newAliasButton:$("newAliasButton"),
  logList:$("logList"),logEmpty:$("logEmpty"),clearLogButton:$("clearLogButton"),
  quickAddOverlay:$("quickAddOverlay"),qaEyebrow:$("qaEyebrow"),
  qaTitle:$("qaTitle"),qaFields:$("qaFields"),qaCancel:$("qaCancel"),qaOk:$("qaOk"),
};

// ── SVG ICONS (static strings — no user data) ──
const SVG = {
  eyeOpen:  `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`,
  lockClosed:`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>`,
  lockOpen:  `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 9.9-1"/></svg>`,
  eyeClosed:`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/><path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/><line x1="1" y1="1" x2="23" y2="23"/></svg>`,
  starFill: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>`,
  starEmpty:`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>`,
  sun: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width:14px;height:14px"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>`,
  moon: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width:14px;height:14px"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>`,
};

// ── SAFE DOM HELPERS ──
// Never call with user-controlled HTML — only with static strings
function setHTML(el, html) { el.innerHTML = html; } // only static SVG/icons
function setText(el, text) { el.textContent = text; }

function el(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "cls") node.className = v;
    else if (k === "text") node.textContent = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v);
  }
  children.forEach(c => c && node.append(c));
  return node;
}

// ── CRYPTO ──
function getStoredVault() {
  try { const r = localStorage.getItem(STORAGE_KEY); return r ? JSON.parse(r) : null; } catch { return null; }
}
function b64(bytes)  { return btoa(String.fromCharCode(...new Uint8Array(bytes))); }
function unb64(s)    { return Uint8Array.from(atob(s), c => c.charCodeAt(0)); }

async function deriveKey(password, salt) {
  const mat = await crypto.subtle.importKey("raw", ENC.encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name:"PBKDF2", salt, iterations:260000, hash:"SHA-256" },
    mat, { name:"AES-GCM", length:256 }, false, ["encrypt","decrypt"]
  );
}
async function encryptVault() {
  const iv  = crypto.getRandomValues(new Uint8Array(12));
  const enc = await crypto.subtle.encrypt({ name:"AES-GCM", iv }, S.key, ENC.encode(JSON.stringify(S.vault)));
  localStorage.setItem(STORAGE_KEY, JSON.stringify({
    version:2, accountName:S.accountName, alertEmail:S.alertEmail,
    salt:b64(S.salt), iv:b64(iv), data:b64(enc),
    updatedAt:new Date().toISOString(),
  }));
}
async function decryptVault(password, stored) {
  const salt = unb64(stored.salt);
  const key  = await deriveKey(password, salt);
  const dec  = await crypto.subtle.decrypt({ name:"AES-GCM", iv:unb64(stored.iv) }, key, unb64(stored.data));
  return { key, salt, vault:JSON.parse(DEC.decode(dec)) };
}

// encrypt a single file buffer
async function encryptBuffer(buf) {
  const iv  = crypto.getRandomValues(new Uint8Array(12));
  const enc = await crypto.subtle.encrypt({ name:"AES-GCM", iv }, S.key, buf);
  return { iv:b64(iv), data:b64(enc) };
}
async function decryptBuffer(ivB64, dataB64) {
  return crypto.subtle.decrypt({ name:"AES-GCM", iv:unb64(ivB64) }, S.key, unb64(dataB64));
}

// ── SHA-1 for HIBP ──
async function sha1hex(str) {
  const buf = await crypto.subtle.digest("SHA-1", ENC.encode(str));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,"0")).join("").toUpperCase();
}

// ── UTILS ──
function uid()   { return crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random()}`; }
function now()   { return new Date().toISOString(); }
function fmtDate(iso) {
  if (!iso) return "";
  return new Date(iso).toLocaleDateString("de-DE", { day:"2-digit", month:"2-digit", year:"numeric", hour:"2-digit", minute:"2-digit" });
}
function fmtSize(bytes) {
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1024*1024) return (bytes/1024).toFixed(1) + " KB";
  return (bytes/(1024*1024)).toFixed(1) + " MB";
}
function activeEntry() { return S.vault.entries.find(e => e.id === S.activeId) || null; }
function filteredEntries() {
  const needle = S.search.trim().toLowerCase();
  return S.vault.entries
    .filter(e => S.filter==="favorite" ? e.favorite : S.filter==="all" ? true : e.type===S.filter)
    .filter(e => !needle || [e.title,e.username,e.url,e.notes,...(e.tags||[])].join(" ").toLowerCase().includes(needle))
    .sort((a,b) => {
      if (S.sort==="alpha")   return (a.title||"").localeCompare(b.title||"","de");
      if (S.sort==="created") return b.createdAt.localeCompare(a.createdAt);
      return b.updatedAt.localeCompare(a.updatedAt);
    });
}

// ── ACTIVITY LOG ──
function getLogs() {
  try { return JSON.parse(localStorage.getItem(LOG_KEY)||"[]"); } catch { return []; }
}
function addLog(action, detail="", level="info") {
  const logs = getLogs();
  logs.unshift({ ts:now(), action, detail, level });
  if (logs.length > 200) logs.splice(200);
  localStorage.setItem(LOG_KEY, JSON.stringify(logs));
  if (S.activeTab === "log") renderLog();
}

// ── ALARM EMAIL (via mailto — no backend needed) ──
function triggerAlarm(reason) {
  if (!S.alertEmail) return;
  const subject = encodeURIComponent("⚠️ Tresor Alarm: " + reason);
  const body    = encodeURIComponent(
    `Alarm-Zeitpunkt: ${new Date().toLocaleString("de-DE")}\nGrund: ${reason}\n\nFalls du das nicht warst, ändere dein Master-Passwort sofort.`
  );
  window.open(`mailto:${S.alertEmail}?subject=${subject}&body=${body}`, "_blank");
}

// ── TOAST ──
function toast(msg, type="info", duration=3000) {
  const icons = {
    success:`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>`,
    error:  `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>`,
    warning:`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`,
    info:   `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`,
  };
  const t = el("div", { cls:`toast toast-${type}` });
  // icons are static SVG strings — safe
  setHTML(t, (icons[type]||"") + "<span></span>");
  setText(t.querySelector("span"), msg); // user-visible text via textContent
  els.toastContainer.append(t);
  requestAnimationFrame(() => t.classList.add("visible"));
  setTimeout(() => { t.classList.remove("visible"); setTimeout(()=>t.remove(),300); }, duration);
}

// ── PASSWORD STRENGTH ──
function pwStrength(pw) {
  if (!pw) return 0;
  let s=0;
  if(pw.length>=10)s++; if(pw.length>=16)s++;
  if(/[A-Z]/.test(pw)&&/[a-z]/.test(pw))s++;
  if(/[0-9]/.test(pw))s++;
  if(/[^A-Za-z0-9]/.test(pw))s++;
  return Math.min(4,Math.round(s*4/5));
}
function updateStrength(pw) {
  if(!pw){els.strengthMeter.style.display="none";return;}
  els.strengthMeter.style.display="";
  const lv=pwStrength(pw);
  const cls=`filled-${lv}`;
  [els.sb1,els.sb2,els.sb3,els.sb4].forEach((b,i)=>{b.className="strength-bar "+(i<lv?cls:"");});
  setText(els.strengthLabel,["","Schwach","Mäßig","Gut","Stark"][lv]||"");
  els.strengthLabel.style.color=lv<=1?"var(--danger)":lv===2?"var(--gold)":"var(--success)";
}

// ── BREACH CHECK ──
async function checkBreach(pw) {
  if (!pw) { toast("Kein Passwort eingegeben.","warning"); return; }
  toast("Prüfe Datenleck…","info",2000);
  try {
    const hash   = await sha1hex(pw);
    const prefix = hash.slice(0,5);
    const suffix = hash.slice(5);
    const res    = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`,{headers:{"Add-Padding":"true"}});
    if (!res.ok) throw new Error();
    const match  = (await res.text()).split("\r\n").find(l=>l.startsWith(suffix));
    if (match) {
      const count = parseInt(match.split(":")[1],10);
      toast(`Dieses Passwort wurde ${count.toLocaleString("de-DE")}× in Datenlecks gefunden!`,"error",7000);
      addLog("Breach-Check","Passwort kompromittiert gefunden","error");
      triggerAlarm("Kompromittiertes Passwort gefunden");
    } else {
      toast("Passwort nicht in Datenlecks gefunden.","success",4000);
      addLog("Breach-Check","Sauber","info");
    }
  } catch { toast("Breach-Check fehlgeschlagen. Online?","warning"); }
}

// ── AUTO-LOCK ──
function resetAutoLock() { S.autoLockRemaining = AUTO_LOCK_SEC; }
function startAutoLock() {
  stopAutoLock(); S.autoLockRemaining = AUTO_LOCK_SEC;
  els.autoLockTimer.classList.remove("hidden");
  S.autoLockTimer = setInterval(()=>{
    S.autoLockRemaining--;
    const m=String(Math.floor(S.autoLockRemaining/60)).padStart(2,"0");
    const s=String(S.autoLockRemaining%60).padStart(2,"0");
    setText(els.autoLockLabel,`${m}:${s}`);
    if(S.autoLockRemaining<=0){ lock(); toast("Tresor automatisch gesperrt.","info"); }
  },1000);
}
function stopAutoLock() { clearInterval(S.autoLockTimer); S.autoLockTimer=null; els.autoLockTimer.classList.add("hidden"); }
["click","keydown","mousemove","touchstart"].forEach(ev=>{
  document.addEventListener(ev,()=>{ if(S.key) resetAutoLock(); },{passive:true});
});

// ── OFFLINE ──
function updateOnline() { els.offlineBanner.classList.toggle("hidden",navigator.onLine); }
window.addEventListener("online",updateOnline);
window.addEventListener("offline",updateOnline);

// ── URL FORMAT ──
function autoFormatUrl(v) {
  if(!v) return v;
  if(/^https?:\/\//i.test(v)) return v;
  if(v.includes(".")) return "https://"+v;
  return v;
}

// ══════════════════════════════════════════════
//  RENDER — VAULT
// ══════════════════════════════════════════════
function renderList() {
  const entries = filteredEntries();
  setText(els.entryCount, String(entries.length));
  els.entryList.innerHTML="";

  if(!entries.length){
    els.entryList.append(el("p",{cls:"message",text:"Keine passenden Einträge."}));
    return;
  }

  const pwMap={};
  entries.forEach(e=>{ if(e.password) pwMap[e.password]=(pwMap[e.password]||0)+1; });

  const sections = S.filter==="all"||S.filter==="favorite"
    ? [{title:"Passwörter",type:"password"},{title:"Notizen",type:"note"}]
    : [{title:S.filter==="password"?"Passwörter":"Notizen",type:S.filter}];

  for(const sec of sections){
    const grp=entries.filter(e=>e.type===sec.type);
    if(!grp.length) continue;
    const wrap=el("section",{cls:"entry-section"});
    wrap.append(el("h4",{text:sec.title}));
    grp.forEach(entry=>wrap.append(makeCard(entry,pwMap)));
    els.entryList.append(wrap);
  }
}

function makeCard(entry, pwMap) {
  const isNote = entry.type==="note";
  const isDup  = entry.password && (pwMap[entry.password]||0)>1;
  const isExp  = entry.expiryDate && new Date(entry.expiryDate)<new Date();

  const card = el("button",{
    cls:`entry-card${entry.id===S.activeId?" active":""} entry-card-new`,
    type:"button",
  });
  card.dataset.id = entry.id;

  // header row
  const header = el("div",{cls:"card-header"});

  // type pill — only static text, no user data
  const pill = el("span",{cls:`type-pill${isNote?" note":""}`});
  // static SVG icon
  setHTML(pill, isNote
    ? `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>`
    : `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>`
  );
  // append static label text
  pill.append(document.createTextNode(isNote?" Notiz":" Passwort"));
  header.append(pill);

  if(entry.favorite) header.append(el("span",{cls:"card-star",text:"★"}));
  if(isDup)  header.append(el("span",{cls:"card-warn",text:"Doppeltes PW"}));
  if(isExp)  header.append(el("span",{cls:"card-warn",text:"Abgelaufen"}));

  const sub = isNote
    ? (entry.notes||"Leere Notiz").slice(0,80)
    : (entry.username||entry.url||"Kein Login hinterlegt");

  card.append(
    header,
    el("strong",{text:entry.title||"Ohne Titel"}),
    el("span",{cls:"card-sub",text:sub}),
    el("span",{cls:"card-date",text:fmtDate(entry.updatedAt)}),
  );

  card.addEventListener("click",()=>selectEntry(entry.id));
  requestAnimationFrame(()=>card.classList.remove("entry-card-new"));
  return card;
}

function renderEditor() {
  const entry = activeEntry();
  if(!entry){
    els.entryForm.classList.add("hidden");
    els.emptyState.classList.remove("hidden");
    return;
  }
  els.emptyState.classList.add("hidden");
  els.entryForm.classList.remove("hidden");
  setText(els.formType, entry.type==="note"?"Notiz":"Passwort");
  setText(els.formTitle, entry.title||"Neuer Eintrag");
  setText(els.formMeta, `Erstellt ${fmtDate(entry.createdAt)} · Bearbeitet ${fmtDate(entry.updatedAt)}`);
  els.passwordFields.classList.toggle("hidden",entry.type==="note");
  els.titleInput.value    = entry.title||"";
  els.usernameInput.value = entry.username||"";
  els.urlInput.value      = entry.url||"";
  els.passwordInput.value = entry.password||"";
  els.notesInput.value    = entry.notes||"";
  setText(els.saveState,"");

  // favorite button — static SVG only
  setHTML(els.favoriteButton, entry.favorite ? SVG.starFill : SVG.starEmpty);
  els.favoriteButton.style.color = entry.favorite?"var(--gold)":"";

  renderTags(entry.tags||[]);

  const hasExp = Boolean(entry.expiryDate);
  els.expiryEnabled.checked = hasExp;
  els.expiryDate.classList.toggle("hidden",!hasExp);
  els.expiryDate.value = entry.expiryDate||"";

  const hist = entry.passwordHistory||[];
  if(hist.length){
    els.pwHistoryRow.classList.remove("hidden");
    els.pwHistoryList.innerHTML="";
    hist.slice().reverse().forEach(pw=>{
      const item = el("span",{cls:"pw-history-item",text:"•".repeat(Math.min(pw.length,12)),title:"Klicken zum Wiederherstellen"});
      item.addEventListener("click",()=>{ els.passwordInput.value=pw; updateStrength(pw); toast("Altes Passwort wiederhergestellt.","info"); });
      els.pwHistoryList.append(item);
    });
  } else { els.pwHistoryRow.classList.add("hidden"); }

  updateStrength(entry.password||"");
}

function renderTags(tags) {
  els.tagList.innerHTML="";
  tags.forEach(tag=>{
    const pill = el("span",{cls:"tag-pill"});
    pill.append(
      document.createTextNode(tag),
      (() => {
        const rm = el("button",{cls:"tag-remove",type:"button",text:"×"});
        rm.dataset.tag = tag;
        rm.addEventListener("click",()=>removeTag(tag));
        return rm;
      })()
    );
    els.tagList.append(pill);
  });
}

function render() { renderList(); renderEditor(); }

function selectEntry(id) {
  S.activeId=id;
  localStorage.setItem(LAST_ID_KEY,id);
  render();
}

function createEntry(type) {
  const entry = { id:uid(), type, title:type==="note"?"Neue Notiz":"Neues Passwort", username:"", url:"", password:"", notes:"", tags:[], favorite:false, passwordHistory:[], expiryDate:"", createdAt:now(), updatedAt:now() };
  S.vault.entries.push(entry);
  S.activeId = entry.id;
  addLog("Erstellt", entry.title);
  saveAndRender("Angelegt.");
}

async function saveAndRender(msg="Gespeichert.") {
  await encryptVault();
  render();
  setText(els.saveState, msg);
  setTimeout(()=>{ if(els.saveState.textContent===msg) setText(els.saveState,""); },1800);
}

function fillFromForm() {
  const entry = activeEntry(); if(!entry) return null;
  const newPw = els.passwordInput.value;
  if(newPw && newPw!==entry.password && entry.password){
    const h = entry.passwordHistory||[];
    h.push(entry.password);
    entry.passwordHistory = h.slice(-3);
  }
  entry.title    = els.titleInput.value.trim()||"Ohne Titel";
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
  const e=activeEntry(); if(!e) return;
  e.tags=(e.tags||[]).filter(t=>t!==tag); e.updatedAt=now(); saveAndRender();
}
function openTagModal() {
  els.tagInput.value="";
  els.tagOverlay.classList.remove("hidden");
  setTimeout(()=>els.tagInput.focus(),50);
  return new Promise(r=>{S.pendingTag=r;});
}
function closeTagModal(v) {
  els.tagOverlay.classList.add("hidden");
  if(S.pendingTag) S.pendingTag(v); S.pendingTag=null;
}
els.tagCancel.addEventListener("click",()=>closeTagModal(null));
els.tagOk.addEventListener("click",()=>closeTagModal(els.tagInput.value.trim()));
els.tagInput.addEventListener("keydown",e=>{if(e.key==="Enter"){e.preventDefault();closeTagModal(els.tagInput.value.trim());}});
els.addTagButton.addEventListener("click",async()=>{
  const tag=await openTagModal(); if(!tag) return;
  const e=activeEntry(); if(!e) return;
  e.tags=[...new Set([...(e.tags||[]),tag])]; e.updatedAt=now(); saveAndRender();
});

// ── GENERATE PW ──
function generatePw(len,symbols) {
  const pool="ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"+(symbols?"!@#$%&*?-_+=":"");
  const bytes=crypto.getRandomValues(new Uint32Array(len));
  return Array.from(bytes,v=>pool[v%pool.length]).join("");
}

// ── EXPORT / IMPORT ──
function download(filename,text) {
  const url=URL.createObjectURL(new Blob([text],{type:"application/json"}));
  const a=el("a",{href:url,download:filename}); a.click(); URL.revokeObjectURL(url);
}

// ══════════════════════════════════════════════
//  FILES TAB
// ══════════════════════════════════════════════
async function handleFileUpload(files) {
  for(const file of files){
    if(file.size > 10*1024*1024){ toast(`${file.name}: max 10 MB.`,"error"); continue; }
    const buf = await file.arrayBuffer();
    const enc = await encryptBuffer(buf);
    S.vault.files = S.vault.files||[];
    S.vault.files.push({ id:uid(), name:file.name, size:file.size, type:file.type, iv:enc.iv, data:enc.data, addedAt:now() });
    addLog("Datei hinzugefügt", file.name);
  }
  await encryptVault();
  renderFiles();
  toast("Datei(en) verschlüsselt gespeichert.","success");
}

async function downloadFile(f) {
  try {
    const buf  = await decryptBuffer(f.iv, f.data);
    const blob = new Blob([buf],{type:f.type||"application/octet-stream"});
    const url  = URL.createObjectURL(blob);
    const a    = el("a",{href:url,download:f.name}); a.click();
    URL.revokeObjectURL(url);
    addLog("Datei heruntergeladen", f.name);
  } catch { toast("Entschlüsselung fehlgeschlagen.","error"); }
}

function renderFiles() {
  const files = S.vault.files||[];
  els.fileEmpty.classList.toggle("hidden", files.length>0);
  els.fileList.innerHTML="";

  const ext2icon = name => {
    const e=(name.split(".").pop()||"").toLowerCase();
    if(["jpg","jpeg","png","gif","webp","svg"].includes(e)) return "🖼";
    if(["pdf"].includes(e)) return "📄";
    if(["mp4","mov","avi","mkv"].includes(e)) return "🎬";
    if(["mp3","wav","ogg","m4a"].includes(e)) return "🎵";
    if(["zip","rar","7z","tar","gz"].includes(e)) return "🗜";
    return "📎";
  };

  files.slice().reverse().forEach(f=>{
    const card = el("div",{cls:"file-card"});
    const icon = el("div",{cls:"file-icon",text:ext2icon(f.name)});
    const info = el("div",{cls:"file-info"});
    info.append(
      el("strong",{text:f.name}),
      el("span",{cls:"file-meta",text:`${fmtSize(f.size)} · ${fmtDate(f.addedAt)}`}),
    );
    const actions = el("div",{cls:"file-actions"});
    const dlBtn = el("button",{cls:"secondary-button compact",text:"⬇ Herunterladen",type:"button"});
    dlBtn.addEventListener("click",()=>downloadFile(f));
    const rmBtn = el("button",{cls:"danger-button compact",text:"Löschen",type:"button"});
    rmBtn.addEventListener("click",async()=>{
      const ok=await openConfirm({title:"Datei löschen?",text:`"${f.name}" wirklich löschen?`});
      if(!ok) return;
      S.vault.files=S.vault.files.filter(x=>x.id!==f.id);
      await encryptVault(); renderFiles();
      addLog("Datei gelöscht",f.name);
      toast("Datei gelöscht.","success");
    });
    actions.append(dlBtn,rmBtn);
    card.append(icon,info,actions);
    els.fileList.append(card);
  });
}

// ══════════════════════════════════════════════
//  QUICK-ADD MODAL (Bookmarks, Codes, Aliases)
// ══════════════════════════════════════════════
function openQA({ eyebrow, title, fields }) {
  setText(els.qaEyebrow, eyebrow);
  setText(els.qaTitle,   title);
  els.qaFields.innerHTML="";
  fields.forEach(f=>{
    const wrap = el("label",{cls:"qa-label"});
    const lbl  = document.createTextNode(f.label);
    const input = el("input",{type:f.type||"text",placeholder:f.placeholder||"",id:"qa_"+f.key,autocomplete:"off"});
    if(f.value) input.value=f.value;
    wrap.append(lbl,input);
    els.qaFields.append(wrap);
    if(f.hint){
      const h=el("p",{cls:"qa-hint",text:f.hint});
      els.qaFields.append(h);
    }
  });
  els.quickAddOverlay.classList.remove("hidden");
  setTimeout(()=>els.qaFields.querySelector("input")?.focus(),50);
  return new Promise(r=>{S.pendingQA=r;});
}
function closeQA(ok) {
  els.quickAddOverlay.classList.add("hidden");
  if(!S.pendingQA) return;
  if(!ok){ S.pendingQA(null); S.pendingQA=null; return; }
  const result={};
  els.qaFields.querySelectorAll("input").forEach(i=>{ result[i.id.replace("qa_","")] = i.value.trim(); });
  S.pendingQA(result); S.pendingQA=null;
}
els.qaCancel.addEventListener("click",()=>closeQA(false));
els.qaOk.addEventListener("click",()=>closeQA(true));

// ══════════════════════════════════════════════
//  BOOKMARKS
// ══════════════════════════════════════════════
function renderBookmarks() {
  const list=S.vault.bookmarks||[];
  els.bookmarkEmpty.classList.toggle("hidden",list.length>0);
  els.bookmarkList.innerHTML="";
  list.slice().reverse().forEach(b=>{
    const row=el("div",{cls:"simple-row"});
    const info=el("div",{cls:"simple-info"});
    info.append(
      el("strong",{text:b.title||b.url}),
      el("span",{cls:"simple-sub",text:b.url}),
      b.note?el("span",{cls:"simple-note",text:b.note}):null,
    );
    const actions=el("div",{cls:"simple-actions"});

    // validate URL before opening to prevent javascript: XSS
    const openBtn=el("button",{cls:"secondary-button compact",text:"Öffnen",type:"button"});
    openBtn.addEventListener("click",()=>{
      try {
        const u=new URL(b.url);
        if(u.protocol==="https:"||u.protocol==="http:") window.open(u.href,"_blank","noopener,noreferrer");
        else toast("Unsichere URL.","error");
      } catch { toast("Ungültige URL.","error"); }
    });

    const copyBtn=el("button",{cls:"ghost-button compact",text:"Kopieren",type:"button"});
    copyBtn.addEventListener("click",()=>{ navigator.clipboard.writeText(b.url); toast("URL kopiert.","success"); });

    const rmBtn=el("button",{cls:"danger-button compact",text:"Löschen",type:"button"});
    rmBtn.addEventListener("click",async()=>{
      const ok=await openConfirm({title:"Lesezeichen löschen?",text:`"${b.title||b.url}" löschen?`});
      if(!ok) return;
      S.vault.bookmarks=S.vault.bookmarks.filter(x=>x.id!==b.id);
      await encryptVault(); renderBookmarks(); addLog("Lesezeichen gelöscht",b.title||b.url);
      toast("Lesezeichen gelöscht.","success");
    });
    actions.append(openBtn,copyBtn,rmBtn);
    row.append(info,actions);
    els.bookmarkList.append(row);
  });
}

els.newBookmarkButton.addEventListener("click",async()=>{
  const r=await openQA({ eyebrow:"Lesezeichen", title:"Neues Lesezeichen", fields:[
    {key:"title",label:"Titel",placeholder:"z. B. Mein geheimes Forum"},
    {key:"url",label:"URL",type:"url",placeholder:"https://..."},
    {key:"note",label:"Notiz (optional)",placeholder:"Wozu benutzt du diese Seite?"},
  ]});
  if(!r||!r.url) return;
  S.vault.bookmarks=S.vault.bookmarks||[];
  S.vault.bookmarks.push({id:uid(),title:r.title,url:autoFormatUrl(r.url),note:r.note,addedAt:now()});
  await encryptVault(); renderBookmarks(); addLog("Lesezeichen hinzugefügt",r.title||r.url);
  toast("Lesezeichen gespeichert.","success");
});

// ══════════════════════════════════════════════
//  CODES
// ══════════════════════════════════════════════
function renderCodes() {
  const list=S.vault.codes||[];
  els.codeEmpty.classList.toggle("hidden",list.length>0);
  els.codeList.innerHTML="";
  list.slice().reverse().forEach(c=>{
    const row=el("div",{cls:"simple-row"});
    const info=el("div",{cls:"simple-info"});

    // code display — masked by default
    const codeSpan=el("span",{cls:"code-value",text:"••••••••"});
    codeSpan.dataset.visible="0";
    codeSpan.dataset.code=c.code; // store in data attr, not injected HTML

    info.append(
      el("strong",{text:c.label}),
      el("span",{cls:"simple-sub",text:c.category||"Sicherheitscode"}),
      codeSpan,
      c.note?el("span",{cls:"simple-note",text:c.note}):null,
    );

    const actions=el("div",{cls:"simple-actions"});
    const showBtn=el("button",{cls:"secondary-button compact",text:"Anzeigen",type:"button"});
    showBtn.addEventListener("click",()=>{
      const vis=codeSpan.dataset.visible==="1";
      codeSpan.textContent = vis ? "••••••••" : codeSpan.dataset.code;
      codeSpan.dataset.visible = vis?"0":"1";
      setText(showBtn, vis?"Anzeigen":"Verstecken");
      if(!vis) setTimeout(()=>{ codeSpan.textContent="••••••••"; codeSpan.dataset.visible="0"; setText(showBtn,"Anzeigen"); },10000);
    });
    const copyBtn=el("button",{cls:"ghost-button compact",text:"Kopieren",type:"button"});
    copyBtn.addEventListener("click",()=>{ navigator.clipboard.writeText(c.code); toast("Code kopiert.","success"); });
    const rmBtn=el("button",{cls:"danger-button compact",text:"Löschen",type:"button"});
    rmBtn.addEventListener("click",async()=>{
      const ok=await openConfirm({title:"Code löschen?",text:`"${c.label}" löschen?`});
      if(!ok) return;
      S.vault.codes=S.vault.codes.filter(x=>x.id!==c.id);
      await encryptVault(); renderCodes(); addLog("Code gelöscht",c.label);
      toast("Code gelöscht.","success");
    });
    actions.append(showBtn,copyBtn,rmBtn);
    row.append(info,actions);
    els.codeList.append(row);
  });
}

els.newCodeButton.addEventListener("click",async()=>{
  const r=await openQA({ eyebrow:"Codes", title:"Neuer Sicherheitscode", fields:[
    {key:"label",label:"Bezeichnung",placeholder:"z. B. Fahrradschloss, Safe-PIN, Alarm"},
    {key:"category",label:"Kategorie",placeholder:"z. B. PIN, Kombination, Code"},
    {key:"code",label:"Code / PIN",placeholder:"z. B. 1234 oder 42-17-8"},
    {key:"note",label:"Notiz (optional)",placeholder:"Wo befindet sich das Schloss?"},
  ]});
  if(!r||!r.code) return;
  S.vault.codes=S.vault.codes||[];
  S.vault.codes.push({id:uid(),label:r.label||"Unbenannt",category:r.category,code:r.code,note:r.note,addedAt:now()});
  await encryptVault(); renderCodes(); addLog("Code hinzugefügt",r.label);
  toast("Code gespeichert.","success");
});

// ══════════════════════════════════════════════
//  ALIASES
// ══════════════════════════════════════════════
function renderAliases() {
  const list=S.vault.aliases||[];
  els.aliasEmpty.classList.toggle("hidden",list.length>0);
  els.aliasList.innerHTML="";
  list.slice().reverse().forEach(a=>{
    const row=el("div",{cls:"simple-row"});
    const info=el("div",{cls:"simple-info"});
    const badge=el("span",{cls:"alias-badge"});
    const statusText = a.active!==false?"Aktiv":"Deaktiviert";
    badge.textContent=statusText;
    badge.className="alias-badge "+(a.active!==false?"active":"inactive");
    info.append(
      el("strong",{text:a.alias}),
      el("span",{cls:"simple-sub",text:`Benutzt bei: ${a.service||"Unbekannt"}`}),
      badge,
      a.note?el("span",{cls:"simple-note",text:a.note}):null,
    );
    const actions=el("div",{cls:"simple-actions"});
    const copyBtn=el("button",{cls:"ghost-button compact",text:"Kopieren",type:"button"});
    copyBtn.addEventListener("click",()=>{ navigator.clipboard.writeText(a.alias); toast("Alias kopiert.","success"); });
    const toggleBtn=el("button",{cls:"secondary-button compact",type:"button"});
    toggleBtn.textContent=a.active!==false?"Deaktivieren":"Aktivieren";
    toggleBtn.addEventListener("click",async()=>{
      a.active=!(a.active!==false);
      await encryptVault(); renderAliases(); addLog("Alias geändert",a.alias);
    });
    const rmBtn=el("button",{cls:"danger-button compact",text:"Löschen",type:"button"});
    rmBtn.addEventListener("click",async()=>{
      const ok=await openConfirm({title:"Alias löschen?",text:`"${a.alias}" löschen?`});
      if(!ok) return;
      S.vault.aliases=S.vault.aliases.filter(x=>x.id!==a.id);
      await encryptVault(); renderAliases(); addLog("Alias gelöscht",a.alias);
      toast("Alias gelöscht.","success");
    });
    actions.append(copyBtn,toggleBtn,rmBtn);
    row.append(info,actions);
    els.aliasList.append(row);
  });
}

els.newAliasButton.addEventListener("click",async()=>{
  const r=await openQA({ eyebrow:"E-Mail Aliase", title:"Neuer Alias", fields:[
    {key:"alias",label:"Alias E-Mail",type:"email",placeholder:"alias@simplelogin.io"},
    {key:"service",label:"Benutzt bei Service",placeholder:"z. B. Reddit, Amazon"},
    {key:"note",label:"Notiz (optional)",placeholder:"Weitere Infos…"},
  ]});
  if(!r||!r.alias) return;
  S.vault.aliases=S.vault.aliases||[];
  S.vault.aliases.push({id:uid(),alias:r.alias,service:r.service,note:r.note,active:true,addedAt:now()});
  await encryptVault(); renderAliases(); addLog("Alias hinzugefügt",r.alias);
  toast("Alias gespeichert.","success");
});

// ══════════════════════════════════════════════
//  LOG TAB
// ══════════════════════════════════════════════
function renderLog() {
  const logs=getLogs();
  els.logEmpty.classList.toggle("hidden",logs.length>0);
  els.logList.innerHTML="";
  const levelIcon={ info:"ℹ️", success:"✅", error:"🚨", warning:"⚠️" };
  logs.forEach(l=>{
    const row=el("div",{cls:`log-row log-${l.level||"info"}`});
    row.append(
      el("span",{cls:"log-icon",text:levelIcon[l.level]||"ℹ️"}),
      el("span",{cls:"log-action",text:l.action}),
      el("span",{cls:"log-detail",text:l.detail}),
      el("span",{cls:"log-ts",text:fmtDate(l.ts)}),
    );
    els.logList.append(row);
  });
}

els.clearLogButton.addEventListener("click",async()=>{
  const ok=await openConfirm({title:"Log leeren?",text:"Alle Aktivitäts-Einträge werden gelöscht."});
  if(!ok) return;
  localStorage.removeItem(LOG_KEY);
  renderLog();
  toast("Log geleert.","success");
});

// ══════════════════════════════════════════════
//  TABS
// ══════════════════════════════════════════════
document.querySelectorAll(".nav-tab").forEach(btn=>{
  btn.addEventListener("click",()=>{
    const tab=btn.dataset.tab;
    document.querySelectorAll(".nav-tab").forEach(b=>b.classList.remove("active"));
    btn.classList.add("active");
    document.querySelectorAll(".tab-content").forEach(t=>t.classList.add("hidden"));
    $("tab"+tab.charAt(0).toUpperCase()+tab.slice(1)).classList.remove("hidden");
    S.activeTab=tab;
    if(tab==="files")     renderFiles();
    if(tab==="bookmarks") renderBookmarks();
    if(tab==="codes")     renderCodes();
    if(tab==="aliases")   renderAliases();
    if(tab==="log")       renderLog();
  });
});

// ══════════════════════════════════════════════
//  LOCK / UNLOCK
// ══════════════════════════════════════════════
function setUnlocked() {
  els.lockScreen.classList.add("hidden");
  els.vaultScreen.classList.remove("hidden");
  setText(els.accountLabel, S.accountName?`Angemeldet als ${S.accountName}`:"");
  els.accountName.value=""; els.masterPassword.value="";
  updateOnline();
  startAutoLock();
  const lastId=localStorage.getItem(LAST_ID_KEY);
  if(lastId && S.vault.entries.find(e=>e.id===lastId)) S.activeId=lastId;
  // ensure sub-lists exist
  ["files","bookmarks","codes","aliases"].forEach(k=>{ if(!S.vault[k]) S.vault[k]=[]; });
  render();
  addLog("Entsperrt",S.accountName,"success");
}

function lock() {
  stopAutoLock(); clearInterval(S.clipboardTimer);
  S.key=null; S.salt=null; S.vault={entries:[],files:[],bookmarks:[],codes:[],aliases:[]};
  S.accountName=""; S.alertEmail=""; S.activeId=null;
  els.vaultScreen.classList.add("hidden");
  els.lockScreen.classList.remove("hidden");
  setText(els.lockMessage,"");
  updateLockCopy();
  els.masterPassword.focus();
}

function updateLockCopy() {
  const stored=getStoredVault(); const has=Boolean(stored);
  setText(els.lockHeading, has ? "Willkommen zurück" : "Tresor erstellen");
  setText(els.lockHint, has
    ? "Gib deinen Account-Namen und dein Master-Passwort ein, um den Tresor zu entsperren."
    : "Erstelle einen Account mit Master-Passwort. Deine Daten bleiben verschlüsselt in diesem Browser.");
  els.accountName.placeholder = stored?.accountName||"z. B. Paul";
  els.alertEmailLabel.classList.toggle("hidden", has);
  setHTML(els.unlockButton, has
    ? `${SVG.lockOpen}<span>Entsperren</span>`
    : `${SVG.lockClosed}<span>Tresor erstellen</span>`);
  // Show QR transfer only if vault exists
  if(els.qrSection) els.qrSection.style.display = has ? "" : "none";
}

// ══════════════════════════════════════════════
//  EVENTS
// ══════════════════════════════════════════════
els.unlockForm.addEventListener("submit", async e=>{
  e.preventDefault();
  const accountName=els.accountName.value.trim();
  const password=els.masterPassword.value;
  setText(els.lockMessage,"Einen Moment…");
  els.unlockButton.disabled=true;
  try {
    if(!accountName){ setText(els.lockMessage,"Bitte gib einen Account-Namen ein."); return; }
    const stored=getStoredVault();
    if(stored){
      if(stored.accountName && stored.accountName.toLowerCase()!==accountName.toLowerCase()){
        setText(els.lockMessage,"Dieser Account-Name passt nicht zu diesem Tresor.");
        addLog("Fehlgeschlagener Login",`Falscher Account-Name: ${accountName}`,"error");
        triggerAlarm("Fehlgeschlagener Login-Versuch");
        return;
      }
      try {
        const r=await decryptVault(password,stored);
        S.key=r.key; S.salt=r.salt; S.vault=r.vault;
        S.accountName=stored.accountName||accountName;
        S.alertEmail=stored.alertEmail||"";
        if(!stored.accountName) await encryptVault();
      } catch {
        setText(els.lockMessage,"Master-Passwort stimmt nicht oder Backup ist beschädigt.");
        addLog("Fehlgeschlagener Login","Falsches Master-Passwort","error");
        triggerAlarm("Fehlgeschlagener Login-Versuch mit falschem Passwort");
        return;
      }
    } else {
      S.salt=crypto.getRandomValues(new Uint8Array(16));
      S.key=await deriveKey(password,S.salt);
      S.vault={entries:[],files:[],bookmarks:[],codes:[],aliases:[]};
      S.accountName=accountName;
      S.alertEmail=els.alertEmail.value.trim();
      await encryptVault();
    }
    setUnlocked();
  } finally { els.unlockButton.disabled=false; }
});

function toggleVis(input,btn) {
  const show=input.type==="password";
  input.type=show?"text":"password";
  setHTML(btn, show?SVG.eyeClosed:SVG.eyeOpen);
  if(show){
    const k=btn.id; clearTimeout(S.pwRevealTimers[k]);
    S.pwRevealTimers[k]=setTimeout(()=>{ input.type="password"; setHTML(btn,SVG.eyeOpen); },10000);
  }
}
els.toggleMaster.addEventListener("click",()=>toggleVis(els.masterPassword,els.toggleMaster));
els.togglePassword.addEventListener("click",()=>toggleVis(els.passwordInput,els.togglePassword));

els.copyPassword.addEventListener("click",async()=>{
  if(!els.passwordInput.value) return;
  await navigator.clipboard.writeText(els.passwordInput.value);
  toast("Passwort kopiert — wird in 30 Sek. gelöscht.","success",3000);
  addLog("Passwort kopiert",activeEntry()?.title||"");
  clearInterval(S.clipboardTimer);
  let rem=30;
  S.clipboardTimer=setInterval(async()=>{ rem--; if(rem<=0){ clearInterval(S.clipboardTimer); try{await navigator.clipboard.writeText("");}catch{} } },1000);
});

els.breachCheckButton.addEventListener("click",()=>checkBreach(els.passwordInput.value));
els.passwordInput.addEventListener("input",()=>updateStrength(els.passwordInput.value));

els.entryForm.addEventListener("submit",async e=>{
  e.preventDefault(); fillFromForm();
  await saveAndRender();
  addLog("Gespeichert",activeEntry()?.title||"");
  toast("Gespeichert.","success");
});

for(const inp of [els.titleInput,els.usernameInput,els.urlInput,els.passwordInput,els.notesInput]){
  inp.addEventListener("change",async()=>{ fillFromForm(); await saveAndRender(); });
}

els.urlInput.addEventListener("blur",()=>{
  const f=autoFormatUrl(els.urlInput.value.trim()); if(f!==els.urlInput.value) els.urlInput.value=f;
});

els.deleteButton.addEventListener("click",async()=>{
  const entry=activeEntry(); if(!entry) return;
  const ok=await openConfirm({title:"Eintrag löschen?",text:`"${entry.title||"Eintrag"}" wirklich löschen?`});
  if(!ok) return;
  const deleted={...entry};
  const idx=S.vault.entries.findIndex(e=>e.id===entry.id);
  S.vault.entries.splice(idx,1);
  S.activeId=S.vault.entries[0]?.id||null;
  await saveAndRender("Gelöscht.");
  addLog("Gelöscht",deleted.title,"warning");

  // undo toast
  const ut=el("div",{cls:"toast toast-warning visible toast-undo"});
  const sp=el("span"); setText(sp,`"${deleted.title}" gelöscht.`);
  const ub=el("button",{cls:"toast-undo-btn",type:"button",text:"Rückgängig"});
  let undone=false;
  ub.addEventListener("click",async()=>{
    undone=true; S.vault.entries.splice(idx,0,deleted); S.activeId=deleted.id;
    await saveAndRender("Wiederhergestellt."); toast("Wiederhergestellt.","success");
    ut.classList.remove("visible"); setTimeout(()=>ut.remove(),300);
    addLog("Wiederhergestellt",deleted.title);
  });
  ut.append(sp,ub); els.toastContainer.append(ut);
  setTimeout(()=>{ if(!undone){ut.classList.remove("visible");setTimeout(()=>ut.remove(),300);} },6000);
});

els.duplicateButton.addEventListener("click",async()=>{
  const entry=activeEntry(); if(!entry) return;
  const copy={...JSON.parse(JSON.stringify(entry)),id:uid(),title:entry.title+" (Kopie)",createdAt:now(),updatedAt:now()};
  S.vault.entries.push(copy); S.activeId=copy.id;
  await saveAndRender("Dupliziert."); addLog("Dupliziert",entry.title); toast("Dupliziert.","success");
});

els.favoriteButton.addEventListener("click",async()=>{
  const entry=activeEntry(); if(!entry) return;
  entry.favorite=!entry.favorite; entry.updatedAt=now(); await saveAndRender();
  setHTML(els.favoriteButton, entry.favorite?SVG.starFill:SVG.starEmpty);
  els.favoriteButton.style.color=entry.favorite?"var(--gold)":"";
  toast(entry.favorite?"Als Favorit markiert.":"Favorit entfernt.","info");
});

els.expiryEnabled.addEventListener("change",()=>{
  els.expiryDate.classList.toggle("hidden",!els.expiryEnabled.checked);
  if(els.expiryEnabled.checked) els.expiryDate.focus();
});

els.newPasswordButton.addEventListener("click",()=>createEntry("password"));
els.newNoteButton.addEventListener("click",()=>createEntry("note"));
document.querySelectorAll("[data-create]").forEach(btn=>btn.addEventListener("click",()=>createEntry(btn.dataset.create)));
document.querySelectorAll(".segment").forEach(btn=>{
  btn.addEventListener("click",()=>{
    document.querySelectorAll(".segment").forEach(s=>s.classList.remove("active"));
    btn.classList.add("active"); S.filter=btn.dataset.filter; renderList();
  });
});

els.searchInput.addEventListener("input",()=>{ S.search=els.searchInput.value; renderList(); });
els.sortSelect.addEventListener("change",()=>{ S.sort=els.sortSelect.value; renderList(); });
els.lengthInput.addEventListener("input",()=>{ setText(els.lengthOutput,els.lengthInput.value); });

els.generateButton.addEventListener("click",()=>{
  const pw=generatePw(Number(els.lengthInput.value),els.symbolsInput.checked);
  els.passwordInput.value=pw; updateStrength(pw); fillFromForm();
  saveAndRender("Generiert."); toast("Passwort generiert.","success");
});

els.exportButton.addEventListener("click",()=>{
  const stored=localStorage.getItem(STORAGE_KEY); if(!stored) return;
  download(`tresor-backup-${new Date().toISOString().slice(0,10)}.json`,stored);
  addLog("Export","Backup erstellt"); toast("Backup exportiert.","success");
});

els.importFile.addEventListener("change",async()=>{
  const file=els.importFile.files[0]; if(!file) return;
  try {
    const parsed=JSON.parse(await file.text());
    if(!parsed.salt||!parsed.iv||!parsed.data) throw new Error();
    localStorage.setItem(STORAGE_KEY,JSON.stringify(parsed));
    toast("Backup importiert. Bitte neu entsperren.","success",4000);
    addLog("Import","Backup importiert");
    lock();
  } catch { toast("Ungültiges Backup.","error"); }
  finally { els.importFile.value=""; }
});

els.lockButton.addEventListener("click",()=>{ addLog("Gesperrt","Manuell","info"); lock(); });

els.fileUploadInput.addEventListener("change",async()=>{
  if(els.fileUploadInput.files.length) await handleFileUpload([...els.fileUploadInput.files]);
  els.fileUploadInput.value="";
});

// ── CONFIRM MODAL ──
function openConfirm({title,text}) {
  setText(els.confirmTitle,title); setText(els.confirmText,text);
  els.confirmOverlay.classList.remove("hidden");
  els.confirmOverlay.setAttribute("aria-hidden","false");
  setTimeout(()=>els.confirmCancel.focus(),50);
  return new Promise(r=>{S.pendingConfirm=r;});
}
function closeConfirm(r) {
  els.confirmOverlay.classList.add("hidden");
  els.confirmOverlay.setAttribute("aria-hidden","true");
  if(S.pendingConfirm) S.pendingConfirm(r); S.pendingConfirm=null;
}
els.confirmCancel.addEventListener("click",()=>closeConfirm(false));
els.confirmOk.addEventListener("click",()=>closeConfirm(true));
els.confirmOverlay.addEventListener("click",e=>{ if(e.target===els.confirmOverlay) closeConfirm(false); });

// ── KEYBOARD SHORTCUTS ──
document.addEventListener("keydown",e=>{
  if(e.key==="Escape"){
    if(S.pendingConfirm) closeConfirm(false);
    if(S.pendingTag)     closeTagModal(null);
    if(S.pendingQA)      closeQA(false);
    return;
  }
  if(!S.key) return;
  const ctrl=e.ctrlKey||e.metaKey;
  if(ctrl&&e.key==="n"){ e.preventDefault(); createEntry("password"); }
  if(ctrl&&e.key==="f"){ e.preventDefault(); els.searchInput.focus(); els.searchInput.select(); }
  if(ctrl&&e.key==="l"){ e.preventDefault(); addLog("Gesperrt","Tastenkürzel"); lock(); }
});

// ── THEME ──
function applyTheme(t) {
  const theme=t==="dark"?"dark":"light";
  document.body.dataset.theme=theme;
  localStorage.setItem(THEME_KEY,theme);
  const d=theme==="dark";
  setHTML(els.themeButton, d?`${SVG.sun}<span>Hell</span>`:`${SVG.moon}<span>Dunkel</span>`);
}
els.themeButton.addEventListener("click",()=>applyTheme(document.body.dataset.theme==="dark"?"light":"dark"));

// ── INIT ──
applyTheme(localStorage.getItem(THEME_KEY)||"dark");
updateLockCopy();
updateOnline();

// ── QR CODE TRANSFER ──
// Uses a tiny inline QR encoder (no external lib needed for small data)
// We encode the encrypted vault JSON as a QR code so user can scan on phone
// The vault is already AES-encrypted — safe to transmit via QR

async function loadQRLib() {
  return new Promise((resolve, reject) => {
    if (window.QRCode) { resolve(); return; }
    const s = document.createElement("script");
    s.src = "https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js";
    s.onload = resolve; s.onerror = reject;
    document.head.append(s);
  });
}

let qrInstance = null;

els.qrToggle && els.qrToggle.addEventListener("click", async () => {
  const box = els.qrBox;
  const isOpen = box.classList.contains("open");
  if (isOpen) { box.classList.remove("open"); return; }

  const stored = localStorage.getItem(STORAGE_KEY);
  if (!stored) { toast("Kein Tresor zum Übertragen.", "warning"); return; }

  // Check size — QR codes can hold ~2-3KB max reliably
  const bytes = new TextEncoder().encode(stored).length;
  if (bytes > 2800) {
    toast("Tresor ist zu groß für QR-Code (" + Math.round(bytes/1024*10)/10 + " KB). Nutze Export stattdessen.", "warning", 6000);
    // Still show export hint
    box.classList.add("open");
    els.qrCanvas.style.display = "none";
    const hint = box.querySelector("p");
    if(hint) setText(hint, "Dein Tresor ist zu groß für einen QR-Code. Nutze stattdessen den Export-Button oben rechts — lade die JSON-Datei dann auf deinem Handy hoch.");
    return;
  }

  els.qrCanvas.style.display = "";
  const hint = box.querySelector("p");
  if(hint) setText(hint, "Scanne diesen QR-Code mit deinem Handy um den verschlüsselten Tresor zu übertragen. Dein Master-Passwort bleibt dabei geheim.");

  try {
    await loadQRLib();
    box.classList.add("open");
    // Clear previous
    els.qrCanvas.innerHTML = "";
    if (qrInstance) { try { qrInstance.clear(); } catch {} }

    qrInstance = new QRCode(els.qrCanvas, {
      text: stored,
      width: 220, height: 220,
      colorDark: "#000000", colorLight: "#ffffff",
      correctLevel: QRCode.CorrectLevel.M,
    });
    addLog("QR-Transfer", "QR-Code generiert");
  } catch(e) {
    toast("QR-Code konnte nicht geladen werden.", "error");
    console.error(e);
  }
});
