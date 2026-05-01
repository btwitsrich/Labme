'use strict';

// ── DOM Refs ──────────────────────────────────────────────────────────────────
const autoScan       = document.getElementById('auto-scan');
const blockCritical  = document.getElementById('block-critical');
const sensitivity    = document.getElementById('sensitivity');
const apiURL         = document.getElementById('api-url');
const notifications  = document.getElementById('notifications');
const saveHistory    = document.getElementById('save-history');
const wlInput        = document.getElementById('wl-input');
const wlAddBtn       = document.getElementById('wl-add-btn');
const wlTags         = document.getElementById('whitelist-tags');
const historyContainer = document.getElementById('history-container');
const clearHistoryBtn  = document.getElementById('clear-history-btn');
const saveBanner       = document.getElementById('save-banner');
const backendStatus    = document.getElementById('backend-status');

// ── Settings Load/Save ────────────────────────────────────────────────────────
function defaultSettings() {
  return {
    autoScan:        true,
    blockCritical:   false,
    sensitivityLevel:'medium',
    apiURL:          'http://127.0.0.1:8000',
    notifications:   true,
    saveHistory:     true,
    whitelist:       []
  };
}

async function loadSettings() {
  const { settings = defaultSettings() } = await chrome.storage.local.get(['settings']);
  autoScan.checked      = settings.autoScan     !== false;
  blockCritical.checked = settings.blockCritical === true;
  sensitivity.value     = settings.sensitivityLevel || 'medium';
  apiURL.value          = settings.apiURL  || 'http://127.0.0.1:8000';
  notifications.checked = settings.notifications !== false;
  saveHistory.checked   = settings.saveHistory   !== false;
  renderWhitelist(settings.whitelist || []);
}

async function saveSettings() {
  const { settings = defaultSettings() } = await chrome.storage.local.get(['settings']);
  const updated = {
    ...settings,
    autoScan:        autoScan.checked,
    blockCritical:   blockCritical.checked,
    sensitivityLevel: sensitivity.value,
    apiURL:          apiURL.value.trim(),
    notifications:   notifications.checked,
    saveHistory:     saveHistory.checked
  };
  await chrome.storage.local.set({ settings: updated });
  flashSaved();
}

function flashSaved() {
  saveBanner.classList.add('show');
  setTimeout(() => saveBanner.classList.remove('show'), 2200);
}

// ── Whitelist ─────────────────────────────────────────────────────────────────
function renderWhitelist(list) {
  wlTags.innerHTML = '';
  if (!list || list.length === 0) {
    wlTags.innerHTML = '<span class="wl-empty">No trusted domains yet</span>';
    return;
  }
  list.forEach(domain => {
    const tag = document.createElement('div');
    tag.className = 'wl-tag';
    tag.innerHTML = `<span>${escapeHtml(domain)}</span>
      <button class="wl-remove" title="Remove">×</button>`;
    tag.querySelector('.wl-remove').addEventListener('click', () => removeDomain(domain));
    wlTags.appendChild(tag);
  });
}

async function addDomain() {
  const val = wlInput.value.trim().toLowerCase()
    .replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  if (!val || !val.includes('.')) return;

  const { settings = defaultSettings() } = await chrome.storage.local.get(['settings']);
  if (!settings.whitelist.includes(val)) {
    settings.whitelist.push(val);
    await chrome.storage.local.set({ settings });
    renderWhitelist(settings.whitelist);
    flashSaved();
  }
  wlInput.value = '';
}

async function removeDomain(domain) {
  const { settings = defaultSettings() } = await chrome.storage.local.get(['settings']);
  settings.whitelist = settings.whitelist.filter(d => d !== domain);
  await chrome.storage.local.set({ settings });
  renderWhitelist(settings.whitelist);
  flashSaved();
}

// ── History Table ─────────────────────────────────────────────────────────────
function getLevel(trust) {
  if (trust >= 80) return { name: 'Safe',     color: '#3fb950' };
  if (trust >= 60) return { name: 'Low',      color: '#a8d672' };
  if (trust >= 40) return { name: 'Medium',   color: '#d29922' };
  if (trust >= 20) return { name: 'High',     color: '#f85149' };
  return              { name: 'Critical', color: '#da3633' };
}

async function loadHistory() {
  const { history = [] } = await chrome.storage.local.get(['history']);
  if (history.length === 0) {
    historyContainer.innerHTML = '<div class="history-empty">No scan history yet</div>';
    return;
  }

  const table = document.createElement('table');
  table.className = 'history-table';
  table.innerHTML = `<thead><tr>
    <th>Domain</th><th>Trust Score</th><th>Risk Level</th><th>Time</th>
  </tr></thead>`;

  const tbody = document.createElement('tbody');
  history.slice(0, 50).forEach(item => {
    const trust = item.trust_score ?? 50;
    const level = getLevel(trust);
    let domain  = item.url;
    try { domain = new URL(item.url).hostname; } catch {}

    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td style="max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"
          title="${escapeHtml(item.url)}">${escapeHtml(domain)}</td>
      <td><span class="score-pill" style="background:${level.color}22;color:${level.color}">${trust}/100</span></td>
      <td style="color:${level.color};font-weight:500">${level.name}</td>
      <td style="color:var(--text1)">${timeAgo(item.timestamp)}</td>
    `;
    tbody.appendChild(tr);
  });

  table.appendChild(tbody);
  historyContainer.innerHTML = '';
  historyContainer.appendChild(table);
}

async function clearHistory() {
  await chrome.storage.local.set({ history: [] });
  loadHistory();
  flashSaved();
}

// ── Backend Status Check ──────────────────────────────────────────────────────
async function checkBackend() {
  const { settings = defaultSettings() } = await chrome.storage.local.get(['settings']);
  const base = settings.apiURL || 'http://127.0.0.1:8000';
  try {
    const res = await fetch(`${base}/health`, { signal: AbortSignal.timeout(3000) });
    const ok  = res.ok;
    backendStatus.innerHTML = `<span class="status-dot" style="background:${ok ? '#3fb950' : '#f85149'}"></span>${ok ? 'Online' : 'Error'}`;
  } catch {
    backendStatus.innerHTML = '<span class="status-dot" style="background:#f85149"></span>Offline';
  }
}

// ── Listeners ─────────────────────────────────────────────────────────────────
wlAddBtn.addEventListener('click', addDomain);
wlInput.addEventListener('keydown', e => { if (e.key === 'Enter') addDomain(); });
clearHistoryBtn.addEventListener('click', clearHistory);

[autoScan, blockCritical, notifications, saveHistory].forEach(el => {
  el.addEventListener('change', saveSettings);
});
[sensitivity, apiURL].forEach(el => {
  el.addEventListener('change', saveSettings);
});

// ── Helpers ───────────────────────────────────────────────────────────────────
function escapeHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function timeAgo(ts) {
  const d = Date.now() - ts;
  if (d < 60000)    return 'Just now';
  if (d < 3600000)  return `${Math.floor(d/60000)}m ago`;
  if (d < 86400000) return `${Math.floor(d/3600000)}h ago`;
  return new Date(ts).toLocaleDateString();
}

// ── Init ──────────────────────────────────────────────────────────────────────
loadSettings();
loadHistory();
checkBackend();
