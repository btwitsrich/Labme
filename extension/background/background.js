/**
 * PhishGuard Background Service Worker (Manifest V3)
 * Orchestrates scanning, caches results, manages badge + notifications
 */

'use strict';

const API_BASE = 'http://127.0.0.1:8000';
const tabCache = new Map(); // tabId → result

// ── Navigation Listener ───────────────────────────────────────────────────────
chrome.webNavigation.onCommitted.addListener(async (details) => {
  if (details.frameId !== 0) return;
  const { tabId, url } = details;
  if (isSkippableURL(url)) return;

  setBadge(tabId, 'scanning');
  await runScan(tabId, url);
}, { url: [{ schemes: ['http', 'https'] }] });

// ── Message Router ────────────────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {

  if (msg.type === 'GET_RESULT') {
    sendResponse({ result: tabCache.get(msg.tabId) || null });
    return false;
  }

  if (msg.type === 'CACHE_RESULT') {
    tabCache.set(msg.tabId, msg.result);
    if (msg.result) applyResult(msg.tabId, msg.result);
    sendResponse({ ok: true });
    return false;
  }

  if (msg.type === 'CONTENT_SCAN_RESULT') {
    handleContentResult(sender.tab?.id, msg);
    sendResponse({ ok: true });
    return false;
  }

  if (msg.type === 'ADD_WHITELIST') {
    addToWhitelist(msg.domain);
    sendResponse({ ok: true });
    return false;
  }

  if (msg.type === 'REPORT_PHISHING') {
    submitReport(msg.url);
    sendResponse({ ok: true });
    return false;
  }

  if (msg.type === 'GET_HISTORY') {
    chrome.storage.local.get(['history'], data => {
      sendResponse({ history: data.history || [] });
    });
    return true; // async
  }

  if (msg.type === 'GET_SETTINGS') {
    chrome.storage.local.get(['settings'], data => {
      sendResponse({ settings: data.settings || defaultSettings() });
    });
    return true;
  }
});

// ── Core Scan ─────────────────────────────────────────────────────────────────
async function runScan(tabId, url) {
  const settings = await getSettings();

  // Whitelist check
  try {
    const hostname = new URL(url).hostname;
    if (settings.whitelist.some(w => hostname === w || hostname.endsWith('.' + w))) {
      const r = whitelistedResult(url);
      tabCache.set(tabId, r);
      setBadge(tabId, 'safe');
      return;
    }
  } catch {}

  try {
    const response = await fetch(`${API_BASE}/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, dom_text: '', title: '', forms: [], screenshot: null }),
      signal: AbortSignal.timeout(10000)
    });

    if (response.ok) {
      const result = await response.json();
      result.url = url;
      tabCache.set(tabId, result);
      applyResult(tabId, result);
    } else {
      throw new Error('API error');
    }
  } catch {
    // Fallback to local heuristics
    const fallback = localURLScan(url);
    tabCache.set(tabId, fallback);
    applyResult(tabId, fallback);
  }
}

// ── Content Script Result ─────────────────────────────────────────────────────
function handleContentResult(tabId, msg) {
  if (!tabId) return;
  const existing = tabCache.get(tabId);
  if (!existing) return;

  // Merge content score into cached result
  const contentScore = msg.contentScore || 0;
  const merged = {
    ...existing,
    trust_score: Math.round(Math.max(0, (existing.trust_score || 100) - contentScore * 0.4)),
    findings: [...(existing.findings || []), ...(msg.contentFindings || [])]
  };

  tabCache.set(tabId, merged);
  applyResult(tabId, merged);
  saveHistory(merged);

  // Broadcast to any open popup
  chrome.runtime.sendMessage({ type: 'SCAN_UPDATED', tabId, result: merged }).catch(() => {});
}

// ── Apply Result (badge + warning) ───────────────────────────────────────────
async function applyResult(tabId, result) {
  const trust = result.trust_score ?? 50;
  const level = getLevel(100 - trust);

  setBadge(tabId, level);
  saveHistory(result);

  const settings = await getSettings();

  // Show Chrome notification for high/critical
  if (settings.notifications && (level === 'high' || level === 'critical')) {
    showNotification(level, result.url);
  }

  // Redirect to warning page for critical
  if (settings.blockCritical && level === 'critical') {
    const warningURL = chrome.runtime.getURL('warning/warning.html') +
      `?url=${encodeURIComponent(result.url)}&score=${trust}`;
    chrome.tabs.update(tabId, { url: warningURL });
  }
}

// ── Badge ─────────────────────────────────────────────────────────────────────
const BADGE_COLORS = {
  scanning: '#58a6ff',
  safe:     '#3fb950',
  low:      '#a8d672',
  medium:   '#d29922',
  high:     '#f85149',
  critical: '#da3633'
};
const BADGE_TEXTS = {
  scanning: '…',
  safe:     '',
  low:      '!',
  medium:   '!!',
  high:     '!!!',
  critical: '⚠'
};

function setBadge(tabId, level) {
  chrome.action.setBadgeBackgroundColor({ color: BADGE_COLORS[level] || '#8b949e', tabId });
  chrome.action.setBadgeText({ text: BADGE_TEXTS[level] ?? '?', tabId });
}

// ── Notification ──────────────────────────────────────────────────────────────
function showNotification(level, url) {
  let domain = url;
  try { domain = new URL(url).hostname; } catch {}

  chrome.notifications.create(`pg-${Date.now()}`, {
    type: 'basic',
    iconUrl: chrome.runtime.getURL('icons/icon48.png'),
    title: level === 'critical' ? '⚠ PhishGuard: Phishing Detected!' : '⚠ PhishGuard: High Risk',
    message: `${domain} — ${level === 'critical' ? 'DO NOT enter any credentials!' : 'Proceed with caution.'}`,
    priority: 2
  });
}

// ── History ───────────────────────────────────────────────────────────────────
async function saveHistory(result) {
  const settings = await getSettings();
  if (!settings.saveHistory) return;

  const { history = [] } = await chrome.storage.local.get(['history']);
  const entry = {
    url:         result.url || '',
    trust_score: result.trust_score ?? 50,
    timestamp:   Date.now()
  };
  const deduped = history.filter(h => h.url !== entry.url);
  chrome.storage.local.set({ history: [entry, ...deduped].slice(0, 100) });
}

// ── Whitelist ─────────────────────────────────────────────────────────────────
async function addToWhitelist(domain) {
  const s = await getSettings();
  if (!s.whitelist.includes(domain)) s.whitelist.push(domain);
  chrome.storage.local.set({ settings: s });
}

// ── Report Phishing ───────────────────────────────────────────────────────────
async function submitReport(url) {
  try {
    await fetch(`${API_BASE}/report`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, reporter: 'extension', timestamp: Date.now() })
    });
  } catch {}
}

// ── Local URL Heuristics ──────────────────────────────────────────────────────
function localURLScan(url) {
  let risk = 0;
  const findings = [];
  try {
    const u = new URL(url);
    if (u.protocol === 'http:') { risk += 15; findings.push({ type: 'warning', msg: 'No HTTPS' }); }
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(u.hostname)) { risk += 30; findings.push({ type: 'danger', msg: 'IP address as domain' }); }
    if (u.hostname.split('.').length > 4) { risk += 15; findings.push({ type: 'warning', msg: 'Excessive subdomains' }); }
    if (url.includes('@')) { risk += 30; findings.push({ type: 'danger', msg: 'URL contains @ symbol' }); }
    for (const tld of ['.tk','.ml','.ga','.cf','.gq','.pw','.xyz','.zip']) {
      if (u.hostname.endsWith(tld)) { risk += 20; findings.push({ type: 'warning', msg: `Suspicious TLD: ${tld}` }); break; }
    }
    if (findings.length === 0) findings.push({ type: 'safe', msg: 'URL appears normal (local check only)' });
  } catch { findings.push({ type: 'info', msg: 'Could not parse URL' }); }

  return {
    url,
    trust_score: Math.max(0, 100 - Math.min(risk, 100)),
    is_https: url.startsWith('https://'),
    findings,
    threat_dna: { url_score: risk/100, nlp_score: 0, visual_score: 0, domain_age: 0, ssl_score: 0, content_score: 0 }
  };
}

// ── Whitelisted Result ────────────────────────────────────────────────────────
function whitelistedResult(url) {
  return {
    url, trust_score: 100, is_https: url.startsWith('https://'),
    findings: [{ type: 'safe', msg: 'Domain is in your whitelist' }],
    threat_dna: { url_score: 0, nlp_score: 0, visual_score: 0, domain_age: 0, ssl_score: 0, content_score: 0 }
  };
}

// ── Settings ──────────────────────────────────────────────────────────────────
async function getSettings() {
  const { settings } = await chrome.storage.local.get(['settings']);
  return settings || defaultSettings();
}

function defaultSettings() {
  return {
    notifications:   true,
    saveHistory:     true,
    blockCritical:   false,
    sensitivityLevel: 'medium',
    whitelist:       []
  };
}

function getLevel(riskScore) {
  if (riskScore >= 85) return 'critical';
  if (riskScore >= 65) return 'high';
  if (riskScore >= 40) return 'medium';
  if (riskScore >= 20) return 'low';
  return 'safe';
}

function isSkippableURL(url) {
  return !url || url.startsWith('chrome://') || url.startsWith('chrome-extension://') ||
         url.startsWith('about:') || url.startsWith('data:') || url.startsWith('blob:');
}

// ── Tab Cleanup ───────────────────────────────────────────────────────────────
chrome.tabs.onRemoved.addListener(tabId => tabCache.delete(tabId));
