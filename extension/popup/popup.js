/**
 * PhishGuard Popup Script
 * Renders scan results, history, and Trust Score from the AI backend
 */

'use strict';

// ── Config ────────────────────────────────────────────────────────────────────
const API_BASE = 'http://127.0.0.1:8000'; // FastAPI backend URL

// ── DOM Refs ─────────────────────────────────────────────────────────────────
const scanPanel     = document.getElementById('scan-panel');
const historyPanel  = document.getElementById('history-panel');
const loadingState  = document.getElementById('loading-state');
const resultState   = document.getElementById('result-state');
const errorState    = document.getElementById('error-state');
const loadingStep   = document.getElementById('loading-step');

const scoreNum      = document.getElementById('score-num');
const ringArc       = document.getElementById('ring-arc');
const riskBadge     = document.getElementById('risk-badge');
const riskIcon      = document.getElementById('risk-icon');
const riskText      = document.getElementById('risk-text');
const urlText       = document.getElementById('url-text');
const urlLockIcon   = document.getElementById('url-lock-icon');
const dnaGrid       = document.getElementById('dna-grid');
const findingsList  = document.getElementById('findings-list');

const refreshBtn    = document.getElementById('refresh-btn');
const settingsBtn   = document.getElementById('settings-btn');
const whitelistBtn  = document.getElementById('whitelist-btn');
const reportBtn     = document.getElementById('report-btn');
const navScan       = document.getElementById('nav-scan');
const navHistory    = document.getElementById('nav-history');
const historyList   = document.getElementById('history-list');
const clearHistory  = document.getElementById('clear-history-btn');

// ── Risk Helpers ──────────────────────────────────────────────────────────────
const RISK = {
  safe:     { label: 'Safe',             icon: '✓', color: '#3fb950' },
  low:      { label: 'Low Risk',         icon: '!', color: '#a8d672' },
  medium:   { label: 'Moderate Risk',    icon: '!!',color: '#d29922' },
  high:     { label: 'High Risk',        icon: '⚠', color: '#f85149' },
  critical: { label: 'PHISHING DETECTED',icon: '☠', color: '#da3633' }
};

function getLevel(score) {
  if (score >= 85) return 'critical';
  if (score >= 65) return 'high';
  if (score >= 40) return 'medium';
  if (score >= 20) return 'low';
  return 'safe';
}

// ── Score Ring ────────────────────────────────────────────────────────────────
function animateRing(trustScore) {
  // trustScore: 0-100 where 100 = SAFE, 0 = definitely phishing
  const circumference = 314; // 2π × 50
  const fraction      = trustScore / 100;
  const offset        = circumference * (1 - fraction);

  const level = getLevel(100 - trustScore); // invert for ring colour
  const color  = RISK[level]?.color || '#3fb950';

  ringArc.style.strokeDashoffset = offset;
  ringArc.style.stroke           = color;
  scoreNum.textContent           = trustScore;
  scoreNum.style.color           = color;
}

// ── Risk Badge ────────────────────────────────────────────────────────────────
function renderRiskBadge(level) {
  const r = RISK[level] || RISK.safe;
  riskBadge.className  = `risk-badge ${level}`;
  riskIcon.textContent = r.icon;
  riskText.textContent = r.label;
}

// ── Threat DNA Grid ───────────────────────────────────────────────────────────
const DNA_AXES = [
  { key: 'url_score',     label: 'URL Risk'    },
  { key: 'nlp_score',     label: 'NLP'         },
  { key: 'visual_score',  label: 'Visual'      },
  { key: 'domain_age',    label: 'Domain Age'  },
  { key: 'ssl_score',     label: 'SSL/TLS'     },
  { key: 'content_score', label: 'Content'     }
];

function renderDNA(dna) {
  dnaGrid.innerHTML = '';
  DNA_AXES.forEach(({ key, label }) => {
    const raw   = dna?.[key] ?? 0;
    const pct   = Math.round(raw * 100);
    const level = getLevel(pct);
    const color = RISK[level]?.color || '#3fb950';

    const item = document.createElement('div');
    item.className = 'dna-item';
    item.innerHTML = `
      <div class="dna-label">${label}</div>
      <div class="dna-bar-track">
        <div class="dna-bar-fill" style="width:${pct}%;background:${color}"></div>
      </div>
      <div class="dna-score" style="color:${color}">${pct}%</div>
    `;
    dnaGrid.appendChild(item);
  });
}

// ── LIME Findings ─────────────────────────────────────────────────────────────
function renderFindings(findings) {
  findingsList.innerHTML = '';
  if (!findings || findings.length === 0) {
    findingsList.innerHTML = '<div class="finding-card safe"><div class="finding-dot"></div><span>No threats detected on this page.</span></div>';
    return;
  }
  findings.slice(0, 8).forEach(f => {
    const card = document.createElement('div');
    card.className = `finding-card ${f.type || 'info'}`;
    card.innerHTML = `<div class="finding-dot"></div><span>${escapeHtml(f.msg)}</span>`;
    findingsList.appendChild(card);
  });
}

// ── URL Bar ───────────────────────────────────────────────────────────────────
function renderURL(url, isHTTPS) {
  urlText.textContent = url.length > 50 ? url.slice(0, 50) + '…' : url;
  urlLockIcon.style.color = isHTTPS ? 'var(--safe)' : 'var(--high)';
}

// ── Main Render ───────────────────────────────────────────────────────────────
function renderResult(result) {
  showState('result');

  const trustScore = result.trust_score ?? (100 - (result.score ?? 0));
  const level      = getLevel(100 - trustScore);

  animateRing(trustScore);
  renderRiskBadge(level);
  renderURL(result.url || '', result.is_https !== false);
  renderDNA(result.threat_dna || result.dna || {});
  renderFindings(result.findings || result.explanations || []);
}

// ── State Switcher ────────────────────────────────────────────────────────────
function showState(state) {
  loadingState.classList.add('hidden');
  resultState.classList.add('hidden');
  errorState.classList.add('hidden');

  if (state === 'loading') loadingState.classList.remove('hidden');
  if (state === 'result')  resultState.classList.remove('hidden');
  if (state === 'error')   errorState.classList.remove('hidden');
}

// ── Load Current Tab ──────────────────────────────────────────────────────────
async function loadCurrentTab() {
  showState('loading');

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.url || tab.url.startsWith('chrome://') || tab.url.startsWith('about:')) {
    document.getElementById('error-msg').textContent = 'This page type cannot be scanned (browser internal page).';
    showState('error');
    return;
  }

  // First check cached result from background worker
  const cached = await getCachedResult(tab.id);
  if (cached) {
    renderResult(cached);
    return;
  }

  // Otherwise request a fresh scan
  loadingStep.textContent = 'Extracting page data…';
  try {
    // Inject content script to extract DOM data
    const [injection] = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func:   extractPageData
    });
    const pageData = injection?.result || {};

    loadingStep.textContent = 'Running NLP + Vision models…';
    const result = await callAnalyzeAPI(tab.url, pageData);
    renderResult(result);

    // Cache in background
    chrome.runtime.sendMessage({ type: 'CACHE_RESULT', tabId: tab.id, result });

  } catch (err) {
    console.error('[PhishGuard] Scan error:', err);
    document.getElementById('error-msg').textContent = 'Backend unreachable. Using local heuristics only.';

    // Fallback: local URL-only analysis
    const fallback = localFallback(tab.url);
    renderResult(fallback);
  }
}

// ── API Call ──────────────────────────────────────────────────────────────────
async function callAnalyzeAPI(url, pageData) {
  const response = await fetch(`${API_BASE}/analyze`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({
      url,
      dom_text:   pageData.bodyText  || '',
      title:      pageData.title     || '',
      forms:      pageData.forms     || [],
      screenshot: pageData.screenshot || null
    }),
    signal: AbortSignal.timeout(8000) // 8s timeout
  });

  if (!response.ok) throw new Error(`API ${response.status}`);
  return response.json();
}

// ── DOM Extraction (runs in page context) ─────────────────────────────────────
function extractPageData() {
  const forms = Array.from(document.querySelectorAll('form')).map(f => ({
    action:   f.action,
    method:   f.method,
    hasPass:  !!f.querySelector('input[type=password]'),
    hasEmail: !!f.querySelector('input[type=email]')
  }));
  return {
    title:    document.title,
    bodyText: (document.body?.innerText || '').slice(0, 4000),
    forms,
    screenshot: null  // screenshot captured separately if needed
  };
}

// ── Local Fallback (no backend) ───────────────────────────────────────────────
function localFallback(url) {
  let score    = 0;
  const findings = [];

  try {
    const u        = new URL(url);
    const hostname = u.hostname;
    const parts    = hostname.split('.');

    if (u.protocol === 'http:') {
      score += 15;
      findings.push({ type: 'warning', msg: 'No HTTPS — connection is unencrypted' });
    }
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
      score += 30;
      findings.push({ type: 'danger', msg: 'IP address used instead of domain name' });
    }
    if (parts.length > 4) {
      score += 15;
      findings.push({ type: 'warning', msg: `Excessive subdomain depth (${parts.length} levels)` });
    }
    if (url.includes('@')) {
      score += 30;
      findings.push({ type: 'danger', msg: 'URL contains @ — real destination is obscured' });
    }
    const suspTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.xyz', '.top', '.zip'];
    for (const tld of suspTLDs) {
      if (hostname.endsWith(tld)) {
        score += 20;
        findings.push({ type: 'warning', msg: `Suspicious top-level domain: ${tld}` });
        break;
      }
    }
    if (score === 0) findings.push({ type: 'safe', msg: 'URL structure appears normal' });
    findings.push({ type: 'info', msg: 'Local analysis only — backend unavailable' });
  } catch {}

  const trust = Math.max(0, 100 - Math.min(score, 100));
  return {
    url, trust_score: trust,
    is_https: url.startsWith('https://'),
    findings,
    threat_dna: { url_score: score/100, nlp_score: 0, visual_score: 0, domain_age: 0, ssl_score: score < 15 ? 0.1 : 0, content_score: 0 }
  };
}

// ── History ───────────────────────────────────────────────────────────────────
async function loadHistory() {
  const { history = [] } = await chrome.storage.local.get(['history']);
  historyList.innerHTML = '';

  if (history.length === 0) {
    historyList.innerHTML = '<p style="color:var(--text2);font-size:12px;text-align:center;padding:24px 0">No history yet</p>';
    return;
  }

  history.slice(0, 50).forEach(item => {
    const level = getLevel(100 - (item.trust_score ?? 50));
    const color = RISK[level]?.color || '#8b949e';
    let domain  = item.url;
    try { domain = new URL(item.url).hostname; } catch {}

    const el = document.createElement('div');
    el.className = 'history-item';
    el.innerHTML = `
      <div class="history-dot" style="background:${color}"></div>
      <div class="history-info">
        <div class="history-domain">${escapeHtml(domain)}</div>
        <div class="history-time">${timeAgo(item.timestamp)}</div>
      </div>
      <div class="history-score" style="background:${color}22;color:${color}">${item.trust_score ?? '?'}</div>
    `;
    historyList.appendChild(el);
  });
}

// ── Background comms ──────────────────────────────────────────────────────────
function getCachedResult(tabId) {
  return new Promise(resolve => {
    chrome.runtime.sendMessage({ type: 'GET_RESULT', tabId }, resp => {
      resolve(resp?.result || null);
    });
  });
}

// ── Nav ───────────────────────────────────────────────────────────────────────
function showPanel(name) {
  scanPanel.classList.toggle('hidden', name !== 'scan');
  historyPanel.classList.toggle('hidden', name !== 'history');
  navScan.classList.toggle('active', name === 'scan');
  navHistory.classList.toggle('active', name === 'history');
  if (name === 'history') loadHistory();
}

// ── Listeners ─────────────────────────────────────────────────────────────────
navScan.addEventListener('click',    () => showPanel('scan'));
navHistory.addEventListener('click', () => showPanel('history'));
refreshBtn.addEventListener('click', () => loadCurrentTab());
settingsBtn.addEventListener('click', () => chrome.runtime.openOptionsPage());

clearHistory.addEventListener('click', () => {
  chrome.storage.local.set({ history: [] }, loadHistory);
});

whitelistBtn.addEventListener('click', async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.url) return;
  try {
    const domain = new URL(tab.url).hostname;
    chrome.runtime.sendMessage({ type: 'ADD_WHITELIST', domain });
    riskBadge.className = 'risk-badge safe';
    riskText.textContent = 'Whitelisted';
  } catch {}
});

reportBtn.addEventListener('click', async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.url) return;
  chrome.runtime.sendMessage({ type: 'REPORT_PHISHING', url: tab.url });
  reportBtn.textContent = 'Reported ✓';
  reportBtn.disabled = true;
});

// Listen for live updates from background
chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type === 'SCAN_UPDATED') {
    const result = msg.result;
    if (result?.trust_score !== undefined) renderResult(result);
  }
});

// ── Helpers ───────────────────────────────────────────────────────────────────
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function timeAgo(ts) {
  const diff = Date.now() - ts;
  if (diff < 60000)  return 'Just now';
  if (diff < 3600000) return `${Math.floor(diff/60000)}m ago`;
  if (diff < 86400000) return `${Math.floor(diff/3600000)}h ago`;
  return `${Math.floor(diff/86400000)}d ago`;
}

// ── Boot ──────────────────────────────────────────────────────────────────────
loadCurrentTab();
