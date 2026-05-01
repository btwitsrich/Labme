/**
 * PhishGuard Content Script
 * Runs in page context — extracts DOM data and injects warning banners
 */

(function () {
  'use strict';
  if (window.__phishguard_v2) return;
  window.__phishguard_v2 = true;

  // ── Extract Page Data ────────────────────────────────────────────────────────
  function extractData() {
    // Visible text via TreeWalker (mirrors PhishGuard paper methodology)
    const walker = document.createTreeWalker(
      document.body || document.documentElement,
      NodeFilter.SHOW_TEXT,
      {
        acceptNode(node) {
          const parent = node.parentElement;
          if (!parent) return NodeFilter.FILTER_REJECT;
          const style = getComputedStyle(parent);
          if (style.display === 'none' || style.visibility === 'hidden') return NodeFilter.FILTER_REJECT;
          const tag = parent.tagName?.toLowerCase();
          if (['script', 'style', 'noscript'].includes(tag)) return NodeFilter.FILTER_REJECT;
          return NodeFilter.FILTER_ACCEPT;
        }
      }
    );

    let text = '';
    let node;
    while ((node = walker.nextNode()) && text.length < 4000) {
      text += node.textContent.trim() + ' ';
    }

    const forms = Array.from(document.querySelectorAll('form')).map(f => ({
      action:       f.action || '',
      method:       (f.method || 'get').toLowerCase(),
      hasPassword:  !!f.querySelector('input[type="password"]'),
      hasEmail:     !!f.querySelector('input[type="email"]'),
      fieldCount:   f.querySelectorAll('input, select, textarea').length
    }));

    const links = Array.from(document.querySelectorAll('a[href]'))
      .map(a => { try { return new URL(a.href).hostname; } catch { return ''; } })
      .filter(Boolean);

    const srcDoc = (document.documentElement.outerHTML || '').slice(0, 30000);
    const disabledContextMenu   = /contextmenu.*?return\s+false/i.test(srcDoc);
    const disabledTextSelection = /user-select\s*:\s*none/i.test(srcDoc) || /selectstart/i.test(srcDoc);

    return {
      url:   window.location.href,
      title: document.title,
      bodyText: text.trim().slice(0, 4000),
      forms,
      externalLinks: links,
      disabledContextMenu,
      disabledTextSelection,
      hasIframe: document.querySelectorAll('iframe').length > 0,
      metaRefresh: !!document.querySelector('meta[http-equiv="refresh"]')
    };
  }

  // ── Local Content Heuristics ─────────────────────────────────────────────────
  const URGENT = [
    'account suspended','verify now','act immediately','your account has been',
    'confirm your identity','unusual activity','limited time','click here to verify',
    'enter your password','security alert','fraud alert','unauthorized access',
    'you have won','claim your prize','account locked','immediate action required'
  ];
  const BRANDS = [
    'paypal','amazon','apple','google','microsoft','netflix',
    'facebook','instagram','twitter','linkedin','dropbox',
    'chase','wellsfargo','bankofamerica','citibank','hsbc'
  ];

  function scoreContent(data) {
    let score = 0;
    const findings = [];
    const text      = (data.bodyText || '').toLowerCase();
    const title     = (data.title    || '').toLowerCase();
    const url       = data.url       || '';

    // Urgency language
    let hits = URGENT.filter(p => text.includes(p) || title.includes(p)).length;
    if (hits > 0) {
      score += Math.min(hits * 8, 30);
      findings.push({ type: 'warning', msg: `${hits} urgency phrase(s) detected` });
    }

    // Password on HTTP
    const hasPwd  = data.forms.some(f => f.hasPassword);
    const isHTTPS = url.startsWith('https://');
    if (hasPwd && !isHTTPS) {
      score += 40;
      findings.push({ type: 'danger', msg: 'Password field on unencrypted (HTTP) page' });
    }

    // Cross-domain form submission
    let pageHost = '';
    try { pageHost = new URL(url).hostname; } catch {}
    for (const f of data.forms) {
      if (!f.action) continue;
      try {
        const formHost = new URL(f.action).hostname;
        if (formHost && formHost !== pageHost) {
          score += 30;
          findings.push({ type: 'danger', msg: `Form submits to external domain: ${formHost}` });
        }
      } catch {}
    }

    // Brand impersonation
    for (const b of BRANDS) {
      if ((title.includes(b) || text.slice(0, 600).includes(b)) && !pageHost.includes(b)) {
        score += 25;
        findings.push({ type: 'danger', msg: `Page references "${b}" but domain doesn't match` });
        break;
      }
    }

    // Evasion techniques
    if (data.disabledContextMenu || data.disabledTextSelection) {
      score += 15;
      findings.push({ type: 'warning', msg: 'Page disables right-click or text selection' });
    }
    if (data.metaRefresh) {
      score += 15;
      findings.push({ type: 'warning', msg: 'Meta-refresh redirect detected' });
    }

    // Sparse content + form
    if (text.trim().length < 120 && data.forms.length > 0) {
      score += 20;
      findings.push({ type: 'warning', msg: 'Minimal page content with credential form' });
    }

    return { score: Math.min(score, 100), findings };
  }

  // ── Warning Banner ───────────────────────────────────────────────────────────
  function injectBanner(level, score) {
    if (document.getElementById('__pg_banner__')) return;

    const cfg = {
      high:     { bg: '#1a0b0b', border: '#f85149', text: '#fca5a1', label: '⚠ HIGH RISK SITE' },
      critical: { bg: '#130505', border: '#da3633', text: '#fecaca', label: '☠ PHISHING DETECTED' }
    }[level] || cfg.high;

    const banner = document.createElement('div');
    banner.id    = '__pg_banner__';
    Object.assign(banner.style, {
      position:       'fixed',
      top:            '0', left: '0', right: '0',
      zIndex:         '2147483647',
      background:     cfg.bg,
      borderBottom:   `2px solid ${cfg.border}`,
      color:          cfg.text,
      padding:        '10px 16px',
      fontFamily:     'system-ui, -apple-system, sans-serif',
      fontSize:       '13px',
      fontWeight:     '500',
      display:        'flex',
      alignItems:     'center',
      justifyContent: 'space-between',
      gap:            '12px',
      boxShadow:      '0 4px 20px rgba(0,0,0,0.6)'
    });

    banner.innerHTML = `
      <div style="display:flex;align-items:center;gap:10px;flex:1">
        <span style="font-size:20px;flex-shrink:0">🛡</span>
        <div>
          <strong style="display:block;margin-bottom:1px">${cfg.label}</strong>
          <span style="opacity:.85;font-size:12px">
            PhishGuard AI detected threats on this page (risk score: ${100 - score}/100).
            ${level === 'critical' ? 'Do NOT enter passwords or personal information.' : 'Exercise extreme caution.'}
          </span>
        </div>
      </div>
      <button id="__pg_dismiss__" style="
        background:transparent;border:1px solid ${cfg.border};color:${cfg.text};
        padding:4px 12px;border-radius:5px;cursor:pointer;font-size:11px;white-space:nowrap;
        font-weight:600;font-family:inherit;
      ">Dismiss</button>
    `;

    document.body.prepend(banner);
    document.getElementById('__pg_dismiss__')?.addEventListener('click', () => {
      banner.remove();
      document.body.style.marginTop = '';
    });

    // Push content down to avoid overlap
    const h = banner.getBoundingClientRect().height;
    document.body.style.marginTop = h + 'px';
  }

  // ── Main ─────────────────────────────────────────────────────────────────────
  function run() {
    const data   = extractData();
    const result = scoreContent(data);

    // Report to background worker
    chrome.runtime.sendMessage({
      type:            'CONTENT_SCAN_RESULT',
      contentScore:    result.score,
      contentFindings: result.findings
    }).catch(() => {});

    // Banner injection threshold
    if (result.score >= 55) {
      const level = result.score >= 75 ? 'critical' : 'high';
      injectBanner(level, result.score);
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', run);
  } else {
    run();
  }
})();
