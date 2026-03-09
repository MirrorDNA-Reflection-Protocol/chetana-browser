// Chetana Browser v6 — Content Script
// Extracts page signals, renders trust overlay, guards forms

(function() {
  'use strict';

  // Prevent double-injection
  if (window.__chetanaInjected) return;
  window.__chetanaInjected = true;

  // --- Signal Extraction ---

  function extractSignals() {
    const forms = document.querySelectorAll('form');
    const inputs = document.querySelectorAll('input');
    const links = document.querySelectorAll('a[href]');

    let hasPassword = false;
    let hasEmail = false;
    let hasCreditCard = false;
    let hasLoginForm = false;
    let hasPaymentForm = false;
    const formActionHosts = [];

    inputs.forEach(input => {
      const type = (input.type || '').toLowerCase();
      const name = (input.name || '').toLowerCase();
      const autocomplete = (input.autocomplete || '').toLowerCase();

      if (type === 'password') hasPassword = true;
      if (type === 'email' || name.includes('email') || autocomplete === 'email') hasEmail = true;
      if (autocomplete.includes('cc-number') || name.includes('card') || name.includes('credit'))
        hasCreditCard = true;
    });

    forms.forEach(form => {
      const action = form.action || '';
      if (action && action.startsWith('http')) {
        try {
          const actionHost = new URL(action).hostname;
          const pageHost = window.location.hostname;
          if (actionHost !== pageHost) {
            formActionHosts.push(actionHost);
          }
        } catch {}
      }

      const formText = form.textContent.toLowerCase();
      const formInputs = form.querySelectorAll('input');
      let formHasPassword = false;
      let formHasEmail = false;

      formInputs.forEach(input => {
        if (input.type === 'password') formHasPassword = true;
        if (input.type === 'email' || (input.name || '').includes('email')) formHasEmail = true;
      });

      if (formHasPassword && (formHasEmail || formText.includes('sign in') || formText.includes('log in'))) {
        hasLoginForm = true;
      }

      if (hasCreditCard || formText.includes('payment') || formText.includes('checkout') ||
          formText.includes('billing')) {
        hasPaymentForm = true;
      }
    });

    // Link analysis
    const pageHost = window.location.hostname;
    const visibleLinkHostsSet = new Set();
    let externalLinkCount = 0;

    links.forEach(link => {
      try {
        const href = link.href;
        if (!href || !href.startsWith('http')) return;
        const linkHost = new URL(href).hostname;
        if (linkHost !== pageHost) {
          externalLinkCount++;
          if (link.offsetParent !== null) { // visible
            visibleLinkHostsSet.add(linkHost);
          }
        }
      } catch {}
    });

    return {
      hasPassword,
      hasEmail,
      hasCreditCard,
      hasLoginForm,
      hasPaymentForm,
      formActionHosts: [...new Set(formActionHosts)],
      visibleLinkHosts: [...visibleLinkHostsSet].slice(0, 20),
      externalLinkCount
    };
  }

  function extractVisibleText() {
    const walker = document.createTreeWalker(
      document.body,
      NodeFilter.SHOW_TEXT,
      {
        acceptNode(node) {
          const tag = node.parentElement?.tagName;
          if (!tag) return NodeFilter.FILTER_REJECT;
          if (['SCRIPT', 'STYLE', 'NOSCRIPT', 'SVG'].includes(tag)) return NodeFilter.FILTER_REJECT;
          if (node.textContent.trim().length === 0) return NodeFilter.FILTER_REJECT;
          return NodeFilter.FILTER_ACCEPT;
        }
      }
    );

    let text = '';
    while (walker.nextNode()) {
      text += walker.currentNode.textContent.trim() + ' ';
      if (text.length > 15000) break;
    }
    return text.slice(0, 15000);
  }

  function detectNewsArticle() {
    // Check meta tags
    const ogType = document.querySelector('meta[property="og:type"]');
    if (ogType && ogType.content === 'article') return true;

    // Check schema.org
    const ldScripts = document.querySelectorAll('script[type="application/ld+json"]');
    for (const script of ldScripts) {
      try {
        const data = JSON.parse(script.textContent);
        const types = Array.isArray(data['@type']) ? data['@type'] : [data['@type']];
        if (types.some(t => t && (t.includes('NewsArticle') || t.includes('Article')))) return true;
      } catch {}
    }

    // Check semantic elements
    const hasArticle = document.querySelector('article') !== null;
    const hasTime = document.querySelector('time[datetime]') !== null;
    const hasAuthor = document.querySelector('[rel="author"], .author, .byline, meta[name="author"]') !== null;

    return hasArticle && (hasTime || hasAuthor);
  }

  // ─── WhatsApp Web Message Extractor ──────────────────────────────────────
  // Reads recent incoming messages from WhatsApp Web DOM.
  // Returns text + links for local gate + backend analysis.

  function extractWhatsAppMessages() {
    if (!window.location.hostname.includes('web.whatsapp.com')) return null;

    const messages = [];
    const links = [];

    // WhatsApp Web: incoming messages are in data-id attributed divs
    // Message bubbles have class pattern: message-in / copyable-text
    const bubbles = document.querySelectorAll('[data-id]');
    bubbles.forEach(bubble => {
      // Only process last 20 messages to avoid performance hit
      if (messages.length >= 20) return;

      const textEl = bubble.querySelector('.selectable-text, [class*="copyable-text"]');
      if (!textEl) return;
      const text = textEl.innerText?.trim();
      if (!text || text.length < 5) return;

      messages.push(text);

      // Extract URLs from message
      const urlMatches = text.match(/https?:\/\/[^\s]+/g) || [];
      links.push(...urlMatches);

      // Also catch WhatsApp-formatted links (no http prefix)
      const bareUrlMatches = text.match(/(?:www\.|bit\.ly\/|tinyurl\.com\/)[^\s]+/g) || [];
      links.push(...bareUrlMatches.map(u => 'https://' + u));
    });

    if (messages.length === 0) return null;

    return {
      source: 'whatsapp-web',
      messageCount: messages.length,
      text: messages.join('\n'),
      links: [...new Set(links)].slice(0, 10),
    };
  }

  // ─── Telegram Web Message Extractor ──────────────────────────────────────
  function extractTelegramMessages() {
    if (!window.location.hostname.includes('web.telegram.org')) return null;

    const messages = [];
    const msgEls = document.querySelectorAll('.message.spoilers-container, .text-content');
    msgEls.forEach(el => {
      if (messages.length >= 20) return;
      const text = el.innerText?.trim();
      if (text && text.length > 5) messages.push(text);
    });

    if (messages.length === 0) return null;
    return {
      source: 'telegram-web',
      messageCount: messages.length,
      text: messages.join('\n'),
    };
  }

  function buildSnapshot() {
    const signals = extractSignals();
    const isNewsArticle = detectNewsArticle();

    // WhatsApp / Telegram: send message text instead of page text
    const waData = extractWhatsAppMessages();
    const tgData = extractTelegramMessages();
    const messagingData = waData || tgData;

    let visibleText;
    if (messagingData) {
      visibleText = messagingData.text;
    } else {
      visibleText = extractVisibleText();
    }

    return {
      url: window.location.href,
      title: document.title,
      domain: window.location.hostname,
      visibleText,
      pageText: visibleText,
      isNewsArticle,
      signals,
      messaging: messagingData || null,
      meta: {
        description: document.querySelector('meta[name="description"]')?.content || '',
        ogTitle: document.querySelector('meta[property="og:title"]')?.content || '',
        ogDescription: document.querySelector('meta[property="og:description"]')?.content || ''
      },
      timestamp: Date.now()
    };
  }

  // --- Trust Overlay ---

  let overlayEl = null;
  let overlayTimeout = null;

  function createOverlay(assessment, settings) {
    removeOverlay();

    const score = Math.round(assessment.trustScore);
    const level = assessment.riskLevel;
    const color = getTrustColor(score);
    const position = settings?.overlayPosition || 'bottom-right';
    const autoHide = settings?.overlayAutoHide ?? 10000;

    const overlay = document.createElement('div');
    overlay.id = 'chetana-trust-overlay';

    // Position
    const posStyles = {
      'top-right': 'top: 16px; right: 16px;',
      'bottom-right': 'bottom: 16px; right: 16px;',
      'bottom-left': 'bottom: 16px; left: 16px;'
    };

    const topSignals = (assessment.signals || []).slice(0, 3);
    const signalHTML = topSignals.map(s => {
      const icon = s.severity === 'high' ? '\u26a0' : s.severity === 'medium' ? '\u26a1' : '\u2139';
      return `<div style="font-size: 12px; color: #cbd5e1; margin: 2px 0;">${icon} ${escapeHtml(s.label || s.message || s.name || 'Signal')}</div>`;
    }).join('');

    const factCheckBtn = assessment.isNewsArticle
      ? `<button id="chetana-factcheck-btn" style="
            background: #334155; color: #e2e8f0; border: 1px solid #475569;
            padding: 4px 10px; border-radius: 4px; cursor: pointer; font-size: 11px; margin-right: 4px;
          ">Fact Check</button>`
      : '';

    overlay.innerHTML = `
      <div style="
        position: fixed; ${posStyles[position] || posStyles['bottom-right']}
        z-index: 2147483647; font-family: system-ui, -apple-system, sans-serif;
        background: #0f172a; border: 1px solid ${color}44; border-radius: 12px;
        padding: 14px 16px; width: 240px; box-shadow: 0 8px 32px rgba(0,0,0,0.4);
        opacity: 0; transform: translateY(10px);
        transition: opacity 0.3s ease, transform 0.3s ease;
      " id="chetana-overlay-inner">
        <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 8px;">
          <div style="
            width: 44px; height: 44px; border-radius: 50%;
            border: 3px solid ${color}; display: flex; align-items: center;
            justify-content: center; font-size: 18px; font-weight: 700; color: ${color};
            flex-shrink: 0;
          ">${score}</div>
          <div>
            <div style="font-size: 13px; font-weight: 600; color: ${color}; text-transform: uppercase; letter-spacing: 0.5px;">
              ${level}
            </div>
            <div style="font-size: 11px; color: #64748b; margin-top: 2px;">Chetana Trust</div>
          </div>
          <button id="chetana-dismiss" style="
            margin-left: auto; background: none; border: none; color: #64748b;
            cursor: pointer; font-size: 16px; padding: 2px 4px; line-height: 1;
          ">\u00d7</button>
        </div>
        ${signalHTML ? `<div style="margin: 8px 0; padding-top: 8px; border-top: 1px solid #1e293b;">${signalHTML}</div>` : ''}
        <div style="display: flex; gap: 4px; margin-top: 8px;">
          ${factCheckBtn}
          <button id="chetana-details-btn" style="
            background: #334155; color: #e2e8f0; border: 1px solid #475569;
            padding: 4px 10px; border-radius: 4px; cursor: pointer; font-size: 11px;
          ">Details</button>
        </div>
      </div>
    `;

    document.body.appendChild(overlay);
    overlayEl = overlay;

    // Animate in
    requestAnimationFrame(() => {
      const inner = document.getElementById('chetana-overlay-inner');
      if (inner) {
        inner.style.opacity = '1';
        inner.style.transform = 'translateY(0)';
      }
    });

    // Dismiss button
    const dismissBtn = document.getElementById('chetana-dismiss');
    if (dismissBtn) {
      dismissBtn.addEventListener('click', () => removeOverlay());
    }

    // Details button — open side panel
    const detailsBtn = document.getElementById('chetana-details-btn');
    if (detailsBtn) {
      detailsBtn.addEventListener('click', () => {
        chrome.runtime.sendMessage({ action: 'openSidePanel' });
      });
    }

    // Fact check button
    const fcBtn = document.getElementById('chetana-factcheck-btn');
    if (fcBtn) {
      fcBtn.addEventListener('click', async () => {
        fcBtn.textContent = 'Checking...';
        fcBtn.disabled = true;
        const snapshot = buildSnapshot();
        const result = await chrome.runtime.sendMessage({
          action: 'factCheck',
          payload: {
            url: snapshot.url,
            title: snapshot.title,
            text: snapshot.visibleText,
            domain: snapshot.domain
          }
        });
        fcBtn.textContent = result ? 'Done' : 'Failed';
      });
    }

    // Auto-hide
    if (autoHide && autoHide > 0) {
      overlayTimeout = setTimeout(() => removeOverlay(), autoHide);
    }
  }

  function removeOverlay() {
    if (overlayTimeout) {
      clearTimeout(overlayTimeout);
      overlayTimeout = null;
    }
    if (overlayEl) {
      const inner = document.getElementById('chetana-overlay-inner');
      if (inner) {
        inner.style.opacity = '0';
        inner.style.transform = 'translateY(10px)';
        setTimeout(() => {
          overlayEl?.remove();
          overlayEl = null;
        }, 300);
      } else {
        overlayEl.remove();
        overlayEl = null;
      }
    }
  }

  function getTrustColor(score) {
    if (score >= 80) return '#22c55e';
    if (score >= 50) return '#eab308';
    if (score >= 25) return '#f97316';
    return '#ef4444';
  }

  function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  // --- Submit Guard ---

  function installSubmitGuard() {
    document.addEventListener('submit', (e) => {
      const cached = window.__chetanaLastAssessment;
      if (!cached || cached.riskLevel !== 'DANGER') return;

      e.preventDefault();
      e.stopImmediatePropagation();

      const confirmed = confirm(
        `\u26a0\ufe0f Chetana Trust Warning\n\n` +
        `This page has a DANGER trust score (${Math.round(cached.trustScore)}/100).\n\n` +
        `Detected risks:\n` +
        (cached.signals || []).slice(0, 3).map(s => `  \u2022 ${s.label || s.message || 'Risk detected'}`).join('\n') +
        `\n\nAre you sure you want to submit this form?`
      );

      if (confirmed) {
        e.target.submit();
      }
    }, true);
  }

  // --- Link Hover Tooltip ---

  let hoverTooltip = null;

  function installLinkHoverTooltips() {
    document.addEventListener('mouseover', (e) => {
      const link = e.target.closest('a[href]');
      if (!link) return;

      try {
        const href = link.href;
        if (!href || !href.startsWith('http')) return;
        const linkHost = new URL(href).hostname;
        const pageHost = window.location.hostname;
        if (linkHost === pageHost) return;

        showLinkTooltip(link, linkHost);
      } catch {}
    });

    document.addEventListener('mouseout', (e) => {
      const link = e.target.closest('a[href]');
      if (link && hoverTooltip) {
        hoverTooltip.remove();
        hoverTooltip = null;
      }
    });
  }

  function showLinkTooltip(link, host) {
    if (hoverTooltip) {
      hoverTooltip.remove();
    }

    const tooltip = document.createElement('div');
    tooltip.style.cssText = `
      position: absolute; z-index: 2147483646;
      background: #1e293b; color: #e2e8f0; border: 1px solid #334155;
      padding: 4px 8px; border-radius: 4px; font-size: 11px;
      font-family: system-ui, sans-serif; pointer-events: none;
      white-space: nowrap; box-shadow: 0 2px 8px rgba(0,0,0,0.3);
    `;
    tooltip.textContent = `\u2197 ${host}`;

    const rect = link.getBoundingClientRect();
    tooltip.style.left = `${rect.left + window.scrollX}px`;
    tooltip.style.top = `${rect.top + window.scrollY - 28}px`;

    document.body.appendChild(tooltip);
    hoverTooltip = tooltip;
  }

  // --- Message Listeners ---

  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'snapshotPage') {
      try {
        const snapshot = buildSnapshot();
        sendResponse(snapshot);
      } catch (err) {
        sendResponse({ error: err.message });
      }
      return false;
    }

    if (message.action === 'renderAssessment') {
      const { assessment, settings } = message;
      window.__chetanaLastAssessment = assessment;
      createOverlay(assessment, settings);
      sendResponse({ ok: true });
      return false;
    }

    return false;
  });

  // ─── WhatsApp Web — Live Message Observer ────────────────────────────────
  // MutationObserver watches for new message bubbles arriving in real time.
  // Debounced 1.5s so we batch rapid incoming messages into one scan.

  function installWhatsAppObserver() {
    if (!window.location.hostname.includes('web.whatsapp.com')) return;

    let debounceTimer = null;
    let lastScannedText = '';

    const observer = new MutationObserver(() => {
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(() => {
        const waData = extractWhatsAppMessages();
        if (!waData || waData.text === lastScannedText) return;
        lastScannedText = waData.text;

        // Run local gate immediately for instant feedback
        const localResult = window.__chetanaLocalGate
          ? window.__chetanaLocalGate(waData.text)
          : null;

        if (localResult && localResult.signals.length > 0) {
          // Show inline warning banner in the chat
          showWhatsAppWarning(localResult);
        }

        // Also ask background to do full scan
        chrome.runtime.sendMessage({
          action: 'scanText',
          text: waData.text,
          url: window.location.href,
          source: 'whatsapp-web',
        });
      }, 1500);
    });

    // Watch the message list container
    const tryObserve = () => {
      const pane = document.querySelector('#main') || document.querySelector('[data-tab="8"]');
      if (pane) {
        observer.observe(pane, { childList: true, subtree: true });
      } else {
        setTimeout(tryObserve, 2000); // WhatsApp loads lazily
      }
    };
    tryObserve();
  }

  function showWhatsAppWarning(result) {
    const existing = document.getElementById('chetana-wa-warning');
    if (existing) existing.remove();

    const banner = document.createElement('div');
    banner.id = 'chetana-wa-warning';
    banner.style.cssText = `
      position: fixed; top: 60px; right: 12px; z-index: 9999;
      background: #1a1a2e; border: 1px solid #ef4444; border-radius: 10px;
      padding: 10px 14px; max-width: 280px; box-shadow: 0 4px 20px rgba(0,0,0,0.4);
      font-family: system-ui, sans-serif; font-size: 12px; color: #e2e8f0;
    `;
    const topSignals = result.signals.slice(0, 2).join(' · ');
    banner.innerHTML = `
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">
        <span style="font-size:16px;">🛡️</span>
        <strong style="color:#ef4444;font-size:13px;">Chetana: Scam Risk Detected</strong>
        <button id="chetana-wa-dismiss" style="margin-left:auto;background:none;border:none;color:#94a3b8;cursor:pointer;font-size:14px;">✕</button>
      </div>
      <div style="color:#94a3b8;line-height:1.5;">${topSignals}</div>
      <div style="margin-top:6px;color:#f97316;font-size:11px;">Do not share OTP, UPI PIN, or personal details.</div>
    `;

    document.body.appendChild(banner);
    document.getElementById('chetana-wa-dismiss')?.addEventListener('click', () => banner.remove());
    setTimeout(() => banner?.remove(), 15000);
  }

  // Expose local gate to content script context for WA observer
  // (simplified — just keyword check for instant response)
  window.__chetanaLocalGate = (text) => {
    const signals = [];
    const t = text.toLowerCase();
    if (/upi.{0,20}collect|kyc.{0,20}expir|aadhaar.{0,20}updat/.test(t)) signals.push('UPI/KYC urgency');
    if (/digital.{0,10}arrest|cbi.{0,20}notice|arrest.{0,10}warrant/.test(t)) signals.push('Digital arrest scam');
    if (/(?:share|send|give).{0,20}otp|one.time.pass/.test(t)) signals.push('OTP solicitation');
    if (/guaranteed.{0,15}return|daily.{0,10}profit|task.{0,15}earn/.test(t)) signals.push('Investment/task scam');
    if (/kbc.{0,20}(?:winner|prize)|congratulation.{0,20}won/.test(t)) signals.push('Lottery scam');
    if (/(?:bit\.ly|tinyurl).*(?:bank|kyc|upi|pay|urgent)/.test(t)) signals.push('Suspicious link');
    return { signals, trustScore: signals.length > 0 ? Math.max(20, 72 - signals.length * 20) : 80 };
  };

  // --- Init ---

  chrome.storage?.local?.get('chetana_settings', (result) => {
    const s = result?.chetana_settings || {};
    if (s.submitGuard !== false) installSubmitGuard();
    if (s.linkHoverTooltips !== false) installLinkHoverTooltips();
    installWhatsAppObserver(); // always on for WhatsApp Web
  });

})();
