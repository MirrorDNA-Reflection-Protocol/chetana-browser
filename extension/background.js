// Chetana Browser v6.1 — Background Service Worker
// Coordinates page analysis via backend, manages badge, caches results
// v6.1: Local gate (offline), persistent domain cache, WhatsApp scanning

const DEFAULT_SETTINGS = {
  backendUrl: 'http://127.0.0.1:8799',
  autoScan: true,
  submitGuard: true,
  overlayPosition: 'bottom-right',
  overlayAutoHide: 10000,
  linkHoverTooltips: true
};

const tabCache = new Map();
let backendOnline = false;
let settings = { ...DEFAULT_SETTINGS };

// ─── Persistent Domain Reputation Cache ───────────────────────────────────
// Survives service worker restarts. Key: hostname, value: {score, riskLevel, ts}
const DOMAIN_CACHE_KEY = 'chetana_domain_cache';
const DOMAIN_CACHE_TTL = 24 * 60 * 60 * 1000; // 24h

async function getDomainCache() {
  const s = await chrome.storage.local.get(DOMAIN_CACHE_KEY);
  return s[DOMAIN_CACHE_KEY] || {};
}

async function setCachedDomain(hostname, result) {
  const cache = await getDomainCache();
  cache[hostname] = { ...result, ts: Date.now() };
  // Prune entries older than TTL (keep cache lean)
  for (const [k, v] of Object.entries(cache)) {
    if (Date.now() - v.ts > DOMAIN_CACHE_TTL) delete cache[k];
  }
  await chrome.storage.local.set({ [DOMAIN_CACHE_KEY]: cache });
}

async function getCachedDomain(hostname) {
  const cache = await getDomainCache();
  const entry = cache[hostname];
  if (!entry) return null;
  if (Date.now() - entry.ts > DOMAIN_CACHE_TTL) return null;
  return entry;
}

// ─── Local Gate (runs with NO backend) ────────────────────────────────────
// Pattern-matched rules for India scam detection.
// Returns same shape as backend response so callers are unaware.

const LOCAL_GATE_RULES = [
  // UPI / KYC urgency
  { re: /upi.{0,20}collect|collect.{0,20}request|kyc.{0,20}expir|aadhaar.{0,20}updat|pan.{0,20}block|account.{0,20}suspend/i,
    signal: 'UPI/KYC urgency trigger', score: -28 },
  // Digital arrest scam
  { re: /digital.{0,10}arrest|cbi.{0,20}notice|arrest.{0,10}warrant|customs.{0,20}seize|police.{0,20}case.{0,20}your/i,
    signal: 'Digital arrest scam pattern', score: -38 },
  // OTP theft
  { re: /(?:share|send|give|enter|tell).{0,30}otp|otp.{0,30}(?:share|send|give)|one.time.password/i,
    signal: 'OTP solicitation', score: -25 },
  // Investment / task scam
  { re: /guaranteed.{0,15}return|daily.{0,10}profit|(?:easy|simple).{0,15}earn|task.{0,15}earn.{0,15}(?:\$|₹|rs\.?)/i,
    signal: 'Investment/task scam pattern', score: -22 },
  // Lottery / prize
  { re: /kbc.{0,20}(?:winner|prize|lottery)|congratulation.{0,20}(?:won|winner|prize)|lucky.{0,10}draw.{0,10}winner/i,
    signal: 'Lottery/prize scam', score: -30 },
  // Loan fraud
  { re: /instant.{0,15}loan.{0,15}approv|loan.{0,15}without.{0,15}(?:cibil|documents|docs)|pre.approv.{0,15}loan/i,
    signal: 'Fake loan offer', score: -20 },
  // Suspicious URL shorteners / TLDs
  { re: /(?:bit\.ly|tinyurl|t\.me\/[^c]|cutt\.ly|rb\.gy|is\.gd|ow\.ly)/i,
    signal: 'URL shortener redirect', score: -12 },
  // Fake .gov typosquats (common in India scams)
  { re: /(?:gov-in|govin|\.gov\.com|india-gov|\.gov\.org)/i,
    signal: 'Fake government domain', score: -35 },
  // Electricity/gas urgency
  { re: /electricity.{0,20}(?:cut|disconnect|block|suspend)|power.{0,20}(?:cut|disconnect).{0,20}tonight/i,
    signal: 'Utility disconnection threat', score: -25 },
  // Courier / delivery (FedEx/DHL scam)
  { re: /(?:fedex|dhl|india.post|courier).{0,30}(?:held|seized|customs|pay.{0,15}fee|release)/i,
    signal: 'Courier impersonation', score: -22 },
];

function localGateCheck(payload) {
  const url = (payload.url || '').toLowerCase();
  const text = [payload.text, payload.title, payload.pageText].filter(Boolean).join(' ');
  const combined = (url + ' ' + text).slice(0, 20000);

  const signals = [];
  let scoreDelta = 0;

  for (const rule of LOCAL_GATE_RULES) {
    if (rule.re.test(combined)) {
      signals.push(rule.signal);
      scoreDelta += rule.score;
    }
  }

  // Suspicious TLD check on URL
  try {
    const hostname = new URL(payload.url || 'https://example.com').hostname;
    if (/\.(xyz|top|click|tk|ml|gq|cf|ga|pw|work|loan|racing)$/.test(hostname)) {
      signals.push('Suspicious domain TLD');
      scoreDelta -= 18;
    }
    // UPI ID patterns in text (qr code scams)
    if (/[a-z0-9.\-_]+@(?:okicici|okhdfcbank|okaxis|oksbi|paytm|upi|ybl|ibl|apl|aubank)/.test(text)) {
      // UPI ID present — neutral, but flag if combined with urgency
      if (scoreDelta < -15) {
        signals.push('UPI ID with urgency signals');
        scoreDelta -= 10;
      }
    }
  } catch {}

  const trustScore = Math.max(0, Math.min(100, 72 + scoreDelta)); // 72 = baseline trust
  return {
    trustScore,
    riskLevel: getRiskLevel(trustScore),
    signals,
    recommendations: signals.length > 0
      ? ['Do not share OTP or personal details', 'Verify via official channels only', 'Report to cybercrime.gov.in or call 1930']
      : [],
    source: 'local-gate',
    backendOnline: false,
  };
}

// --- Badge Colors ---
const TRUST_COLORS = {
  SAFE:    { color: '#22c55e', range: [80, 100] },
  CAUTION: { color: '#eab308', range: [50, 79] },
  WARNING: { color: '#f97316', range: [25, 49] },
  DANGER:  { color: '#ef4444', range: [0, 24] }
};

function getRiskLevel(score) {
  if (score >= 80) return 'SAFE';
  if (score >= 50) return 'CAUTION';
  if (score >= 25) return 'WARNING';
  return 'DANGER';
}

function getBadgeColor(score) {
  const level = getRiskLevel(score);
  return TRUST_COLORS[level].color;
}

// --- Badge Update ---
async function updateBadge(tabId, score) {
  if (score === null || score === undefined) {
    await chrome.action.setBadgeText({ tabId, text: '' });
    return;
  }
  const text = String(Math.round(score));
  const color = getBadgeColor(score);
  await chrome.action.setBadgeText({ tabId, text });
  await chrome.action.setBadgeBackgroundColor({ tabId, color });
}

// --- Settings ---
async function loadSettings() {
  const stored = await chrome.storage.local.get('chetana_settings');
  if (stored.chetana_settings) {
    settings = { ...DEFAULT_SETTINGS, ...stored.chetana_settings };
  }
  return settings;
}

async function saveSettings(newSettings) {
  settings = { ...DEFAULT_SETTINGS, ...newSettings };
  await chrome.storage.local.set({ chetana_settings: settings });
  return settings;
}

// --- History ---
async function addToHistory(entry) {
  const stored = await chrome.storage.local.get('chetana_history');
  const history = stored.chetana_history || [];
  history.unshift({
    url: entry.url,
    title: entry.title,
    score: entry.trustScore,
    riskLevel: entry.riskLevel,
    timestamp: Date.now()
  });
  // Keep last 50
  if (history.length > 50) history.length = 50;
  await chrome.storage.local.set({ chetana_history: history });
}

async function getHistory() {
  const stored = await chrome.storage.local.get('chetana_history');
  return stored.chetana_history || [];
}

async function clearHistory() {
  await chrome.storage.local.set({ chetana_history: [] });
}

// --- Backend Communication ---
async function checkBackendHealth() {
  try {
    const resp = await fetch(`${settings.backendUrl}/health`, {
      method: 'GET',
      signal: AbortSignal.timeout(5000)
    });
    backendOnline = resp.ok;
  } catch {
    backendOnline = false;
  }
  return backendOnline;
}

const CLOUD_API = 'https://chetana.activemirror.ai/api/scan/full';
let cloudAvailable = true;

async function analyzeWithCloud(payload) {
  if (!cloudAvailable) return null;
  try {
    // Map extension snapshot to Chetana API format
    const body = {
      text: [payload.visibleText, payload.title, payload.url].filter(Boolean).join('\n').slice(0, 3000),
      lang: 'en',
      context: payload.messaging?.source || 'browser',
    };
    const resp = await fetch(CLOUD_API, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(12000)
    });
    if (!resp.ok) { cloudAvailable = false; return null; }
    const data = await resp.json();
    // Normalize to extension format
    const score = data.risk_score !== undefined ? (100 - data.risk_score) : 50;
    return {
      trustScore: score,
      riskLevel: getRiskLevel(score),
      signals: data.why_flagged || [],
      recommendations: data.action_eligibility === 'WARN'
        ? ['Do not share personal details', 'Verify through official channels', 'Report to 1930 or cybercrime.gov.in']
        : [],
      verdict: data.verdict,
      source: 'cloud',
    };
  } catch {
    cloudAvailable = false;
    return null;
  }
}

// Restore cloud availability periodically
setInterval(() => { cloudAvailable = true; }, 5 * 60 * 1000);

async function analyzeWithBackend(payload) {
  if (!backendOnline) {
    await checkBackendHealth();
    if (!backendOnline) return null;
  }
  try {
    const resp = await fetch(`${settings.backendUrl}/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(15000)
    });
    if (!resp.ok) return null;
    return await resp.json();
  } catch {
    backendOnline = false;
    return null;
  }
}

async function factCheckWithBackend(payload) {
  if (!backendOnline) {
    await checkBackendHealth();
    if (!backendOnline) return null;
  }
  try {
    const resp = await fetch(`${settings.backendUrl}/fact-check`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(20000)
    });
    if (!resp.ok) return null;
    return await resp.json();
  } catch {
    backendOnline = false;
    return null;
  }
}

// --- Page Scanning ---
async function scanTab(tabId) {
  let snapshot;
  try {
    const response = await chrome.tabs.sendMessage(tabId, { action: 'snapshotPage' });
    snapshot = response;
  } catch {
    return { error: 'Could not access page content' };
  }

  if (!snapshot || snapshot.error) {
    return { error: snapshot?.error || 'No snapshot returned' };
  }

  // Check persistent domain cache first
  let cachedResult = null;
  try {
    const hostname = new URL(snapshot.url).hostname;
    cachedResult = await getCachedDomain(hostname);
  } catch {}

  // Fallback chain: cache → Ollama → cloud API → local gate
  let result = cachedResult
    || await analyzeWithBackend(snapshot)
    || await analyzeWithCloud(snapshot)
    || localGateCheck(snapshot);

  const assessment = {
    url: snapshot.url,
    title: snapshot.title,
    trustScore: result.trustScore ?? result.trust_score ?? 50,
    riskLevel: result.riskLevel ?? result.risk_level ?? getRiskLevel(result.trustScore ?? result.trust_score ?? 50),
    signals: result.signals || [],
    recommendations: result.recommendations || [],
    isNewsArticle: snapshot.isNewsArticle || false,
    factCheck: result.factCheck || result.fact_check || null,
    timestamp: Date.now(),
    backendOnline: result.source !== 'local-gate',
    source: result.source || 'backend',
  };

  // Ensure riskLevel is consistent with score
  assessment.riskLevel = getRiskLevel(assessment.trustScore);

  // Persist to domain cache if backend answered (not local gate)
  if (assessment.backendOnline && assessment.trustScore !== 50) {
    try {
      const hostname = new URL(snapshot.url).hostname;
      await setCachedDomain(hostname, {
        trustScore: assessment.trustScore,
        riskLevel: assessment.riskLevel,
        signals: assessment.signals,
      });
    } catch {}
  }

  tabCache.set(tabId, assessment);
  await updateBadge(tabId, assessment.trustScore);
  await addToHistory(assessment);

  // Send overlay render to content script
  try {
    await chrome.tabs.sendMessage(tabId, {
      action: 'renderAssessment',
      assessment,
      settings
    });
  } catch {
    // Content script may not be ready
  }

  return assessment;
}

// --- Event Listeners ---

// Tab navigation: auto-scan if enabled
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== 'complete') return;
  if (!tab.url || (!tab.url.startsWith('http://') && !tab.url.startsWith('https://'))) return;

  await loadSettings();
  if (settings.autoScan) {
    // Small delay to let content script initialize
    setTimeout(() => scanTab(tabId), 500);
  }
});

// Tab removal: cleanup cache
chrome.tabs.onRemoved.addListener((tabId) => {
  tabCache.delete(tabId);
});

// Action click: open side panel
chrome.action.onClicked.addListener(async (tab) => {
  await chrome.sidePanel.open({ tabId: tab.id });
});

// Health check alarm
chrome.alarms.create('healthCheck', { periodInMinutes: 1 });
chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === 'healthCheck') {
    await checkBackendHealth();
  }
});

// ─── Context Menu — "Check with Chetana" ─────────────────────────────────
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: 'chetana-check-selection',
    title: 'Check with Chetana 🛡',
    contexts: ['selection', 'link'],
  });
  chrome.contextMenus.create({
    id: 'chetana-check-page',
    title: 'Check this page — Chetana 🛡',
    contexts: ['page'],
  });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (!tab?.id) return;

  if (info.menuItemId === 'chetana-check-selection' || info.menuItemId === 'chetana-check-page') {
    const text = info.selectionText || info.linkUrl || '';
    const url = info.pageUrl || tab.url || '';

    // Build a minimal snapshot from the selected text / link
    const snapshot = {
      url,
      title: tab.title || '',
      visibleText: text,
      pageText: text,
      signals: {},
      messaging: text ? { source: 'context-menu', text, messageCount: 1 } : null,
    };

    const result = await analyzeWithBackend(snapshot)
      || await analyzeWithCloud(snapshot)
      || localGateCheck(snapshot);

    const assessment = {
      url,
      title: tab.title || '',
      trustScore: result.trustScore ?? 50,
      riskLevel: result.riskLevel ?? getRiskLevel(result.trustScore ?? 50),
      signals: result.signals || [],
      recommendations: result.recommendations || [],
      source: result.source || 'local-gate',
      timestamp: Date.now(),
      backendOnline: result.source !== 'local-gate',
      contextScan: true,
      scannedText: text.slice(0, 200),
    };

    tabCache.set(tab.id, assessment);
    await updateBadge(tab.id, assessment.trustScore);

    // Push result to side panel
    try {
      await chrome.tabs.sendMessage(tab.id, { action: 'renderAssessment', assessment, settings });
    } catch {}

    // Open side panel to show result
    await chrome.sidePanel.open({ tabId: tab.id });
  }
});

// --- Message Handlers ---
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  handleMessage(message, sender).then(sendResponse);
  return true; // async response
});

async function handleMessage(message, sender) {
  await loadSettings();

  switch (message.action) {
    case 'snapshotPage': {
      // Forwarded from panel — snapshot comes from content script
      const tabId = message.tabId;
      if (!tabId) return { error: 'No tabId' };
      try {
        const snapshot = await chrome.tabs.sendMessage(tabId, { action: 'snapshotPage' });
        return snapshot;
      } catch {
        return { error: 'Could not reach content script' };
      }
    }

    case 'scanActiveTab': {
      let tabId = message.tabId;
      if (!tabId) {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!tab) return { error: 'No active tab' };
        tabId = tab.id;
      }
      return await scanTab(tabId);
    }

    case 'getLastScan': {
      let tabId = message.tabId;
      if (!tabId) {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!tab) return null;
        tabId = tab.id;
      }
      return tabCache.get(tabId) || null;
    }

    case 'scanText': {
      // Scan arbitrary text (from WhatsApp observer, context menu, etc.)
      const snapshot = {
        url: message.url || '',
        title: message.source || 'text-scan',
        visibleText: message.text || '',
        pageText: message.text || '',
        signals: {},
        messaging: { source: message.source || 'text', text: message.text, messageCount: 1 },
      };
      const result = await analyzeWithBackend(snapshot)
        || await analyzeWithCloud(snapshot)
        || localGateCheck(snapshot);
      return result;
    }

    case 'factCheck': {
      const result = await factCheckWithBackend(message.payload);
      return result;
    }

    case 'getSettings': {
      return settings;
    }

    case 'saveSettings': {
      return await saveSettings(message.settings);
    }

    case 'getHistory': {
      return await getHistory();
    }

    case 'clearHistory': {
      await clearHistory();
      return { ok: true };
    }

    case 'getBackendStatus': {
      return { online: backendOnline };
    }

    case 'checkHealth': {
      const online = await checkBackendHealth();
      return { online };
    }

    default:
      return { error: 'Unknown action' };
  }
}

// --- Init ---
(async () => {
  await loadSettings();
  await checkBackendHealth();
  console.log('[Chetana] Service worker initialized. Backend:', backendOnline ? 'online' : 'offline');
})();
