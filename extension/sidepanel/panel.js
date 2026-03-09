// Chetana Browser v6 — Side Panel Logic

const TRUST_COLORS = {
  SAFE: '#22c55e',
  CAUTION: '#eab308',
  WARNING: '#f97316',
  DANGER: '#ef4444'
};

const RING_CIRCUMFERENCE = 2 * Math.PI * 52; // ~326.73

let currentAssessment = null;

// --- Helpers ---

function getRiskLevel(score) {
  if (score >= 80) return 'SAFE';
  if (score >= 50) return 'CAUTION';
  if (score >= 25) return 'WARNING';
  return 'DANGER';
}

function getColor(score) {
  return TRUST_COLORS[getRiskLevel(score)];
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str || '';
  return div.innerHTML;
}

function timeAgo(ts) {
  const diff = Date.now() - ts;
  if (diff < 60000) return 'just now';
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
  if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
  return `${Math.floor(diff / 86400000)}d ago`;
}

async function sendMsg(msg) {
  return chrome.runtime.sendMessage(msg);
}

// --- Rendering ---

function renderTrustScore(score) {
  const el = document.getElementById('trust-score');
  const ring = document.getElementById('ring-fill');
  const color = getColor(score);

  el.textContent = Math.round(score);
  el.style.color = color;

  const offset = RING_CIRCUMFERENCE * (1 - score / 100);
  ring.style.strokeDashoffset = offset;
  ring.style.stroke = color;
}

function renderRiskBadge(level) {
  const badge = document.getElementById('risk-badge');
  badge.textContent = level;
  badge.className = 'risk-badge ' + level.toLowerCase();
}

function renderPageInfo(title, url) {
  document.getElementById('page-title').textContent = title || 'Unknown Page';
  document.getElementById('page-url').textContent = url || '';
}

function renderSignals(signals) {
  const section = document.getElementById('signals-section');
  const list = document.getElementById('signal-list');

  if (!signals || signals.length === 0) {
    section.style.display = 'none';
    return;
  }

  section.style.display = 'block';
  list.innerHTML = signals.map(s => {
    const severity = s.severity || 'info';
    const icons = { high: '\u26d4', medium: '\u26a0\ufe0f', low: '\u26a1', info: '\u2139\ufe0f' };
    return `
      <div class="signal-item signal-severity-${severity}">
        <span class="signal-icon">${icons[severity] || icons.info}</span>
        <span class="signal-text">${escapeHtml(s.label || s.message || s.name || 'Signal detected')}</span>
      </div>
    `;
  }).join('');
}

function renderFactCheck(factCheck, isNewsArticle) {
  const section = document.getElementById('factcheck-section');
  const content = document.getElementById('factcheck-content');

  if (!isNewsArticle || !factCheck) {
    section.style.display = 'none';
    return;
  }

  section.style.display = 'block';

  const credibility = factCheck.sourceCredibility ?? factCheck.source_credibility ?? '--';
  const claimCount = factCheck.claimCount ?? factCheck.claim_count ?? 0;
  const verified = factCheck.verifiedClaims ?? factCheck.verified_claims ?? 0;
  const unverified = factCheck.unverifiedClaims ?? factCheck.unverified_claims ?? 0;
  const claims = factCheck.claims || [];

  let html = `
    <div class="factcheck-grid">
      <div class="factcheck-stat">
        <div class="factcheck-stat-value" style="color: ${getColor(typeof credibility === 'number' ? credibility : 50)}">${credibility}</div>
        <div class="factcheck-stat-label">Source Credibility</div>
      </div>
      <div class="factcheck-stat">
        <div class="factcheck-stat-value" style="color: #e2e8f0">${claimCount}</div>
        <div class="factcheck-stat-label">Claims Found</div>
      </div>
      <div class="factcheck-stat">
        <div class="factcheck-stat-value" style="color: #22c55e">${verified}</div>
        <div class="factcheck-stat-label">Verified</div>
      </div>
      <div class="factcheck-stat">
        <div class="factcheck-stat-value" style="color: #f97316">${unverified}</div>
        <div class="factcheck-stat-label">Unverified</div>
      </div>
    </div>
  `;

  if (claims.length > 0) {
    html += claims.slice(0, 5).map(c => `
      <div class="claim-item">
        <span class="${c.verified ? 'claim-verified' : 'claim-unverified'}">
          ${c.verified ? '\u2713' : '\u2717'}
        </span>
        ${escapeHtml(c.text || c.claim || '')}
      </div>
    `).join('');
  }

  content.innerHTML = html;
}

function renderRecommendations(recommendations) {
  const section = document.getElementById('recommendations-section');
  const list = document.getElementById('recommendations-list');

  if (!recommendations || recommendations.length === 0) {
    section.style.display = 'none';
    return;
  }

  section.style.display = 'block';
  list.innerHTML = recommendations.map(r => {
    const text = typeof r === 'string' ? r : (r.text || r.message || '');
    return `<li><span class="rec-icon">\u2192</span> ${escapeHtml(text)}</li>`;
  }).join('');
}

function renderAssessment(assessment) {
  if (!assessment) return;
  currentAssessment = assessment;

  renderTrustScore(assessment.trustScore);
  renderRiskBadge(assessment.riskLevel);
  renderPageInfo(assessment.title, assessment.url);
  renderSignals(assessment.signals);
  renderFactCheck(assessment.factCheck, assessment.isNewsArticle);
  renderRecommendations(assessment.recommendations);

  // Show copy button
  document.getElementById('copy-evidence-btn').style.display = 'inline-block';
}

function renderEmpty() {
  document.getElementById('trust-score').textContent = '--';
  document.getElementById('ring-fill').style.strokeDashoffset = RING_CIRCUMFERENCE;
  document.getElementById('ring-fill').style.stroke = '#64748b';
  renderRiskBadge('NOT SCANNED');
  renderPageInfo('Navigate to a page', '\u2014');
  document.getElementById('signals-section').style.display = 'none';
  document.getElementById('factcheck-section').style.display = 'none';
  document.getElementById('recommendations-section').style.display = 'none';
  document.getElementById('copy-evidence-btn').style.display = 'none';
  currentAssessment = null;
}

async function renderHistory() {
  const list = document.getElementById('history-list');
  const history = await sendMsg({ action: 'getHistory' });

  if (!history || history.length === 0) {
    list.innerHTML = '<p class="muted-text">No scan history yet.</p>';
    return;
  }

  list.innerHTML = history.slice(0, 10).map((h, i) => {
    const color = getColor(h.score);
    const borderColor = color + '44';
    return `
      <div class="history-item" data-index="${i}" title="${escapeHtml(h.url)}">
        <div class="history-score" style="border: 2px solid ${borderColor}; color: ${color};">
          ${Math.round(h.score)}
        </div>
        <div class="history-info">
          <div class="history-title">${escapeHtml(h.title || 'Unknown')}</div>
          <div class="history-url">${escapeHtml(h.url || '')}</div>
        </div>
        <span class="history-time">${timeAgo(h.timestamp)}</span>
      </div>
    `;
  }).join('');
}

// --- Connection Status ---

async function checkConnection() {
  const status = document.getElementById('connection-status');
  const text = status.querySelector('.status-text');

  const result = await sendMsg({ action: 'checkHealth' });

  if (result?.online) {
    status.className = 'connection-status online';
    text.textContent = 'Backend Online';
  } else {
    status.className = 'connection-status offline';
    text.textContent = 'Backend Offline';
  }
}

// --- Scan ---

async function scanPage() {
  const btn = document.getElementById('scan-btn');
  btn.textContent = 'Scanning...';
  btn.disabled = true;

  try {
    const result = await sendMsg({ action: 'scanActiveTab' });

    if (result?.error) {
      btn.textContent = result.error;
      setTimeout(() => {
        btn.textContent = 'Scan This Page';
        btn.disabled = false;
      }, 2000);
      return;
    }

    renderAssessment(result);
    await renderHistory();
  } catch (err) {
    btn.textContent = 'Error: ' + (err.message || 'Unknown');
  }

  btn.textContent = 'Scan This Page';
  btn.disabled = false;
}

// --- Copy Evidence ---

function copyEvidence() {
  if (!currentAssessment) return;

  const evidence = {
    chetana_version: '6.0.0',
    timestamp: new Date(currentAssessment.timestamp).toISOString(),
    url: currentAssessment.url,
    title: currentAssessment.title,
    trustScore: currentAssessment.trustScore,
    riskLevel: currentAssessment.riskLevel,
    signals: currentAssessment.signals,
    recommendations: currentAssessment.recommendations,
    factCheck: currentAssessment.factCheck
  };

  navigator.clipboard.writeText(JSON.stringify(evidence, null, 2)).then(() => {
    const btn = document.getElementById('copy-evidence-btn');
    btn.textContent = 'Copied!';
    setTimeout(() => { btn.textContent = 'Copy Evidence'; }, 1500);
  });
}

// --- Tab Change Listener ---

chrome.tabs.onActivated?.addListener(async (activeInfo) => {
  const lastScan = await sendMsg({ action: 'getLastScan', tabId: activeInfo.tabId });
  if (lastScan) {
    renderAssessment(lastScan);
  } else {
    renderEmpty();
  }
});

chrome.tabs.onUpdated?.addListener(async (tabId, changeInfo) => {
  if (changeInfo.status !== 'complete') return;
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab && tab.id === tabId) {
    const lastScan = await sendMsg({ action: 'getLastScan', tabId });
    if (lastScan) {
      renderAssessment(lastScan);
    } else {
      renderEmpty();
    }
  }
});

// --- Init ---

document.addEventListener('DOMContentLoaded', async () => {
  // Bind buttons
  document.getElementById('scan-btn').addEventListener('click', scanPage);
  document.getElementById('copy-evidence-btn').addEventListener('click', copyEvidence);
  document.getElementById('settings-link').addEventListener('click', (e) => {
    e.preventDefault();
    chrome.runtime.openOptionsPage();
  });

  // Check connection
  await checkConnection();

  // Load last scan for active tab
  try {
    const lastScan = await sendMsg({ action: 'getLastScan' });
    if (lastScan) {
      renderAssessment(lastScan);
    } else {
      renderEmpty();
    }
  } catch {
    renderEmpty();
  }

  // Load history
  await renderHistory();
});
