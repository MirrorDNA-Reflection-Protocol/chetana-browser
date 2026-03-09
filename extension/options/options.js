// Chetana Browser v6 — Options Page Logic

const DEFAULT_SETTINGS = {
  backendUrl: 'http://127.0.0.1:8799',
  autoScan: true,
  submitGuard: true,
  overlayPosition: 'bottom-right',
  overlayAutoHide: 10000,
  linkHoverTooltips: true
};

const fields = {
  backendUrl: document.getElementById('backendUrl'),
  autoScan: document.getElementById('autoScan'),
  submitGuard: document.getElementById('submitGuard'),
  linkHoverTooltips: document.getElementById('linkHoverTooltips'),
  overlayPosition: document.getElementById('overlayPosition'),
  overlayAutoHide: document.getElementById('overlayAutoHide')
};

function loadSettingsIntoUI(settings) {
  const s = { ...DEFAULT_SETTINGS, ...settings };
  fields.backendUrl.value = s.backendUrl;
  fields.autoScan.checked = s.autoScan;
  fields.submitGuard.checked = s.submitGuard;
  fields.linkHoverTooltips.checked = s.linkHoverTooltips;
  fields.overlayPosition.value = s.overlayPosition;
  fields.overlayAutoHide.value = String(s.overlayAutoHide);
}

function readSettingsFromUI() {
  return {
    backendUrl: fields.backendUrl.value.trim() || DEFAULT_SETTINGS.backendUrl,
    autoScan: fields.autoScan.checked,
    submitGuard: fields.submitGuard.checked,
    linkHoverTooltips: fields.linkHoverTooltips.checked,
    overlayPosition: fields.overlayPosition.value,
    overlayAutoHide: parseInt(fields.overlayAutoHide.value, 10)
  };
}

function showSaved() {
  const status = document.getElementById('saveStatus');
  status.classList.add('visible');
  setTimeout(() => status.classList.remove('visible'), 2000);
}

// Load
chrome.runtime.sendMessage({ action: 'getSettings' }, (settings) => {
  if (settings) loadSettingsIntoUI(settings);
});

// Save
document.getElementById('saveBtn').addEventListener('click', () => {
  const settings = readSettingsFromUI();
  chrome.runtime.sendMessage({ action: 'saveSettings', settings }, () => {
    showSaved();
  });
});

// Clear history
document.getElementById('clearHistory').addEventListener('click', () => {
  if (confirm('Clear all scan history?')) {
    chrome.runtime.sendMessage({ action: 'clearHistory' }, () => {
      const btn = document.getElementById('clearHistory');
      btn.textContent = 'Cleared!';
      setTimeout(() => { btn.textContent = 'Clear History'; }, 1500);
    });
  }
});
