// Gnasque Web UI JavaScript

let logs = [];

const logContainer = document.getElementById('log-container');
const masqueStatus = document.getElementById('masque-status');
const masqueStatusText = document.getElementById('masque-status-text');
const warpStatus = document.getElementById('warp-status');
const warpStatusText = document.getElementById('warp-status-text');

function addLog(message) {
  const timestamp = new Date().toISOString().slice(0, 19).replace('T', ' ');
  const logEntry = `[${timestamp}] ${message}`;
  logs.push(logEntry);
  if (logs.length > 1000) logs = logs.slice(-1000);
  updateLogDisplay();
}

function updateLogDisplay() {
  logContainer.innerHTML = logs.join('<br>');
  logContainer.scrollTop = logContainer.scrollHeight;
}

function updateStatus() {
  fetch('/api/status')
    .then(r => r.json())
    .then(data => {
      if (data.masque && data.masque.running) {
        masqueStatus.className = 'status-indicator status-running';
        masqueStatusText.textContent = 'Running';
      } else {
        masqueStatus.className = 'status-indicator status-stopped';
        masqueStatusText.textContent = 'Stopped';
      }
      if (data.warp && data.warp.running) {
        warpStatus.className = 'status-indicator status-running';
        warpStatusText.textContent = 'Running';
      } else {
        warpStatus.className = 'status-indicator status-stopped';
        warpStatusText.textContent = 'Stopped';
      }
    })
    .catch(err => addLog(`Error fetching status: ${err}`));
}

document.addEventListener('DOMContentLoaded', function () {
  addLog('Gnasque Web UI initialized');
  updateStatus();
  setInterval(updateStatus, 5000);

  // Start MASQUE
  document.getElementById('masque-form').addEventListener('submit', function (e) {
    e.preventDefault();
    const formData = {
      endpoint: document.getElementById('masque-endpoint').value,
      bind: document.getElementById('masque-bind').value,
      usque_path: document.getElementById('masque-usque-path').value
    };
    fetch('/api/masque/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(formData)
    })
      .then(r => r.json())
      .then(data => {
        if (data.success) {
          addLog('MASQUE started successfully');
          updateStatus();
        } else {
          addLog(`Error starting MASQUE: ${data.error}`);
        }
      })
      .catch(err => addLog(`Error starting MASQUE: ${err}`));
  });

  // Stop MASQUE
  document.getElementById('stop-masque').addEventListener('click', function () {
    fetch('/api/masque/stop', { method: 'POST' })
      .then(r => r.json())
      .then(data => {
        if (data.success) {
          addLog('MASQUE stopped successfully');
          updateStatus();
        } else {
          addLog(`Error stopping MASQUE: ${data.error}`);
        }
      })
      .catch(err => addLog(`Error stopping MASQUE: ${err}`));
  });

  // Start WARP
  document.getElementById('warp-form').addEventListener('submit', function (e) {
    e.preventDefault();
    const formData = {
      bind: document.getElementById('warp-bind').value,
      endpoint: document.getElementById('warp-endpoint').value,
      sing_box_path: document.getElementById('warp-sing-box-path').value,
      license: document.getElementById('warp-license').value
    };
    fetch('/api/warp/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(formData)
    })
      .then(r => r.json())
      .then(data => {
        if (data.success) {
          addLog('WARP started successfully');
          updateStatus();
        } else {
          addLog(`Error starting WARP: ${data.error}`);
        }
      })
      .catch(err => addLog(`Error starting WARP: ${err}`));
  });

  // Stop WARP
  document.getElementById('stop-warp').addEventListener('click', function () {
    fetch('/api/warp/stop', { method: 'POST' })
      .then(r => r.json())
      .then(data => {
        if (data.success) {
          addLog('WARP stopped successfully');
          updateStatus();
        } else {
          addLog(`Error stopping WARP: ${data.error}`);
        }
      })
      .catch(err => addLog(`Error stopping WARP: ${err}`));
  });

  document.getElementById('refresh-status').addEventListener('click', updateStatus);
  document.getElementById('clear-logs').addEventListener('click', function () {
    logs = [];
    updateLogDisplay();
    addLog('Logs cleared');
  });

  // SSE initial dump (optional)
  fetch('/api/logs/stream').then(r => {
    if (r.ok) addLog('Loaded recent logs');
  });
});