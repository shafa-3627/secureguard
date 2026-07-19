let employees = {};
let logs = [];
let settings = { alertThreshold: 70 };
let selectedEmployeeId = null;
let threatChart = null;
let riskTrendChart = null;
let socket = null;

const getWebSocketUrl = () => {
  const wsHost = window.location.hostname || 'localhost';
  const wsPort = window.location.port === '5000' ? '5001' : (window.location.port || '3000');
  const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${wsProtocol}//${wsHost}:${wsPort}/?type=dashboard`;
};

const initWebSocket = () => {
  const url = getWebSocketUrl();
  socket = new WebSocket(url);
  
  socket.onopen = () => {
    document.querySelector('.status-dot').className = 'status-dot pulsing green';
    document.querySelector('.status-value').className = 'status-value green';
    document.querySelector('.status-value').textContent = 'ONLINE';
  };
  
  socket.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      handleSocketMessage(data);
    } catch (e) {
      console.error(e);
    }
  };
  
  socket.onclose = () => {
    document.querySelector('.status-dot').className = 'status-dot red';
    document.querySelector('.status-value').className = 'status-value red';
    document.querySelector('.status-value').textContent = 'OFFLINE';
    setTimeout(initWebSocket, 3000);
  };
};

const handleSocketMessage = (data) => {
  switch (data.type) {
    case 'INIT_STATE':
      employees = data.employees;
      logs = data.logs || [];
      if (data.settings) settings = data.settings;
      renderAll();
      break;
      
    case 'EMPLOYEE_UPDATE':
      employees[data.empId] = data.employee;
      updateOverviewMetrics();
      renderLeaderboard();
      renderEmployeeGrid();
      updateCharts();
      if (selectedEmployeeId === data.empId) {
        renderEmployeeDetail(data.empId);
      }
      checkGlobalAlerts();
      break;
      
    case 'LOG_ADDED':
      logs.unshift(data.log);
      renderLogsTable();
      renderRecentThreatFeed();
      renderReportsPreview();
      break;
      
    case 'LOGS_CLEARED':
      logs = [];
      renderLogsTable();
      renderRecentThreatFeed();
      renderReportsPreview();
      break;
  }
};

document.querySelectorAll('.nav-item').forEach(item => {
  item.addEventListener('click', (e) => {
    const navItem = e.currentTarget;
    const targetPageId = navItem.getAttribute('data-target');
    document.querySelectorAll('.nav-item').forEach(i => i.classList.remove('active'));
    navItem.classList.add('active');
    document.querySelectorAll('.page-section').forEach(page => page.classList.remove('active'));
    document.getElementById(targetPageId).classList.add('active');
  });
});

const sendMitigation = async (username, action, payload = '') => {
  try {
    await fetch('/api/mitigate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, action, payload })
    });
  } catch (error) {
    console.error(error);
  }
};

const sendReset = async (username) => {
  try {
    await fetch('/api/reset-employee', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username })
    });
  } catch (error) {
    console.error(error);
  }
};

const triggerSimulation = async (username) => {
  try {
    await fetch('/api/simulate-threat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username })
    });
  } catch (error) {
    console.error(error);
  }
};

const renderAll = () => {
  updateOverviewMetrics();
  initCharts();
  renderRecentThreatFeed();
  renderLeaderboard();
  renderEmployeeGrid();
  renderLogsTable();
  renderReportsPreview();
  checkGlobalAlerts();
};

const updateOverviewMetrics = () => {
  const empList = Object.values(employees);
  const total = empList.length;
  
  const activeThreats = empList.filter(e => e.riskScore >= settings.alertThreshold).length;
  const isolated = empList.filter(e => e.status === 'Isolated').length;
  const activeUsb = empList.filter(e => e.usbStatus !== 'No USB Connected' && !e.usbStatus.includes('Blocked')).length;
  const agentCount = empList.filter(e => e.isAgentConnected).length;
  
  document.getElementById('protected-ratio').textContent = `${total - activeThreats - isolated}/${total}`;
  document.getElementById('active-threats-count').textContent = activeThreats;
  document.getElementById('usb-active-count').textContent = activeUsb;
  document.getElementById('isolated-systems-count').textContent = isolated;
  document.getElementById('active-agents-count').textContent = `${agentCount}/${total}`;
  
  const globalThreatLevelEl = document.getElementById('global-threat-level');
  if (activeThreats > 0) {
    globalThreatLevelEl.textContent = 'HIGH';
    globalThreatLevelEl.className = 'metric-value red';
  } else if (empList.some(e => e.riskScore >= 40)) {
    globalThreatLevelEl.textContent = 'MEDIUM';
    globalThreatLevelEl.className = 'metric-value orange';
  } else {
    globalThreatLevelEl.textContent = 'LOW';
    globalThreatLevelEl.className = 'metric-value green';
  }
};

const renderRecentThreatFeed = () => {
  const feedContainer = document.getElementById('realtime-feed-list');
  feedContainer.innerHTML = '';
  const recentLogs = logs.slice(0, 5);
  
  if (recentLogs.length === 0) {
    feedContainer.innerHTML = '<div class="feed-item empty">No security events logged in this session.</div>';
    return;
  }
  
  recentLogs.forEach(log => {
    const item = document.createElement('div');
    item.className = 'feed-item';
    let color = 'blue';
    let actionColorClass = 'green';
    if (log.risk >= 70) { color = 'red'; actionColorClass = 'red'; }
    else if (log.risk >= 40) { color = 'orange'; actionColorClass = 'orange'; }
    
    if (log.actionTaken.includes('Killed') || log.actionTaken.includes('Blocked') || log.actionTaken.includes('Isolated')) {
      color = 'purple';
      actionColorClass = 'purple';
    }
    
    item.innerHTML = `
      <div class="feed-icon ${color}"></div>
      <div class="feed-info">
        <div class="feed-meta">
          <span>${log.date} @ ${log.time}</span>
          <span class="feed-user-tag">${log.username} (${log.deviceName})</span>
        </div>
        <div class="feed-title">${log.event}</div>
        <div class="feed-desc">Action taken: <span class="feed-action-tag ${actionColorClass}">${log.actionTaken}</span></div>
      </div>
    `;
    feedContainer.appendChild(item);
  });
};

const renderLeaderboard = () => {
  const container = document.getElementById('risk-leaderboard-list');
  container.innerHTML = '';
  
  const highRiskEmployees = Object.values(employees)
    .filter(e => e.riskScore > 12)
    .sort((a, b) => b.riskScore - a.riskScore)
    .slice(0, 5);
    
  if (highRiskEmployees.length === 0) {
    container.innerHTML = '<div class="leaderboard-item-placeholder">All users operating inside normal ranges.</div>';
    return;
  }
  
  highRiskEmployees.forEach(emp => {
    const item = document.createElement('div');
    item.className = 'leaderboard-item';
    let colorClass = 'green';
    if (emp.riskScore >= settings.alertThreshold) colorClass = 'red';
    else if (emp.riskScore >= 40) colorClass = 'orange';
    
    item.innerHTML = `
      <div class="leaderboard-user">
        <span class="leaderboard-name">${emp.name}</span>
        <span class="leaderboard-dept">${emp.department}</span>
      </div>
      <div class="leaderboard-score-bar-wrapper">
        <span class="leaderboard-score-num ${colorClass}">${emp.riskScore}/100</span>
        <div class="progress-container" style="height: 4px;">
          <div class="progress-bar ${colorClass}" style="width: ${emp.riskScore}%;"></div>
        </div>
      </div>
    `;
    
    item.addEventListener('click', () => {
      document.querySelector('.nav-item[data-target="page-employees"]').click();
      selectEmployeeCard(emp.name.toLowerCase());
    });
    container.appendChild(item);
  });
};

const renderEmployeeGrid = () => {
  const grid = document.getElementById('employees-grid-list');
  const searchVal = document.getElementById('employee-search').value.toLowerCase();
  const filterVal = document.getElementById('employee-status-filter').value;
  grid.innerHTML = '';
  
  const filtered = Object.values(employees).filter(emp => {
    const matchesSearch = emp.name.toLowerCase().includes(searchVal) || 
                          emp.department.toLowerCase().includes(searchVal) ||
                          emp.deviceName.toLowerCase().includes(searchVal);
    let matchesStatus = true;
    if (filterVal === 'high') matchesStatus = emp.riskScore >= settings.alertThreshold;
    else if (filterVal === 'medium') matchesStatus = emp.riskScore >= 40 && emp.riskScore < settings.alertThreshold;
    else if (filterVal === 'low') matchesStatus = emp.riskScore < 40;
    return matchesSearch && matchesStatus;
  });
  
  if (filtered.length === 0) {
    grid.innerHTML = '<div class="empty-state" style="grid-column: 1/-1;">No endpoints match search filters.</div>';
    return;
  }
  
  filtered.forEach(emp => {
    const card = document.createElement('div');
    const empId = emp.name.toLowerCase();
    card.className = `employee-card ${selectedEmployeeId === empId ? 'active' : ''}`;
    card.setAttribute('data-id', empId);
    
    let riskColor = 'green';
    if (emp.riskScore >= settings.alertThreshold) riskColor = 'red';
    else if (emp.riskScore >= 40) riskColor = 'orange';
    
    let statusClass = 'green';
    if (emp.status === 'Compromised') statusClass = 'red';
    else if (emp.status === 'Vulnerable') statusClass = 'orange';
    else if (emp.status === 'Isolated') statusClass = 'purple';
    
    card.innerHTML = `
      <div class="card-top-row">
        <span class="employee-card-name">${emp.name}</span>
        <span class="agent-dot-indicator ${emp.isAgentConnected ? 'connected' : ''}"></span>
      </div>
      <span class="employee-card-dept">${emp.department} &bull; ${emp.deviceName}</span>
      <div class="card-stats-row">
        <span class="card-risk-badge ${riskColor}">${emp.riskScore}</span>
        <span class="card-status-label ${statusClass}">${emp.status}</span>
      </div>
    `;
    card.addEventListener('click', () => selectEmployeeCard(empId));
    grid.appendChild(card);
  });
};

const selectEmployeeCard = (empId) => {
  selectedEmployeeId = empId;
  document.querySelectorAll('.employee-card').forEach(c => {
    c.classList.remove('active');
    if (c.getAttribute('data-id') === empId) c.classList.add('active');
  });
  renderEmployeeDetail(empId);
};

const renderEmployeeDetail = (empId) => {
  const emp = employees[empId];
  if (!emp) return;
  
  document.getElementById('detail-placeholder').classList.add('hide');
  document.getElementById('detail-content').classList.remove('hide');
  
  document.getElementById('detail-emp-name').textContent = emp.name;
  document.getElementById('detail-emp-dept').textContent = `${emp.department} Department`;
  document.getElementById('detail-device-name').textContent = emp.deviceName;
  document.getElementById('detail-agent-status').textContent = emp.isAgentConnected ? 'CONNECTED' : 'Simulated Telemetry';
  document.getElementById('detail-agent-status').className = emp.isAgentConnected ? 'bold text-green' : '';
  
  const usbText = document.getElementById('detail-usb-status');
  usbText.textContent = emp.usbStatus;
  if (emp.usbStatus.includes('Unverified')) usbText.className = 'bold text-red';
  else if (emp.usbStatus.includes('Blocked')) usbText.className = 'bold text-purple';
  else usbText.className = '';
  
  const riskScoreText = document.getElementById('detail-risk-score');
  riskScoreText.textContent = `${emp.riskScore}/100`;
  
  let threatText = emp.threatLevel;
  if (emp.status === 'Isolated') threatText = 'ISOLATED';
  const threatBadge = document.getElementById('detail-threat-badge');
  threatBadge.textContent = threatText;
  threatBadge.className = `threat-status-badge ${threatText}`;
  
  const cpuBar = document.getElementById('detail-cpu-bar');
  const memBar = document.getElementById('detail-mem-bar');
  document.getElementById('detail-cpu-text').textContent = `${emp.cpuUsage}%`;
  document.getElementById('detail-mem-text').textContent = `${emp.memoryUsage}%`;
  cpuBar.style.width = `${emp.cpuUsage}%`;
  memBar.style.width = `${emp.memoryUsage}%`;
  
  const processList = document.getElementById('detail-process-list');
  processList.innerHTML = '';
  const whitelist = ['chrome.exe', 'code.exe', 'explorer.exe', 'excel.exe', 'winword.exe', 'node.exe', 'python.exe', 'cmd.exe', 'powershell.exe', 'taskmgr.exe', 'system idle process'];
  
  emp.runningProcesses.forEach(proc => {
    const item = document.createElement('li');
    const isSuspicious = !whitelist.includes(proc.toLowerCase());
    item.className = `process-item ${isSuspicious ? 'suspicious' : ''}`;
    item.innerHTML = `
      <span class="process-item-name">${isSuspicious ? '⚠️ ' : ''}${proc}</span>
      ${isSuspicious ? `<button class="kill-inline-btn" onclick="sendMitigation('${emp.name}', 'KILL_PROCESS', '${proc}')">X</button>` : ''}
    `;
    processList.appendChild(item);
  });
  
  const timeline = document.getElementById('detail-timeline');
  timeline.innerHTML = '';
  emp.activityTimeline.forEach(evt => {
    const item = document.createElement('div');
    item.className = `timeline-item ${evt.type || 'info'}`;
    item.innerHTML = `<div class="timeline-meta"><span class="timeline-time">${evt.time}</span></div><div class="timeline-event">${evt.event}</div>`;
    timeline.appendChild(item);
  });
  
  const isolateBtn = document.getElementById('control-btn-isolate');
  if (emp.status === 'Isolated') {
    isolateBtn.textContent = 'Quarantined';
    isolateBtn.disabled = true;
    isolateBtn.className = 'btn btn-outline';
  } else {
    isolateBtn.textContent = 'Isolate Network';
    isolateBtn.disabled = false;
    isolateBtn.className = 'btn btn-danger';
  }
  
  const blockUsbBtn = document.getElementById('control-btn-blockusb');
  blockUsbBtn.disabled = emp.usbStatus === 'No USB Connected' || emp.usbStatus.includes('Blocked');
  
  document.getElementById('control-btn-reset').onclick = () => sendReset(emp.name);
  isolateBtn.onclick = () => sendMitigation(emp.name, 'ISOLATE_SYSTEM');
  blockUsbBtn.onclick = () => sendMitigation(emp.name, 'BLOCK_USB');
};

const renderLogsTable = () => {
  const tbody = document.getElementById('logs-table-body');
  const searchVal = document.getElementById('log-search').value.toLowerCase();
  const riskVal = document.getElementById('log-risk-filter').value;
  const emptyState = document.getElementById('logs-empty-state');
  tbody.innerHTML = '';
  
  const filteredLogs = logs.filter(log => {
    const matchesSearch = log.username.toLowerCase().includes(searchVal) || log.event.toLowerCase().includes(searchVal);
    let matchesRisk = true;
    if (riskVal === 'critical') matchesRisk = log.risk >= settings.alertThreshold;
    else if (riskVal === 'warning') matchesRisk = log.risk >= 30 && log.risk < settings.alertThreshold;
    else if (riskVal === 'info') matchesRisk = log.risk < 30;
    return matchesSearch && matchesRisk;
  });
  
  if (filteredLogs.length === 0) {
    emptyState.classList.remove('hide');
    return;
  }
  emptyState.classList.add('hide');
  
  filteredLogs.forEach(log => {
    const tr = document.createElement('tr');
    let pillClass = log.risk >= settings.alertThreshold ? 'high' : (log.risk >= 40 ? 'medium' : 'low');
    tr.innerHTML = `<td>${log.date}</td><td>${log.time}</td><td>${log.username}</td><td>${log.deviceName}</td><td>${log.event}</td><td><span class="risk-pill ${pillClass}">${log.risk}</span></td><td>${log.actionTaken}</td>`;
    tbody.appendChild(tr);
  });
};

const checkGlobalAlerts = () => {
  const alertBanner = document.getElementById('live-alert-container');
  const criticalEmp = Object.values(employees).find(e => e.riskScore >= settings.alertThreshold && e.status !== 'Isolated');
  
  if (criticalEmp) {
    document.getElementById('banner-employee-name').textContent = criticalEmp.name;
    document.getElementById('banner-employee-dept').textContent = criticalEmp.department;
    document.getElementById('banner-alert-time').textContent = new Date().toLocaleTimeString();
    
    const reasonsContainer = document.getElementById('banner-alert-reasons');
    reasonsContainer.innerHTML = '';
    criticalEmp.alerts.forEach(reason => {
      const li = document.createElement('li');
      li.textContent = reason;
      reasonsContainer.appendChild(li);
    });
    
    document.getElementById('banner-btn-isolate').onclick = () => {
      sendMitigation(criticalEmp.name, 'ISOLATE_SYSTEM');
      alertBanner.classList.add('hide');
    };
    
    document.getElementById('banner-btn-kill').onclick = () => {
      const suspiciousProc = criticalEmp.runningProcesses.find(p => p.toLowerCase() === 'malware.exe' || p.toLowerCase() === 'ransomware.exe');
      sendMitigation(criticalEmp.name, 'KILL_PROCESS', suspiciousProc || 'malware.exe');
      alertBanner.classList.add('hide');
    };
    
    document.getElementById('banner-btn-dismiss').onclick = () => alertBanner.classList.add('hide');
    alertBanner.classList.remove('hide');
  } else {
    alertBanner.classList.add('hide');
  }
};

const renderReportsPreview = () => {
  const empList = Object.values(employees);
  const activeThreats = empList.filter(e => e.riskScore >= settings.alertThreshold).length;
  
  let highestUser = 'None';
  let highestScore = 0;
  empList.forEach(e => {
    if (e.riskScore > highestScore) {
      highestScore = e.riskScore;
      highestUser = e.name;
    }
  });
  if (highestScore <= 12) highestUser = 'None';
  else highestUser = `${highestUser} (${highestScore}/100)`;
  
  const blockedUsbEvents = logs.filter(log => log.event.includes('USB') && log.actionTaken.includes('Blocked')).length;
  
  document.getElementById('report-blocked-usb').textContent = blockedUsbEvents;
  document.getElementById('report-threats-count').textContent = activeThreats;
  document.getElementById('report-highest-risk-user').textContent = highestUser;
  document.getElementById('report-date-str').textContent = new Date().toLocaleDateString(undefined, { year: 'numeric', month: 'long', day: 'numeric' });
  
  const statusBadge = document.getElementById('report-status-badge');
  statusBadge.textContent = activeThreats > 0 ? 'VULNERABLE' : 'SECURE';
  statusBadge.className = activeThreats > 0 ? 'status-pill red' : 'status-pill green';
};

const initCharts = () => {
  const threatCtx = document.getElementById('threat-chart').getContext('2d');
  const trendCtx = document.getElementById('risk-trend-chart').getContext('2d');
  const empList = Object.values(employees);
  
  const counts = { Protected: 0, Vulnerable: 0, Compromised: 0, Isolated: 0 };
  empList.forEach(e => counts[e.status] = (counts[e.status] || 0) + 1);
  
  if (threatChart) threatChart.destroy();
  threatChart = new Chart(threatCtx, {
    type: 'doughnut',
    data: {
      labels: ['Protected', 'Vulnerable', 'Compromised', 'Isolated'],
      datasets: [{
        data: [counts.Protected, counts.Vulnerable, counts.Compromised, counts.Isolated],
        backgroundColor: ['#10b981', '#f59e0b', '#ef4444', '#8b5cf6'],
        borderWidth: 2,
        borderColor: '#0b1021'
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { position: 'right', labels: { color: '#94a3b8', font: { family: 'Outfit', size: 11 } } } },
      cutout: '65%'
    }
  });
  
  const sortedEmps = empList.sort((a, b) => b.riskScore - a.riskScore);
  if (riskTrendChart) riskTrendChart.destroy();
  riskTrendChart = new Chart(trendCtx, {
    type: 'bar',
    data: {
      labels: sortedEmps.map(e => e.name),
      datasets: [{
        label: 'Risk Score',
        data: sortedEmps.map(e => e.riskScore),
        backgroundColor: sortedEmps.map(e => e.riskScore >= settings.alertThreshold ? '#ef4444' : (e.riskScore >= 40 ? '#f59e0b' : '#10b981')),
        borderRadius: 4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: { ticks: { color: '#64748b', font: { size: 8 } }, grid: { display: false } },
        y: { min: 0, max: 100, ticks: { color: '#64748b' }, grid: { color: '#1a2544' } }
      },
      plugins: { legend: { display: false } }
    }
  });
};

const updateCharts = () => {
  if (!threatChart || !riskTrendChart) return;
  const empList = Object.values(employees);
  const counts = { Protected: 0, Vulnerable: 0, Compromised: 0, Isolated: 0 };
  empList.forEach(e => counts[e.status] = (counts[e.status] || 0) + 1);
  threatChart.data.datasets[0].data = [counts.Protected, counts.Vulnerable, counts.Compromised, counts.Isolated];
  threatChart.update();
  
  const sortedEmps = empList.sort((a, b) => b.riskScore - a.riskScore);
  riskTrendChart.data.labels = sortedEmps.map(e => e.name);
  riskTrendChart.data.datasets[0].data = sortedEmps.map(e => e.riskScore);
  riskTrendChart.data.datasets[0].backgroundColor = sortedEmps.map(e => e.riskScore >= settings.alertThreshold ? '#ef4444' : (e.riskScore >= 40 ? '#f59e0b' : '#10b981'));
  riskTrendChart.update();
};

document.getElementById('employee-search').addEventListener('input', renderEmployeeGrid);
document.getElementById('employee-status-filter').addEventListener('change', renderEmployeeGrid);
document.getElementById('log-search').addEventListener('input', renderLogsTable);
document.getElementById('log-risk-filter').addEventListener('change', renderLogsTable);

document.getElementById('btn-clear-logs').addEventListener('click', async () => {
  if (confirm('Flush log archives?')) {
    await fetch('/api/logs/clear', { method: 'POST' });
  }
});

document.getElementById('input-threshold').addEventListener('change', (e) => {
  const newVal = parseInt(e.target.value);
  if (newVal >= 10 && newVal <= 95) {
    settings.alertThreshold = newVal;
    Object.values(employees).forEach(emp => {
      if (emp.riskScore >= settings.alertThreshold) {
        emp.status = 'Compromised';
        emp.threatLevel = 'HIGH';
      } else if (emp.riskScore >= 40) {
        emp.status = 'Vulnerable';
        emp.threatLevel = 'MEDIUM';
      } else {
        emp.status = 'Protected';
        emp.threatLevel = 'LOW';
      }
      if (emp.isIsolated) emp.status = 'Isolated';
    });
    renderAll();
  }
});

document.getElementById('btn-demo-normal').addEventListener('click', () => {
  sendReset('rithish');
});
document.getElementById('btn-demo-threat').addEventListener('click', () => {
  triggerSimulation('kumar');
});
document.getElementById('btn-demo-threat2').addEventListener('click', () => {
  triggerSimulation('employee-07');
});

window.onload = initWebSocket;