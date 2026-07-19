let employees = {};
let logs = [];
let settings = { alertThreshold: 70 };
let selectedEmployeeId = null;
let threatChart = null;
let riskTrendChart = null;
let socket = null;

// ==========================================
// 1. OFFLINE DEMO SIMULATION FALLBACK
// ==========================================

const isLocal = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1' || window.location.hostname === '';
let useDemoMode = !isLocal;
let activeSimulations = {};

const initializeDemoState = () => {
  console.log("[EDR-DEMO] Initializing Browser Mock Telemetry Mode.");
  useDemoMode = true;
  
  // Seed 20 employees (mirroring Python backend)
  const employeeNames = [
    'Rithish', 'Rahul', 'Kumar', 'Vijay', 'Anand', 
    'Employee-07', 'Suresh', 'Priya', 'Amit', 'Deepa', 
    'Vikram', 'Neha', 'Kavitha', 'Arjun', 'Sanjay', 
    'Divya', 'Meera', 'Rajesh', 'Karthik', 'Manoj'
  ];
  const departments = ['IT', 'Engineering', 'Finance', 'HR', 'Sales', 'Finance', 'IT', 'Operations', 'Engineering', 'Marketing', 'Sales', 'Legal', 'HR', 'IT', 'Finance', 'Engineering', 'Marketing', 'Operations', 'IT', 'Sales'];
  
  employeeNames.forEach((name, i) => {
    const empId = name.toLowerCase();
    if (!employees[empId]) {
      employees[empId] = {
        name: name,
        department: departments[i],
        deviceName: `WORKSTATION-${name.toUpperCase()}`,
        status: 'Protected',
        riskScore: 12,
        threatLevel: 'LOW',
        isAgentConnected: i === 2 || i === 5, // Kumar and Employee-07 have agent connected in demo
        usbStatus: 'No USB Connected',
        cpuUsage: 12,
        memoryUsage: 35,
        runningProcesses: ['chrome.exe', 'code.exe', 'explorer.exe'],
        alerts: [],
        activityTimeline: [
          { time: '09:00 AM', event: 'System Boot & Login', risk: 0, type: 'info' },
          { time: '09:10 AM', event: 'Chrome Browser Opened', risk: 0, type: 'info' },
          { time: '09:15 AM', event: 'VS Code IDE Opened', risk: 0, type: 'info' }
        ],
        isIsolated: false,
        underActiveThreatSimulation: false
      };
    }
  });

  // Seed default threat logs if empty
  if (logs.length === 0) {
    const now = new Date();
    logs = [
      {
        id: 'log-1',
        time: new Date(now.getTime() - 200 * 60 * 000).toLocaleTimeString(),
        date: new Date(now.getTime() - 200 * 60 * 000).toLocaleDateString(),
        username: 'Rahul',
        deviceName: 'WORKSTATION-RAHUL',
        event: 'USB Connected',
        risk: 20,
        actionTaken: 'Monitored'
      },
      {
        id: 'log-2',
        time: new Date(now.getTime() - 100 * 60 * 000).toLocaleTimeString(),
        date: new Date(now.getTime() - 100 * 60 * 000).toLocaleDateString(),
        username: 'Vijay',
        deviceName: 'WORKSTATION-VIJAY',
        event: 'Unknown Process Opened: cheatengine.exe',
        risk: 40,
        actionTaken: 'Alert Generated'
      },
      {
        id: 'log-3',
        time: new Date(now.getTime() - 98 * 60 * 000).toLocaleTimeString(),
        date: new Date(now.getTime() - 98 * 60 * 000).toLocaleDateString(),
        username: 'Vijay',
        deviceName: 'WORKSTATION-VIJAY',
        event: 'Sensitive Folder Access: D:\\HR_SalaryReview',
        risk: 60,
        actionTaken: 'Process Terminated'
      }
    ];
  }

  renderAll();

  // Fluctuate CPU/Memory every 4 seconds
  if (!window.demoWorkerInterval) {
    window.demoWorkerInterval = setInterval(() => {
      if (!useDemoMode) return;
      
      Object.keys(employees).forEach(empId => {
        const emp = employees[empId];
        if (emp.isIsolated || emp.underActiveThreatSimulation) return;
        
        // Minor telemetry shifts
        emp.cpuUsage = Math.max(5, Math.min(65, Math.floor(emp.cpuUsage + (Math.random() * 10 - 5))));
        emp.memoryUsage = Math.max(20, Math.min(80, Math.floor(emp.memoryUsage + (Math.random() * 6 - 3))));
        
        calculateRiskLocal(emp);
      });
      
      updateOverviewMetrics();
      renderLeaderboard();
      renderEmployeeGrid();
      updateCharts();
      if (selectedEmployeeId) {
        renderEmployeeDetail(selectedEmployeeId);
      }
    }, 4000);
  }
};

const calculateRiskLocal = (employee) => {
  let score = 10;
  let alerts = [];
  
  const outOfHours = employee.activityTimeline.some(e => e.event.includes("Outside Office Hours"));
  if (outOfHours) { score += 20; alerts.push('Login Outside Office Hours'); }
  
  if (employee.usbStatus !== 'No USB Connected' && !employee.usbStatus.includes("Blocked")) {
    score += 20;
    alerts.push('Unknown USB Device Connected');
  }
  
  if (employee.cpuUsage > 80) { score += 15; alerts.push('Abnormal High CPU Usage'); }
  
  const suspiciousProcess = employee.runningProcesses.some(proc => 
    !['chrome.exe', 'code.exe', 'explorer.exe', 'excel.exe', 'winword.exe', 'outlook.exe', 'teams.exe', 'slack.exe', 'spotify.exe', 'node.exe', 'python.exe', 'cmd.exe', 'powershell.exe', 'taskmgr.exe', 'system idle process'].includes(proc.toLowerCase()) ||
    ['malware.exe', 'ransomware.exe', 'mimikatz.exe'].includes(proc.toLowerCase())
  );
  if (suspiciousProcess) { score += 30; alerts.push('Suspicious Executable Started'); }
  
  const folderAccess = employee.activityTimeline.some(e => e.event.includes("Sensitive Folder Access"));
  if (folderAccess) { score += 25; alerts.push('Multiple Sensitive Folder Access'); }
  
  score = Math.min(100, Math.max(0, score));
  
  let level = 'LOW';
  if (score >= settings.alertThreshold) {
    level = 'HIGH';
    employee.status = 'Compromised';
  } else if (score >= 40) {
    level = 'MEDIUM';
    employee.status = 'Vulnerable';
  } else {
    level = 'LOW';
    employee.status = 'Protected';
  }
  
  if (employee.isIsolated) {
    employee.status = 'Isolated';
  }
  
  employee.riskScore = score;
  employee.threatLevel = level;
  employee.alerts = alerts;
};

const logEventLocal = (username, deviceName, event, risk, action) => {
  const now = new Date();
  const log = {
    id: `log-${Date.now()}-${Math.random().toString(36).substr(2, 4)}`,
    time: now.toLocaleTimeString(),
    date: now.toLocaleDateString(),
    username,
    deviceName,
    event,
    risk,
    actionTaken: action
  };
  
  logs.unshift(log);
  renderLogsTable();
  renderRecentThreatFeed();
  renderReportsPreview();
};

const runSimulationStepLocal = (empId) => {
  if (!activeSimulations[empId]) {
    activeSimulations[empId] = 0;
  }
  
  const step = activeSimulations[empId];
  const emp = employees[empId];
  if (!emp || !emp.underActiveThreatSimulation) {
    delete activeSimulations[empId];
    return;
  }
  
  const timeStr = new Date().toLocaleTimeString();
  
  if (step === 0) {
    emp.activityTimeline.push({ time: timeStr, event: 'Login Outside Office Hours (Alert Triggered)', risk: 20, type: 'warning' });
    calculateRiskLocal(emp);
    logEventLocal(emp.name, emp.deviceName, 'Login Outside Office Hours', emp.riskScore, 'Monitored');
  } else if (step === 1) {
    emp.usbStatus = 'Kingston USB 3.0 (Unverified)';
    emp.activityTimeline.push({ time: timeStr, event: 'Unknown USB Device Connected', risk: 20, type: 'warning' });
    calculateRiskLocal(emp);
    logEventLocal(emp.name, emp.deviceName, 'USB Device Inserted: Kingston USB 3.0', emp.riskScore, 'Alert Generated');
  } else if (step === 2) {
    emp.runningProcesses.push('malware.exe');
    emp.activityTimeline.push({ time: timeStr, event: 'Unknown Process Started: malware.exe', risk: 30, type: 'threat' });
    calculateRiskLocal(emp);
    logEventLocal(emp.name, emp.deviceName, 'Process Started: malware.exe (Suspicious)', emp.riskScore, 'Alert Generated');
  } else if (step === 3) {
    emp.cpuUsage = 88;
    emp.activityTimeline.push({ time: timeStr, event: 'Abnormal CPU Usage detected (88%)', risk: 15, type: 'warning' });
    calculateRiskLocal(emp);
    logEventLocal(emp.name, emp.deviceName, 'High CPU Usage Detected (88%)', emp.riskScore, 'Monitored');
  } else if (step === 4) {
    emp.activityTimeline.push({ time: timeStr, event: 'Multiple Sensitive Folder Access (D:\\Finance\\Salaries)', risk: 25, type: 'threat' });
    calculateRiskLocal(emp);
    logEventLocal(emp.name, emp.deviceName, 'Unauthorized Folder Access Attempt: D:\\Finance\\Salaries', emp.riskScore, 'Security Rule Triggered');
    emp.underActiveThreatSimulation = false;
    delete activeSimulations[empId];
  }
  
  updateOverviewMetrics();
  renderLeaderboard();
  renderEmployeeGrid();
  updateCharts();
  if (selectedEmployeeId === empId) {
    renderEmployeeDetail(empId);
  }
  checkGlobalAlerts();
  
  if (emp.underActiveThreatSimulation) {
    activeSimulations[empId]++;
    setTimeout(() => runSimulationStepLocal(empId), 3500);
  }
};

// ==========================================
// 2. ROUTING AND AUTHENTICATION
// ==========================================

const checkAuth = () => {
  const isLoggedIn = sessionStorage.getItem('isLoggedIn') === 'true';
  const currentHash = window.location.hash;
  
  if (!isLoggedIn) {
    if (currentHash !== '#/login') {
      window.location.hash = '#/login';
    }
    showLoginView();
  } else {
    if (currentHash === '#/login' || currentHash === '') {
      window.location.hash = '#/overview';
    }
    showAppView();
    if (useDemoMode) {
      initializeDemoState();
    } else if (!socket || socket.readyState !== WebSocket.OPEN) {
      initWebSocket();
    }
  }
};

const showLoginView = () => {
  document.getElementById('login-container').classList.remove('hide');
  document.getElementById('app-container').classList.add('hide');
};

const showAppView = () => {
  document.getElementById('login-container').classList.add('hide');
  document.getElementById('app-container').classList.remove('hide');
};

const handleRouting = () => {
  const hash = window.location.hash || '#/overview';
  
  if (hash === '#/login') {
    showLoginView();
    return;
  }
  
  showAppView();
  
  const routeMap = {
    '#/overview': 'page-overview',
    '#/endpoints': 'page-employees',
    '#/logs': 'page-logs',
    '#/reports': 'page-reports',
    '#/agent-onboarding': 'page-onboarding'
  };
  
  const targetPageId = routeMap[hash] || 'page-overview';
  
  document.querySelectorAll('.sidebar .nav-item').forEach(item => {
    const target = item.getAttribute('data-target');
    if (targetPageId === target) {
      item.classList.add('active');
    } else {
      item.classList.remove('active');
    }
  });
  
  document.querySelectorAll('.page-section').forEach(page => {
    if (page.id === targetPageId) {
      page.classList.add('active');
    } else {
      page.classList.remove('active');
    }
  });
  
  if (hash === '#/overview' && employees && Object.keys(employees).length > 0) {
    setTimeout(initCharts, 50);
  }
  
  if (hash === '#/agent-onboarding') {
    renderOnboardingPage();
  }
};

// Wire up login form
document.getElementById('login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const usernameInput = document.getElementById('login-username').value;
  const passwordInput = document.getElementById('login-password').value;
  const errorMsg = document.getElementById('login-error-msg');
  
  errorMsg.classList.add('hide');
  
  if (useDemoMode) {
    if (usernameInput === 'admin' && passwordInput === 'secureguard') {
      sessionStorage.setItem('isLoggedIn', 'true');
      sessionStorage.setItem('username', usernameInput);
      window.location.hash = '#/overview';
      checkAuth();
    } else {
      errorMsg.textContent = '⚠️ Invalid credentials. Use admin / secureguard';
      errorMsg.classList.remove('hide');
    }
    return;
  }
  
  try {
    const res = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: usernameInput, password: passwordInput })
    });
    
    const data = await res.json();
    if (data.success) {
      sessionStorage.setItem('isLoggedIn', 'true');
      sessionStorage.setItem('username', usernameInput);
      window.location.hash = '#/overview';
      checkAuth();
    } else {
      errorMsg.textContent = `⚠️ ${data.message || 'Invalid credentials'}`;
      errorMsg.classList.remove('hide');
    }
  } catch (err) {
    console.error("[EDR] Login API failed. Falling back to Demo Mode credentials.");
    if (usernameInput === 'admin' && passwordInput === 'secureguard') {
      useDemoMode = true;
      sessionStorage.setItem('isLoggedIn', 'true');
      sessionStorage.setItem('username', usernameInput);
      window.location.hash = '#/overview';
      checkAuth();
    } else {
      errorMsg.textContent = '⚠️ Invalid credentials (admin / secureguard).';
      errorMsg.classList.remove('hide');
    }
  }
});

// Wire up logout button
document.getElementById('btn-logout').addEventListener('click', () => {
  sessionStorage.clear();
  if (socket) {
    socket.close();
  }
  window.location.hash = '#/login';
  checkAuth();
});

// Wire up sidebar clicks for routing
document.querySelectorAll('.sidebar .nav-item').forEach(item => {
  item.addEventListener('click', (e) => {
    const target = e.currentTarget.getAttribute('data-target');
    const routeMap = {
      'page-overview': '#/overview',
      'page-employees': '#/endpoints',
      'page-logs': '#/logs',
      'page-reports': '#/reports',
      'page-onboarding': '#/agent-onboarding'
    };
    if (routeMap[target]) {
      window.location.hash = routeMap[target];
    }
  });
});

// Wire up onboarding page copy buttons
document.querySelectorAll('.btn-copy-code').forEach(btn => {
  btn.addEventListener('click', (e) => {
    const targetId = e.currentTarget.getAttribute('data-target');
    const text = document.getElementById(targetId).textContent;
    navigator.clipboard.writeText(text).then(() => {
      const originalText = e.currentTarget.textContent;
      e.currentTarget.textContent = 'Copied!';
      setTimeout(() => {
        e.currentTarget.textContent = originalText;
      }, 1500);
    });
  });
});

window.addEventListener('hashchange', handleRouting);

// ==========================================
// 3. WEBSOCKET LOGIC & FEEDS
// ==========================================

const getWebSocketUrl = () => {
  const wsHost = window.location.hostname || 'localhost';
  const wsPort = window.location.port === '5000' ? '5001' : (window.location.port || '3000');
  const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${wsProtocol}//${wsHost}:${wsPort}/?type=dashboard`;
};

const initWebSocket = () => {
  if (useDemoMode) return;
  if (sessionStorage.getItem('isLoggedIn') !== 'true') return;
  
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
  
  socket.onerror = () => {
    console.error("[EDR-WS] Telemetry websocket failed to connect. Loading offline simulator.");
    useDemoMode = true;
    initializeDemoState();
  };
  
  socket.onclose = () => {
    document.querySelector('.status-dot').className = 'status-dot red';
    document.querySelector('.status-value').className = 'status-value red';
    document.querySelector('.status-value').textContent = 'OFFLINE';
    
    if (sessionStorage.getItem('isLoggedIn') === 'true' && !useDemoMode) {
      setTimeout(initWebSocket, 3000);
    }
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
      renderOnboardingPage();
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

const sendMitigation = async (username, action, payload = '') => {
  const empId = username.toLowerCase();
  const emp = employees[empId];
  
  if (useDemoMode && emp) {
    const timeStr = new Date().toLocaleTimeString();
    if (action === 'KILL_PROCESS') {
      emp.runningProcesses = emp.runningProcesses.filter(p => p !== payload);
      if (payload === 'malware.exe') emp.cpuUsage = 15;
      emp.activityTimeline.push({ time: timeStr, event: `Process Blocked & Killed: ${payload}`, risk: 0, type: 'mitigation' });
      calculateRiskLocal(emp);
      logEventLocal(emp.name, emp.deviceName, `Process Terminated: ${payload}`, emp.riskScore, 'Admin Action: Killed Process');
    } else if (action === 'BLOCK_USB') {
      emp.usbStatus = 'No USB Connected (Blocked)';
      emp.activityTimeline.push({ time: timeStr, event: 'USB Device Blocked & Ejected', risk: 0, type: 'mitigation' });
      calculateRiskLocal(emp);
      logEventLocal(emp.name, emp.deviceName, 'USB Drive Blocked & Ejected', emp.riskScore, 'Admin Action: Blocked USB');
    } else if (action === 'ISOLATE_SYSTEM') {
      emp.isIsolated = true;
      emp.activityTimeline.push({ time: timeStr, event: 'Network Isolation Triggered', risk: 0, type: 'mitigation' });
      calculateRiskLocal(emp);
      logEventLocal(emp.name, emp.deviceName, 'System Network Isolated', emp.riskScore, 'Admin Action: Isolated System');
    }
    
    renderAll();
    if (selectedEmployeeId === empId) {
      renderEmployeeDetail(empId);
    }
    return;
  }

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
  const empId = username.toLowerCase();
  const emp = employees[empId];
  
  if (useDemoMode && emp) {
    emp.underActiveThreatSimulation = false;
    emp.isIsolated = false;
    emp.cpuUsage = 12;
    emp.memoryUsage = 35;
    emp.usbStatus = 'No USB Connected';
    emp.runningProcesses = ['chrome.exe', 'code.exe', 'explorer.exe'];
    emp.activityTimeline = [
      { time: '09:00 AM', event: 'System Boot & Login', risk: 0, type: 'info' },
      { time: '09:10 AM', event: 'Chrome Opened', risk: 0, type: 'info' },
      { time: '09:15 AM', event: 'VS Code Opened', risk: 0, type: 'info' }
    ];
    calculateRiskLocal(emp);
    renderAll();
    if (selectedEmployeeId === empId) {
      renderEmployeeDetail(empId);
    }
    return;
  }

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
  const empId = username.toLowerCase();
  const emp = employees[empId];
  
  if (useDemoMode && emp) {
    if (emp.underActiveThreatSimulation) return;
    emp.underActiveThreatSimulation = true;
    emp.isIsolated = false;
    emp.cpuUsage = 15;
    emp.usbStatus = 'No USB Connected';
    emp.runningProcesses = ['chrome.exe', 'code.exe', 'explorer.exe'];
    emp.activityTimeline = [
      { time: new Date().toLocaleTimeString(), event: 'System Boot & Login', risk: 0, type: 'info' }
    ];
    calculateRiskLocal(emp);
    
    renderAll();
    if (selectedEmployeeId === empId) {
      renderEmployeeDetail(empId);
    }
    
    activeSimulations[empId] = 0;
    setTimeout(() => runSimulationStepLocal(empId), 3000);
    return;
  }

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
  renderOnboardingPage();
};

const updateOverviewMetrics = () => {
  const empList = Object.values(employees);
  const total = empList.length;
  if (total === 0) return;
  
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
  if (!feedContainer) return;
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
  if (!container) return;
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
      window.location.hash = '#/endpoints';
      setTimeout(() => {
        selectEmployeeCard(emp.name.toLowerCase());
      }, 100);
    });
    container.appendChild(item);
  });
};

const renderEmployeeGrid = () => {
  const grid = document.getElementById('employees-grid-list');
  if (!grid) return;
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
  
  const placeholder = document.getElementById('detail-placeholder');
  const content = document.getElementById('detail-content');
  if (!placeholder || !content) return;
  
  placeholder.classList.add('hide');
  content.classList.remove('hide');
  
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
  if (!tbody) return;
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
  if (!alertBanner) return;
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
  if (empList.length === 0) return;
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
  
  const blockedUsbEl = document.getElementById('report-blocked-usb');
  if (blockedUsbEl) blockedUsbEl.textContent = blockedUsbEvents;
  
  const threatsCountEl = document.getElementById('report-threats-count');
  if (threatsCountEl) threatsCountEl.textContent = activeThreats;
  
  const highestUserEl = document.getElementById('report-highest-risk-user');
  if (highestUserEl) highestUserEl.textContent = highestUser;
  
  const dateStrEl = document.getElementById('report-date-str');
  if (dateStrEl) dateStrEl.textContent = new Date().toLocaleDateString(undefined, { year: 'numeric', month: 'long', day: 'numeric' });
  
  const statusBadge = document.getElementById('report-status-badge');
  if (statusBadge) {
    statusBadge.textContent = activeThreats > 0 ? 'VULNERABLE' : 'SECURE';
    statusBadge.className = activeThreats > 0 ? 'status-pill red' : 'status-pill green';
  }
};

const renderOnboardingPage = () => {
  const container = document.getElementById('onboarding-agents-list');
  const countEl = document.getElementById('onboarding-active-count');
  if (!container || !countEl) return;
  
  const activeAgents = Object.values(employees).filter(emp => emp.isAgentConnected);
  countEl.textContent = activeAgents.length;
  
  if (activeAgents.length === 0) {
    container.innerHTML = '<div class="list-placeholder" style="color: var(--text-muted); font-size: 0.8rem; font-style: italic; padding: 20px 0; text-align: center;">No real agents connected yet. Launch the script above to see live updates.</div>';
    return;
  }
  
  container.innerHTML = '';
  activeAgents.forEach(agent => {
    const item = document.createElement('div');
    item.className = 'onboarding-agent-item';
    item.style.cssText = 'display: flex; justify-content: space-between; align-items: center; padding: 8px 12px; background-color: rgba(255, 255, 255, 0.02); border: 1px solid var(--border-color); border-radius: 6px; margin-bottom: 8px;';
    item.innerHTML = `
      <div>
        <span class="onboarding-agent-name" style="font-weight: 600; font-size: 0.85rem; color: #fff;">${agent.name}</span>
        <span class="onboarding-agent-meta" style="font-size: 0.75rem; color: var(--text-muted);"> &bull; ${agent.deviceName} (${agent.department})</span>
      </div>
      <span class="status-pill green" style="font-size: 0.65rem; font-weight: 700; padding: 1px 6px; border-radius: 10px; background-color: var(--color-safe-glow); color: var(--color-safe);">ACTIVE</span>
    `;
    container.appendChild(item);
  });
};

const initCharts = () => {
  const threatCanvas = document.getElementById('threat-chart');
  const trendCanvas = document.getElementById('risk-trend-chart');
  if (!threatCanvas || !trendCanvas) return;
  
  const threatCtx = threatCanvas.getContext('2d');
  const trendCtx = trendCanvas.getContext('2d');
  const empList = Object.values(employees);
  if (empList.length === 0) return;
  
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

// Wire up inputs
const searchInput = document.getElementById('employee-search');
if (searchInput) searchInput.addEventListener('input', renderEmployeeGrid);

const filterSelect = document.getElementById('employee-status-filter');
if (filterSelect) filterSelect.addEventListener('change', renderEmployeeGrid);

const logSearchInput = document.getElementById('log-search');
if (logSearchInput) logSearchInput.addEventListener('input', renderLogsTable);

const logRiskSelect = document.getElementById('log-risk-filter');
if (logRiskSelect) logRiskSelect.addEventListener('change', renderLogsTable);

const clearLogsBtn = document.getElementById('btn-clear-logs');
if (clearLogsBtn) {
  clearLogsBtn.addEventListener('click', async () => {
    if (confirm('Flush log archives?')) {
      if (useDemoMode) {
        logs = [];
        renderLogsTable();
        renderRecentThreatFeed();
        renderReportsPreview();
        return;
      }
      await fetch('/api/logs/clear', { method: 'POST' });
    }
  });
}

const thresholdInput = document.getElementById('input-threshold');
if (thresholdInput) {
  thresholdInput.addEventListener('change', (e) => {
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
}

const demoNormalBtn = document.getElementById('btn-demo-normal');
if (demoNormalBtn) demoNormalBtn.addEventListener('click', () => sendReset('rithish'));

const demoThreatBtn = document.getElementById('btn-demo-threat');
if (demoThreatBtn) demoThreatBtn.addEventListener('click', () => triggerSimulation('kumar'));

const demoThreat2Btn = document.getElementById('btn-demo-threat2');
if (demoThreat2Btn) demoThreat2Btn.addEventListener('click', () => triggerSimulation('employee-07'));

// Initial check on load
window.onload = () => {
  checkAuth();
  handleRouting();
};
