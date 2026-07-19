import os
import json
import time
import datetime
import threading
import asyncio
import websockets
from flask import Flask, jsonify, request, send_from_directory

app = Flask(__name__, static_folder='public')
DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'database.json')

PROCESS_WHITELIST = [
    'chrome.exe', 'code.exe', 'explorer.exe', 'excel.exe', 'winword.exe', 
    'outlook.exe', 'teams.exe', 'slack.exe', 'spotify.exe', 'node.exe', 
    'python.exe', 'cmd.exe', 'powershell.exe', 'taskmgr.exe', 'system idle process'
]

db_lock = threading.Lock()
db_state = {
    'logs': [],
    'settings': {
        'alertThreshold': 70,
        'sensitiveFolders': ['C:\\SensitiveData', 'D:\\FinanceDocuments', 'C:\\Users\\Administrator']
    }
}

def load_database():
    global db_state
    if os.path.exists(DB_FILE):
        try:
            with open(DB_FILE, 'r') as f:
                db_state = json.load(f)
        except Exception as e:
            print("Error loading database.json, initializing fresh:", e)
            seed_database()
    else:
        seed_database()

def seed_database():
    global db_state
    now = datetime.datetime.now()
    db_state['logs'] = [
        {
            'id': 'log-1',
            'time': (now - datetime.timedelta(minutes=200)).strftime("%I:%M:%S %p"),
            'date': (now - datetime.timedelta(minutes=200)).strftime("%m/%d/%Y"),
            'username': 'Rahul',
            'deviceName': 'DESKTOP-RAHUL-ENG',
            'event': 'USB Connected',
            'risk': 20,
            'actionTaken': 'Monitored'
        },
        {
            'id': 'log-2',
            'time': (now - datetime.timedelta(minutes=100)).strftime("%I:%M:%S %p"),
            'date': (now - datetime.timedelta(minutes=100)).strftime("%m/%d/%Y"),
            'username': 'Vijay',
            'deviceName': 'DESKTOP-VIJAY-HR',
            'event': 'Unknown Process Opened: cheatengine.exe',
            'risk': 40,
            'actionTaken': 'Alert Generated'
        },
        {
            'id': 'log-3',
            'time': (now - datetime.timedelta(minutes=98)).strftime("%I:%M:%S %p"),
            'date': (now - datetime.timedelta(minutes=98)).strftime("%m/%d/%Y"),
            'username': 'Vijay',
            'deviceName': 'DESKTOP-VIJAY-HR',
            'event': 'Sensitive Folder Access: D:\\HR_SalaryReview',
            'risk': 60,
            'actionTaken': 'Process Terminated'
        }
    ]
    save_database()

def save_database():
    with open(DB_FILE, 'w') as f:
        json.dump(db_state, f, indent=2)

load_database()

employees = {}
employee_names = [
    'Rithish', 'Rahul', 'Kumar', 'Vijay', 'Anand', 
    'Employee-07', 'Suresh', 'Priya', 'Amit', 'Deepa', 
    'Vikram', 'Neha', 'Kavitha', 'Arjun', 'Sanjay', 
    'Divya', 'Meera', 'Rajesh', 'Karthik', 'Manoj'
]
departments = ['IT', 'Engineering', 'Finance', 'HR', 'Sales', 'Finance', 'IT', 'Operations', 'Engineering', 'Marketing', 'Sales', 'Legal', 'HR', 'IT', 'Finance', 'Engineering', 'Marketing', 'Operations', 'IT', 'Sales']

for i, name in enumerate(employee_names):
    employees[name.lower()] = {
        'name': name,
        'department': departments[i],
        'deviceName': f"WORKSTATION-{name.upper()}",
        'status': 'Protected',
        'riskScore': 12,
        'threatLevel': 'LOW',
        'isAgentConnected': False,
        'usbStatus': 'No USB Connected',
        'cpuUsage': 12,
        'memoryUsage': 35,
        'runningProcesses': ['chrome.exe', 'code.exe', 'explorer.exe'],
        'alerts': [],
        'activityTimeline': [
            { 'time': '09:00 AM', 'event': 'System Boot & Login', 'risk': 0, 'type': 'info' },
            { 'time': '09:10 AM', 'event': 'Chrome Browser Opened', 'risk': 0, 'type': 'info' },
            { 'time': '09:15 AM', 'event': 'VS Code IDE Opened', 'risk': 0, 'type': 'info' }
        ],
        'isIsolated': False,
        'underActiveThreatSimulation': False
    }

dashboard_sockets = set()
active_agents = {}
loop = None

def run_async(coro):
    if loop is not None:
        asyncio.run_coroutine_threadsafe(coro, loop)

async def broadcast_to_dashboards_async(message_dict):
    if not dashboard_sockets:
        return
    message = json.dumps(message_dict)
    dead_sockets = set()
    for ws in dashboard_sockets:
        try:
            await ws.send(message)
        except Exception:
            dead_sockets.add(ws)
    if dead_sockets:
        dashboard_sockets.difference_update(dead_sockets)

def broadcast_to_dashboards(message_dict):
    run_async(broadcast_to_dashboards_async(message_dict))

def notify_employee_update(emp_id):
    with db_lock:
        emp = employees.get(emp_id)
        if emp:
            emp_copy = json.loads(json.dumps(emp))
            broadcast_to_dashboards({
                'type': 'EMPLOYEE_UPDATE',
                'empId': emp_id,
                'employee': emp_copy
            })

def calculate_risk(employee):
    score = 10
    alerts = []
    
    out_of_hours = any("Login Outside Office Hours" in e['event'] for e in employee['activityTimeline'])
    if out_of_hours:
        score += 20
        alerts.append('Login Outside Office Hours')
        
    if employee['usbStatus'] != 'No USB Connected' and "Blocked" not in employee['usbStatus']:
        score += 20
        alerts.append('Unknown USB Device Connected')
        
    if employee['cpuUsage'] > 80:
        score += 15
        alerts.append('Abnormal High CPU Usage')
        
    suspicious_process = False
    for proc in employee['runningProcesses']:
        lower_proc = proc.lower()
        if lower_proc not in PROCESS_WHITELIST or lower_proc in ['malware.exe', 'ransomware.exe', 'mimikatz.exe']:
            suspicious_process = True
            
    if suspicious_process:
        score += 30
        alerts.append('Suspicious Executable Started')
        
    file_access = any("Sensitive Folder Access" in e['event'] for e in employee['activityTimeline'])
    if file_access:
        score += 25
        alerts.append('Multiple Sensitive Folder Access')
        
    score = min(100, max(0, score))
    
    level = 'LOW'
    if score >= 70:
        level = 'HIGH'
        employee['status'] = 'Compromised'
    elif score >= 40:
        level = 'MEDIUM'
        employee['status'] = 'Vulnerable'
    else:
        level = 'LOW'
        employee['status'] = 'Protected'
        
    if employee['isIsolated']:
        employee['status'] = 'Isolated'
        
    employee['riskScore'] = score
    employee['threatLevel'] = level
    employee['alerts'] = alerts

def log_event(username, device_name, event_name, risk_score, action_taken):
    now = datetime.datetime.now()
    log = {
        'id': f"log-{int(time.time()*1000)}-{os.urandom(2).hex()}",
        'time': now.strftime("%I:%M:%S %p"),
        'date': now.strftime("%m/%d/%Y"),
        'username': username,
        'deviceName': device_name,
        'event': event_name,
        'risk': risk_score,
        'actionTaken': action_taken
    }
    with db_lock:
        db_state['logs'].insert(0, log)
        save_database()
        
    broadcast_to_dashboards({
        'type': 'LOG_ADDED',
        'log': log
    })

def simulation_worker():
    import random
    while True:
        time.sleep(4.0)
        with db_lock:
            for name in employee_names:
                emp_id = name.lower()
                emp = employees[emp_id]
                
                if emp['isIsolated'] or emp['underActiveThreatSimulation'] or emp['isAgentConnected']:
                    continue
                
                old_cpu = emp['cpuUsage']
                emp['cpuUsage'] = max(5, min(65, int(emp['cpuUsage'] + random.randint(-5, 5))))
                emp['memoryUsage'] = max(20, min(80, int(emp['memoryUsage'] + random.randint(-3, 3))))
                
                if abs(old_cpu - emp['cpuUsage']) > 5:
                    calculate_risk(emp)
                    emp_copy = json.loads(json.dumps(emp))
                    broadcast_to_dashboards({
                        'type': 'EMPLOYEE_UPDATE',
                        'empId': emp_id,
                        'employee': emp_copy
                    })

@app.route('/')
def index():
    return send_from_directory('public', 'index.html')

@app.route('/<path:path>')
def static_proxy(path):
    return send_from_directory('public', path)

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.json or {}
    username = data.get('username', '')
    password = data.get('password', '')
    
    if username == 'admin' and password == 'secureguard':
        return jsonify({'success': True, 'message': 'Authenticated'})
    else:
        return jsonify({'success': False, 'message': 'Invalid username or password'}), 401

@app.route('/api/agents')
def get_agents():
    with db_lock:
        connected = [emp['name'] for emp in employees.values() if emp['isAgentConnected']]
        return jsonify(connected)

@app.route('/api/employees')
def get_employees():
    with db_lock:
        return jsonify(employees)

@app.route('/api/logs')
def get_logs():
    with db_lock:
        return jsonify(db_state['logs'])

@app.route('/api/logs/clear', methods=['POST'])
def clear_logs():
    with db_lock:
        db_state['logs'] = []
        save_database()
    broadcast_to_dashboards({'type': 'LOGS_CLEARED'})
    return jsonify({'success': True})

@app.route('/api/simulate-threat', methods=['POST'])
def simulate_threat():
    data = request.json or {}
    username = data.get('username', '')
    emp_id = username.lower()
    
    with db_lock:
        emp = employees.get(emp_id)
        if not emp:
            return jsonify({'error': 'Employee not found'}), 404
            
        if emp['underActiveThreatSimulation']:
            return jsonify({'success': True, 'message': 'Simulation already running.'})
            
        emp['underActiveThreatSimulation'] = True
        emp['isIsolated'] = False
        emp['cpuUsage'] = 15
        emp['usbStatus'] = 'No USB Connected'
        emp['runningProcesses'] = ['chrome.exe', 'code.exe', 'explorer.exe']
        emp['activityTimeline'] = [
            { 'time': datetime.datetime.now().strftime("%I:%M:%S %p"), 'event': 'System Boot & Login', 'risk': 0, 'type': 'info' }
        ]
        calculate_risk(emp)
        
    notify_employee_update(emp_id)
    threading.Thread(target=run_scenario_simulation, args=(emp_id,), daemon=True).start()
    return jsonify({'success': True, 'message': f"Threat simulation started for {emp['name']}"})

def run_scenario_simulation(emp_id):
    steps = 5
    for step in range(steps):
        time.sleep(3.5)
        with db_lock:
            emp = employees.get(emp_id)
            if not emp or not emp['underActiveThreatSimulation']:
                break
                
            time_str = datetime.datetime.now().strftime("%I:%M:%S %p")
            
            if step == 0:
                emp['activityTimeline'].append({ 'time': '02:15 AM', 'event': 'Login Outside Office Hours (Alert Triggered)', 'risk': 20, 'type': 'warning' })
                calculate_risk(emp)
                log_event(emp['name'], emp['deviceName'], 'Login Outside Office Hours', emp['riskScore'], 'Monitored')
            elif step == 1:
                emp['usbStatus'] = 'Kingston USB 3.0 (Unverified)'
                emp['activityTimeline'].append({ 'time': time_str, 'event': 'Unknown USB Device Connected', 'risk': 20, 'type': 'warning' })
                calculate_risk(emp)
                log_event(emp['name'], emp['deviceName'], 'USB Device Inserted: Kingston USB 3.0', emp['riskScore'], 'Alert Generated')
            elif step == 2:
                emp['runningProcesses'].append('malware.exe')
                emp['activityTimeline'].append({ 'time': time_str, 'event': 'Unknown Process Started: malware.exe', 'risk': 30, 'type': 'threat' })
                calculate_risk(emp)
                log_event(emp['name'], emp['deviceName'], 'Process Started: malware.exe (Suspicious)', emp['riskScore'], 'Alert Generated')
            elif step == 3:
                emp['cpuUsage'] = 88
                emp['activityTimeline'].append({ 'time': time_str, 'event': 'Abnormal CPU Usage detected (88%)', 'risk': 15, 'type': 'warning' })
                calculate_risk(emp)
                log_event(emp['name'], emp['deviceName'], 'High CPU Usage Detected (88%)', emp['riskScore'], 'Monitored')
            elif step == 4:
                emp['activityTimeline'].append({ 'time': time_str, 'event': 'Multiple Sensitive Folder Access (D:\\Finance\\Salaries)', 'risk': 25, 'type': 'threat' })
                calculate_risk(emp)
                log_event(emp['name'], emp['deviceName'], 'Unauthorized Folder Access Attempt: D:\\Finance\\Salaries', emp['riskScore'], 'Security Rule Triggered')
                emp['underActiveThreatSimulation'] = False
                
        notify_employee_update(emp_id)

@app.route('/api/reset-employee', methods=['POST'])
def reset_employee():
    data = request.json or {}
    username = data.get('username', '')
    emp_id = username.lower()
    
    with db_lock:
        emp = employees.get(emp_id)
        if not emp:
            return jsonify({'error': 'Employee not found'}), 404
            
        emp['underActiveThreatSimulation'] = False
        emp['isIsolated'] = False
        emp['cpuUsage'] = 12
        emp['memoryUsage'] = 35
        emp['usbStatus'] = 'No USB Connected'
        emp['runningProcesses'] = ['chrome.exe', 'code.exe', 'explorer.exe']
        emp['activityTimeline'] = [
            { 'time': '09:00 AM', 'event': 'System Boot & Login', 'risk': 0, 'type': 'info' },
            { 'time': '09:10 AM', 'event': 'Chrome Opened', 'risk': 0, 'type': 'info' },
            { 'time': '09:15 AM', 'event': 'VS Code Opened', 'risk': 0, 'type': 'info' }
        ]
        calculate_risk(emp)
        
    notify_employee_update(emp_id)
    
    if emp_id in active_agents:
        ws = active_agents[emp_id]
        async def send_reset():
            try:
                await ws.send(json.dumps({'type': 'RESET_STATE'}))
            except Exception:
                pass
        run_async(send_reset())
        
    return jsonify({'success': True, 'message': f"Reset employee {emp['name']}"})

@app.route('/api/mitigate', methods=['POST'])
def mitigate():
    data = request.json or {}
    username = data.get('username', '')
    action = data.get('action', '')
    payload = data.get('payload', '')
    emp_id = username.lower()
    
    with db_lock:
        emp = employees.get(emp_id)
        if not emp:
            return jsonify({'error': 'Employee not found'}), 404
            
        time_str = datetime.datetime.now().strftime("%I:%M:%S %p")
        
        if action == 'KILL_PROCESS':
            proc_name = payload or 'Suspicious Process'
            emp['runningProcesses'] = [p for p in emp['runningProcesses'] if p != proc_name]
            if proc_name in ['malware.exe', 'ransomware.exe']:
                emp['cpuUsage'] = 15
            emp['activityTimeline'].append({ 'time': time_str, 'event': f"Process Blocked & Killed: {proc_name}", 'risk': 0, 'type': 'mitigation' })
            calculate_risk(emp)
            log_event(emp['name'], emp['deviceName'], f"Process Terminated: {proc_name}", emp['riskScore'], 'Admin Action: Killed Process')
            
        elif action == 'BLOCK_USB':
            emp['usbStatus'] = 'No USB Connected (Blocked)'
            emp['activityTimeline'].append({ 'time': time_str, 'event': 'USB Device Blocked & Ejected', 'risk': 0, 'type': 'mitigation' })
            calculate_risk(emp)
            log_event(emp['name'], emp['deviceName'], 'USB Drive Blocked & Ejected', emp['riskScore'], 'Admin Action: Blocked USB')
            
        elif action == 'ISOLATE_SYSTEM':
            emp['isIsolated'] = True
            emp['activityTimeline'].append({ 'time': time_str, 'event': 'Network Isolation Triggered', 'risk': 0, 'type': 'mitigation' })
            calculate_risk(emp)
            log_event(emp['name'], emp['deviceName'], 'System Network Isolated', emp['riskScore'], 'Admin Action: Isolated System')
            
    notify_employee_update(emp_id)
    
    if emp_id in active_agents:
        ws = active_agents[emp_id]
        async def send_mitigation():
            try:
                await ws.send(json.dumps({
                    'type': 'MITIGATION_COMMAND',
                    'action': action,
                    'payload': payload
                }))
            except Exception:
                pass
        run_async(send_mitigation())
        
    return jsonify({'success': True, 'message': f"Mitigation {action} triggered"})

async def ws_handler(ws, path_str=None):
    if path_str is None:
        path_str = getattr(ws, 'path', '/')
    import urllib.parse
    parsed = urllib.parse.urlparse(path_str)
    params = urllib.parse.parse_qs(parsed.query)
    
    client_type = params.get('type', ['dashboard'])[0]
    agent_username = params.get('username', ['rithish'])[0].lower()
    
    if client_type == 'dashboard':
        dashboard_sockets.add(ws)
        with db_lock:
            init_payload = {
                'type': 'INIT_STATE',
                'employees': json.loads(json.dumps(employees)),
                'logs': db_state['logs'],
                'settings': db_state['settings']
            }
        try:
            await ws.send(json.dumps(init_payload))
            async for message in ws:
                pass
        except Exception:
            pass
        finally:
            dashboard_sockets.discard(ws)
            
    elif client_type == 'agent':
        with db_lock:
            emp = employees.get(agent_username)
            if not emp:
                await ws.close(1008, 'Unknown employee username')
                return
            
            print(f"Real Python agent connected for endpoint: {emp['name']}")
            active_agents[agent_username] = ws
            emp['isAgentConnected'] = True
            emp['activityTimeline'].append({
                'time': datetime.datetime.now().strftime("%I:%M:%S %p"),
                'event': 'SecureGuard Agent Connected Successfully',
                'risk': 0,
                'type': 'info'
            })
            calculate_risk(emp)
            
        notify_employee_update(agent_username)
        
        try:
            async for message in ws:
                data = json.loads(message)
                time_str = datetime.datetime.now().strftime("%I:%M:%S %p")
                
                if data.get('type') == 'TELEMETRY':
                    with db_lock:
                        emp = employees.get(agent_username)
                        if not emp:
                            continue
                            
                        emp['cpuUsage'] = int(data.get('cpuUsage', 0))
                        emp['memoryUsage'] = int(data.get('memoryUsage', 0))
                        emp['runningProcesses'] = data.get('processes', [])
                        
                        previous_usb = emp['usbStatus']
                        if data.get('usbConnected'):
                            emp['usbStatus'] = data.get('usbDeviceName', 'Unknown USB Device')
                            if previous_usb == 'No USB Connected':
                                emp['activityTimeline'].append({ 'time': time_str, 'event': f"USB Device Connected: {emp['usbStatus']}", 'risk': 20, 'type': 'warning' })
                                log_event(emp['name'], emp['deviceName'], f"USB Connected: {emp['usbStatus']}", emp['riskScore'], 'Real Agent Event')
                        else:
                            emp['usbStatus'] = 'No USB Connected'
                            if previous_usb != 'No USB Connected' and "Blocked" not in previous_usb:
                                emp['activityTimeline'].append({ 'time': time_str, 'event': 'USB Device Disconnected', 'risk': 0, 'type': 'info' })
                                
                        file_alerts = data.get('fileAlerts', [])
                        for alert_file in file_alerts:
                            file_evt = f"Sensitive Folder Access: {alert_file}"
                            already_logged = any(e['event'] == file_evt for e in emp['activityTimeline'])
                            if not already_logged:
                                emp['activityTimeline'].append({ 'time': time_str, 'event': file_evt, 'risk': 25, 'type': 'threat' })
                                log_event(emp['name'], emp['deviceName'], f"File Access Event: {alert_file}", emp['riskScore'], 'Real Agent Event')
                                
                        for proc_name in emp['runningProcesses']:
                            lower_name = proc_name.lower()
                            if lower_name not in PROCESS_WHITELIST:
                                proc_alert = f"Unknown Process Started: {proc_name}"
                                already_alerted = any(proc_name in e['event'] for e in emp['activityTimeline'])
                                if not already_alerted:
                                    emp['activityTimeline'].append({ 'time': time_str, 'event': proc_alert, 'risk': 30, 'type': 'threat' })
                                    log_event(emp['name'], emp['deviceName'], f"Suspicious Process Started: {proc_name}", emp['riskScore'], 'Real Agent Event')
                                    
                        calculate_risk(emp)
                    notify_employee_update(agent_username)
                    
        except Exception as e:
            print(f"Error handling agent communication: {e}")
        finally:
            with db_lock:
                emp = employees.get(agent_username)
                if emp:
                    print(f"Real Python agent disconnected for endpoint: {emp['name']}")
                    active_agents.pop(agent_username, None)
                    emp['isAgentConnected'] = False
                    emp['activityTimeline'].append({
                        'time': datetime.datetime.now().strftime("%I:%M:%S %p"),
                        'event': 'SecureGuard Agent Disconnected',
                        'risk': 0,
                        'type': 'info'
                    })
                    calculate_risk(emp)
            notify_employee_update(agent_username)

async def main_websocket_server():
    global loop
    loop = asyncio.get_running_loop()
    async with websockets.serve(ws_handler, "0.0.0.0", 5001):
        await asyncio.Future()

def run_flask_app():
    import logging
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    print("[SERVER] Flask API Server listening on http://localhost:5000")
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)

if __name__ == '__main__':
    sim_thread = threading.Thread(target=simulation_worker, daemon=True)
    sim_thread.start()
    
    flask_thread = threading.Thread(target=run_flask_app, daemon=True)
    flask_thread.start()
    
    print("[WS-HUB] WebSocket Telemetry Hub listening on ws://localhost:5001")
    try:
        asyncio.run(main_websocket_server())
    except KeyboardInterrupt:
        print("\nStopping SecureGuard Enterprise EDR Server...")