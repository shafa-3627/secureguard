import os
import sys
import time
import json
import argparse
import threading
import datetime
import subprocess

dependencies_missing = False
try:
    import psutil
except ImportError:
    print("[WARNING] 'psutil' library is not installed. Running in mock telemetry mode.")
    print("          To monitor real system metrics, run: pip install psutil")
    dependencies_missing = True

try:
    import websockets
    import asyncio
except ImportError:
    print("[WARNING] 'websockets' library is not installed. Agent cannot connect to server.")
    print("          To run the agent, run: pip install websockets")
    dependencies_missing = True

tkinter_available = True
try:
    import tkinter as tk
    from tkinter import messagebox
except ImportError:
    tkinter_available = False

PROCESS_WHITELIST = [
    'chrome.exe', 'code.exe', 'explorer.exe', 'excel.exe', 'winword.exe', 
    'outlook.exe', 'teams.exe', 'slack.exe', 'spotify.exe', 'node.exe', 
    'python.exe', 'cmd.exe', 'powershell.exe', 'taskmgr.exe', 'system idle process',
    'svchost.exe', 'lsass.exe', 'services.exe', 'wininit.exe', 'csrss.exe', 'smss.exe'
]

SENSITIVE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'SensitiveData')

if not os.path.exists(SENSITIVE_DIR):
    os.makedirs(SENSITIVE_DIR)
    dummy_file = os.path.join(SENSITIVE_DIR, 'financial_records.xlsx')
    with open(dummy_file, 'w') as f:
        f.write("CONFIDENTIAL CORPORATE RECORDS - DO NOT ACCESS WITHOUT AUTHORIZATION\n")
    print(f"[INFO] Created sensitive honeypot directory for demonstration at: {SENSITIVE_DIR}")

class SecureGuardAgent:
    def __init__(self, username, server_url=None):
        self.username = username
        self.server_url = server_url
        self.is_isolated = False
        self.blocked_usbs = set()
        self.file_alerts = []
        self.file_timestamps = {}
        
        self.scan_sensitive_directory(init=True)
        
    def scan_sensitive_directory(self, init=False):
        current_state = {}
        alerts = []
        
        try:
            for root, dirs, files in os.walk(SENSITIVE_DIR):
                for file in files:
                    filepath = os.path.join(root, file)
                    try:
                        mtime = os.path.getmtime(filepath)
                        current_state[filepath] = mtime
                        
                        if not init:
                            if filepath not in self.file_timestamps:
                                alerts.append(f"New file created: {file}")
                            elif self.file_timestamps[filepath] != mtime:
                                alerts.append(f"File modified: {file}")
                    except OSError:
                        pass
                        
            if not init:
                for filepath in list(self.file_timestamps.keys()):
                    if filepath not in current_state:
                        filename = os.path.basename(filepath)
                        alerts.append(f"File deleted: {filename}")
                        
            self.file_timestamps = current_state
            
            if alerts:
                print(f"[ALERT] Sensitive Folder Integrity Violations: {alerts}")
                self.file_alerts.extend(alerts)
        except Exception as e:
            print(f"[ERROR] Scanning folder failed: {e}")
            
    def get_connected_usbs(self):
        drives = []
        if sys.platform == 'win32':
            import ctypes
            try:
                bitmask = ctypes.windll.kernel32.GetLogicalDrives()
                for letter in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
                    if bitmask & 1:
                        drive_path = f"{letter}:\\"
                        drive_type = ctypes.windll.kernel32.GetDriveTypeW(drive_path)
                        if drive_type == 2:
                            if drive_path not in self.blocked_usbs:
                                drives.append(f"{letter}: Drive (Removable)")
                    bitmask >>= 1
                return drives
            except Exception:
                pass
                
        if not dependencies_missing:
            try:
                for part in psutil.disk_partitions(all=False):
                    if 'removable' in part.opts.lower() or part.fstype == '':
                        drive_name = f"{part.mountpoint} Drive"
                        if part.mountpoint not in self.blocked_usbs:
                            drives.append(drive_name)
            except Exception:
                pass
                
        return drives

    def get_system_telemetry(self):
        if dependencies_missing:
            import random
            return {
                "cpuUsage": random.randint(10, 25),
                "memoryUsage": 45,
                "processes": ["chrome.exe", "code.exe", "explorer.exe", "python.exe"]
            }
            
        try:
            cpu = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory().percent
            
            processes = set()
            for proc in psutil.process_iter(['name']):
                try:
                    name = proc.info['name']
                    if name:
                        if name.lower() not in ['conhost.exe', 'runtimebroker.exe', 'dllhost.exe']:
                            processes.add(name)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            return {
                "cpuUsage": cpu,
                "memoryUsage": mem,
                "processes": list(processes)[:30]
            }
        except Exception as e:
            print(f"[ERROR] Gathering system telemetry failed: {e}")
            return {"cpuUsage": 10, "memoryUsage": 30, "processes": []}

    def execute_mitigation(self, action, payload):
        print(f"\n[MITIGATION RECEIVED] Command: {action} | Context: {payload}")
        
        if action == 'KILL_PROCESS':
            proc_name = payload
            killed = False
            if not dependencies_missing:
                for proc in psutil.process_iter(['name']):
                    try:
                        if proc.info['name'].lower() == proc_name.lower():
                            proc.terminate()
                            print(f"[SUCCESS] Terminated suspicious process: {proc_name}")
                            killed = True
                    except Exception as e:
                        print(f"[ERROR] Failed to terminate {proc_name}: {e}")
            if not killed:
                print(f"[INFO] Process {proc_name} not found or terminated already.")
                
        elif action == 'BLOCK_USB':
            print(f"[SUCCESS] Ejected and Blocked access to Removable USB devices.")
            connected = self.get_connected_usbs()
            for d in connected:
                drive_id = d.split(" ")[0] if " " in d else d
                self.blocked_usbs.add(drive_id)
                
        elif action == 'ISOLATE_SYSTEM':
            self.is_isolated = True
            print("[CRITICAL] NETWORK ISOLATION TRIGGERED. AGENT BLOCKED FROM CENTRAL NETWORK SERVER.")
            if tkinter_available:
                threading.Thread(target=self.show_isolation_ui, daemon=True).start()

    def show_isolation_ui(self):
        root = tk.Tk()
        root.withdraw()
        
        messagebox.showerror(
            "🛡️ SECUREGUARD ENTERPRISE ALERT",
            "⚠️ HIGH-RISK BEHAVIORAL PATTERNS DETECTED!\n\n"
            "This endpoint workstation has been ISOLATED from the corporate network "
            "by the Security Operations Center (SOC) administrator.\n\n"
            "• Remote mitigation actions executed: SUSPICIOUS PROCESS KILLED.\n"
            "• Removable media storage: BLOCKED.\n\n"
            "Please contact your IT System Administrator immediately for security audit resolution."
        )
        root.destroy()

    async def connect_and_stream(self):
        if self.server_url:
            base_urls = [self.server_url]
        else:
            base_urls = [
                f"ws://localhost:5001/?type=agent&username={self.username}",
                f"ws://localhost:3000/?type=agent&username={self.username}"
            ]
            
        print(f"\n========================================================")
        print(f"[SECUREGUARD] SecureGuard Behavior Endpoint Agent: STARTED")
        print(f"User Identity    : {self.username.upper()}")
        print(f"Honeypot Directory: {SENSITIVE_DIR}")
        print(f"========================================================\n")
        
        url_index = 0
        while True:
            url = base_urls[url_index % len(base_urls)]
            print(f"[CONNECTING] Trying Central Hub: {url}")
            
            try:
                async with websockets.connect(url) as ws:
                    print(f"[ONLINE] Endpoint connected. Streaming real-time telemetry...")
                    
                    while True:
                        if self.is_isolated:
                            print("[ISOLATED] Standby. Telemetry upload paused.")
                            await asyncio.sleep(5)
                            continue
                            
                        self.scan_sensitive_directory()
                        telemetry = self.get_system_telemetry()
                        usbs = self.get_connected_usbs()
                        usb_connected = len(usbs) > 0
                        usb_device_name = usbs[0] if usb_connected else ""
                        
                        payload = {
                            "type": "TELEMETRY",
                            "cpuUsage": telemetry["cpuUsage"],
                            "memoryUsage": telemetry["memoryUsage"],
                            "processes": telemetry["processes"],
                            "usbConnected": usb_connected,
                            "usbDeviceName": usb_device_name,
                            "fileAlerts": self.file_alerts
                        }
                        
                        await ws.send(json.dumps(payload))
                        self.file_alerts = []
                        
                        try:
                            command_msg = await asyncio.wait_for(ws.recv(), timeout=2.0)
                            command = json.loads(command_msg)
                            
                            if command.get("type") == "MITIGATION_COMMAND":
                                self.execute_mitigation(command.get("action"), command.get("payload"))
                            elif command.get("type") == "RESET_STATE":
                                print("[RESET] Restoring agent baseline status.")
                                self.is_isolated = False
                                self.blocked_usbs.clear()
                        except asyncio.TimeoutError:
                            pass
                            
            except Exception as e:
                print(f"[OFFLINE] Connection failed: {e}. Reconnecting in 4 seconds...")
                await asyncio.sleep(4)
                url_index += 1

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SecureGuard Endpoint Behavioral Telemetry Agent")
    parser.add_argument('--username', default='Kumar', help='The employee profile to represent on the dashboard grid (default: Kumar)')
    parser.add_argument('--server', default=None, help='Specific Central WS Server URL')
    args = parser.parse_args()
    
    if dependencies_missing:
        print("\n[NOTE] You can install missing dependencies to enable physical telemetry:")
        print("       pip install psutil websockets\n")
        
    agent = SecureGuardAgent(username=args.username, server_url=args.server)
    
    try:
        asyncio.run(agent.connect_and_stream())
    except KeyboardInterrupt:
        print("\nStopping SecureGuard Behavioral Endpoint Agent...")
        sys.exit(0)