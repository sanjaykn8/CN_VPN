# client.py
import socket
import threading
import tkinter as tk
from tkinter import ttk, messagebox
import json
import struct
import psutil
import platform
import subprocess
import os
import time
from PIL import ImageGrab
import io
import base64

# Constants
SERVER_HOST = '172.20.10.12'   # change to server IP or use input in GUI
SERVER_PORT = 5000
BUFFER_SIZE = 4096

def recv_all(sock, n):
    data = b''
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data

def send_all(sock, data):
    total = 0
    while total < len(data):
        sent = sock.send(data[total:])
        if sent == 0:
            return False
        total += sent
    return True

class ClientCore:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.socket = None
        self.connected = False
        self.running = True

    def connect(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            self.connected = True
            print(f"Connected to server {self.host}:{self.port}")
            return True
        except Exception as e:
            print(f"Connection failed: {e}")
            return False

    def start_listening(self):
        while self.running and self.connected:
            try:
                message = self.recv_message()
                if message:
                    self.handle_command(message)
                else:
                    self.connected = False
                    break
            except Exception as e:
                print(f"Error receiving message: {e}")
                self.connected = False
                break

    def handle_command(self, command_data):
        if isinstance(command_data, dict):
            cmd = command_data.get('command')
            data = command_data.get('data', {})
            response = None
            if cmd == "CHAT":
                response = self.handle_chat_message(data)
            elif cmd == "FILE_LIST":
                response = self.get_file_list(data.get('path', '.'))
            elif cmd == "SCREENSHOT":
                response = self.take_screenshot()
            elif cmd == "PROCESS_LIST":
                response = self.get_process_list()
            elif cmd == "PROCESS_KILL":
                response = self.kill_process(data.get('pid'))
            elif cmd == "SYSTEM_INFO":
                response = self.get_system_info()
            elif cmd == "SYSTEM_ACTION":
                response = self.system_action(data.get('action'))
            elif cmd == "NETWORK_STATS":
                response = self.get_network_stats()
            if response:
                self.send_message(response)

    def handle_chat_message(self, data):
        return {'type': 'chat_response', 'message': f"Received: {data.get('message')}"}

    def get_file_list(self, path):
        try:
            files = []
            for item in os.listdir(path):
                item_path = os.path.join(path, item)
                files.append({
                    'name': item,
                    'is_dir': os.path.isdir(item_path),
                    'size': os.path.getsize(item_path) if os.path.isfile(item_path) else 0
                })
            return {'type': 'file_list', 'files': files, 'path': path}
        except Exception as e:
            return {'type': 'error', 'message': str(e)}

    def take_screenshot(self):
        try:
            screenshot = ImageGrab.grab()
            img_bytes = io.BytesIO()
            screenshot.save(img_bytes, format='JPEG', quality=50)
            imgb = img_bytes.getvalue()
            # encode as base64 string so JSON can carry it
            return {'type': 'screenshot', 'image': base64.b64encode(imgb).decode('ascii')}
        except Exception as e:
            return {'type': 'error', 'message': str(e)}

    def get_process_list(self):
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'memory_percent', 'cpu_percent']):
                try:
                    processes.append({
                        'pid': proc.info['pid'],
                        'name': proc.info['name'],
                        'memory': proc.info.get('memory_percent', 0.0),
                        'cpu': proc.info.get('cpu_percent', 0.0)
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            return {'type': 'process_list', 'processes': processes}
        except Exception as e:
            return {'type': 'error', 'message': str(e)}

    def kill_process(self, pid):
        try:
            process = psutil.Process(pid)
            process.terminate()
            return {'type': 'process_killed', 'pid': pid}
        except Exception as e:
            return {'type': 'error', 'message': str(e)}

    def get_system_info(self):
        try:
            info = {
                'platform': platform.platform(),
                'processor': platform.processor(),
                'memory_total': psutil.virtual_memory().total,
                'memory_used': psutil.virtual_memory().used,
                'cpu_count': psutil.cpu_count(),
                'boot_time': psutil.boot_time(),
                'user': os.getlogin()
            }
            return {'type': 'system_info', 'info': info}
        except Exception as e:
            return {'type': 'error', 'message': str(e)}

    def system_action(self, action):
        try:
            if action == "SHUTDOWN":
                os.system("shutdown /s /t 1")
            elif action == "RESTART":
                os.system("shutdown /r /t 1")
            elif action == "LOCK":
                os.system("rundll32.exe user32.dll,LockWorkStation")
            elif action == "OPEN_CD":
                os.system("powershell (New-Object -com 'WMPlayer.OCX').cdromcollection.item(0).eject()")
            elif action == "RUN_PAINT":
                subprocess.Popen("mspaint.exe")
            elif action == "RUN_NOTEPAD":
                subprocess.Popen("notepad.exe")
            return {'type': 'action_completed', 'action': action}
        except Exception as e:
            return {'type': 'error', 'message': str(e)}

    def get_network_stats(self):
        try:
            stats = psutil.net_io_counters(pernic=True)
            connections = psutil.net_connections()
            net_stats = {}
            for interface, counters in stats.items():
                net_stats[interface] = {
                    'bytes_sent': counters.bytes_sent,
                    'bytes_recv': counters.bytes_recv,
                    'packets_sent': counters.packets_sent,
                    'packets_recv': counters.packets_recv
                }
            conn_info = []
            for conn in connections:
                conn_info.append({
                    'laddr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                    'raddr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                    'status': conn.status
                })
            return {'type': 'network_stats', 'interfaces': net_stats, 'connections': conn_info}
        except Exception as e:
            return {'type': 'error', 'message': str(e)}

    def send_message(self, data):
        # convert to JSON; bytes already base64-encoded where needed
        if isinstance(data, dict):
            payload = json.dumps(data).encode('utf-8')
        elif isinstance(data, str):
            payload = data.encode('utf-8')
        else:
            payload = json.dumps(data).encode('utf-8')
        length = struct.pack('!I', len(payload))
        send_all(self.socket, length)
        send_all(self.socket, payload)

    def recv_message(self):
        length_data = recv_all(self.socket, 4)
        if not length_data:
            return None
        length = struct.unpack('!I', length_data)[0]
        payload = recv_all(self.socket, length)
        if payload is None:
            return None
        try:
            return json.loads(payload.decode('utf-8'))
        except Exception:
            try:
                return payload.decode('utf-8', errors='replace')
            except:
                return payload

    def disconnect(self):
        self.running = False
        self.connected = False
        if self.socket:
            self.socket.close()

# ----------------- Client GUI -----------------
class ClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Remote Manager Client")
        self.root.geometry("400x300")
        self.client = None
        self.connected = False
        self.setup_ui()

    def setup_ui(self):
        conn_frame = ttk.LabelFrame(self.root, text="Connection", padding=10); conn_frame.pack(fill="x", padx=10, pady=5)
        ttk.Label(conn_frame, text="Server IP:").grid(row=0, column=0, sticky="w")
        self.server_ip = ttk.Entry(conn_frame, width=15); self.server_ip.insert(0, SERVER_HOST); self.server_ip.grid(row=0, column=1, padx=5)
        ttk.Label(conn_frame, text="Port:").grid(row=0, column=2, sticky="w", padx=(10,0))
        self.server_port = ttk.Entry(conn_frame, width=10); self.server_port.insert(0, str(SERVER_PORT)); self.server_port.grid(row=0, column=3, padx=5)
        self.connect_btn = ttk.Button(conn_frame, text="Connect", command=self.toggle_connection); self.connect_btn.grid(row=0, column=4, padx=10)
        status_frame = ttk.LabelFrame(self.root, text="Status", padding=10); status_frame.pack(fill="both", expand=True, padx=10, pady=5)
        self.status_text = tk.Text(status_frame, height=10, width=50)
        scrollbar = ttk.Scrollbar(status_frame, orient="vertical", command=self.status_text.yview); scrollbar.pack(side="right", fill="y")
        self.status_text.configure(yscrollcommand=scrollbar.set); self.status_text.pack(fill="both", expand=True)
        self.log("Client started. Ready to connect to server.")

    def toggle_connection(self):
        if not self.connected:
            self.connect_to_server()
        else:
            self.disconnect_from_server()

    def connect_to_server(self):
        try:
            host = self.server_ip.get()
            port = int(self.server_port.get())
            self.client = ClientCore(host, port)
            if self.client.connect():
                self.connected = True
                self.connect_btn.config(text="Disconnect")
                self.log(f"Connected to server {host}:{port}")
                self.listen_thread = threading.Thread(target=self.client.start_listening, daemon=True); self.listen_thread.start()
            else:
                messagebox.showerror("Error", "Failed to connect to server")
        except Exception as e:
            messagebox.showerror("Error", f"Connection error: {e}")

    def disconnect_from_server(self):
        if self.client:
            self.client.disconnect()
        self.connected = False
        self.connect_btn.config(text="Connect")
        self.log("Disconnected from server")

    def log(self, message):
        self.status_text.insert("end", f"{message}\n"); self.status_text.see("end"); self.root.update()

if __name__ == "__main__":
    root = tk.Tk()
    app = ClientGUI(root)
    root.mainloop()
