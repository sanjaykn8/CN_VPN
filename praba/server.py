# server.py
import socket
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, simpledialog
import json
import struct
import psutil
import time
from collections import defaultdict
from PIL import Image, ImageTk
import io
import base64

# Constants
SERVER_HOST = '0.0.0.0'
SERVER_PORT = 5000
BUFFER_SIZE = 4096
MAX_CLIENTS = 10

# Protocol Commands
CMD_CHAT_MESSAGE = "CHAT"
CMD_FILE_LIST = "FILE_LIST"
CMD_SCREENSHOT = "SCREENSHOT"
CMD_PROCESS_LIST = "PROCESS_LIST"
CMD_PROCESS_KILL = "PROCESS_KILL"
CMD_SYSTEM_INFO = "SYSTEM_INFO"
CMD_SYSTEM_ACTION = "SYSTEM_ACTION"
CMD_NETWORK_STATS = "NETWORK_STATS"

# ----------------- helpers -----------------
def recv_all(sock, n):
    """Receive exactly n bytes or return None."""
    data = b''
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data

def send_all(sock, data):
    """Send all bytes, return True on success."""
    total = 0
    while total < len(data):
        sent = sock.send(data[total:])
        if sent == 0:
            return False
        total += sent
    return True

# ----------------- Network monitor -----------------
class NetworkMonitor:
    def __init__(self):
        self.clients_traffic = defaultdict(lambda: {
            'bytes_sent': 0, 'bytes_recv': 0,
            'packets_sent': 0, 'packets_recv': 0,
            'connections': []
        })
        self.running = False

    def start_monitoring(self):
        self.running = True
        threading.Thread(target=self._monitor_loop, daemon=True).start()

    def stop_monitoring(self):
        self.running = False

    def _monitor_loop(self):
        previous_stats = psutil.net_io_counters(pernic=True)
        while self.running:
            time.sleep(2)
            try:
                current_stats = psutil.net_io_counters(pernic=True)
                connections = psutil.net_connections()
                for interface in current_stats:
                    if interface in previous_stats:
                        bytes_sent = current_stats[interface].bytes_sent - previous_stats[interface].bytes_sent
                        bytes_recv = current_stats[interface].bytes_recv - previous_stats[interface].bytes_recv
                        self.clients_traffic[interface].update({
                            'bytes_sent': bytes_sent,
                            'bytes_recv': bytes_recv
                        })
                # collect some recent remote endpoints
                for conn in connections:
                    if conn.raddr:
                        remote_ip = conn.raddr.ip
                        found = False
                        for c in self.clients_traffic[conn.laddr.ip if conn.laddr else 'any']['connections']:
                            if c.get('remote_ip') == remote_ip:
                                found = True
                                break
                        if not found:
                            key = conn.laddr.ip if conn.laddr else 'unknown'
                            self.clients_traffic[key]['connections'].append({
                                'remote_ip': conn.raddr.ip,
                                'remote_port': conn.raddr.port,
                                'local_port': conn.laddr.port if conn.laddr else None,
                                'status': conn.status
                            })
                previous_stats = current_stats
            except Exception as e:
                print(f"Network monitoring error: {e}")

    def get_network_stats(self):
        return dict(self.clients_traffic)

# ----------------- Client handler -----------------
class ClientHandler:
    def __init__(self, client_socket, address, server):
        self.client_socket = client_socket
        self.address = address
        self.server = server
        self.running = True
        self.client_info = {}

    def start(self):
        threading.Thread(target=self.handle_client, daemon=True).start()

    def handle_client(self):
        try:
            # Ask client for its system info on connect
            self.send_command(CMD_SYSTEM_INFO)
            response = self.recv_message()
            if response and isinstance(response, dict) and response.get('type') == 'system_info':
                self.client_info = response.get('info', {})
                self.client_info['ip'] = self.address[0]
                self.server.client_connected(self)

            while self.running:
                message = self.recv_message()
                if message:
                    self.handle_response(message)
                else:
                    break
        except Exception as e:
            print(f"Error handling client {self.address}: {e}")
        finally:
            self.disconnect()

    def handle_response(self, response):
        # response may be dict or string
        if isinstance(response, dict):
            # If screenshot included as base64 string, decode it now
            if response.get('type') == 'screenshot' and 'image' in response:
                try:
                    # image is base64 string
                    response['image'] = base64.b64decode(response['image'])
                except Exception:
                    # if it's already bytes, keep it
                    pass
            self.server.update_client_data(self, response)

    def send_command(self, command, data=None):
        try:
            message = {'command': command}
            if data:
                message['data'] = data
            self.send_message(message)
        except Exception as e:
            print(f"Error sending command to client: {e}")

    def send_message(self, data):
        # convert to JSON, ensure bytes are base64-encoded
        if isinstance(data, dict):
            # convert any bytes in dict to base64 strings (shallow)
            for k, v in list(data.items()):
                if isinstance(v, (bytes, bytearray)):
                    data[k] = base64.b64encode(v).decode('ascii')
            payload = json.dumps(data).encode('utf-8')
        elif isinstance(data, str):
            payload = data.encode('utf-8')
        else:
            payload = json.dumps(data).encode('utf-8')

        length = struct.pack('!I', len(payload))
        if not send_all(self.client_socket, length):
            raise RuntimeError("send length failed")
        if not send_all(self.client_socket, payload):
            raise RuntimeError("send payload failed")

    def recv_message(self):
        length_data = recv_all(self.client_socket, 4)
        if not length_data:
            return None
        length = struct.unpack('!I', length_data)[0]
        payload = recv_all(self.client_socket, length)
        if payload is None:
            return None
        try:
            return json.loads(payload.decode('utf-8'))
        except Exception:
            # fall back to raw text
            try:
                return payload.decode('utf-8', errors='replace')
            except:
                return payload

    def disconnect(self):
        self.running = False
        self.server.client_disconnected(self)
        try:
            self.client_socket.close()
        except:
            pass

# ----------------- Server core & GUI -----------------
class ServerCore:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.server_socket = None
        self.running = False
        self.clients = []
        self.network_monitor = NetworkMonitor()
        self.gui_callback = None

    def set_gui_callback(self, callback):
        self.gui_callback = callback

    def start_server(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(MAX_CLIENTS)
            self.running = True
            self.network_monitor.start_monitoring()
            threading.Thread(target=self.accept_connections, daemon=True).start()
            return True
        except Exception as e:
            print(f"Server start failed: {e}")
            return False

    def accept_connections(self):
        while self.running:
            try:
                client_socket, address = self.server_socket.accept()
                print(f"New connection from {address}")
                client_handler = ClientHandler(client_socket, address, self)
                client_handler.start()
            except Exception as e:
                if self.running:
                    print(f"Error accepting connection: {e}")

    def client_connected(self, client_handler):
        self.clients.append(client_handler)
        if self.gui_callback:
            self.gui_callback('client_connected', client_handler.client_info)

    def client_disconnected(self, client_handler):
        if client_handler in self.clients:
            self.clients.remove(client_handler)
        if self.gui_callback:
            self.gui_callback('client_disconnected', client_handler.client_info)

    def update_client_data(self, client_handler, data):
        # If screenshot 'image' is bytes already, keep it. If base64 string, decode now.
        if isinstance(data, dict) and data.get('type') == 'screenshot' and 'image' in data and isinstance(data['image'], str):
            try:
                data['image'] = base64.b64decode(data['image'])
            except Exception:
                pass
        if self.gui_callback:
            self.gui_callback('client_data', {
                'client': client_handler.client_info,
                'data': data
            })

    def send_to_client(self, client_handler, command, data=None):
        client_handler.send_command(command, data)

    def broadcast_chat(self, message):
        for client in self.clients:
            client.send_command(CMD_CHAT_MESSAGE, {'message': message})

    def get_connected_clients(self):
        return [client.client_info for client in self.clients]

    def get_network_stats(self):
        return self.network_monitor.get_network_stats()

    def stop_server(self):
        self.running = False
        self.network_monitor.stop_monitoring()
        for client in self.clients[:]:
            client.disconnect()
        if self.server_socket:
            self.server_socket.close()

# ----------------- GUI -----------------
class ServerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Remote Manager Server")
        self.root.geometry("1000x700")
        self.server = ServerCore(SERVER_HOST, SERVER_PORT)
        self.server.set_gui_callback(self.handle_server_event)
        self.current_client = None
        self.setup_ui()
        self.start_server()

    def setup_ui(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)
        # Dashboard
        dashboard_frame = ttk.Frame(self.notebook); self.notebook.add(dashboard_frame, text="Dashboard")
        status_frame = ttk.LabelFrame(dashboard_frame, text="Server Status", padding=10); status_frame.pack(fill="x", padx=10, pady=5)
        self.status_label = ttk.Label(status_frame, text="Server: Stopped"); self.status_label.pack(anchor="w")
        self.clients_label = ttk.Label(status_frame, text="Connected Clients: 0"); self.clients_label.pack(anchor="w")
        actions_frame = ttk.LabelFrame(dashboard_frame, text="Quick Actions", padding=10); actions_frame.pack(fill="x", padx=10, pady=5)
        ttk.Button(actions_frame, text="Refresh All Clients", command=self.refresh_all_clients).pack(side="left", padx=5)
        ttk.Button(actions_frame, text="Broadcast Message", command=self.broadcast_message).pack(side="left", padx=5)
        ttk.Button(actions_frame, text="Stop Server", command=self.stop_server).pack(side="left", padx=5)
        # Clients Tab
        clients_frame = ttk.Frame(self.notebook); self.notebook.add(clients_frame, text="Clients")
        list_frame = ttk.LabelFrame(clients_frame, text="Connected Clients", padding=10); list_frame.pack(fill="both", expand=True, padx=10, pady=5)
        columns = ("IP", "User", "Platform", "CPU", "Memory")
        self.clients_tree = ttk.Treeview(list_frame, columns=columns, show="headings")
        for col in columns:
            self.clients_tree.heading(col, text=col); self.clients_tree.column(col, width=100)
        self.clients_tree.pack(fill="both", expand=True); self.clients_tree.bind("<<TreeviewSelect>>", self.on_client_select)
        actions_frame = ttk.Frame(clients_frame); actions_frame.pack(fill="x", padx=10, pady=5)
        ttk.Button(actions_frame, text="Refresh", command=self.refresh_client_info).pack(side="left", padx=5)
        ttk.Button(actions_frame, text="Screenshot", command=self.take_screenshot).pack(side="left", padx=5)
        ttk.Button(actions_frame, text="Process List", command=self.get_process_list).pack(side="left", padx=5)
        ttk.Button(actions_frame, text="System Info", command=self.get_system_info).pack(side="left", padx=5)
        ttk.Button(actions_frame, text="Network Stats", command=self.get_network_stats).pack(side="left", padx=5)
        # Remote Control Tab
        control_frame = ttk.Frame(self.notebook); self.notebook.add(control_frame, text="Remote Control")
        system_frame = ttk.LabelFrame(control_frame, text="System Actions", padding=10); system_frame.pack(fill="x", padx=10, pady=5)
        ttk.Button(system_frame, text="Shutdown", command=lambda: self.system_action("SHUTDOWN")).pack(side="left", padx=5)
        ttk.Button(system_frame, text="Restart", command=lambda: self.system_action("RESTART")).pack(side="left", padx=5)
        ttk.Button(system_frame, text="Lock", command=lambda: self.system_action("LOCK")).pack(side="left", padx=5)
        fun_frame = ttk.LabelFrame(control_frame, text="Fun Actions", padding=10); fun_frame.pack(fill="x", padx=10, pady=5)
        ttk.Button(fun_frame, text="Open CD", command=lambda: self.system_action("OPEN_CD")).pack(side="left", padx=5)
        ttk.Button(fun_frame, text="Run Paint", command=lambda: self.system_action("RUN_PAINT")).pack(side="left", padx=5)
        ttk.Button(fun_frame, text="Run Notepad", command=lambda: self.system_action("RUN_NOTEPAD")).pack(side="left", padx=5)
        screenshot_frame = ttk.LabelFrame(control_frame, text="Remote Desktop", padding=10); screenshot_frame.pack(fill="both", expand=True, padx=10, pady=5)
        self.screenshot_label = ttk.Label(screenshot_frame, text="No screenshot available"); self.screenshot_label.pack(expand=True)
        # Network Monitor Tab
        network_frame = ttk.Frame(self.notebook); self.notebook.add(network_frame, text="Network Monitor")
        traffic_frame = ttk.LabelFrame(network_frame, text="Network Traffic", padding=10); traffic_frame.pack(fill="both", expand=True, padx=10, pady=5)
        self.traffic_text = scrolledtext.ScrolledText(traffic_frame, height=15); self.traffic_text.pack(fill="both", expand=True)
        ttk.Button(network_frame, text="Refresh Traffic", command=self.refresh_network_traffic).pack(pady=5)
        # Chat Tab
        chat_frame = ttk.Frame(self.notebook); self.notebook.add(chat_frame, text="Remote Chat")
        chat_display_frame = ttk.LabelFrame(chat_frame, text="Chat", padding=10); chat_display_frame.pack(fill="both", expand=True, padx=10, pady=5)
        self.chat_text = scrolledtext.ScrolledText(chat_display_frame, height=15); self.chat_text.pack(fill="both", expand=True)
        input_frame = ttk.Frame(chat_frame); input_frame.pack(fill="x", padx=10, pady=5)
        self.message_entry = ttk.Entry(input_frame); self.message_entry.pack(side="left", fill="x", expand=True, padx=5)
        self.message_entry.bind("<Return>", self.send_chat_message)
        ttk.Button(input_frame, text="Send", command=self.send_chat_message).pack(side="right", padx=5)

    def handle_server_event(self, event_type, data):
        if event_type == 'client_connected':
            self.update_clients_list()
            self.log_chat(f"Client {data.get('ip')} connected")
        elif event_type == 'client_disconnected':
            self.update_clients_list()
            self.log_chat(f"Client {data.get('ip')} disconnected")
        elif event_type == 'client_data':
            self.handle_client_data(data)

    def handle_client_data(self, data):
        client = data['client']; response_data = data['data']
        if response_data.get('type') == 'screenshot':
            self.display_screenshot(response_data.get('image'))
        elif response_data.get('type') == 'process_list':
            self.display_process_list(response_data.get('processes'))
        elif response_data.get('type') == 'system_info':
            self.display_system_info(client, response_data.get('info'))
        elif response_data.get('type') == 'network_stats':
            self.display_network_stats(response_data.get('interfaces'), response_data.get('connections'))

    def display_screenshot(self, image_data):
        try:
            if isinstance(image_data, str):
                image_data = base64.b64decode(image_data)
            image = Image.open(io.BytesIO(image_data))
            image.thumbnail((800, 600))
            photo = ImageTk.PhotoImage(image)
            self.screenshot_label.configure(image=photo)
            self.screenshot_label.image = photo
        except Exception as e:
            print(f"Error displaying screenshot: {e}")

    def display_process_list(self, processes):
        process_window = tk.Toplevel(self.root)
        process_window.title("Remote Process List")
        process_window.geometry("600x400")
        tree = ttk.Treeview(process_window, columns=("PID", "Name", "CPU%", "Memory%"), show="headings")
        tree.heading("PID", text="PID"); tree.heading("Name", text="Name"); tree.heading("CPU%", text="CPU%"); tree.heading("Memory%", text="Memory%")
        for process in processes:
            tree.insert("", "end", values=(process['pid'], process['name'], f"{process['cpu']:.1f}", f"{process['memory']:.1f}"))
        tree.pack(fill="both", expand=True, padx=10, pady=10)

    def display_system_info(self, client, info):
        info_text = f"Client: {client.get('ip')}\n"
        info_text += f"Platform: {info.get('platform', 'N/A')}\n"
        info_text += f"Processor: {info.get('processor', 'N/A')}\n"
        info_text += f"Memory: {info.get('memory_used', 0) / (1024**3):.1f}GB / {info.get('memory_total', 0) / (1024**3):.1f}GB\n"
        info_text += f"CPU Cores: {info.get('cpu_count', 'N/A')}\n"
        info_text += f"User: {info.get('user', 'N/A')}"
        messagebox.showinfo("System Information", info_text)

    def display_network_stats(self, interfaces, connections):
        self.traffic_text.delete(1.0, "end")
        self.traffic_text.insert("end", "=== Network Interfaces ===\n\n")
        for interface, stats in interfaces.items():
            self.traffic_text.insert("end", f"Interface: {interface}\n")
            self.traffic_text.insert("end", f"  Bytes Sent: {stats['bytes_sent']}\n")
            self.traffic_text.insert("end", f"  Bytes Received: {stats['bytes_recv']}\n\n")
        self.traffic_text.insert("end", "=== Active Connections ===\n\n")
        for conn in connections[:20]:
            self.traffic_text.insert("end", f"Local: {conn.get('laddr', 'N/A')}\n")
            self.traffic_text.insert("end", f"Remote: {conn.get('raddr', 'N/A')}\n")
            self.traffic_text.insert("end", f"Status: {conn.get('status', 'N/A')}\n\n")

    def start_server(self):
        if self.server.start_server():
            self.status_label.config(text=f"Server: Running on {SERVER_HOST}:{SERVER_PORT}")
            self.log_chat("Server started successfully")
        else:
            messagebox.showerror("Error", "Failed to start server")

    def stop_server(self):
        self.server.stop_server()
        self.status_label.config(text="Server: Stopped")
        self.log_chat("Server stopped")

    def update_clients_list(self):
        for item in self.clients_tree.get_children():
            self.clients_tree.delete(item)
        for client in self.server.get_connected_clients():
            self.clients_tree.insert("", "end", values=(
                client.get('ip', 'N/A'),
                client.get('user', 'N/A'),
                client.get('platform', 'N/A'),
                client.get('cpu_count', 'N/A'),
                f"{client.get('memory_used', 0) / (1024**3):.1f}GB"
            ))
        self.clients_label.config(text=f"Connected Clients: {len(self.server.clients)}")

    def on_client_select(self, event):
        selection = self.clients_tree.selection()
        if selection:
            item = selection[0]
            client_ip = self.clients_tree.item(item, "values")[0]
            self.current_client = self.find_client_by_ip(client_ip)

    def find_client_by_ip(self, ip):
        for client in self.server.clients:
            if client.client_info.get('ip') == ip:
                return client
        return None

    def refresh_all_clients(self):
        for client in self.server.clients:
            client.send_command(CMD_SYSTEM_INFO)

    def refresh_client_info(self):
        if self.current_client:
            self.current_client.send_command(CMD_SYSTEM_INFO)

    def take_screenshot(self):
        if self.current_client:
            self.current_client.send_command(CMD_SCREENSHOT)

    def get_process_list(self):
        if self.current_client:
            self.current_client.send_command(CMD_PROCESS_LIST)

    def get_system_info(self):
        if self.current_client:
            self.current_client.send_command(CMD_SYSTEM_INFO)

    def get_network_stats(self):
        if self.current_client:
            self.current_client.send_command(CMD_NETWORK_STATS)

    def system_action(self, action):
        if self.current_client:
            self.current_client.send_command(CMD_SYSTEM_ACTION, {'action': action})
            self.log_chat(f"Sent {action} command to client")

    def refresh_network_traffic(self):
        stats = self.server.get_network_stats()
        self.display_network_stats(stats, [])

    def send_chat_message(self, event=None):
        message = self.message_entry.get()
        if message:
            if self.current_client:
                self.current_client.send_command(CMD_CHAT_MESSAGE, {'message': message})
            else:
                self.server.broadcast_chat(f"Server: {message}")
            self.log_chat(f"Server: {message}")
            self.message_entry.delete(0, "end")

    def broadcast_message(self):
        message = simpledialog.askstring("Broadcast", "Enter message to broadcast:")
        if message:
            self.server.broadcast_chat(f"Server Broadcast: {message}")
            self.log_chat(f"Server Broadcast: {message}")

    def log_chat(self, message):
        self.chat_text.insert("end", f"{message}\n")
        self.chat_text.see("end")

if __name__ == "__main__":
    root = tk.Tk()
    app = ServerGUI(root)
    root.mainloop()
