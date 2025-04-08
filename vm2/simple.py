import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import time
import requests
import datetime
import phonenumbers
from phonenumbers import geocoder, carrier
from flask import Flask, request
import io
import webbrowser
from PIL import Image, ImageTk
import urllib.request
import os
import json
import random
import joblib
from sklearn.preprocessing import LabelEncoder
import numpy as np
import re  # For IP address regex matching

# Flask application for proxy
app = Flask(__name__)
NODE_SERVER_URL = "http://localhost:3001"
PROXY_PORT = 3000

# Global list to store logs
logs = []
log_lock = threading.Lock()

class ProxyDashboard:
    def __init__(self, root):
        self.root = root
        self.root.title("Proxy Dashboard with Anomaly Detection")
        self.root.geometry("1200x800")
        self.root.configure(bg="#2e2e2e")
        
        # Create notebook (tabs)
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create tabs
        self.proxy_tab = ttk.Frame(self.notebook)
        self.ip_tab = ttk.Frame(self.notebook)
        self.phone_tab = ttk.Frame(self.notebook)
        
        self.notebook.add(self.proxy_tab, text="Proxy Logs")
        self.notebook.add(self.ip_tab, text="IP Geolocation")
        self.notebook.add(self.phone_tab, text="Phone Lookup")
        
        # Set up proxy tab
        self.setup_proxy_tab()
        
        # Set up IP tab
        self.setup_ip_tab()
        
        # Set up Phone tab
        self.setup_phone_tab()
        
        # Initialize anomaly detector
        self.detector = AnomalyDetector()
        
        # Add anomaly log tab
        self.anomaly_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.anomaly_tab, text="Anomaly Log")
        self.setup_anomaly_tab()
        
        # IP tracking variables
        self.ip_data = {}  # Store IP details for logging
        
        # Start log update thread
        self.log_update_thread = threading.Thread(target=self.update_logs, daemon=True)
        self.log_update_thread.start()
    
    def setup_proxy_tab(self):
        # Status frame
        status_frame = tk.Frame(self.proxy_tab, bg="#363636")
        status_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Status indicators
        tk.Label(status_frame, text="Proxy Status:", bg="#363636", fg="white").pack(side=tk.LEFT, padx=5)
        self.status_label = tk.Label(status_frame, text="RUNNING", bg="#363636", fg="#00ff00")
        self.status_label.pack(side=tk.LEFT, padx=5)
        
        tk.Label(status_frame, text=f"Listening on port: {PROXY_PORT}", bg="#363636", fg="white").pack(side=tk.LEFT, padx=20)
        tk.Label(status_frame, text=f"Forwarding to: {NODE_SERVER_URL}", bg="#363636", fg="white").pack(side=tk.LEFT, padx=20)
        
        # Current active connections
        active_frame = tk.Frame(self.proxy_tab)
        active_frame.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Label(active_frame, text="Latest Client IP:").grid(row=0, column=0, sticky=tk.W, padx=5)
        self.latest_ip_label = tk.Label(active_frame, text="None")
        self.latest_ip_label.grid(row=0, column=1, sticky=tk.W, padx=5)
        
        tk.Label(active_frame, text="Location:").grid(row=0, column=2, sticky=tk.W, padx=5)
        self.latest_location_label = tk.Label(active_frame, text="None")
        self.latest_location_label.grid(row=0, column=3, sticky=tk.W, padx=5)
        
        # Log area
        log_frame = tk.Frame(self.proxy_tab)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        tk.Label(log_frame, text="Real-time Proxy Logs:").pack(anchor=tk.W)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=25)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        self.log_text.config(state=tk.DISABLED)
        
        # Control buttons
        control_frame = tk.Frame(self.proxy_tab)
        control_frame.pack(fill=tk.X, pady=5)
        
        self.clear_button = tk.Button(control_frame, text="Clear Logs", command=self.clear_logs)
        self.clear_button.pack(side=tk.RIGHT, padx=10)
        
        self.lookup_button = tk.Button(control_frame, text="Lookup Latest IP", command=self.lookup_latest_ip)
        self.lookup_button.pack(side=tk.RIGHT, padx=10)
    
    def setup_ip_tab(self):
        # IP input frame
        input_frame = tk.Frame(self.ip_tab)
        input_frame.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Label(input_frame, text="IP Address:").pack(side=tk.LEFT, padx=5)
        self.ip_entry = tk.Entry(input_frame, width=20)
        self.ip_entry.pack(side=tk.LEFT, padx=5)
        
        lookup_button = tk.Button(input_frame, text="Lookup", command=self.lookup_ip)
        lookup_button.pack(side=tk.LEFT, padx=5)
        
        # Display area split into two sections
        display_frame = tk.Frame(self.ip_tab)
        display_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Left side - text results
        text_frame = tk.Frame(display_frame)
        text_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        tk.Label(text_frame, text="IP Information:").pack(anchor=tk.W)
        self.ip_result = scrolledtext.ScrolledText(text_frame, height=20)
        self.ip_result.pack(fill=tk.BOTH, expand=True)
        self.ip_result.config(state=tk.DISABLED)
        
        # Right side - map display
        map_frame = tk.Frame(display_frame)
        map_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        tk.Label(map_frame, text="Location Map:").pack(anchor=tk.W)
        self.map_canvas = tk.Canvas(map_frame, bg="white", width=400, height=400)
        self.map_canvas.pack(fill=tk.BOTH, expand=True)
        
        # "Open in browser" button
        self.open_map_button = tk.Button(map_frame, text="Open Map in Browser", command=self.open_map_in_browser, state=tk.DISABLED)
        self.open_map_button.pack(pady=10)
    
    def setup_phone_tab(self):
        # Phone input frame
        input_frame = tk.Frame(self.phone_tab)
        input_frame.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Label(input_frame, text="Country Code (without +):").pack(side=tk.LEFT, padx=5)
        self.country_entry = tk.Entry(input_frame, width=5)
        self.country_entry.pack(side=tk.LEFT, padx=5)
        
        tk.Label(input_frame, text="Phone Number:").pack(side=tk.LEFT, padx=5)
        self.phone_entry = tk.Entry(input_frame, width=20)
        self.phone_entry.pack(side=tk.LEFT, padx=5)
        
        lookup_button = tk.Button(input_frame, text="Lookup", command=self.lookup_phone)
        lookup_button.pack(side=tk.LEFT, padx=5)
        
        # Phone results and map
        display_frame = tk.Frame(self.phone_tab)
        display_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Text results
        text_frame = tk.Frame(display_frame)
        text_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        tk.Label(text_frame, text="Phone Information:").pack(anchor=tk.W)
        self.phone_result = scrolledtext.ScrolledText(text_frame, height=20)
        self.phone_result.pack(fill=tk.BOTH, expand=True)
        self.phone_result.config(state=tk.DISABLED)
        
        # Map for phone location
        map_frame = tk.Frame(display_frame)
        map_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        tk.Label(map_frame, text="Country Location:").pack(anchor=tk.W)
        self.phone_map_canvas = tk.Canvas(map_frame, bg="white", width=400, height=400)
        self.phone_map_canvas.pack(fill=tk.BOTH, expand=True)
    
    def setup_anomaly_tab(self):
        """Setup the anomaly log tab with more detailed information"""
        frame = ttk.Frame(self.anomaly_tab)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Stats frame at the top
        stats_frame = tk.Frame(frame, bg="#363636")
        stats_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(stats_frame, text="Anomaly Statistics:", bg="#363636", fg="white").pack(side=tk.LEFT, padx=5)
        self.total_anomalies_label = tk.Label(stats_frame, text="Total: 0", bg="#363636", fg="white")
        self.total_anomalies_label.pack(side=tk.LEFT, padx=20)
        
        self.ddos_count_label = tk.Label(stats_frame, text="DDoS: 0", bg="#363636", fg="#ff5555")
        self.ddos_count_label.pack(side=tk.LEFT, padx=20)
        
        # Add buttons for actions
        actions_frame = tk.Frame(frame)
        actions_frame.pack(fill=tk.X, pady=5)
        
        self.block_ip_button = tk.Button(actions_frame, text="Block Selected IP", command=self.block_selected_ip)
        self.block_ip_button.pack(side=tk.RIGHT, padx=5)
        
        self.clear_anomalies_button = tk.Button(actions_frame, text="Clear Anomaly Log", command=self.clear_anomaly_log)
        self.clear_anomalies_button.pack(side=tk.RIGHT, padx=5)
        
        # Main log area
        tk.Label(frame, text="Detected Anomalies:").pack(anchor=tk.W)
        
        self.anomaly_text = scrolledtext.ScrolledText(frame, height=25)
        self.anomaly_text.pack(fill=tk.BOTH, expand=True)
        self.anomaly_text.config(state=tk.DISABLED)
        
        # Configure tags for coloring
        self.anomaly_text.tag_config('DDoS', foreground='red')
        self.anomaly_text.tag_config('Service_Attack', foreground='orange')
        self.anomaly_text.tag_config('Anomalous_Traffic', foreground='purple')
        self.anomaly_text.tag_config('Suspicious_Rate', foreground='blue')
        self.anomaly_text.tag_config('normal', foreground='green')
        
        # Initialize counters
        self.anomaly_counts = {'total': 0, 'DDoS': 0, 'Service_Attack': 0, 'Anomalous_Traffic': 0, 'Suspicious_Rate': 0}

    def lookup_latest_ip(self):
        """Look up the most recent IP address from logs"""
        latest_ip = self.latest_ip_label.cget("text")
        if (latest_ip != "None"):
            self.ip_entry.delete(0, tk.END)
            self.ip_entry.insert(0, latest_ip)
            self.lookup_ip()
            # Switch to IP tab
            self.notebook.select(1)
    
    def lookup_ip(self):
        ip_address = self.ip_entry.get().strip()
        if not ip_address:
            self.update_ip_result("Please enter an IP address.")
            return
        
        try:
            # Try method 1 first (ip-api.com)
            url = f'http://ip-api.com/json/{ip_address}'
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'fail':
                    raise Exception(f"IP lookup failed: {data.get('message', 'Unknown error')}")
                
                # Store the IP data
                self.ip_data = data
                
                # Format the result text
                result = f"IP: {ip_address}\n\n"
                result += f"Country: {data.get('country', 'N/A')}\n"
                result += f"City: {data.get('city', 'N/A')}\n"
                result += f"Region: {data.get('regionName', 'N/A')}\n"
                result += f"Latitude: {data.get('lat', 'N/A')}\n"
                result += f"Longitude: {data.get('lon', 'N/A')}\n"
                result += f"ISP: {data.get('isp', 'N/A')}\n"
                result += f"Timezone: {data.get('timezone', 'N/A')}\n"
                result += f"Organization: {data.get('org', 'N/A')}\n"
                result += f"AS: {data.get('as', 'N/A')}\n"
                
                self.update_ip_result(result)
                
                # Update the map
                if 'lat' in data and 'lon' in data:
                    lat, lon = data['lat'], data['lon']
                    self.display_map(lat, lon)
                    self.open_map_button.config(state=tk.NORMAL)
                else:
                    self.map_canvas.delete("all")
                    self.map_canvas.create_text(200, 200, text="No location data available")
                    self.open_map_button.config(state=tk.DISABLED)
            else:
                raise Exception(f"HTTP error: {response.status_code}")
                
        except Exception as e:
            self.update_ip_result(f"Error looking up IP: {str(e)}")
            self.map_canvas.delete("all")
            self.map_canvas.create_text(200, 200, text="Map not available")
            self.open_map_button.config(state=tk.DISABLED)
    
    def display_map(self, lat, lon):
        """Display a map centered on the given coordinates"""
        try:
            # Use OpenStreetMap static map
            zoom = 10
            width, height = 400, 400
            
            # Create a static map URL - using OpenStreetMap with markers
            map_url = f"https://static-maps.yandex.ru/1.x/?ll={lon},{lat}&size={width},{height}&z={zoom}&l=map&pt={lon},{lat},pm2rdl"
            
            # Download the map image
            with urllib.request.urlopen(map_url) as response:
                map_data = response.read()
            
            # Convert to a PhotoImage
            image = Image.open(io.BytesIO(map_data))
            photo = ImageTk.PhotoImage(image)
            
            # Display on canvas
            self.map_canvas.delete("all")
            self.map_canvas.create_image(0, 0, anchor=tk.NW, image=photo)
            self.map_canvas.image = photo  # Keep a reference to prevent garbage collection
            
        except Exception as e:
            self.map_canvas.delete("all")
            self.map_canvas.create_text(200, 200, text=f"Couldn't load map: {str(e)}")
    
    def open_map_in_browser(self):
        """Open the location in a web browser using OpenStreetMap"""
        if not self.ip_data or 'lat' not in self.ip_data or 'lon' not in self.ip_data:
            return
        
        lat, lon = self.ip_data['lat'], self.ip_data['lon']
        url = f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=12/{lat}/{lon}"
        webbrowser.open(url)
    
    def lookup_phone(self):
        country = self.country_entry.get().strip()
        number = self.phone_entry.get().strip()
        
        if not country or not number:
            self.update_phone_result("Please enter both country code and phone number.")
            return
        
        try:
            target_number = '+' + country + number
            phone_number = phonenumbers.parse(target_number)
            
            # Get the country code
            country_code = phone_number.country_code
            country_name = geocoder.description_for_number(phone_number, 'en') or "Unknown"
            
            result = f"Phone: {target_number}\n\n"
            result += f"Valid number: {phonenumbers.is_valid_number(phone_number)}\n"
            result += f"Possible number: {phonenumbers.is_possible_number(phone_number)}\n"
            result += f"Formatted: {phonenumbers.format_number(phone_number, phonenumbers.PhoneNumberFormat.E164)}\n"
            result += f"Country: {country_name} (Code: +{country_code})\n"
            result += f"Carrier: {carrier.name_for_number(phone_number, 'en') or 'Unknown'}\n"
            
            self.update_phone_result(result)
            
            # Display country location (if available)
            # This is a simplified approach since we don't have precise phone location
            self.phone_map_canvas.delete("all")
            self.phone_map_canvas.create_text(200, 200, text=f"Location: {country_name}", font=("Arial", 14))
            
        except Exception as e:
            self.update_phone_result(f"Error looking up phone number: {str(e)}")
    
    def update_ip_result(self, text):
        self.ip_result.config(state=tk.NORMAL)
        self.ip_result.delete(1.0, tk.END)
        self.ip_result.insert(tk.END, text)
        self.ip_result.config(state=tk.DISABLED)
    
    def update_phone_result(self, text):
        self.phone_result.config(state=tk.NORMAL)
        self.phone_result.delete(1.0, tk.END)
        self.phone_result.insert(tk.END, text)
        self.phone_result.config(state=tk.DISABLED)
    
    def clear_logs(self):
        with log_lock:
            logs.clear()
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state=tk.DISABLED)
    
    def update_logs(self):
        """Thread to update logs in real time"""
        while True:
            new_logs = []
            with log_lock:
                if logs:
                    new_logs = logs.copy()
                    logs.clear()
            
            if new_logs:
                self.log_text.config(state=tk.NORMAL)
                for log in new_logs:
                    self.log_text.insert(tk.END, f"{log}\n")
                self.log_text.see(tk.END)  # Auto-scroll to bottom
                self.log_text.config(state=tk.DISABLED)
            
            time.sleep(0.5)  # Update every half second
    
    def update_latest_ip(self, ip_address):
        """Update the latest IP display"""
        self.latest_ip_label.config(text=ip_address)
        
        # Try to get location info
        try:
            url = f'http://ip-api.com/json/{ip_address}'
            response = requests.get(url, timeout=2)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') != 'fail':
                    location = f"{data.get('city', '')}, {data.get('country', '')}"
                    self.latest_location_label.config(text=location)
                    return
        except:
            pass
        
        # If we get here, we couldn't get the location
        self.latest_location_label.config(text="Location lookup failed")

    def log_anomaly(self, ip_address, anomalies, request_data):
        """Log detected anomalies with enhanced information"""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        self.anomaly_text.config(state=tk.NORMAL)
        
        if anomalies:
            # Update anomaly counters
            self.anomaly_counts['total'] += 1
            for anomaly_type in anomalies:
                if anomaly_type in self.anomaly_counts:
                    self.anomaly_counts[anomaly_type] += 1
            
            # Create detailed log message
            log_msg = f"[{timestamp}] ANOMALY from {ip_address}\n"
            log_msg += f"  Types: {', '.join(anomalies)}\n"
            log_msg += f"  Method: {request_data.get('method', 'N/A')}\n"
            log_msg += f"  Path: {request_data.get('path', 'N/A')}\n"
            log_msg += f"  Status: {request_data.get('status_code', 'N/A')}\n"
            log_msg += f"  Content Length: {request_data.get('content_length', 0)}\n"
            log_msg += "  ---\n"
            
            # Insert with color based on most severe anomaly
            if 'DDoS' in anomalies:
                self.anomaly_text.insert(tk.END, log_msg, 'DDoS')
            elif 'Service_Attack' in anomalies:
                self.anomaly_text.insert(tk.END, log_msg, 'Service_Attack')
            elif 'Anomalous_Traffic' in anomalies:
                self.anomaly_text.insert(tk.END, log_msg, 'Anomalous_Traffic')
            elif 'Suspicious_Rate' in anomalies:
                self.anomaly_text.insert(tk.END, log_msg, 'Suspicious_Rate')
            else:
                self.anomaly_text.insert(tk.END, log_msg)
        else:
            # For normal traffic, just add a simple entry with 5% probability
            if random.random() < 0.05:  # Only log 5% of normal traffic to avoid clutter
                log_msg = f"[{timestamp}] Normal traffic from {ip_address}\n"
                self.anomaly_text.insert(tk.END, log_msg, 'normal')
        
        # Update stats
        self.total_anomalies_label.config(text=f"Total: {self.anomaly_counts['total']}")
        self.ddos_count_label.config(text=f"DDoS: {self.anomaly_counts['DDoS']}")
        
        self.anomaly_text.see(tk.END)
        self.anomaly_text.config(state=tk.DISABLED)

    def block_selected_ip(self):
        """Block the selected IP address"""
        try:
            selected_text = self.anomaly_text.get("sel.first", "sel.last")
            # Extract IP from selected text
            ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', selected_text)
            if ip_match:
                ip = ip_match.group(0)
                # Add to blocked list
                with open('blocked_ips.txt', 'a') as f:
                    f.write(f"{ip}\n")
                messagebox.showinfo("IP Blocked", f"IP {ip} has been added to blocked list.")
            else:
                messagebox.showwarning("No IP Found", "No valid IP address found in selection.")
        except tk.TclError:
            messagebox.showwarning("No Selection", "Please select text containing an IP address.")

    def clear_anomaly_log(self):
        """Clear the anomaly log"""
        self.anomaly_text.config(state=tk.NORMAL)
        self.anomaly_text.delete(1.0, tk.END)
        self.anomaly_text.config(state=tk.DISABLED)
        
        # Reset counters
        self.anomaly_counts = {'total': 0, 'DDoS': 0, 'Service_Attack': 0, 'Anomalous_Traffic': 0, 'Suspicious_Rate': 0}
        self.total_anomalies_label.config(text="Total: 0")
        self.ddos_count_label.config(text="DDoS: 0")


# Store client IPs for better tracking
client_ips = {}

# Flask route for proxy
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def proxy(path):
    """Forward all requests to Node.js server with anomaly detection"""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    client_ip = request.remote_addr
    
    if client_ip == '127.0.0.1':
        forwarded_for = request.headers.get('X-Forwarded-For')
        if forwarded_for:
            client_ip = forwarded_for.split(',')[0].strip()
    
    # Check if IP is blocked
    try:
        with open('blocked_ips.txt', 'r') as f:
            blocked_ips = f.read().splitlines()
            if client_ip in blocked_ips:
                return "Access Denied - IP Blocked", 403
    except FileNotFoundError:
        pass
    
    # Prepare request data for anomaly detection
    request_data = {
        'timestamp': timestamp,
        'method': request.method,
        'path': path,
        'content_length': request.content_length or 0,
        'is_encrypted': request.scheme == 'https',
        'status_code': 200  # Will be updated after forwarding
    }
    
    # Forward the request
    try:
        resp = requests.request(
            method=request.method,
            url=f"{NODE_SERVER_URL}/{path}",
            headers={key: value for (key, value) in request.headers if key != 'Host'},
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False
        )
        
        # Update status code for anomaly detection
        request_data['status_code'] = resp.status_code
        
        # Detect anomalies
        anomalies = []
        if 'dashboard' in globals():
            anomalies = dashboard.detector.detect_anomalies(client_ip, request_data)
            dashboard.log_anomaly(client_ip, anomalies, request_data)
        
        # Format log entry
        if anomalies:
            log_entry = f"[{timestamp}] ⚠️ ANOMALY ({', '.join(anomalies)}) {request.method} /{path} from {client_ip}, Status: {resp.status_code}"
        else:
            log_entry = f"[{timestamp}] {request.method} /{path} from {client_ip}, Status: {resp.status_code}"
        
        with log_lock:
            logs.append(log_entry)
        
        # Update dashboard with latest client info
        client_ips[client_ip] = timestamp
        if 'dashboard' in globals():
            dashboard.update_latest_ip(client_ip)
        
        return (resp.content, resp.status_code, resp.headers.items())
    
    except Exception as e:
        error_msg = f"[{timestamp}] ERROR: {str(e)} for {request.method} /{path}"
        with log_lock:
            logs.append(error_msg)
        
        # Still try to detect anomalies in error cases
        if 'dashboard' in globals():
            request_data['status_code'] = 500  # Assume server error
            anomalies = dashboard.detector.detect_anomalies(client_ip, request_data)
            dashboard.log_anomaly(client_ip, anomalies, request_data)
        
        return f"Proxy Error: {str(e)}", 500

class AnomalyDetector:
    def __init__(self):
        # Load all trained models
        self.models = {
            'DDoS': joblib.load('ddos_detector.pkl'),
            'MITM': joblib.load('mitm_detector.pkl'),
            'DNS_Spoofing': joblib.load('dns_spoofing_detector.pkl'),
            'Data_Exfiltration': joblib.load('data_exfiltration_detector.pkl')
        }
        
        # Store features needed for each model
        self.model_features = {
            'DDoS': ['source_ip_numeric', 'method', 'target_url', 'status_code', 'bytes_sent', 'hour', 'day_of_week'],
            'MITM': ['source_ip_numeric', 'destination_ip_numeric', 'protocol', 'action', 'data_size', 'is_encrypted'],
            'DNS_Spoofing': ['client_ip_numeric', 'query', 'response', 'response_type', 'ttl', 'hour'],
            'Data_Exfiltration': ['source_ip_numeric', 'destination_ip_numeric', 'method', 'data_type', 'data_size', 'is_encrypted']
        }
        
        # For IP conversion
        self.ip_encoder = LabelEncoder()
        
    def prepare_features(self, ip_data, request_data):
        """Prepare features for all models from the available data"""
        features = {}
        
        # Convert IPs to numerical representation
        features['source_ip_numeric'] = int(''.join([f"{int(n):03d}" for n in ip_data['query'].split('.')][:3])) if 'query' in ip_data else 0
        features['destination_ip_numeric'] = int(''.join([f"{int(n):03d}" for n in ip_data['status'].split('.')][:3])) if 'status' in ip_data else 0
        features['client_ip_numeric'] = features['source_ip_numeric']
        
        # Add basic request features
        features['method'] = request_data.get('method', 'GET')
        features['protocol'] = request_data.get('protocol', 'HTTP')
        features['data_size'] = request_data.get('content_length', 0)
        
        # Add temporal features
        now = datetime.datetime.now()
        features['hour'] = now.hour
        features['day_of_week'] = now.weekday()
        
        # Add dummy values for other required features
        features['target_url'] = request_data.get('path', '/')
        features['status_code'] = 200  # Default
        features['action'] = 'Normal'
        features['is_encrypted'] = request_data.get('is_encrypted', False)
        features['query'] = request_data.get('path', '/').split('/')[-1]
        features['response'] = '192.168.1.1'  # Default
        features['response_type'] = 'A'
        features['ttl'] = 300
        features['data_type'] = 'Normal'
        
        return features
    
    def detect_anomalies(self, ip_address, request_data):
        """Detect anomalies across all models"""
        try:
            # Get IP geolocation data
            ip_data = self.get_ip_data(ip_address)
            if not ip_data:
                return []
            
            # Prepare features
            features = self.prepare_features(ip_data, request_data)
            
            anomalies = []
            for model_name, model in self.models.items():
                # Get required features for this model
                required_features = self.model_features[model_name]
                X = np.array([[features[feat] for feat in required_features]]).reshape(1, -1)
                
                # Predict
                prediction = model.predict(X)
                if prediction[0] == 1:  # Anomaly detected
                    anomalies.append(model_name)
            
            return anomalies
        except Exception as e:
            print(f"Anomaly detection error: {str(e)}")
            return []

    def get_ip_data(self, ip_address):
        """Get IP geolocation data"""
        try:
            url = f'http://ip-api.com/json/{ip_address}'
            response = requests.get(url, timeout=2)
            if response.status_code == 200:
                return response.json()
        except:
            return None

def run_flask():
    """Run Flask in a separate thread"""
    app.run(host='0.0.0.0', port=PROXY_PORT, threaded=True)

if __name__ == "__main__":
    # Create a directory for cached map images
    os.makedirs("map_cache", exist_ok=True)
    
    # Start Flask in a separate thread
    flask_thread = threading.Thread(target=run_flask, daemon=True)
    flask_thread.start()
    
    # Start the GUI
    root = tk.Tk()
    dashboard = ProxyDashboard(root)
    
    # Make the dashboard accessible globally
    globals()['dashboard'] = dashboard
    
    root.mainloop()
