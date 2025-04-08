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
        self.root.title("Proxy Dashboard with IP Location")
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
    
    def lookup_latest_ip(self):
        """Look up the most recent IP address from logs"""
        latest_ip = self.latest_ip_label.cget("text")
        if latest_ip != "None":
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


# Store client IPs for better tracking
client_ips = {}

# Flask route for proxy
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def proxy(path):
    """Forward all requests to Node.js server"""
    # Log the request
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    client_ip = request.remote_addr
    
    # Extract client IP properly
    if client_ip == '127.0.0.1':
        # Try to get the real IP from X-Forwarded-For header
        forwarded_for = request.headers.get('X-Forwarded-For')
        if forwarded_for:
            client_ip = forwarded_for.split(',')[0].strip()
    
    log_entry = f"[{timestamp}] {request.method} /{path} from {client_ip}"
    
    # Add to logs
    with log_lock:
        logs.append(log_entry)
    
    # Update client IP tracking
    client_ips[client_ip] = timestamp
    
    # Update the GUI with the latest IP (if dashboard exists)
    if 'dashboard' in globals():
        dashboard.update_latest_ip(client_ip)
    
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
        
        # Log the response
        log_response = f"[{timestamp}] Response: {resp.status_code} for {request.method} /{path}"
        with log_lock:
            logs.append(log_response)
        
        return (resp.content, resp.status_code, resp.headers.items())
    except Exception as e:
        error_msg = f"[{timestamp}] ERROR: {str(e)} for {request.method} /{path}"
        with log_lock:
            logs.append(error_msg)
        return f"Proxy Error: {str(e)}", 500

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
    