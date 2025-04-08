import requests
import random
import time
import threading
from faker import Faker
import socket
import numpy as np

# Configuration
TARGET_URL = "http://localhost:3000"  # Your proxy endpoint
NORMAL_USERS = 5                     # Number of legitimate users
ATTACKERS = 50                       # Number of attacking bots
DURATION = 300                       # Test duration in seconds
ATTACK_START = 60                    # When to start attacks (seconds)

fake = Faker()

def generate_ip():
    """Generate random IPs similar to your dataset"""
    return f"10.0.0.{random.randint(1, 254)}"

def normal_user(user_id):
    """Simulate legitimate user behavior"""
    print(f"👤 Normal user {user_id} started")
    while True:
        try:
            # Generate normal traffic patterns
            headers = {
                'User-Agent': fake.user_agent(),
                'X-Forwarded-For': generate_ip()
            }
            
            # Random normal request characteristics
            delay = random.uniform(0.5, 2.0)
            resp = requests.get(
                TARGET_URL,
                headers=headers,
                timeout=5
            )
            
            if resp.status_code == 403:
                print(f"⚠️ Normal user {user_id} got blocked (false positive)")
            
            time.sleep(delay)
            
        except Exception as e:
            print(f"User {user_id} error: {str(e)}")
            time.sleep(5)

def attacker(attacker_id):
    """Simulate DDoS attacker"""
    time.sleep(ATTACK_START)  # Wait for attack phase
    
    print(f"☠️ Attacker {attacker_id} activated")
    while True:
        try:
            # Generate attack patterns matching your dataset
            attack_ip = generate_ip()
            headers = {
                'User-Agent': 'Mozilla/5.0',
                'X-Forwarded-For': attack_ip
            }
            
            # Attack characteristics (matching your malicious samples)
            attack_duration = random.uniform(0.01, 0.1)  # Very fast requests
            payload_size = random.choice([
                1024, 2048, 4096,  # Common attack payload sizes
                random.randint(500, 5000)  # Random sizes
            ])
            
            # Generate random payload
            payload = bytes([random.randint(0, 255) for _ in range(payload_size)])
            
            requests.post(
                f"{TARGET_URL}/api/v1/attack",
                headers=headers,
                data=payload,
                timeout=1
            )
            
            time.sleep(attack_duration)
            
        except Exception as e:
            # print(f"Attacker {attacker_id} error: {str(e)}")  # Uncomment for debugging
            time.sleep(0.1)

def monitor_traffic():
    """Display traffic statistics"""
    print("\n🚦 Traffic Monitor 🚦")
    print("---------------------")
    print("Time (s) | Status")
    print("---------------------")
    
    start_time = time.time()
    while True:
        elapsed = int(time.time() - start_time)
        if elapsed >= DURATION:
            print("\n✅ Simulation complete")
            os._exit(0)
            
        if elapsed == ATTACK_START:
            print("\n🔥 ATTACK PHASE STARTED 🔥")
        
        time.sleep(1)

if __name__ == "__main__":
    print(f"""
██████╗ ██████╗ ██████╗ ███████╗
██╔══██╗██╔══██╗██╔══██╗██╔════╝
██║  ██║██║  ██║██║  ██║███████╗
██║  ██║██║  ██║██║  ██║╚════██║
██████╔╝██████╔╝██████╔╝███████║
╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝

Starting DDoS Simulation:
- Target: {TARGET_URL}
- Duration: {DURATION} seconds
- Normal Users: {NORMAL_USERS}
- Attackers: {ATTACKERS}
- Attack starts at: {ATTACK_START}s
""")

    # Start monitor
    threading.Thread(target=monitor_traffic, daemon=True).start()

    # Start normal users
    for i in range(NORMAL_USERS):
        threading.Thread(target=normal_user, args=(i+1,), daemon=True).start()

    # Start attackers
    for i in range(ATTACKERS):
        threading.Thread(target=attacker, args=(i+1,), daemon=True).start()

    # Keep main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 Simulation stopped by user")