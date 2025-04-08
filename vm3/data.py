import pandas as pd
import random
from datetime import datetime, timedelta

def generate_ddos_data(num_records=1000):
    data = []
    methods = ['GET', 'POST', 'HEAD', 'OPTIONS', 'PUT', 'DELETE']  # Added more methods
    status_codes = [200, 404, 503, 403, 500, 302]  # Added more status codes
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
        'python-requests/2.28.1',  # Bot-like user agents
        'curl/7.68.0',
        ''
    ]
    
    base_time = datetime.now()
    
    # Attack traffic (90%)
    for i in range(int(num_records*0.9)):
        timestamp = base_time - timedelta(seconds=random.randint(0, 60))  # More concentrated in time
        src_ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
        
        # More varied target URLs
        target_url = random.choice([
            f"https://victim.com/{random.choice(['login', 'api', 'admin', 'wp-admin', 'checkout'])}?id={random.randint(1000,9999)}",
            f"https://victim.com/{''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=8))}.php",
            f"https://api.victim.com/v1/{random.choice(['users', 'products', 'orders'])}"
        ])
        
        data.append({
            'timestamp': timestamp,
            'source_ip': src_ip,
            'method': random.choices(methods, weights=[5, 3, 1, 1, 1, 1], k=1)[0],  # Weighted methods
            'target_url': target_url,
            'status_code': random.choices(status_codes, weights=[3, 2, 5, 2, 1, 1], k=1)[0],  # Weighted status codes
            'bytes_sent': random.choices([0, 100, 500, 1000, 5000], weights=[2, 5, 3, 1, 1], k=1)[0],  # Weighted sizes
            'user_agent': random.choices(user_agents, weights=[3, 2, 4, 3, 1], k=1)[0],  # Weighted user agents
            'request_rate': random.randint(10, 1000),  # Requests per second
            'attack_label': 1
        })
    
    # Normal traffic (10%)
    for i in range(int(num_records*0.1)):
        data.append({
            'timestamp': base_time - timedelta(seconds=random.randint(0, 3600)),
            'source_ip': f"192.168.1.{random.randint(1, 50)}",
            'method': random.choices(['GET', 'POST'], weights=[8, 2], k=1)[0],
            'target_url': random.choice([
                "https://victim.com/home",
                "https://victim.com/about",
                "https://victim.com/contact"
            ]),
            'status_code': 200,
            'bytes_sent': random.randint(500, 2000),
            'user_agent': random.choice(user_agents[:2]),  # Only real browsers
            'request_rate': random.randint(1, 5),
            'attack_label': 0
        })
        
    return pd.DataFrame(data).sample(frac=1).reset_index(drop=True)
# 2. MITM Attack Dataset
def generate_mitm_data(num_records=1000):
    data = []
    protocols = ['HTTP', 'HTTPS', 'FTP', 'SMTP']
    actions = ['Packet Capture', 'Session Hijack', 'SSL Stripping']
    
    for i in range(num_records):
        timestamp = datetime.now() - timedelta(minutes=random.randint(0, 60))
        data.append({
            'timestamp': timestamp, 'source_ip': f"10.0.0.{random.randint(1, 50)}",
            'destination_ip': f"192.168.1.{random.randint(1, 50)}", 'protocol': random.choice(protocols),
            'action': random.choice(actions), 'data_size': random.randint(100, 5000),
            'is_encrypted': random.choice([True, False]), 'attack_label': 1
        })
    
    # Normal traffic (20%)
    for i in range(int(num_records*0.2)):
        data.append({
            'timestamp': datetime.now() - timedelta(minutes=random.randint(0, 60)),
            'source_ip': f"10.0.0.{random.randint(1, 50)}", 'destination_ip': f"10.0.0.{random.randint(51, 100)}",
            'protocol': random.choice(['HTTP', 'HTTPS']), 'action': 'Normal',
            'data_size': random.randint(500, 2000), 'is_encrypted': True, 'attack_label': 0
        })
    return pd.DataFrame(data).sample(frac=1).reset_index(drop=True)

# 3. DNS Spoofing Dataset
def generate_dns_spoofing_data(num_records=1000):
    domains = ['bank.com', 'login.example.com', 'payments.service.com']
    spoofed_ips = ['192.168.1.100', '10.0.0.15']
    
    data = []
    for i in range(num_records):
        is_attack = random.random() > 0.7  # 30% attack traffic
        timestamp = datetime.now() - timedelta(minutes=random.randint(0, 120))
        
        if is_attack:
            data.append({
                'timestamp': timestamp, 'client_ip': f"192.168.1.{random.randint(1, 50)}",
                'query': random.choice(domains), 'response': random.choice(spoofed_ips),
                'response_type': 'A', 'ttl': random.randint(60, 300), 'is_spoofed': True, 'attack_label': 1
            })
        else:
            data.append({
                'timestamp': timestamp, 'client_ip': f"192.168.1.{random.randint(51, 100)}",
                'query': f"www.{random.choice(['example.org', 'test.com'])}",
                'response': f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                'response_type': random.choice(['A', 'AAAA']), 'ttl': random.randint(300, 3600),
                'is_spoofed': False, 'attack_label': 0
            })
    return pd.DataFrame(data)

# 4. Data Exfiltration Dataset
def generate_exfiltration_data(num_records=1000):
    methods = ['DNS', 'HTTP', 'ICMP', 'FTP']
    data_types = ['Credit Card', 'Credentials', 'API Keys']
    
    data = []
    for i in range(num_records):
        is_attack = random.random() > 0.8  # 20% attack traffic
        timestamp = datetime.now() - timedelta(hours=random.randint(0, 24))
        
        if is_attack:
            data.append({
                'timestamp': timestamp, 'source_ip': f"10.0.0.{random.randint(1, 50)}",
                'destination_ip': f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                'method': random.choice(methods), 'data_type': random.choice(data_types),
                'data_size': random.randint(100, 50000), 'is_encrypted': random.choice([True, False]),
                'attack_label': 1
            })
        else:
            data.append({
                'timestamp': timestamp, 'source_ip': f"10.0.0.{random.randint(51, 100)}",
                'destination_ip': f"10.0.1.{random.randint(1, 50)}", 'method': 'HTTP',
                'data_type': 'Normal', 'data_size': random.randint(500, 2000),
                'is_encrypted': True, 'attack_label': 0
            })
    return pd.DataFrame(data).sample(frac=1).reset_index(drop=True)

# Generate and save all datasets
ddos_df = generate_ddos_data(5000)
mitm_df = generate_mitm_data(3000)
dns_df = generate_dns_spoofing_data(2000)
exfil_df = generate_exfiltration_data(1500)

ddos_df.to_csv('ddos_dataset.csv', index=False)
mitm_df.to_csv('mitm_dataset.csv', index=False)
dns_df.to_csv('dns_spoofing_dataset.csv', index=False)
exfil_df.to_csv('exfiltration_dataset.csv', index=False)

print("All datasets generated successfully!")