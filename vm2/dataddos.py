import pandas as pd
import numpy as np
import random
import pickle
from datetime import datetime, timedelta
import ipaddress

# Set random seed for reproducibility
np.random.seed(42)
random.seed(42)

def generate_normal_traffic(start_time, num_records=1000):
    """Generate normal traffic logs"""
    records = []
    
    # Create a pool of client IPs (normal users)
    num_regular_users = 150
    regular_ips = [str(ipaddress.IPv4Address(random.randint(1, 2**32-1))) for _ in range(num_regular_users)]
    
    # Common HTTP methods with realistic distribution
    http_methods = ['GET'] * 80 + ['POST'] * 15 + ['PUT'] * 3 + ['DELETE'] * 2
    
    # Common URL paths
    common_paths = [
        '/home', '/login', '/dashboard', '/products', '/api/data', '/api/users', 
        '/about', '/contact', '/services', '/blog', '/cart', '/checkout',
        '/account', '/settings', '/search', '/api/search', '/api/products',
        '/images', '/static/css', '/static/js', '/favicon.ico'
    ]
    
    # Status code distribution (mostly successful)
    status_codes = [200] * 85 + [201] * 5 + [204] * 2 + [301] * 2 + [302] * 2 + [404] * 3 + [500] * 1
    
    # Time between requests (in seconds)
    time_gaps = np.random.exponential(2, num_records)
    
    current_time = start_time
    for i in range(num_records):
        client_ip = random.choice(regular_ips)
        method = random.choice(http_methods)
        path = random.choice(common_paths)
        status_code = random.choice(status_codes)
        content_length = int(np.random.lognormal(8, 1)) if method != 'GET' else int(np.random.lognormal(6, 1.5))
        is_encrypted = random.random() < 0.85  # 85% of traffic is HTTPS
        
        # Add time gap
        current_time += timedelta(seconds=time_gaps[i])
        
        records.append({
            'timestamp': current_time.strftime('%Y-%m-%d %H:%M:%S'),
            'client_ip': client_ip,
            'http_method': method,
            'request_path': path,
            'status_code': status_code,
            'content_length': content_length,
            'is_encrypted': is_encrypted,
            'is_attack': 0  # Not an attack
        })
    
    return records

def generate_ddos_attack(start_time, attack_duration_minutes=15, intensity=100):
    """Generate DDoS attack traffic"""
    records = []
    
    # Create a pool of attacking IPs
    num_attack_ips = int(intensity / 2)  # Number of IPs scales with intensity
    attack_ips = [str(ipaddress.IPv4Address(random.randint(1, 2**32-1))) for _ in range(num_attack_ips)]
    
    # Target paths for the attack
    target_paths = ['/login', '/api/data', '/search', '/dashboard']
    target_path = random.choice(target_paths)
    
    # HTTP methods for attack (mostly GET for basic DDoS)
    attack_methods = ['GET'] * 95 + ['POST'] * 5
    
    # Calculate number of attack requests
    requests_per_minute = intensity * 60  # Scale with intensity
    total_requests = int(requests_per_minute * attack_duration_minutes)
    
    # Time gaps between attack requests (much smaller than normal traffic)
    time_gaps = np.random.exponential(60 / requests_per_minute, total_requests)
    
    current_time = start_time
    for i in range(total_requests):
        client_ip = random.choice(attack_ips)
        method = random.choice(attack_methods)
        path = target_path
        
        # Status code distribution during attack (more errors)
        if random.random() < 0.7:  # 70% chance of success despite the attack
            status_code = 200
        else:
            status_code = random.choice([408, 429, 500, 503, 504])
        
        # Content length is more uniform in attacks
        content_length = int(np.random.normal(200, 50)) if method == 'POST' else 0
        is_encrypted = random.random() < 0.6  # Lower HTTPS ratio in attack traffic
        
        # Add time gap
        current_time += timedelta(seconds=time_gaps[i])
        
        records.append({
            'timestamp': current_time.strftime('%Y-%m-%d %H:%M:%S'),
            'client_ip': client_ip,
            'http_method': method,
            'request_path': path,
            'status_code': status_code,
            'content_length': content_length,
            'is_encrypted': is_encrypted,
            'is_attack': 1  # Attack traffic
        })
    
    return records

def generate_dataset(output_file='proxy_logs_with_ddos.csv', pickle_file='proxy_logs_with_ddos.pkl', num_days=7):
    """Generate a complete dataset with normal traffic and DDoS attacks"""
    all_records = []
    start_date = datetime(2023, 1, 1, 0, 0, 0)
    
    for day in range(num_days):
        day_start = start_date + timedelta(days=day)
        
        # Morning traffic (moderate)
        morning_start = day_start + timedelta(hours=8)
        records = generate_normal_traffic(morning_start, num_records=1200)
        all_records.extend(records)
        
        # Mid-day traffic (heavy)
        midday_start = day_start + timedelta(hours=12)
        records = generate_normal_traffic(midday_start, num_records=2000)
        all_records.extend(records)
        
        # Evening traffic (moderate)
        evening_start = day_start + timedelta(hours=18)
        records = generate_normal_traffic(evening_start, num_records=1500)
        all_records.extend(records)
        
        # Night traffic (light)
        night_start = day_start + timedelta(hours=22)
        records = generate_normal_traffic(night_start, num_records=800)
        all_records.extend(records)
        
        # Add DDoS attack on random days (not every day)
        if random.random() < 0.3:  # 30% chance of attack on any given day
            # Random attack time
            attack_hour = random.randint(9, 20)  # Attacks during business hours
            attack_start = day_start + timedelta(hours=attack_hour)
            
            # Random attack intensity
            intensity = random.choice([50, 100, 200])  # Low, medium, high intensity
            
            # Random attack duration
            duration = random.choice([5, 10, 15, 30])  # minutes
            
            # Generate attack traffic
            attack_records = generate_ddos_attack(
                attack_start,
                attack_duration_minutes=duration,
                intensity=intensity
            )
            all_records.extend(attack_records)
    
    # Convert to DataFrame and sort by timestamp
    df = pd.DataFrame(all_records)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df = df.sort_values('timestamp').reset_index(drop=True)
    
    # Save to CSV
    df.to_csv(output_file, index=False)
    print(f"Dataset with {len(df)} records created and saved to {output_file}")
    
    # Save to pickle
    with open(pickle_file, 'wb') as f:
        pickle.dump(df, f)
    print(f"Dataset also saved as pickle file to {pickle_file}")
    
    # Print attack statistics
    attack_records = df[df['is_attack'] == 1]
    if len(attack_records) > 0:
        attack_times = attack_records['timestamp'].dt.strftime('%Y-%m-%d %H:%M:%S').unique()
        print(f"DDoS attacks occur at: {', '.join(attack_times)}")
    else:
        print("No DDoS attacks in this dataset")
    
    return df

def add_derived_features(df):
    """Add derived features useful for anomaly detection"""
    # Convert timestamp to datetime if it's not already
    if not pd.api.types.is_datetime64_any_dtype(df['timestamp']):
        df['timestamp'] = pd.to_datetime(df['timestamp'])
    
    # Time-based features
    df['hour'] = df['timestamp'].dt.hour
    df['day_of_week'] = df['timestamp'].dt.dayofweek
    
    # Create 1-minute time windows for aggregation
    df['time_window'] = df['timestamp'].dt.floor('1min')
    
    # Requests per minute per IP
    requests_per_ip = df.groupby(['time_window', 'client_ip']).size().reset_index(name='requests_per_min_per_ip')
    df = pd.merge(df, requests_per_ip, on=['time_window', 'client_ip'], how='left')
    
    # Requests per minute per path
    requests_per_path = df.groupby(['time_window', 'request_path']).size().reset_index(name='requests_per_min_per_path')
    df = pd.merge(df, requests_per_path, on=['time_window', 'request_path'], how='left')
    
    # Error rate per minute (5xx/4xx status codes)
    df['is_error'] = df['status_code'] >= 400
    error_rates = df.groupby('time_window')['is_error'].mean().reset_index(name='error_rate')
    df = pd.merge(df, error_rates, on='time_window', how='left')
    
    # Unique IPs per minute
    unique_ips = df.groupby('time_window')['client_ip'].nunique().reset_index(name='unique_ips_per_min')
    df = pd.merge(df, unique_ips, on='time_window', how='left')
    
    # Total requests per minute
    total_requests = df.groupby('time_window').size().reset_index(name='total_requests_per_min')
    df = pd.merge(df, total_requests, on='time_window', how='left')
    
    return df

# Generate the dataset and then add derived features
print("Generating the initial dataset...")
df = generate_dataset(
    output_file='proxy_logs_with_ddos.csv', 
    pickle_file='proxy_logs_with_ddos.pkl',
    num_days=7
)

print("\nAdding derived features...")
df_with_features = add_derived_features(df)

# Save the enhanced dataset to both CSV and pickle
df_with_features.to_csv('proxy_logs_with_features.csv', index=False)
with open('proxy_logs_with_features.pkl', 'wb') as f:
    pickle.dump(df_with_features, f)
print("Enhanced dataset saved to proxy_logs_with_features.csv and proxy_logs_with_features.pkl")

# Sample of the dataset
print("\nSample of the dataset with features:")
print(df_with_features.sample(5))

# Basic statistics
print("\nBasic statistics:")
print(f"Total records: {len(df_with_features)}")
print(f"Attack records: {df_with_features['is_attack'].sum()} ({df_with_features['is_attack'].mean()*100:.2f}%)")
print(f"Mean requests per minute per IP during normal traffic: {df_with_features[df_with_features['is_attack']==0]['requests_per_min_per_ip'].mean():.2f}")
print(f"Mean requests per minute per IP during attacks: {df_with_features[df_with_features['is_attack']==1]['requests_per_min_per_ip'].mean():.2f}")

# Example of how to build a simple anomaly detection model using Isolation Forest
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

def train_isolation_forest(df):
    # Select relevant features for the model
    features = [
        'requests_per_min_per_ip',
        'requests_per_min_per_path',
        'error_rate',
        'unique_ips_per_min',
        'total_requests_per_min',
        'hour',
        'day_of_week'
    ]
    
    # Normalize the features
    scaler = StandardScaler()
    X = scaler.fit_transform(df[features])
    
    # Train the model
    model = IsolationForest(contamination=0.05, random_state=42)
    model.fit(X)
    
    # Predict anomalies
    df['anomaly_score'] = model.decision_function(X)
    df['is_anomaly'] = model.predict(X) == -1
    
    # Evaluate using the known attack labels
    true_positives = ((df['is_anomaly'] == True) & (df['is_attack'] == 1)).sum()
    false_positives = ((df['is_anomaly'] == True) & (df['is_attack'] == 0)).sum()
    true_negatives = ((df['is_anomaly'] == False) & (df['is_attack'] == 0)).sum()
    false_negatives = ((df['is_anomaly'] == False) & (df['is_attack'] == 1)).sum()
    
    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    
    print("\nAnomaly Detection Results:")
    print(f"Precision: {precision:.4f}")
    print(f"Recall: {recall:.4f}")
    print(f"F1 Score: {f1:.4f}")
    
    return df, model, scaler

# Train the model and evaluate
print("\nTraining anomaly detection model...")
df_with_predictions, model, scaler = train_isolation_forest(df_with_features)

# Save the final dataset with predictions to both CSV and pickle
df_with_predictions.to_csv('proxy_logs_with_predictions.csv', index=False)
with open('proxy_logs_with_predictions.pkl', 'wb') as f:
    pickle.dump(df_with_predictions, f)
print("Final dataset with predictions saved to proxy_logs_with_predictions.csv and proxy_logs_with_predictions.pkl")

# Also save the trained model and scaler
with open('ddos_detection_model.pkl', 'wb') as f:
    pickle.dump({'model': model, 'scaler': scaler}, f)
print("Trained model and scaler saved to ddos_detection_model.pkl")

