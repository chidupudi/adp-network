import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.pipeline import make_pipeline
import joblib
from tabulate import tabulate

# 1. Enhanced Data Preparation
def prepare_data(df, time_feature='timestamp'):
    """Preprocess dataset with robust feature engineering"""
    df = df.copy()
    
    # Handle timestamps if present
    if time_feature in df.columns:
        df[time_feature] = pd.to_datetime(df[time_feature], errors='coerce')
        df['hour'] = df[time_feature].dt.hour
        df['day_of_week'] = df[time_feature].dt.dayofweek
        df['is_weekend'] = df['day_of_week'].isin([5,6]).astype(int)
        df.drop(time_feature, axis=1, inplace=True)
    
    # Convert IP addresses to numerical representations
    ip_cols = [col for col in df.columns if 'ip' in col.lower()]
    for col in ip_cols:
        if df[col].dtype == 'object':
            df[col+'_numeric'] = df[col].apply(lambda x: int(''.join([f"{int(n):03d}" for n in x.split('.')][:3])))
            df.drop(col, axis=1, inplace=True)
    
    # Advanced categorical encoding
    cat_cols = df.select_dtypes(include=['object']).columns
    for col in cat_cols:
        if len(df[col].unique()) <= 10:  # Low cardinality
            df = pd.get_dummies(df, columns=[col], prefix=col)
        else:  # High cardinality
            freq = df[col].value_counts(normalize=True)
            df[col] = df[col].map(freq)
    
    # Ensure target exists
    if 'attack_label' not in df.columns:
        raise ValueError("Target column 'attack_label' not found")
    
    X = df.drop('attack_label', axis=1)
    y = df['attack_label']
    
    return X, y

# 2. Model Training with Enhanced Evaluation
def train_evaluate_model(X, y, model_name):
    """Train model with comprehensive evaluation"""
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y)
    
    model = make_pipeline(
        StandardScaler(),
        RandomForestClassifier(
            n_estimators=150,
            max_depth=10,
            random_state=42,
            class_weight='balanced',
            n_jobs=-1
        )
    )
    
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:,1]
    
    # Generate evaluation metrics
    report = classification_report(y_test, y_pred, output_dict=True)
    cm = confusion_matrix(y_test, y_pred)
    
    # Create printable results
    metrics = {
        'Model': model_name,
        'Accuracy': round(accuracy_score(y_test, y_pred), 3),
        'Precision (Attack)': round(report['1']['precision'], 3),
        'Recall (Attack)': round(report['1']['recall'], 3),
        'F1 (Attack)': round(report['1']['f1-score'], 3),
        'Support (Attack)': report['1']['support'],
        'TN/FP/FN/TP': f"{cm[0,0]}/{cm[0,1]}/{cm[1,0]}/{cm[1,1]}"
    }
    
    return model, metrics

# 3. Dataset Processing Pipeline
def process_datasets():
    datasets = {
        'DDoS': pd.read_csv('ddos_dataset.csv'),
        'MITM': pd.read_csv('mitm_dataset.csv'),
        'DNS_Spoofing': pd.read_csv('dns_spoofing_dataset.csv'),
        'Data_Exfiltration': pd.read_csv('exfiltration_dataset.csv')
    }
    
    all_metrics = []
    models = {}
    
    for name, df in datasets.items():
        print(f"\n{'-'*50}")
        print(f"Processing {name} Dataset")
        print(f"{'-'*50}")
        
        # Dataset stats
        stats = {
            'Dataset': name,
            'Total Samples': len(df),
            'Attack %': f"{df['attack_label'].mean()*100:.1f}%",
            'Features': df.shape[1] - 1
        }
        all_metrics.append(stats)
        
        # Prepare data and train model
        X, y = prepare_data(df)
        model, metrics = train_evaluate_model(X, y, name)
        models[name] = model
        all_metrics.append(metrics)
        
        # Save model
        model_file = f"{name.lower()}_detector.pkl"
        joblib.dump(model, model_file)
        print(f"Saved model to {model_file}")
        
        # Feature importance (top 5)
        if hasattr(model.named_steps['randomforestclassifier'], 'feature_importances_'):
            importances = model.named_steps['randomforestclassifier'].feature_importances_
            features = X.columns
            top_features = sorted(zip(features, importances), key=lambda x: x[1], reverse=True)[:5]
            print("\nTop 5 Features:")
            for feat, imp in top_features:
                print(f"- {feat}: {imp:.3f}")
    
    # Print summary tables
    print("\n\nDATASET STATISTICS:")
    print(tabulate([m for m in all_metrics if 'Dataset' in m], headers="keys", tablefmt="grid"))
    
    print("\nMODEL PERFORMANCE:")
    print(tabulate([m for m in all_metrics if 'Model' in m], headers="keys", tablefmt="grid"))
    
    return models

# 4. Main Execution
if __name__ == "__main__":
    print("Network Anomaly Detection Training")
    print("================================\n")
    
    trained_models = process_datasets()
    
    print("\nTraining completed. Models saved as:")
    for name in trained_models:
        print(f"- {name.lower()}_detector.pkl")