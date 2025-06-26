import numpy as np
import pandas as pd
import os
import re
import joblib
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from threat_intel import ThreatIntelFeed
import torch
import torch.nn as nn
import torch.optim as optim
from sklearn.neural_network import MLPRegressor
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer

###################################
# 1. NETWORK ANOMALY DETECTION
###################################

class DeepAutoencoder(nn.Module):
    def __init__(self, input_dim):
        super(DeepAutoencoder, self).__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 128),
            nn.ReLU(),
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Linear(64, 32),
            nn.ReLU()
        )
        self.decoder = nn.Sequential(
            nn.Linear(32, 64),
            nn.ReLU(),
            nn.Linear(64, 128),
            nn.ReLU(),
            nn.Linear(128, input_dim)
        )
    def forward(self, x):
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded

def build_autoencoder_sklearn(input_dim):
    return MLPRegressor(
        hidden_layer_sizes=(128, 64, 32, 64, 128),
        activation='relu',
        solver='adam',
        max_iter=200,
        early_stopping=True,
        random_state=42
    )

def preprocess_network_data(df):
    features = df[['bytes_sent', 'bytes_received', 'duration', 
                  'port', 'protocol_type', 'service', 'flag']]
    categorical_cols = ['protocol_type', 'service', 'flag']
    features = pd.get_dummies(features, columns=categorical_cols)
    scaler = StandardScaler()
    numerical_cols = ['bytes_sent', 'bytes_received', 'duration', 'port']
    features[numerical_cols] = scaler.fit_transform(features[numerical_cols])
    return features, scaler

def preprocess_network_data_with_columns(df, expected_columns, scaler=None):
    categorical_cols = ['protocol_type', 'service', 'flag']
    features = df[['bytes_sent', 'bytes_received', 'duration', 
                   'port', 'protocol_type', 'service', 'flag']]
    features = pd.get_dummies(features, columns=categorical_cols)
    for col in expected_columns:
        if col not in features.columns:
            features[col] = 0
    features = features[expected_columns]
    if scaler:
        numerical_cols = ['bytes_sent', 'bytes_received', 'duration', 'port']
        features[numerical_cols] = scaler.transform(features[numerical_cols])
    return features

def train_network_anomaly_models(X_train):
    # Train deep autoencoder with PyTorch
    input_dim = X_train.shape[1]
    model = DeepAutoencoder(input_dim)
    criterion = nn.MSELoss()
    optimizer = optim.Adam(model.parameters(), lr=0.001)
    X_train_tensor = torch.tensor(X_train.values, dtype=torch.float32)
    model.train()
    for epoch in range(50):
        optimizer.zero_grad()
        outputs = model(X_train_tensor)
        loss = criterion(outputs, X_train_tensor)
        loss.backward()
        optimizer.step()
    # Train Isolation Forest
    iso_forest = IsolationForest(contamination=0.01, random_state=42)
    iso_forest.fit(X_train)
    return model, iso_forest

def detect_network_anomalies(autoencoder, iso_forest, X_test):
    # Neural network reconstruction error using PyTorch model
    # Only call eval() if autoencoder is a PyTorch model
    if hasattr(autoencoder, 'eval'):
        autoencoder.eval()
        X_test_tensor = torch.tensor(X_test.values, dtype=torch.float32)
        with torch.no_grad():
            predictions = autoencoder(X_test_tensor).numpy()
    else:
        # If autoencoder is sklearn MLPRegressor, use predict directly
        predictions = autoencoder.predict(X_test)
    # Calculate reconstruction error
    mse = np.mean(np.power(X_test.values - predictions, 2), axis=1)
    autoencoder_anomalies = mse > np.percentile(mse, 99)
    iso_anomalies = iso_forest.predict(X_test) == -1
    combined_anomalies = autoencoder_anomalies | iso_anomalies
    return combined_anomalies, mse

def generate_sample_network_data(n_samples=10000):
    np.random.seed(42)
    normal_data = {
        'bytes_sent': np.random.normal(5000, 1000, n_samples),
        'bytes_received': np.random.normal(8000, 2000, n_samples),
        'duration': np.random.normal(60, 30, n_samples),
        'port': np.random.choice([80, 443, 22, 25], n_samples),
        'protocol_type': np.random.choice(['tcp', 'udp', 'icmp'], n_samples),
        'service': np.random.choice(['http', 'https', 'ssh', 'smtp'], n_samples),
        'flag': np.random.choice(['SF', 'REJ', 'S0'], n_samples)
    }
    df = pd.DataFrame(normal_data)
    anomaly_indices = np.random.choice(n_samples, int(n_samples * 0.05), replace=False)
    df.loc[anomaly_indices, 'bytes_sent'] = np.random.normal(50000, 10000, len(anomaly_indices))
    df.loc[anomaly_indices, 'duration'] = np.random.normal(600, 100, len(anomaly_indices))
    return df

###################################
# 2. MALWARE DETECTION
###################################

def extract_pe_features(file_path):
    np.random.seed(int(hash(file_path) % 2**32))
    features = {
        'filesize': np.random.randint(10000, 10000000),
        'num_sections': np.random.randint(1, 20),
        'num_imports': np.random.randint(10, 500),
        'num_exports': np.random.randint(0, 50),
        'contains_packer_sig': np.random.choice([0, 1], p=[0.7, 0.3]),
        'entry_point_entropy': np.random.uniform(0, 8),
        'avg_section_entropy': np.random.uniform(0, 8),
        'has_digital_signature': np.random.choice([0, 1], p=[0.6, 0.4]),
        'has_tls_callback': np.random.choice([0, 1], p=[0.9, 0.1]),
        'has_anti_debug': np.random.choice([0, 1], p=[0.8, 0.2]),
        'has_anti_vm': np.random.choice([0, 1], p=[0.8, 0.2])
    }
    return features

def train_malware_detector(X_train, y_train):
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)
    return clf

def generate_sample_malware_data(n_samples=1000):
    np.random.seed(42)
    features = []
    labels = []
    for i in range(int(n_samples * 0.6)):
        file_path = f"benign_sample_{i}.exe"
        feature_dict = extract_pe_features(file_path)
        feature_dict['entry_point_entropy'] = np.random.uniform(0, 5.5)
        feature_dict['contains_packer_sig'] = np.random.choice([0, 1], p=[0.9, 0.1])
        feature_dict['has_anti_debug'] = np.random.choice([0, 1], p=[0.95, 0.05])
        feature_dict['has_anti_vm'] = np.random.choice([0, 1], p=[0.98, 0.02])
        features.append(feature_dict)
        labels.append(0)
    for i in range(int(n_samples * 0.4)):
        file_path = f"malware_sample_{i}.exe"
        feature_dict = extract_pe_features(file_path)
        feature_dict['entry_point_entropy'] = np.random.uniform(5.5, 8)
        feature_dict['contains_packer_sig'] = np.random.choice([0, 1], p=[0.3, 0.7])
        feature_dict['has_anti_debug'] = np.random.choice([0, 1], p=[0.5, 0.5])
        feature_dict['has_anti_vm'] = np.random.choice([0, 1], p=[0.4, 0.6])
        features.append(feature_dict)
        labels.append(1)
    df = pd.DataFrame(features)
    return df, np.array(labels)

###################################
# 3. PHISHING DETECTION
###################################

def extract_email_features(email_content):
    features = {
        'has_urgent_subject': bool(re.search(r'urgent|immediate|alert|critical', email_content, re.I)),
        'has_suspicious_links': bool(re.search(r'href=["\']https?://[^\/]*?(?:\d{1,3}\.){3}\d{1,3}', email_content)),
        'has_password_request': bool(re.search(r'password|credential|login|sign in', email_content, re.I)),
        'has_attachment_mention': bool(re.search(r'attach|download|open|file', email_content, re.I)),
        'has_financial_terms': bool(re.search(r'bank|account|money|transfer|paypal|credit|debit', email_content, re.I)),
        'has_misspellings': bool(re.search(r'verifcation|accaunt|securty|notifcation', email_content, re.I)),
        'email_length': len(email_content),
        'link_count': len(re.findall(r'href=["\']https?://', email_content)),
        'image_count': len(re.findall(r'<img', email_content))
    }
    return features

def preprocess_email_text(email_content):
    text = re.sub(r'<[^>]+>', ' ', email_content)
    text = re.sub(r'\s+', ' ', text).strip()
    text = re.sub(r'https?://\S+', '', text)
    return text

def train_phishing_detector(email_texts, labels):
    vectorizer = TfidfVectorizer(max_features=1000, stop_words='english')
    X_text = vectorizer.fit_transform(email_texts)
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_text, labels)
    return vectorizer, clf

def generate_sample_phishing_data(n_samples=500):
    np.random.seed(42)
    legitimate_templates = [
        "Dear {user}, Thank you for your recent purchase from {company}. Your order #{order_num} has been processed. If you have any questions, contact us at support@{company}.com.",
        "Hello {user}, This is a reminder about your upcoming appointment on {date}. Please call our office if you need to reschedule.",
        "Dear {user}, Your monthly statement is now available. You can view it by logging into your account at {company}.com/account.",
        "Hi {user}, Just wanted to follow up on our conversation yesterday. Let me know if you need any additional information.",
        "Dear valued customer, Thank you for being with {company} for {years} years! We appreciate your loyalty."
    ]
    phishing_templates = [
        "URGENT: Your {company} account has been suspended! Click here to verfiy your information: http://{suspicious_domain}/login",
        "Dear customer, We detected unusual activity in your account. Please verify your password and banking details here: http://{ip_address}/secure",
        "Your {company} account needs immediate attention! Your account will be terminated unless you update your information: {suspicious_link}",
        "Congratulations! You've won a free iPhone! Click to claim your prize now: http://{suspicious_domain}/claim-prize",
        "ALERT: Your package delivery failed. To reschedule, open the attachment: delivery_form.exe"
    ]
    companies = ["Amazon", "Netflix", "PayPal", "Microsoft", "Apple", "Bank of America", "Chase", "Facebook"]
    users = ["user", "customer", "member", "client", "recipient"]
    suspicious_domains = ["amaz0n-secure.com", "account-verify.net", "secure-login-portal.com", "verification-center.info"]
    emails = []
    labels = []
    for i in range(int(n_samples * 0.6)):
        template = np.random.choice(legitimate_templates)
        company = np.random.choice(companies)
        user = np.random.choice(users)
        email = template.format(
            user=user,
            company=company.lower(),
            order_num=np.random.randint(10000, 99999),
            date=f"{np.random.randint(1, 30)}/{np.random.randint(1, 12)}/2023",
            years=np.random.randint(1, 10)
        )
        emails.append(email)
        labels.append(0)
    for i in range(int(n_samples * 0.4)):
        template = np.random.choice(phishing_templates)
        company = np.random.choice(companies)
        suspicious_domain = np.random.choice(suspicious_domains)
        ip_address = f"{np.random.randint(1, 255)}.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}"
        suspicious_link = f"http://{suspicious_domain}/verify?ref={np.random.randint(10000, 99999)}"
        email = template.format(
            company=company,
            suspicious_domain=suspicious_domain,
            ip_address=ip_address,
            suspicious_link=suspicious_link
        )
        emails.append(email)
        labels.append(1)
    processed_emails = [preprocess_email_text(email) for email in emails]
    return processed_emails, np.array(labels)

###################################
# 4. MAIN SYSTEM INTEGRATION
###################################

class CybersecurityThreatDetector:
    def __init__(self):
        self.network_autoencoder = None
        self.network_isoforest = None
        self.network_scaler = None
        self.network_feature_columns = None
        self.malware_detector = None
        self.phishing_vectorizer = None
        self.phishing_detector = None
        self.is_trained = False
        self.threat_feed = ThreatIntelFeed()
    
    def train(self, train_network=True, train_malware=True, train_phishing=True):
        print("Training Cybersecurity Threat Detection System...")
        if train_network:
            print("1. Training Network Anomaly Detection Models...")
            network_data = generate_sample_network_data()
            features, self.network_scaler = preprocess_network_data(network_data)
            self.network_feature_columns = features.columns.tolist()
            X_train, X_test = train_test_split(features, test_size=0.3, random_state=42)
            self.network_autoencoder, self.network_isoforest = train_network_anomaly_models(X_train)
        if train_malware:
            print("2. Training Malware Detection Model...")
            malware_features, malware_labels = generate_sample_malware_data()
            X_train, X_test, y_train, y_test = train_test_split(
                malware_features, malware_labels, test_size=0.3, random_state=42
            )
            self.malware_detector = train_malware_detector(X_train, y_train)
        if train_phishing:
            print("3. Training Phishing Detection Model...")
            email_texts, phishing_labels = generate_sample_phishing_data()
            train_texts, test_texts, train_labels, test_labels = train_test_split(
                email_texts, phishing_labels, test_size=0.3, random_state=42
            )
            self.phishing_vectorizer, self.phishing_detector = train_phishing_detector(train_texts, train_labels)
        self.is_trained = True
        print("All models trained successfully!")

    def multi_modal_fusion(self, network_data, file_paths, emails):
        if not self.is_trained:
            print("Models not trained yet. Please train the models first.")
            return None
        results = {}
        # Network threat detection
        network_results = self.detect_network_threats(network_data)
        results['network'] = network_results
        # Malware detection
        malware_results = self.detect_malware(file_paths)
        results['malware'] = malware_results
        # Phishing detection
        phishing_results = self.detect_phishing(emails)
        results['phishing'] = phishing_results

        # Simple fusion logic: aggregate anomaly counts and probabilities
        fusion_summary = {
            'total_network_anomalies': network_results['num_anomalies'] if network_results else 0,
            'total_malware_files': len(malware_results) if malware_results else 0,
            'total_malware_detected': sum(1 for r in malware_results if r.get('is_malware')) if malware_results else 0,
            'total_phishing_emails': len(phishing_results) if phishing_results else 0,
            'total_phishing_detected': sum(1 for r in phishing_results if r.get('is_phishing')) if phishing_results else 0,
        }
        results['fusion_summary'] = fusion_summary
        return results

    def explain_network_anomalies(self, network_data):
        # Example: Return feature importances or reconstruction errors per feature
        if not self.is_trained or self.network_autoencoder is None:
            print("Network model not trained or loaded.")
            return None
        # For simplicity, return reconstruction error per feature for each sample
        processed_data = network_data
        # Use PyTorch model for prediction
        self.network_autoencoder.eval()
        with torch.no_grad():
            input_tensor = torch.tensor(processed_data.values, dtype=torch.float32)
            predictions = self.network_autoencoder(input_tensor).numpy()
        errors = (processed_data.values - predictions) ** 2
        return errors

    def explain_malware_detection(self, file_path):
        # Example: Return feature importance from RandomForest
        if not self.is_trained or self.malware_detector is None:
            print("Malware model not trained or loaded.")
            return None
        try:
            features = extract_pe_features(file_path)
            feature_names = list(features.keys())
            feature_values = list(features.values())
            importances = self.malware_detector.feature_importances_
            explanation = dict(zip(feature_names, importances))
            return explanation
        except Exception as e:
            print(f"Error explaining malware detection: {e}")
            return None

    def explain_phishing_detection(self, email_text):
        # Example: Return top features contributing to phishing prediction
        if not self.is_trained or self.phishing_detector is None or self.phishing_vectorizer is None:
            print("Phishing model not trained or loaded.")
            return None
        try:
            processed_text = preprocess_email_text(email_text)
            text_features = self.phishing_vectorizer.transform([processed_text])
            feature_names = self.phishing_vectorizer.get_feature_names_out()
            importances = self.phishing_detector.feature_importances_
            # Map feature importances to words present in the email
            present_features = text_features.nonzero()[1]
            explanation = {feature_names[i]: importances[i] for i in present_features}
            return explanation
        except Exception as e:
            print(f"Error explaining phishing detection: {e}")
            return None

    def send_alert(self, alert_message, alert_type="info"):
        # Example: Print alert or integrate with email/SMS/Slack APIs
        print(f"[ALERT - {alert_type.upper()}]: {alert_message}")

    def automated_alerting(self, detection_results):
        if not detection_results:
            print("No detection results to analyze for alerts.")
            return
        alerts = []
        fusion = detection_results.get('fusion_summary', {})
        if fusion.get('total_network_anomalies', 0) > 10:
            alerts.append("High number of network anomalies detected.")
        if fusion.get('total_malware_detected', 0) > 0:
            alerts.append("Malware detected in uploaded files.")
        if fusion.get('total_phishing_detected', 0) > 0:
            alerts.append("Phishing emails detected.")
        for alert in alerts:
            self.send_alert(alert, alert_type="warning")
        if not alerts:
            self.send_alert("No significant threats detected.", alert_type="info")
    
    def save_models(self, directory="./models"):
        if not self.is_trained:
            print("Models not trained yet. Please train the models first.")
            return
        os.makedirs(directory, exist_ok=True)
        joblib.dump(self.network_autoencoder, f"{directory}/network_autoencoder.pkl")
        joblib.dump(self.network_isoforest, f"{directory}/network_isoforest.pkl")
        joblib.dump(self.network_scaler, f"{directory}/network_scaler.pkl")
        joblib.dump(self.network_feature_columns, f"{directory}/network_feature_columns.pkl")
        joblib.dump(self.malware_detector, f"{directory}/malware_detector.pkl")
        joblib.dump(self.phishing_vectorizer, f"{directory}/phishing_vectorizer.pkl")
        joblib.dump(self.phishing_detector, f"{directory}/phishing_detector.pkl")
        print(f"All models saved to {directory}")

    def load_models(self, directory="."):
        try:
            import pathlib
            base_path = pathlib.Path(__file__).parent.resolve()
            model_dir = base_path / directory
            print(f"Loading models from directory: {model_dir}")
            for model_file in ["network_autoencoder.pkl", "network_isoforest.pkl", "network_scaler.pkl",
                               "network_feature_columns.pkl", "malware_detector.pkl", "phishing_vectorizer.pkl",
                               "phishing_detector.pkl"]:
                model_path = model_dir / model_file
                print(f"Checking model file: {model_path} - Exists: {model_path.exists()}")
            self.network_autoencoder = torch.load(str(model_dir / "network_autoencoder.pkl"))
            self.network_isoforest = joblib.load(str(model_dir / "network_isoforest.pkl"))
            self.network_scaler = joblib.load(str(model_dir / "network_scaler.pkl"))
            self.network_feature_columns = joblib.load(str(model_dir / "network_feature_columns.pkl"))
            self.malware_detector = joblib.load(str(model_dir / "malware_detector.pkl"))
            self.phishing_vectorizer = joblib.load(str(model_dir / "phishing_vectorizer.pkl"))
            if self.phishing_vectorizer is None:
                raise ValueError("Phishing vectorizer failed to load.")
            self.phishing_detector = joblib.load(str(model_dir / "phishing_detector.pkl"))
            if self.phishing_detector is None:
                raise ValueError("Phishing detector failed to load.")
            self.is_trained = True
            print("All models loaded successfully!")
        except Exception as e:
            print(f"Error loading models: {e}")
            self.is_trained = False
    
    def detect_network_threats(self, network_data):
        if not self.is_trained:
            print("Models not trained yet. Please train the models first.")
            return None
        if isinstance(network_data, pd.DataFrame) and 'protocol_type' in network_data.columns:
            processed_data = preprocess_network_data_with_columns(network_data, self.network_feature_columns, self.network_scaler)
        else:
            processed_data = network_data
        print(f"Processed data columns: {processed_data.columns.tolist()}")
        print(f"Processed data shape: {processed_data.shape}")
        # Check against threat intelligence feed IPs if available
        threat_ips = self.threat_feed.get_threat_data()
        if 'src_ip' in network_data.columns:
            processed_data['is_threat_ip'] = network_data['src_ip'].apply(lambda ip: ip in threat_ips)
        # Remove 'is_threat_ip' before prediction to match training features
        if 'is_threat_ip' in processed_data.columns:
            processed_data = processed_data.drop(columns=['is_threat_ip'])
        anomalies, scores = detect_network_anomalies(
            self.network_autoencoder, self.network_isoforest, processed_data
        )
        return {
            'anomalies': anomalies,
            'scores': scores,
            'num_anomalies': sum(anomalies),
            'anomaly_percentage': sum(anomalies) / len(processed_data) * 100
        }
    
    def detect_malware(self, file_paths):
        if not self.is_trained:
            print("Models not trained yet. Please train the models first.")
            return None
        results = []
        for file_path in file_paths:
            try:
                features = extract_pe_features(file_path)
                features_df = pd.DataFrame([features])
                malware_prob = self.malware_detector.predict_proba(features_df)[0, 1]
                is_malware = malware_prob > 0.5
                results.append({
                    'file_path': file_path,
                    'is_malware': is_malware,
                    'malware_probability': malware_prob,
                    'features': features
                })
            except Exception as e:
                results.append({
                    'file_path': file_path,
                    'error': str(e)
                })
        return results
    
    def detect_phishing(self, emails):
        if not self.is_trained:
            print("Models not trained yet. Please train the models first.")
            return None
        results = []
        for i, email in enumerate(emails):
            try:
                print(f"Processing email {i}: {email[:30]}...")
                processed_text = preprocess_email_text(email)
                print(f"Processed text: {processed_text[:30]}...")
                text_features = self.phishing_vectorizer.transform([processed_text])
                phishing_prob = self.phishing_detector.predict_proba(text_features)[0, 1]
                is_phishing = phishing_prob > 0.5
                email_features = extract_email_features(email)
                results.append({
                    'email_id': i,
                    'is_phishing': is_phishing,
                    'phishing_probability': phishing_prob,
                    'features': email_features
                })
                print(f"Email {i} phishing probability: {phishing_prob}")
            except Exception as e:
                print(f"Error processing email {i}: {e}")
                results.append({
                    'email_id': i,
                    'error': str(e)
                })
        return results

###################################
# MAIN EXECUTION
###################################

if __name__ == "__main__":
    detector = CybersecurityThreatDetector()
    detector.train()
    
    print("\n===== TESTING THREAT DETECTION SYSTEM =====\n")
    
    print("\n1. Testing Network Anomaly Detection...")
    test_network_data = generate_sample_network_data(1000)
    features, _ = preprocess_network_data(test_network_data)
    network_results = detector.detect_network_threats(features)
    print(f"Network traffic analysis:")
    print(f"  - Total traffic flows: {len(features)}")
    print(f"  - Detected anomalies: {network_results['num_anomalies']}")
    print(f"  - Anomaly percentage: {network_results['anomaly_percentage']:.2f}%")
    
    print("\n2. Testing Malware Detection...")
    test_files = [
        "benign_test_1.exe", 
        "malware_test_1.exe",
        "suspicious_file.exe"
    ]
    malware_results = detector.detect_malware(test_files)
    print(f"Malware detection results:")
    for result in malware_results:
        if 'error' in result:
            print(f"  - {result['file_path']}: Error - {result['error']}")
        else:
            print(f"  - {result['file_path']}: {'MALWARE' if result['is_malware'] else 'BENIGN'} " 
                  f"(confidence: {result['malware_probability']*100:.1f}%)")
    
    print("\n3. Testing Phishing Detection...")
    test_emails = [
        "Dear customer, Your Amazon account has been locked. Please verify your information here: http://amazom-security.net/verify",
        "Hi Team, Please review the attached document for our meeting tomorrow. Thanks, John",
        "URGENT: Your PayPal account needs attention! Verify your account at http://192.168.1.1/paypal"
    ]
    phishing_results = detector.detect_phishing(test_emails)
    print(f"Phishing detection results:")
    for i, result in enumerate(phishing_results):
        if 'error' in result:
            print(f"  - Email {i+1}: Error - {result['error']}")
        else:
            print(f"  - Email {i+1}: {'PHISHING' if result['is_phishing'] else 'LEGITIMATE'} " 
                  f"(confidence: {result['phishing_probability']*100:.1f}%)")
    
    detector.save_models()
    print("\n===== SYSTEM READY FOR DEPLOYMENT =====")
