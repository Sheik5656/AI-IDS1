import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score
import joblib
import os
from pathlib import Path

print("🚀 Starting model training...")

# Create directories
model_dir = Path('models')
model_dir.mkdir(exist_ok=True)

# Generate synthetic training data
print("📊 Generating training data...")
np.random.seed(42)
n_samples = 10000

# Normal traffic (70%)
normal = pd.DataFrame({
    'packet_length': np.random.normal(500, 100, 7000),
    'ttl': np.random.normal(64, 10, 7000),
    'protocol': np.random.choice([6, 17], 7000),
    'src_port': np.random.randint(1024, 65535, 7000),
    'dst_port': np.random.randint(1, 1024, 7000),
    'packet_rate': np.random.normal(10, 5, 7000),
    'unique_ports': np.random.poisson(2, 7000),
    'label': 0
})

# Malicious traffic (30%)
malicious = pd.DataFrame({
    'packet_length': np.random.normal(1500, 200, 3000),
    'ttl': np.random.normal(128, 20, 3000),
    'protocol': np.random.choice([6, 17, 1], 3000),
    'src_port': np.random.randint(1, 1024, 3000),
    'dst_port': np.random.randint(80, 8080, 3000),
    'packet_rate': np.random.normal(100, 30, 3000),
    'unique_ports': np.random.poisson(20, 3000),
    'label': 1
})

# Combine data
data = pd.concat([normal, malicious], ignore_index=True)
data = data.sample(frac=1).reset_index(drop=True)

print(f"✅ Generated {len(data)} samples")
print(f"   Normal traffic: {len(normal)}")
print(f"   Malicious traffic: {len(malicious)}")

# Prepare features and labels
feature_columns = ['packet_length', 'ttl', 'protocol', 'src_port', 'dst_port', 'packet_rate', 'unique_ports']
X = data[feature_columns]
y = data['label']

# Scale features
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Train model
print("🤖 Training Random Forest model...")
model = RandomForestClassifier(
    n_estimators=100,
    max_depth=20,
    random_state=42,
    n_jobs=-1
)
model.fit(X_scaled, y)

# Evaluate
y_pred = model.predict(X_scaled)
accuracy = accuracy_score(y, y_pred)
print(f"✅ Model accuracy: {accuracy:.4f}")

# Save model and scaler
joblib.dump(model, 'models/rf_model.joblib')
joblib.dump(scaler, 'models/scaler.pkl')
joblib.dump(feature_columns, 'models/feature_names.pkl')

print("💾 Model saved to 'models/' folder")
print("🎉 Training complete!")