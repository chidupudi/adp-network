import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score

# Load the dataset
file_path = "dataset_sdn.csv"  # Update if needed
df = pd.read_csv(file_path)

# Basic cleanup
df.columns = df.columns.str.strip()
df["rx_kbps"] = pd.to_numeric(df["rx_kbps"], errors="coerce")
df["tot_kbps"] = pd.to_numeric(df["tot_kbps"], errors="coerce")

# Fill missing numerical values with median
df["rx_kbps"].fillna(df["rx_kbps"].median(), inplace=True)
df["tot_kbps"].fillna(df["tot_kbps"].median(), inplace=True)

# Plot class distribution
plt.figure(figsize=(6, 4))
sns.countplot(x=df["label"])
plt.title("Class Distribution")
plt.show()

# Encode categorical columns
non_numeric_cols = df.select_dtypes(include=["object"]).columns
encoder = LabelEncoder()
for col in non_numeric_cols:
    df[col] = df[col].str.strip()
    df[col] = encoder.fit_transform(df[col])

# Correlation heatmap
plt.figure(figsize=(12, 8))
sns.heatmap(df.corr(), annot=True, fmt=".2f", cmap="coolwarm", linewidths=0.5)
plt.title("Feature Correlation Heatmap")
plt.show()

# Split features and target
X = df.drop(columns=["label"])
y = df["label"]

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# Train Random Forest
rf_model = RandomForestClassifier()
rf_model.fit(X_train, y_train)

# Predict and evaluate
y_pred = rf_model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"Random Forest Accuracy: {accuracy:.4f}")
