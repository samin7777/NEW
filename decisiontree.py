import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score

# Read Randomdata.csv
df = pd.read_csv('Randomdata.csv')

# Select features and target
X = df[['not_local', 'offtime', 'has_malicious_command']]
y = df['is_malicious']

# Split data into training and testing sets with 80/20 ratio
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train a decision tree classifier
dtc = DecisionTreeClassifier()
dtc.fit(X_train, y_train)
y_pred_dtc = dtc.predict(X_test)
print("Decision Tree Classifier accuracy:", accuracy_score(y_test, y_pred_dtc))

# Train a logistic regression classifier
lrc = LogisticRegression()
lrc.fit(X_train, y_train)
y_pred_lrc = lrc.predict(X_test)
print("Logistic Regression Classifier accuracy:", accuracy_score(y_test, y_pred_lrc))

# Read Dataset.csv
df_pred = pd.read_csv('Dataset.csv')

# Check if 'is_malicious' column is already present
if 'is_malicious' in df_pred.columns:
    # Check if 'is_malicious' column has any missing values
    if df_pred['is_malicious'].isnull().sum() > 0:
        # Predict missing values using decision tree classifier
        df_pred.loc[df_pred['is_malicious'].isnull(), 'is_malicious'] = dtc.predict(df_pred[['not_local', 'offtime', 'has_malicious_command']])
    else:
        # 'is_malicious' column is already predicted, no action needed
        pass
else:
    # 'is_malicious' column is not present, predict values and add to dataframe
    df_pred['is_malicious'] = dtc.predict(df_pred[['not_local', 'offtime', 'has_malicious_command']])

# Update 'is_malicious' column in Dataset.csv
df_pred.to_csv('Dataset.csv', index=False)
