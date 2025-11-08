import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

def preprocess_email_data(data):
    # Clean and preprocess the email data
    # This function assumes 'data' is a DataFrame with relevant email features

    # Example preprocessing steps
    data['subject'] = data['subject'].str.lower().str.strip()
    data['body'] = data['body'].str.lower().str.strip()

    # Encode labels if necessary
    if 'label' in data.columns:
        le = LabelEncoder()
        data['label'] = le.fit_transform(data['label'])

    return data

def load_and_preprocess_data(file_path):
    # Load the email data from a CSV file and preprocess it
    data = pd.read_csv(file_path)
    processed_data = preprocess_email_data(data)
    return processed_data

def split_data(data, test_size=0.2):
    # Split the data into training and testing sets
    X = data.drop('label', axis=1)
    y = data['label']
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=test_size, random_state=42)
    return X_train, X_test, y_train, y_test