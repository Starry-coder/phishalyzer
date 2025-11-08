import pandas as pd
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import joblib
import os

def evaluate_model(model_path, validation_data_path):
    # Load the trained model
    model = joblib.load(model_path)

    # Load the validation dataset
    validation_data = pd.read_csv(validation_data_path)
    X_val = validation_data.drop('label', axis=1)  # Assuming 'label' is the target column
    y_val = validation_data['label']

    # Make predictions
    y_pred = model.predict(X_val)

    # Calculate evaluation metrics
    accuracy = accuracy_score(y_val, y_pred)
    precision = precision_score(y_val, y_pred, average='weighted')
    recall = recall_score(y_val, y_pred, average='weighted')
    f1 = f1_score(y_val, y_pred, average='weighted')

    # Print evaluation results
    print("Evaluation Results:")
    print(f"Accuracy: {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall: {recall:.4f}")
    print(f"F1 Score: {f1:.4f}")

if __name__ == "__main__":
    model_path = os.path.join("models", "trained_model.pkl")  # Adjust the model path as needed
    validation_data_path = os.path.join("data", "processed", "validation_data.csv")  # Adjust the data path as needed
    evaluate_model(model_path, validation_data_path)