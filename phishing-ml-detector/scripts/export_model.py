import joblib
import os
from src.ml.model import YourModelClass  # Replace with your actual model class

def export_model(model, model_name="phishing_model"):
    model_dir = "models"
    os.makedirs(model_dir, exist_ok=True)
    model_path = os.path.join(model_dir, f"{model_name}.pkl")
    
    joblib.dump(model, model_path)
    print(f"Model exported to {model_path}")

if __name__ == "__main__":
    # Load your trained model here
    trained_model = YourModelClass()  # Replace with actual model loading logic
    export_model(trained_model)