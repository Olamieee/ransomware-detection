import numpy as np
from .model_loader import load_model

# Load the model
model = load_model()

def predict_ransomware(features):
    """Predicts whether the extracted system data matches ransomware patterns."""
    features = np.array(features).reshape(1, -1)
    prediction = model.predict(features)[0]
    
    return "Ransomware Detected" if prediction == 0 else "Benign"