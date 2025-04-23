import joblib
import os
from django.conf import settings

# Load the trained ransomware detection model
model_path = 'C:/Users/Hp/Desktop/ransomware_detection/models/ransomware_rf_model.pkl'

def load_model():
    return joblib.load(model_path)