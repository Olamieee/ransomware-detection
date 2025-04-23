import psutil
import os
import pandas as pd
import numpy as np
import joblib
from django.shortcuts import render
from .models import RansomwareLog
import subprocess

# Load the trained RandomForest model
model_path = 'C:/Users/Hp/Desktop/ransomware_detection/models/ransomware_rf_model.pkl'
model = joblib.load(model_path)

# Load the trained MinMaxScaler
scaler_path = 'C:/Users/Hp/Desktop/ransomware_detection/models/scaler.pkl'
scaler = joblib.load(scaler_path)

# Admin phone number for SMS alerts
ADMIN_PHONE = "+2349035055838"

def home(request):
    return render(request, 'home.html')

def extract_features():
    """Automatically extracts real-time system features matching the trained dataset format."""

    # 1️⃣ Dynamically Extract System Activity
    num_running_processes = len(psutil.pids())  # Number of active processes
    num_network_connections = len(psutil.net_connections(kind='inet'))  # Active network connections
    memory_info = psutil.virtual_memory().total  # Total system memory
    cpu_usage = psutil.cpu_percent(interval=1)  # CPU usage in the last second
    disk_usage = psutil.disk_usage('/').percent  # Percentage of disk usage

    # 2Assign Extracted Values to Model Features (Match Training Data Order)
    machine = 34404  # Static identifier (change if needed)
    debug_size = 0  # Placeholder (modify if debug info is relevant)
    debug_rva = 0  # Placeholder
    major_image_version = 10  # OS Major version
    major_os_version = 10  # OS Minor version
    export_rva = num_running_processes  # Using active process count for example
    export_size = num_network_connections  # Active network connections
    IatVRA = 0  # Placeholder (modify based on IAT usage)
    major_linker_version = 14  # Static value
    minor_linker_version = 10  # Static value
    number_of_sections = num_running_processes  # Number of running processes
    size_of_stack_reserve = int(memory_info / 1024)  # Convert bytes to KB
    DllCharacteristics = int(cpu_usage * 100)  # Convert CPU % to integer
    resource_size = int(disk_usage * 100)  # Convert disk usage % to integer
    bitcoin_addresses = 0  # Placeholder (implement detection if needed)

    # 3️⃣ Convert Features to a NumPy Array (Same Order as Training Data)
    features = np.array([
        machine, debug_size, debug_rva, major_image_version, major_os_version,
        export_rva, export_size, IatVRA, major_linker_version, minor_linker_version,
        number_of_sections, size_of_stack_reserve, DllCharacteristics, resource_size,
        bitcoin_addresses
    ]).reshape(1, -1)

    return features

def detect_ransomware(request):
    """Automatically detects ransomware using real-time system activity."""
    try:
        # Extract real-time system features
        features = extract_features()

        # Convert features into a DataFrame with proper column names
        feature_names = [
            "Machine", "DebugSize", "DebugRVA", "MajorImageVersion", "MajorOSVersion",
            "ExportRVA", "ExportSize", "IatVRA", "MajorLinkerVersion", "MinorLinkerVersion",
            "NumberOfSections", "SizeOfStackReserve", "DllCharacteristics", "ResourceSize",
            "BitcoinAddresses"
        ]
        features_df = pd.DataFrame(features, columns=feature_names)

        # Scale features using MinMaxScaler
        features_scaled = scaler.transform(features_df)

        # Run prediction using trained model
        prediction = model.predict(features_scaled)[0]
        status = "Ransomware Detected" if prediction == 0 else "Benign"

        # Log the detection in the database
        RansomwareLog.objects.create(
            detected_processes=f"{features[0][5]} active processes",
            detected_files="Auto-detected",
            detected_connections=f"{features[0][6]} network connections",
            status=status
        )

        # Send SMS alert if ransomware is detected
        if status == "Ransomware Detected":
            subprocess.run(["python3", "send_sms.py", ADMIN_PHONE, "⚠️ WARNING: Ransomware Detected!"])

        # Render alert.html with status
        return render(request, "alert.html", {"status": status})

    except Exception as e:
        return render(request, "alert.html", {"status": f"Error: {str(e)}"})