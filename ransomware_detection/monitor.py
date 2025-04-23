import os
import psutil
import requests
import time
import hashlib

# Django API Endpoint for ransomware detection
DETECTION_API_URL = "http://127.0.0.1:8000/detect/"

# Function to monitor running processes
def check_processes():
    suspicious_processes = []
    ransomware_signatures = ["encrypt", "cipher", "locky", "crypto", "ransom"]
    
    for proc in psutil.process_iter(attrs=["pid", "name", "cmdline"]):
        try:
            process_name = proc.info["name"].lower()
            cmdline = " ".join(proc.info["cmdline"]).lower() if proc.info["cmdline"] else ""

            # Check if process name or command line contains ransomware keywords
            if any(sig in process_name or sig in cmdline for sig in ransomware_signatures):
                suspicious_processes.append(process_name)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    
    return suspicious_processes

# Function to monitor file modifications
def check_file_changes(directory="/"):
    suspicious_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                # Get file extension and check if it's newly encrypted (e.g., .locked, .encrypted)
                if file_path.endswith((".locked", ".encrypted", ".cryp1", ".crypz")):
                    suspicious_files.append(file_path)
            except Exception:
                continue
    
    return suspicious_files

# Function to monitor network connections
def check_network_connections():
    suspicious_connections = []
    ransomware_ips = ["192.168.1.100", "10.0.0.200"]  # Example malicious IPs (replace with actual threat data)

    for conn in psutil.net_connections(kind="inet"):
        if conn.raddr and conn.raddr.ip in ransomware_ips:
            suspicious_connections.append(conn.raddr.ip)
    
    return suspicious_connections

# Function to send collected data to Django for classification
def send_data_to_django(processes, files, connections):
    data = {
        "features[]": [len(processes), len(files), len(connections)]  # Feature vector for AI model
    }
    try:
        response = requests.post(DETECTION_API_URL, data=data)
        print(response.json())  # Print server response
    except requests.RequestException as e:
        print(f"Error sending data to Django: {e}")

# Continuous monitoring loop
while True:
    print("🔍 Monitoring for ransomware activity...")

    # Gather suspicious activity
    detected_processes = check_processes()
    detected_files = check_file_changes("/path/to/monitor")  # Update with actual directory
    detected_connections = check_network_connections()

    # If any suspicious activity is found, send data to Django
    if detected_processes or detected_files or detected_connections:
        print("⚠️ Suspicious activity detected! Sending data to Django for analysis...")
        send_data_to_django(detected_processes, detected_files, detected_connections)
    
    time.sleep(10)  # Wait before checking again (adjust as needed)
