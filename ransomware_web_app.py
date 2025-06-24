import streamlit as st
import pandas as pd
import joblib
import numpy as np
import os
import tempfile
import pefile
import re
import sqlite3
import logging
import datetime
import time
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import serial
import serial.tools.list_ports
import threading
import queue
import json
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import psutil
import statistics
from collections import deque

# Logging Configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("ransomware_detector.log", encoding="utf-8"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("ransomware-detector")

# Performance Metrics Logger
perf_logger = logging.getLogger("performance-metrics")
perf_handler = logging.FileHandler("performance_metrics.log", encoding="utf-8")
perf_formatter = logging.Formatter('%(asctime)s - PERF - %(message)s')
perf_handler.setFormatter(perf_formatter)
perf_logger.addHandler(perf_handler)
perf_logger.setLevel(logging.INFO)

DB_PATH = 'ransomware_detector.db'

class PerformanceMonitor:
    def __init__(self):
        self.processing_times = deque(maxlen=100)  # Keep last 100 processing times
        self.arduino_delays = deque(maxlen=100)   # Keep last 100 Arduino delays
        self.files_processed = 0
        self.start_time = time.time()
        self.cpu_readings = deque(maxlen=50)      # Keep last 50 CPU readings
        self.memory_readings = deque(maxlen=50)   # Keep last 50 memory readings
        self.process = psutil.Process()
        
        # Start resource monitoring thread
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_resources, daemon=True)
        self.monitor_thread.start()
    
    def _monitor_resources(self):
        """Background thread to monitor CPU and memory usage"""
        while self.monitoring:
            try:
                cpu_percent = self.process.cpu_percent()
                memory_mb = self.process.memory_info().rss / 1024 / 1024
                
                self.cpu_readings.append(cpu_percent)
                self.memory_readings.append(memory_mb)
                
                time.sleep(2)  # Check every 2 seconds
            except Exception as e:
                logger.error(f"Resource monitoring error: {str(e)}")
                time.sleep(5)
    
    def record_processing_time(self, processing_time_ms):
        """Record file processing time in milliseconds"""
        self.processing_times.append(processing_time_ms)
        self.files_processed += 1
        
        # Log every 10th file or if significant change
        if self.files_processed % 10 == 0 or processing_time_ms > 1000:
            avg_time = statistics.mean(self.processing_times)
            perf_logger.info(f"FILE_PROCESSING_TIME: Current={processing_time_ms:.2f}ms, Average={avg_time:.2f}ms, Total_Files={self.files_processed}")
    
    def record_arduino_delay(self, delay_ms):
        """Record Arduino communication delay in milliseconds"""
        self.arduino_delays.append(delay_ms)
        
        # Log every 5th Arduino communication
        if len(self.arduino_delays) % 5 == 0:
            avg_delay = statistics.mean(self.arduino_delays)
            perf_logger.info(f"ARDUINO_DELAY: Current={delay_ms:.2f}ms, Average={avg_delay:.2f}ms")
    
    def get_files_per_minute(self):
        """Calculate files processed per minute"""
        elapsed_time = time.time() - self.start_time
        if elapsed_time > 0:
            files_per_minute = (self.files_processed / elapsed_time) * 60
            perf_logger.info(f"FILES_PER_MINUTE: {files_per_minute:.2f}, Total_Files={self.files_processed}, Elapsed_Time={elapsed_time:.2f}s")
            return files_per_minute
        return 0
    
    def get_current_metrics(self):
        """Get current performance metrics"""
        metrics = {
            'avg_processing_time': statistics.mean(self.processing_times) if self.processing_times else 0,
            'avg_arduino_delay': statistics.mean(self.arduino_delays) if self.arduino_delays else 0,
            'files_per_minute': self.get_files_per_minute(),
            'avg_cpu_usage': statistics.mean(self.cpu_readings) if self.cpu_readings else 0,
            'avg_memory_usage': statistics.mean(self.memory_readings) if self.memory_readings else 0,
            'current_memory': self.memory_readings[-1] if self.memory_readings else 0
        }
        
        # Log comprehensive metrics every 25 files
        if self.files_processed % 25 == 0 and self.files_processed > 0:
            perf_logger.info(f"COMPREHENSIVE_METRICS: {json.dumps(metrics, indent=2)}")
        
        return metrics
    
    def stop_monitoring(self):
        """Stop the performance monitoring"""
        self.monitoring = False

# Replace your ArduinoManager class with this fixed version

# Replace your ArduinoManager class with this fixed version

class ArduinoManager:
    def __init__(self, performance_monitor):
        self.connection = None
        self.command_queue = queue.Queue()
        self.worker_thread = None
        self.running = False
        self.performance_monitor = performance_monitor
        self.is_ready = False  # Add ready flag
    
    def find_arduino_ports(self):
        ports = serial.tools.list_ports.comports()
        return [port.device for port in ports if any(keyword in port.description.upper() 
                for keyword in ['ARDUINO', 'CH340', 'USB', 'SERIAL'])]
    
    def connect(self, port=None):
        try:
            if self.connection and self.connection.is_open:
                self.connection.close()
            
            if not port:
                ports = self.find_arduino_ports()
                if not ports:
                    return False, "No Arduino found"
                port = ports[0]
            
            # Create connection with proper settings
            self.connection = serial.Serial(
                port=port, 
                baudrate=9600, 
                timeout=2, 
                write_timeout=2,
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE
            )
            
            # Wait for Arduino to initialize (CRITICAL!)
            time.sleep(3)
            
            # Clear any existing data in buffers
            self.connection.flushInput()
            self.connection.flushOutput()
            
            # Wait for Arduino ready message
            self.wait_for_ready()
            
            if not self.running:
                self.start_worker_thread()
            
            logger.info(f"Arduino connected and ready: {port}")
            return True, f"Connected to {port}"
            
        except Exception as e:
            logger.error(f"Arduino connection error: {str(e)}")
            return False, f"Connection error: {str(e)}"
    
    def wait_for_ready(self):
        """Wait for Arduino to send ready message"""
        timeout = 10  # 10 seconds timeout
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            if self.connection.in_waiting > 0:
                try:
                    line = self.connection.readline().decode('utf-8').strip()
                    logger.info(f"Arduino says: {line}")
                    if "Ready" in line or "Waiting" in line:
                        self.is_ready = True
                        return True
                except:
                    pass
            time.sleep(0.1)
        
        # If no ready message, assume it's ready after timeout
        self.is_ready = True
        logger.warning("Arduino ready timeout - assuming ready")
        return True
    
    def start_worker_thread(self):
        self.running = True
        self.worker_thread = threading.Thread(target=self.worker, daemon=True)
        self.worker_thread.start()
    
    def worker(self):
        while self.running:
            try:
                command = self.command_queue.get(timeout=1)
                
                if self.connection and self.connection.is_open and self.is_ready:
                    # Record start time for Arduino communication
                    start_time = time.time()
                    
                    # Send command with proper line ending
                    command_bytes = (command + '\n').encode('utf-8')
                    self.connection.write(command_bytes)
                    self.connection.flush()
                    
                    # Wait a bit for Arduino to process
                    time.sleep(0.1)
                    
                    # Calculate and record Arduino delay
                    delay_ms = (time.time() - start_time) * 1000
                    self.performance_monitor.record_arduino_delay(delay_ms)
                    
                    logger.info(f"✓ Arduino command sent: {command} (Delay: {delay_ms:.2f}ms)")
                    
                    # Check for Arduino response
                    self.check_arduino_response()
                
                self.command_queue.task_done()
                
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Arduino communication error: {str(e)}")
                time.sleep(0.5)
    
    def check_arduino_response(self):
        """Check for Arduino response messages"""
        try:
            if self.connection.in_waiting > 0:
                response = self.connection.readline().decode('utf-8').strip()
                if response:
                    logger.info(f"Arduino response: {response}")
        except:
            pass
    
    def send_command(self, command):
        """Send command to Arduino with validation"""
        if not self.is_connected():
            logger.warning(f"Cannot send command '{command}' - Arduino not connected")
            return False
            
        if not self.is_ready:
            logger.warning(f"Cannot send command '{command}' - Arduino not ready")
            return False
        
        # Add command to queue if not full
        if not self.command_queue.full():
            self.command_queue.put(command.upper())  # Ensure uppercase
            logger.info(f"Command queued: {command}")
            return True
        else:
            logger.warning(f"Command queue full, dropping: {command}")
            return False
    
    def send_command_direct(self, command):
        """Send command directly without queue (for testing)"""
        if self.connection and self.connection.is_open:
            try:
                command_bytes = (command.upper() + '\n').encode('utf-8')
                self.connection.write(command_bytes)
                self.connection.flush()
                logger.info(f"Direct command sent: {command}")
                time.sleep(0.5)  # Give Arduino time to respond
                self.check_arduino_response()
                return True
            except Exception as e:
                logger.error(f"Direct command error: {str(e)}")
                return False
        return False
    
    def test_connection(self):
        """Test Arduino connection with immediate feedback"""
        logger.info("Testing Arduino connection...")
        
        # Test sequence
        test_commands = ["TEST", "BENIGN", "RANSOMWARE", "STOP"]
        
        for cmd in test_commands:
            if self.send_command_direct(cmd):
                logger.info(f"✓ Test command '{cmd}' sent successfully")
                time.sleep(2)  # Wait between commands
            else:
                logger.error(f"✗ Test command '{cmd}' failed")
                return False
                
        return True
    
    def disconnect(self):
        self.running = False
        self.is_ready = False
        if self.connection and self.connection.is_open:
            self.connection.close()
        self.connection = None
        logger.info("Arduino disconnected")
    
    def is_connected(self):
        return self.connection and self.connection.is_open and self.is_ready

class DatabaseManager:
    def __init__(self, db_path):
        self.db_path = db_path
        self.init_db()
    
    def get_connection(self):
        return sqlite3.connect(self.db_path)
    
    def init_db(self):
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS detection_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT,
                filepath TEXT,
                detection_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                prediction INTEGER,
                confidence REAL,
                features TEXT,
                scan_type TEXT,
                processing_time_ms REAL,
                arduino_delay_ms REAL
            )
            ''')
            conn.commit()
            cursor.close()
            conn.close()
            logger.info("Database initialized")
        except Exception as e:
            logger.error(f"Database initialization error: {str(e)}")
    
    def log_detection(self, filename, filepath, prediction, confidence, features, scan_type="manual", processing_time_ms=0, arduino_delay_ms=0):
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            features_json = json.dumps(features) if isinstance(features, dict) else str(features)
            cursor.execute(
                "INSERT INTO detection_logs (filename, filepath, prediction, confidence, features, scan_type, processing_time_ms, arduino_delay_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (filename, filepath, int(prediction), float(confidence), features_json, scan_type, processing_time_ms, arduino_delay_ms)
            )
            conn.commit()
            cursor.close()
            conn.close()
            result = 'BENIGN' if prediction == 1 else 'MALICIOUS'
            logger.info(f"Detection logged - {filename}: {result} ({confidence:.2%}) [Processing: {processing_time_ms:.2f}ms]")
        except Exception as e:
            logger.error(f"Database logging error: {str(e)}")
    
    def get_logs(self):
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM detection_logs ORDER BY detection_time DESC")
            columns = [description[0] for description in cursor.description]
            rows = cursor.fetchall()
            cursor.close()
            conn.close()
            
            df = pd.DataFrame(rows, columns=columns)
            if not df.empty and 'detection_time' in df.columns:
                df['detection_time'] = pd.to_datetime(df['detection_time'])
            return df
        except Exception as e:
            logger.error(f"Error fetching logs: {str(e)}")
            return pd.DataFrame()

class FileScanHandler(FileSystemEventHandler):
    def __init__(self, model, db_manager, arduino_manager, performance_monitor):
        self.model = model
        self.db_manager = db_manager
        self.arduino_manager = arduino_manager
        self.performance_monitor = performance_monitor

    def on_created(self, event):
        if not event.is_directory and event.src_path.lower().endswith(('.exe', '.dll', '.sys')):
            self.scan_file(event.src_path)

    def scan_file(self, filepath):
        filename = os.path.basename(filepath)
        logger.info(f"Scanning new file: {filename}")
        
        # Start timing for file processing
        start_time = time.time()
        
        try:
            features = extract_pe_features(filepath)
            if features:
                input_df = pd.DataFrame([features])
                prediction = self.model.predict(input_df)[0]
                prediction_proba = self.model.predict_proba(input_df)[0]
                confidence = prediction_proba[1] if prediction == 1 else prediction_proba[0]
                
                # Calculate processing time
                processing_time_ms = (time.time() - start_time) * 1000
                self.performance_monitor.record_processing_time(processing_time_ms)
                
                # Send Arduino command and measure delay
                arduino_start = time.time()
                self.arduino_manager.send_command("RANSOMWARE" if prediction == 0 else "BENIGN")
                
                self.db_manager.log_detection(filename, filepath, prediction, confidence, features, "background", processing_time_ms)
                
                result = "BENIGN" if prediction == 1 else "MALICIOUS"
                logger.info(f"Background scan result - {filename}: {result} ({confidence:.2%}) [Processing: {processing_time_ms:.2f}ms]")
            else:
                logger.error(f"Failed to extract features from {filename}")
        except Exception as e:
            logger.error(f"Background scan error for {filename}: {str(e)}")

class FolderMonitor:
    def __init__(self):
        self.observers = {}
        self.running = False

    def start_monitoring(self, folder_path, model, db_manager, arduino_manager, performance_monitor):
        if folder_path in self.observers:
            self.stop_monitoring(folder_path)

        if not os.path.exists(folder_path):
            os.makedirs(folder_path)

        event_handler = FileScanHandler(model, db_manager, arduino_manager, performance_monitor)

        # 🔥 Scan all existing .exe and .dll files in the folder immediately
        for root, _, files in os.walk(folder_path):
            for file in files:
                if file.lower().endswith(('.exe', '.dll')):
                    full_path = os.path.join(root, file)
                    event_handler.scan_file(full_path)

        observer = Observer()
        observer.schedule(event_handler, folder_path, recursive=True)
        observer.start()

        self.observers[folder_path] = observer
        logger.info(f"Started monitoring: {folder_path}")
        return True
    
    def stop_monitoring(self, folder_path):
        if folder_path in self.observers:
            self.observers[folder_path].stop()
            self.observers[folder_path].join()
            del self.observers[folder_path]
            logger.info(f"Stopped monitoring: {folder_path}")
    
    def stop_all(self):
        for folder_path in list(self.observers.keys()):
            self.stop_monitoring(folder_path)

def load_model():
    try:
        model = joblib.load('ransomware_rf_model.pkl')
        logger.info("Model loaded from pkl file")
        return model
    except:
        try:
            model = joblib.load('rf_ransomware_model.joblib')
            logger.info("Model loaded from joblib file")
            return model
        except Exception as e:
            logger.error(f"Failed to load model: {str(e)}")
            return None

def extract_pe_features(file_path):
    pe = None
    try:
        pe = pefile.PE(file_path)
        
        debug_size = debug_rva = 0
        if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG') and len(pe.DIRECTORY_ENTRY_DEBUG) > 0:
            debug_size = pe.DIRECTORY_ENTRY_DEBUG[0].struct.SizeOfData
            debug_rva = pe.DIRECTORY_ENTRY_DEBUG[0].struct.AddressOfRawData
        
        export_rva = export_size = 0
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            export_rva = pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].VirtualAddress
            export_size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].Size
        
        iat_vra = 0
        if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > 12:
            iat_vra = pe.OPTIONAL_HEADER.DATA_DIRECTORY[12].VirtualAddress
        
        resource_size = 0
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            resource_size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[2].Size
        
        bitcoin_addresses = 0
        try:
            raw_data = ' '.join([section.get_data().decode('latin-1', errors='ignore') for section in pe.sections])
            bitcoin_pattern = re.compile(r'[13][a-km-zA-HJ-NP-Z1-9]{25,34}')
            bitcoin_addresses = len(bitcoin_pattern.findall(raw_data))
        except:
            pass
        
        return {
            'Machine': pe.FILE_HEADER.Machine,
            'DebugSize': debug_size,
            'DebugRVA': debug_rva,
            'MajorImageVersion': pe.OPTIONAL_HEADER.MajorImageVersion,
            'MajorOSVersion': pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
            'ExportRVA': export_rva,
            'ExportSize': export_size,
            'IatVRA': iat_vra,
            'MajorLinkerVersion': pe.OPTIONAL_HEADER.MajorLinkerVersion,
            'MinorLinkerVersion': pe.OPTIONAL_HEADER.MinorLinkerVersion,
            'NumberOfSections': pe.FILE_HEADER.NumberOfSections,
            'SizeOfStackReserve': pe.OPTIONAL_HEADER.SizeOfStackReserve,
            'DllCharacteristics': pe.OPTIONAL_HEADER.DllCharacteristics,
            'ResourceSize': resource_size,
            'BitcoinAddresses': bitcoin_addresses
        }
    except Exception as e:
        logger.error(f"Feature extraction error: {str(e)}")
        return None
    finally:
        if pe:
            try:
                pe.close()
            except:
                pass

def create_visualizations(logs_df):
    if logs_df.empty:
        st.info("No data available for visualization")
        return
    
    logs_df['prediction_text'] = logs_df['prediction'].apply(lambda x: "BENIGN" if x == 1 else "MALICIOUS")
    
    viz_type = st.selectbox("Visualization Type", ["Timeline", "Distribution", "Heatmap"])
    
    if viz_type == "Timeline":
        fig = px.line(
            logs_df, x="detection_time", y="confidence", color="prediction_text",
            markers=True, title="Detection Timeline",
            color_discrete_map={"BENIGN": "green", "MALICIOUS": "red"}
        )
        fig.update_layout(yaxis_tickformat=".0%")
        st.plotly_chart(fig, use_container_width=True)
    
    elif viz_type == "Distribution":
        fig = make_subplots(
            rows=2, cols=2,
            subplot_titles=('Predictions', 'Confidence', 'Daily', 'Hourly'),
            specs=[[{"type": "pie"}, {"type": "histogram"}],
                   [{"type": "bar"}, {"type": "bar"}]]
        )
        
        pred_counts = logs_df['prediction_text'].value_counts()
        colors = ['green' if x == 'BENIGN' else 'red' for x in pred_counts.index]
        fig.add_trace(go.Pie(labels=pred_counts.index, values=pred_counts.values, marker_colors=colors), row=1, col=1)
        fig.add_trace(go.Histogram(x=logs_df['confidence'], nbinsx=20, marker_color='blue', opacity=0.7), row=1, col=2)
        
        daily_counts = logs_df.groupby(logs_df['detection_time'].dt.date).size()
        fig.add_trace(go.Bar(x=daily_counts.index, y=daily_counts.values, marker_color='purple'), row=2, col=1)
        
        hourly_counts = logs_df.groupby(logs_df['detection_time'].dt.hour).size()
        fig.add_trace(go.Bar(x=hourly_counts.index, y=hourly_counts.values, marker_color='orange'), row=2, col=2)
        
        fig.update_layout(height=800, showlegend=False)
        st.plotly_chart(fig, use_container_width=True)
    
    elif viz_type == "Heatmap":
        logs_df['hour'] = logs_df['detection_time'].dt.hour
        logs_df['day'] = logs_df['detection_time'].dt.day_name()
        heatmap_data = logs_df.groupby(['day', 'hour']).size().unstack(fill_value=0)
        
        fig = px.imshow(heatmap_data.values, x=heatmap_data.columns, y=heatmap_data.index,
                       aspect="auto", title="Detection Activity Heatmap",
                       labels=dict(x="Hour", y="Day", color="Detections"))
        st.plotly_chart(fig, use_container_width=True)

@st.cache_resource
def get_performance_monitor():
    return PerformanceMonitor()

@st.cache_resource
def get_arduino_manager():
    performance_monitor = get_performance_monitor()
    return ArduinoManager(performance_monitor)

@st.cache_resource
def get_db_manager():
    return DatabaseManager(DB_PATH)

@st.cache_resource
def get_model():
    return load_model()

@st.cache_resource
def get_folder_monitor():
    return FolderMonitor()

def main():
    st.set_page_config(page_title="🛡️ Ransomware Detection System", layout="wide")
    st.title("🛡️ Ransomware Detection System")

    performance_monitor = get_performance_monitor()
    arduino_manager = get_arduino_manager()
    db_manager = get_db_manager()
    model = get_model()
    folder_monitor = get_folder_monitor()

    if not model:
        st.error("❌ Model could not be loaded. Check model files.")
        return

    current_time = time.time()
    if 'last_metric_log' not in st.session_state:
        st.session_state.last_metric_log = current_time

    if current_time - st.session_state.last_metric_log > 30:
        metrics = performance_monitor.get_current_metrics()
        perf_logger.info(f"PERIODIC_METRICS: CPU={metrics['avg_cpu_usage']:.2f}%, Memory={metrics['current_memory']:.2f}MB, Files/min={metrics['files_per_minute']:.2f}")
        st.session_state.last_metric_log = current_time

    with st.sidebar:
        st.subheader("🔌 Arduino Control")

        col1, col2 = st.columns(2)
        with col1:
            if st.button("🔗 Connect"):
                with st.spinner("Connecting to Arduino..."):
                    success, message = arduino_manager.connect()
                    if success:
                        st.success(f"✅ {message}")
                        if arduino_manager.test_connection():
                            st.success("🎯 Arduino test successful!")
                        else:
                            st.warning("⚠️ Arduino connected but test failed")
                    else:
                        st.error(f"❌ {message}")

        with col2:
            if st.button("🔌 Disconnect"):
                arduino_manager.disconnect()
                st.info("Disconnected")

        # Manual port connection
        manual_port = st.text_input("Manual Port", placeholder="COM3 or /dev/ttyUSB0")
        if st.button("Connect Manual") and manual_port:
            with st.spinner(f"Connecting to {manual_port}..."):
                success, message = arduino_manager.connect(manual_port)
                if success:
                    st.success(f"✅ {message}")
                    if arduino_manager.test_connection():
                        st.success("🎯 Arduino test successful!")
                else:
                    st.error(f"❌ {message}")

        # Manual testing buttons
        if arduino_manager.is_connected():
            st.subheader("🧪 Manual Tests")
            test_col1, test_col2 = st.columns(2)

            with test_col1:
                if st.button("🔴 Test Ransomware"):
                    arduino_manager.send_command_direct("RANSOMWARE")
                    st.info("Ransomware alert sent")

                if st.button("🟢 Test Benign"):
                    arduino_manager.send_command_direct("BENIGN")
                    st.info("Benign alert sent")

            with test_col2:
                if st.button("🔧 System Test"):
                    arduino_manager.send_command_direct("TEST")
                    st.info("System test sent")

                if st.button("⏹️ Stop All"):
                    arduino_manager.send_command_direct("STOP")
                    st.info("Stop command sent")

        # Status display
        status = "🟢 Connected & Ready" if arduino_manager.is_connected() else "🔴 Disconnected"
        st.write(f"**Status:** {status}")

        # 🔍 Scan Ports
        if st.button("🔍 Scan Ports"):
            ports = arduino_manager.find_arduino_ports()
            if ports:
                st.write("**Available Ports:**")
                for port in ports:
                    st.write(f"- {port}")
            else:
                st.write("No Arduino ports found")

        # 📁 Folder Monitor Section
        st.subheader("📁 Folder Monitor")
        folder_path = st.text_input("📁 Folder Path", placeholder=r"C:\Users\Hp\Documents\MyFolder")

        if folder_path and not os.path.isdir(folder_path):
            st.error("❌ The folder path does not exist. Please check it.")
            st.stop()

        if folder_path:
            st.write(f"Selected: {folder_path}")

        if folder_path and st.button("▶️ Start Monitoring"):
            if folder_monitor.start_monitoring(folder_path, model, db_manager, arduino_manager, performance_monitor):
                st.success(f"✅ Monitoring: {folder_path}")
                st.session_state.monitoring_folder = folder_path

        if st.button("⏹️ Stop All Monitoring"):
            folder_monitor.stop_all()
            st.info("Monitoring stopped")
            if 'monitoring_folder' in st.session_state:
                del st.session_state.monitoring_folder

        if 'monitoring_folder' in st.session_state:
            st.success(f"📍 Active: {st.session_state.monitoring_folder}")

        # 🔄 Cache clear button
        if st.button("🔄 Clear Cache"):
            st.cache_resource.clear()
            st.rerun()

    # Main Content
    page = st.radio("Navigation", ["🔍 Detection", "📊 Logs", "ℹ️ About"], horizontal=True)
    
    if page == "🔍 Detection":
        tab1, tab2 = st.tabs(["📝 Manual Input", "📁 File Upload"])
        
        with tab1:
            st.header("Manual Feature Input")
            
            with st.form("manual_form"):
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    machine = st.number_input("Machine", min_value=0, value=332)
                    debug_size = st.number_input("Debug Size", min_value=0, value=0)
                    debug_rva = st.number_input("Debug RVA", min_value=0, value=0)
                    major_img = st.number_input("Major Image Version", min_value=0, value=0)
                    major_os = st.number_input("Major OS Version", min_value=0, value=4)
                
                with col2:
                    export_rva = st.number_input("Export RVA", min_value=0, value=0)
                    export_size = st.number_input("Export Size", min_value=0, value=0)
                    iat_vra = st.number_input("IAT VRA", min_value=0, value=8192)
                    major_linker = st.number_input("Major Linker Version", min_value=0, value=8)
                    minor_linker = st.number_input("Minor Linker Version", min_value=0, value=0)
                
                with col3:
                    num_sections = st.number_input("Number of Sections", min_value=1, value=3)
                    stack_reserve = st.number_input("Stack Reserve Size", min_value=0, value=1048576)
                    dll_chars = st.number_input("DLL Characteristics", min_value=0, value=34112)
                    resource_size = st.number_input("Resource Size", min_value=0, value=672)
                    bitcoin_addrs = st.number_input("Bitcoin Addresses", min_value=0, value=0)
                
                if st.form_submit_button("🔍 Analyze", type="primary"):
                    # Start timing for manual analysis
                    start_time = time.time()
                    
                    input_values = {
                        'Machine': machine, 'DebugSize': debug_size, 'DebugRVA': debug_rva,
                        'MajorImageVersion': major_img, 'MajorOSVersion': major_os,
                        'ExportRVA': export_rva, 'ExportSize': export_size, 'IatVRA': iat_vra,
                        'MajorLinkerVersion': major_linker, 'MinorLinkerVersion': minor_linker,
                        'NumberOfSections': num_sections, 'SizeOfStackReserve': stack_reserve,
                        'DllCharacteristics': dll_chars, 'ResourceSize': resource_size,
                        'BitcoinAddresses': bitcoin_addrs
                    }
                    
                    input_df = pd.DataFrame([input_values])
                    prediction = model.predict(input_df)[0]
                    prediction_proba = model.predict_proba(input_df)[0]
                    confidence = prediction_proba[1] if prediction == 1 else prediction_proba[0]
                    
                    # Calculate processing time
                    processing_time_ms = (time.time() - start_time) * 1000
                    performance_monitor.record_processing_time(processing_time_ms)
                    
                    arduino_manager.send_command("RANSOMWARE" if prediction == 0 else "BENIGN")
                    db_manager.log_detection("manual_input", "manual", prediction, confidence, input_values, "manual", processing_time_ms)
                    
                    if prediction == 1:
                        st.success(f"✅ **BENIGN** - Confidence: {confidence:.2%}")
                    else:
                        st.error(f"⚠️ **MALICIOUS (RANSOMWARE)** - Confidence: {confidence:.2%}")
        
        with tab2:
            st.header("File Upload Analysis")
            
            uploaded_file = st.file_uploader("Choose PE File", type=['dll', 'exe'], key="file_upload")
            
            if uploaded_file and st.button("🔍 Analyze File", type="primary"):
                with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(uploaded_file.name)[1]) as tmp_file:
                    tmp_file.write(uploaded_file.getvalue())
                    temp_path = tmp_file.name
                
                try:
                    with st.spinner("Analyzing file..."):
                        # Start timing for file upload analysis
                        start_time = time.time()
                        
                        file_features = extract_pe_features(temp_path)
                        
                        if file_features:
                            input_df = pd.DataFrame([file_features])
                            prediction = model.predict(input_df)[0]
                            prediction_proba = model.predict_proba(input_df)[0]
                            confidence = prediction_proba[1] if prediction == 1 else prediction_proba[0]
                            
                            # Calculate processing time
                            processing_time_ms = (time.time() - start_time) * 1000
                            performance_monitor.record_processing_time(processing_time_ms)
                            
                            arduino_manager.send_command("RANSOMWARE" if prediction == 0 else "BENIGN")
                            db_manager.log_detection(uploaded_file.name, temp_path, prediction, confidence, file_features, "upload", processing_time_ms)
                            
                            col1, col2 = st.columns(2)
                            
                            with col1:
                                if prediction == 1:
                                    st.success(f"✅ **BENIGN FILE**")
                                    st.success(f"Confidence: {confidence:.2%}")
                                else:
                                    st.error(f"⚠️ **MALICIOUS FILE (RANSOMWARE)**")
                                    st.error(f"Confidence: {confidence:.2%}")
                                
                                st.info(f"Processing Time: {processing_time_ms:.2f}ms")
                            
                            with col2:
                                st.subheader("📊 File Features")
                                feature_df = pd.DataFrame([file_features]).T
                                feature_df.columns = ['Value']
                                st.dataframe(feature_df, use_container_width=True)
                        else:
                            st.error("❌ Could not extract features from the file. Please ensure it's a valid PE file.")
                
                finally:
                    try:
                        os.unlink(temp_path)
                    except:
                        pass
    
    elif page == "📊 Logs":
        st.header("📊 Detection Logs & Analytics")
        
        # Get logs from database
        logs_df = db_manager.get_logs()
        
        if not logs_df.empty:
            # Summary metrics
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                total_scans = len(logs_df)
                st.metric("🔍 Total Scans", total_scans)
            
            with col2:
                malicious_count = len(logs_df[logs_df['prediction'] == 0])
                st.metric("⚠️ Malicious Files", malicious_count)
            
            with col3:
                benign_count = len(logs_df[logs_df['prediction'] == 1])
                st.metric("✅ Benign Files", benign_count)
            
            with col4:
                if 'processing_time_ms' in logs_df.columns and not logs_df['processing_time_ms'].isna().all():
                    avg_processing_time = logs_df['processing_time_ms'].mean()
                    st.metric("⏱️ Avg Processing Time", f"{avg_processing_time:.1f}ms")
                else:
                    st.metric("⏱️ Avg Processing Time", "N/A")
            
            # Performance metrics from monitor
            current_metrics = performance_monitor.get_current_metrics()
            
            st.subheader("📈 Current Performance Metrics")
            perf_col1, perf_col2, perf_col3 = st.columns(3)
            
            with perf_col1:
                st.metric("🚀 Files/Minute", f"{current_metrics['files_per_minute']:.1f}")
                st.metric("💾 Memory Usage", f"{current_metrics['current_memory']:.1f}MB")
            
            with perf_col2:
                st.metric("🖥️ CPU Usage", f"{current_metrics['avg_cpu_usage']:.1f}%")
                st.metric("⚡ Avg Processing", f"{current_metrics['avg_processing_time']:.1f}ms")
            
            with perf_col3:
                st.metric("🔌 Arduino Delay", f"{current_metrics['avg_arduino_delay']:.1f}ms")
                st.metric("📁 Files Processed", performance_monitor.files_processed)
            
            # Visualization section
            st.subheader("📊 Data Visualizations")
            create_visualizations(logs_df)
            
            # Recent logs table
            st.subheader("📋 Recent Detection Logs")
            
            # Filter options
            col1, col2, col3 = st.columns(3)
            with col1:
                scan_type_filter = st.selectbox("Scan Type", ["All"] + list(logs_df['scan_type'].unique()))
            with col2:
                prediction_filter = st.selectbox("Result", ["All", "Malicious", "Benign"])
            with col3:
                limit = st.number_input("Show Records", min_value=10, max_value=500, value=50)
            
            # Apply filters
            filtered_df = logs_df.copy()
            
            if scan_type_filter != "All":
                filtered_df = filtered_df[filtered_df['scan_type'] == scan_type_filter]
            
            if prediction_filter == "Malicious":
                filtered_df = filtered_df[filtered_df['prediction'] == 0]
            elif prediction_filter == "Benign":
                filtered_df = filtered_df[filtered_df['prediction'] == 1]
            
            # Display limited records
            display_df = filtered_df.head(limit).copy()
            
            if not display_df.empty:
                # Format the display
                display_df['result'] = display_df['prediction'].apply(lambda x: "✅ BENIGN" if x == 1 else "⚠️ MALICIOUS")
                display_df['confidence_pct'] = (display_df['confidence'] * 100).round(1).astype(str) + "%"
                
                # Select columns to display
                display_columns = ['filename', 'detection_time', 'result', 'confidence_pct', 'scan_type']
                if 'processing_time_ms' in display_df.columns:
                    display_df['processing_ms'] = display_df['processing_time_ms'].round(1)
                    display_columns.append('processing_ms')
                
                st.dataframe(
                    display_df[display_columns],
                    use_container_width=True,
                    column_config={
                        "filename": "File Name",
                        "detection_time": "Detection Time",
                        "result": "Result",
                        "confidence_pct": "Confidence",
                        "scan_type": "Scan Type",
                        "processing_ms": "Processing (ms)"
                    }
                )
                
                # Export functionality
                if st.button("📥 Export Logs to CSV"):
                    csv = filtered_df.to_csv(index=False)
                    st.download_button(
                        label="Download CSV",
                        data=csv,
                        file_name=f"ransomware_logs_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                        mime="text/csv"
                    )
            else:
                st.info("No records match the selected filters.")
        else:
            st.info("No detection logs available yet. Start scanning files to see results here.")
    
    elif page == "ℹ️ About":
        st.header("ℹ️ About Ransomware Detection System")
        
        st.markdown("""
        ### 🛡️ System Overview
        This advanced ransomware detection system uses machine learning to analyze PE (Portable Executable) files 
        and identify potential ransomware threats in real-time.
        
        ### 🔧 Key Features
        - **Real-time File Monitoring**: Automatically scans new files in specified directories
        - **Machine Learning Detection**: Uses Random Forest classifier for accurate threat detection
        - **Arduino Integration**: Physical notification system for security alerts
        - **Performance Monitoring**: Comprehensive logging and metrics tracking
        - **Web Interface**: User-friendly Streamlit interface for system control
        - **Database Logging**: SQLite database for persistent log storage
        
        ### 📊 Performance Metrics Tracked
        - **File Processing Time**: Time taken to analyze each file
        - **Arduino Communication Delay**: Response time for hardware notifications
        - **Throughput**: Files processed per minute
        - **Resource Usage**: CPU and memory consumption monitoring
        - **System Health**: Continuous performance monitoring
        
        ### 🔍 Detection Process
        1. **Feature Extraction**: Analyzes PE file headers and structure
        2. **ML Classification**: Applies trained Random Forest model
        3. **Confidence Scoring**: Provides probability-based confidence levels
        4. **Hardware Alert**: Sends notification to Arduino device
        5. **Database Logging**: Records all detections with performance metrics
        
        ### 📈 System Architecture
        - **Frontend**: Streamlit web interface
        - **Backend**: Python with scikit-learn ML pipeline
        - **Database**: SQLite for log storage
        - **Hardware**: Arduino-based notification system
        - **Monitoring**: Real-time folder watching with background processing
        
        ### 🚀 Performance Optimization
        - Background threading for non-blocking operations
        - Efficient memory management with deque structures
        - Asynchronous Arduino communication
        - Database connection pooling
        - Resource usage monitoring with automatic logging
        """)
        
        # System status
        st.subheader("🔧 System Status")
        
        status_col1, status_col2 = st.columns(2)
        
        with status_col1:
            st.write("**Model Status:**", "✅ Loaded" if model else "❌ Error")
            st.write("**Database Status:**", "✅ Connected")
            st.write("**Arduino Status:**", "🟢 Connected" if arduino_manager.is_connected() else "🔴 Disconnected")
        
        with status_col2:
            st.write("**Monitoring Status:**", "🟢 Active" if 'monitoring_folder' in st.session_state else "🔴 Inactive")
            st.write("**Performance Monitor:**", "🟢 Running")
            st.write("**Log Files:**", "✅ Available")
        
        # Current performance summary
        st.subheader("📊 Current Session Performance")
        metrics = performance_monitor.get_current_metrics()
        
        perf_info = f"""
        - **Files Processed**: {performance_monitor.files_processed}
        - **Average Processing Time**: {metrics['avg_processing_time']:.2f}ms
        - **Files per Minute**: {metrics['files_per_minute']:.2f}
        - **Current Memory Usage**: {metrics['current_memory']:.2f}MB
        - **Average CPU Usage**: {metrics['avg_cpu_usage']:.2f}%
        - **Arduino Average Delay**: {metrics['avg_arduino_delay']:.2f}ms
        """
        
        st.markdown(perf_info)
        
        # Log file access
        st.subheader("📋 Log Files")
        log_col1, log_col2 = st.columns(2)
        
        with log_col1:
            if st.button("📄 View Application Logs"):
                try:
                    with open("ransomware_detector.log", "r") as f:
                        log_content = f.read()
                    st.text_area("Application Logs", log_content[-2000:], height=200)  # Show last 2000 chars
                except FileNotFoundError:
                    st.warning("Application log file not found")
        
        with log_col2:
            if st.button("📊 View Performance Logs"):
                try:
                    with open("performance_metrics.log", "r") as f:
                        perf_content = f.read()
                    st.text_area("Performance Logs", perf_content[-2000:], height=200)  # Show last 2000 chars
                except FileNotFoundError:
                    st.warning("Performance log file not found")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Application interrupted by user")
        # Clean shutdown
        performance_monitor = get_performance_monitor()
        performance_monitor.stop_monitoring()
        
        arduino_manager = get_arduino_manager()
        arduino_manager.disconnect()
        
        folder_monitor = get_folder_monitor()
        folder_monitor.stop_all()
        
        logger.info("Application shutdown complete")
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        raise