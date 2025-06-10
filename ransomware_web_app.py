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

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("ransomware_detector.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("ransomware-detector")

# SQLite Database Configuration
DB_PATH = 'ransomware_detector.db'

class ArduinoManager:
    def __init__(self):
        self.connection = None
        self.command_queue = queue.Queue()
        self.worker_thread = None
        self.running = False
    
    def find_arduino_ports(self):
        ports = serial.tools.list_ports.comports()
        arduino_ports = []
        for port in ports:
            if any(keyword in port.description.upper() for keyword in ['ARDUINO', 'CH340', 'USB']):
                arduino_ports.append(port.device)
        return arduino_ports
    
    def connect(self, port=None):
        try:
            if self.connection and self.connection.is_open:
                self.connection.close()
            
            if not port:
                ports = self.find_arduino_ports()
                if not ports:
                    return False, "No Arduino found"
                port = ports[0]
            
            self.connection = serial.Serial(port, 9600, timeout=2, write_timeout=2)
            time.sleep(3)
            
            if not self.running:
                self.start_worker_thread()
            
            logger.info(f"Arduino connected on port: {port}")
            return True, f"Connected to {port}"
        except serial.SerialException as e:
            logger.error(f"Serial error: {str(e)}")
            return False, f"Serial error: {str(e)}"
        except Exception as e:
            logger.error(f"Arduino connection error: {str(e)}")
            return False, f"Connection error: {str(e)}"
    
    def start_worker_thread(self):
        self.running = True
        self.worker_thread = threading.Thread(target=self.worker, daemon=True)
        self.worker_thread.start()
    
    def worker(self):
        while self.running:
            try:
                command = self.command_queue.get(timeout=1)
                if self.connection and self.connection.is_open:
                    self.connection.write(command.encode() + b'\n')
                    self.connection.flush()
                    logger.info(f"Sent command: {command}")
                self.command_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Arduino communication error: {str(e)}")
    
    def send_command(self, command):
        if not self.command_queue.full():
            self.command_queue.put(command)
    
    def send_batch_result(self, total_files, malicious_count):
        if malicious_count > 0:
            self.send_command(f"BATCH_MALICIOUS:{malicious_count}/{total_files}")
        else:
            self.send_command("BATCH_CLEAN")
    
    def disconnect(self):
        self.running = False
        if self.connection and self.connection.is_open:
            self.connection.close()
        self.connection = None
        logger.info("Arduino disconnected")
    
    def is_connected(self):
        return self.connection and self.connection.is_open

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
                detection_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                prediction INTEGER,
                confidence REAL,
                features TEXT,
                batch_id TEXT
            )
            ''')
            conn.commit()
            cursor.close()
            conn.close()
            logger.info("SQLite database initialized successfully")
        except Exception as e:
            logger.error(f"Database initialization error: {str(e)}")
            st.error(f"Database connection failed: {str(e)}")
    
    def log_detection(self, filename, prediction, confidence, features, batch_id=None):
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            # Convert features dict to JSON string
            features_json = json.dumps(features) if isinstance(features, dict) else str(features)
            
            cursor.execute(
                "INSERT INTO detection_logs (filename, prediction, confidence, features, batch_id) VALUES (?, ?, ?, ?, ?)",
                (filename, int(prediction), float(confidence), features_json, batch_id)
            )
            conn.commit()
            cursor.close()
            conn.close()
            logger.info(f"Logged detection for {filename}: {'BENIGN' if prediction == 1 else 'MALICIOUS'} ({confidence:.2%} confidence)")
        except Exception as e:
            logger.error(f"Database logging error: {str(e)}")
            logger.error(f"Features type: {type(features)}")
    
    def get_logs(self):
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM detection_logs ORDER BY detection_time DESC")
            
            # Get column names
            columns = [description[0] for description in cursor.description]
            
            # Fetch all rows
            rows = cursor.fetchall()
            
            cursor.close()
            conn.close()
            
            # Convert to DataFrame
            df = pd.DataFrame(rows, columns=columns)
            
            # Convert detection_time to datetime
            if not df.empty and 'detection_time' in df.columns:
                df['detection_time'] = pd.to_datetime(df['detection_time'])
            
            return df
        except Exception as e:
            logger.error(f"Error fetching logs: {str(e)}")
            return pd.DataFrame()

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
            st.error(f"Failed to load model: {str(e)}")
            return None

def extract_pe_features(file_path):
    pe = None
    try:
        pe = pefile.PE(file_path)
        
        debug_size = 0
        debug_rva = 0
        if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG') and len(pe.DIRECTORY_ENTRY_DEBUG) > 0:
            debug_size = pe.DIRECTORY_ENTRY_DEBUG[0].struct.SizeOfData
            debug_rva = pe.DIRECTORY_ENTRY_DEBUG[0].struct.AddressOfRawData
        
        export_rva = 0
        export_size = 0
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
        
        features = {
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
        return features
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
    st.subheader("Detection Analytics")
    
    viz_type = st.selectbox("Choose Visualization", 
                           ["Timeline", "Distribution", "Heatmap"])
    
    if viz_type == "Timeline":
        fig = px.line(
            logs_df,
            x="detection_time",
            y="confidence",
            color="prediction_text",
            markers=True,
            title="Detection Confidence Timeline",
            color_discrete_map={"BENIGN": "green", "MALICIOUS": "red"}
        )
        fig.update_layout(yaxis_tickformat=".0%")
        st.plotly_chart(fig, use_container_width=True)
    
    elif viz_type == "Distribution":
        fig = make_subplots(
            rows=2, cols=2,
            subplot_titles=('Prediction Distribution', 'Confidence Distribution', 
                          'Daily Detections', 'Hourly Pattern'),
            specs=[[{"type": "pie"}, {"type": "histogram"}],
                   [{"type": "bar"}, {"type": "bar"}]]
        )
        
        pred_counts = logs_df['prediction_text'].value_counts()
        fig.add_trace(go.Pie(labels=pred_counts.index, values=pred_counts.values,
                            marker_colors=['green' if x == 'BENIGN' else 'red' for x in pred_counts.index]),
                     row=1, col=1)
        
        fig.add_trace(go.Histogram(x=logs_df['confidence'], nbinsx=20, 
                                  marker_color='blue', opacity=0.7),
                     row=1, col=2)
        
        daily_counts = logs_df.groupby(logs_df['detection_time'].dt.date).size()
        fig.add_trace(go.Bar(x=daily_counts.index, y=daily_counts.values,
                            marker_color='purple'),
                     row=2, col=1)
        
        hourly_counts = logs_df.groupby(logs_df['detection_time'].dt.hour).size()
        fig.add_trace(go.Bar(x=hourly_counts.index, y=hourly_counts.values,
                            marker_color='orange'),
                     row=2, col=2)
        
        fig.update_layout(height=800, showlegend=False)
        st.plotly_chart(fig, use_container_width=True)
    
    elif viz_type == "Heatmap":
        logs_df['hour'] = logs_df['detection_time'].dt.hour
        logs_df['day'] = logs_df['detection_time'].dt.day_name()
        
        heatmap_data = logs_df.groupby(['day', 'hour']).size().unstack(fill_value=0)
        
        fig = px.imshow(heatmap_data.values,
                       x=heatmap_data.columns,
                       y=heatmap_data.index,
                       aspect="auto",
                       title="Detection Activity Heatmap",
                       labels=dict(x="Hour of Day", y="Day of Week", color="Detections"))
        
        st.plotly_chart(fig, use_container_width=True)

@st.cache_resource
def get_arduino_manager():
    return ArduinoManager()

@st.cache_resource
def get_db_manager():
    return DatabaseManager(DB_PATH)

@st.cache_resource
def get_model():
    return load_model()

def main():
    st.set_page_config(page_title="Ransomware Detection System", layout="wide")
    st.title("🛡️ Ransomware Detection System")
    
    arduino_manager = get_arduino_manager()
    db_manager = get_db_manager()
    model = get_model()
    
    if not model:
        st.error("Model could not be loaded. Please check the model files.")
        return
    
    st.sidebar.subheader("🔌 Arduino Status")
    
    col1, col2 = st.sidebar.columns(2)
    with col1:
        if st.button("🔗 Connect"):
            success, message = arduino_manager.connect()
            if success:
                st.sidebar.success(f"✅ {message}")
            else:
                st.sidebar.error(f"❌ {message}")
    
    with col2:
        if st.button("🔌 Disconnect"):
            arduino_manager.disconnect()
            st.sidebar.info("Disconnected")
    
    manual_port = st.sidebar.text_input("Manual Port", placeholder="COM3 or /dev/ttyUSB0")
    if st.sidebar.button("Connect Manual") and manual_port:
        success, message = arduino_manager.connect(manual_port)
        st.sidebar.success(message) if success else st.sidebar.error(message)
    
    if arduino_manager.is_connected():
        st.sidebar.success("🟢 Arduino Ready")
    else:
        st.sidebar.warning("🔴 Arduino Disconnected")
    
    page = st.sidebar.radio("📍 Navigation", ["Detection", "Logs", "About"])
    
    features = ['Machine', 'DebugSize', 'DebugRVA', 'MajorImageVersion', 
                'MajorOSVersion', 'ExportRVA', 'ExportSize', 'IatVRA', 
                'MajorLinkerVersion', 'MinorLinkerVersion', 'NumberOfSections', 
                'SizeOfStackReserve', 'DllCharacteristics', 'ResourceSize', 
                'BitcoinAddresses']
    
    if page == "Detection":
        tab1, tab2, tab3 = st.tabs(["📝 Manual Input", "📁 File Upload", "📊 CSV Upload"])
        
        with tab1:
            st.header("Enter File Characteristics")
            
            with st.form("manual_form"):
                col1, col2, col3 = st.columns(3)
                input_values = {}
                
                with col1:
                    input_values['Machine'] = st.number_input("Machine", min_value=0, value=332)
                    input_values['DebugSize'] = st.number_input("Debug Size", min_value=0, value=0)
                    input_values['DebugRVA'] = st.number_input("Debug RVA", min_value=0, value=0)
                    input_values['MajorImageVersion'] = st.number_input("Major Image Version", min_value=0, value=0)
                    input_values['MajorOSVersion'] = st.number_input("Major OS Version", min_value=0, value=4)
                
                with col2:
                    input_values['ExportRVA'] = st.number_input("Export RVA", min_value=0, value=0)
                    input_values['ExportSize'] = st.number_input("Export Size", min_value=0, value=0)
                    input_values['IatVRA'] = st.number_input("Iat VRA", min_value=0, value=8192)
                    input_values['MajorLinkerVersion'] = st.number_input("Major Linker Version", min_value=0, value=8)
                    input_values['MinorLinkerVersion'] = st.number_input("Minor Linker Version", min_value=0, value=0)
                
                with col3:
                    input_values['NumberOfSections'] = st.number_input("Number Of Sections", min_value=1, value=3)
                    input_values['SizeOfStackReserve'] = st.number_input("Size Of Stack Reserve", min_value=0, value=1048576)
                    input_values['DllCharacteristics'] = st.number_input("Dll Characteristics", min_value=0, value=34112)
                    input_values['ResourceSize'] = st.number_input("Resource Size", min_value=0, value=672)
                    input_values['BitcoinAddresses'] = st.number_input("Bitcoin Addresses", min_value=0, value=0)
                
                if st.form_submit_button("🔍 Analyze"):
                    logger.info("Starting manual input analysis...")
                    input_df = pd.DataFrame([input_values])
                    
                    logger.info("Making prediction with Random Forest model...")
                    prediction = model.predict(input_df)[0]
                    prediction_proba = model.predict_proba(input_df)[0]
                    confidence = prediction_proba[1] if prediction == 1 else prediction_proba[0]
                    
                    result_text = "BENIGN" if prediction == 1 else "MALICIOUS (RANSOMWARE)"
                    logger.info(f"Prediction complete: {result_text} with {confidence:.2%} confidence")
                    
                    arduino_manager.send_command("RANSOMWARE" if prediction == 0 else "BENIGN")
                    db_manager.log_detection("manual_input", prediction, confidence, input_values)
                    
                    if prediction == 1:
                        st.success(f"✅ BENIGN - {prediction_proba[1]:.2%} confidence")
                    else:
                        st.error(f"⚠️ MALICIOUS (RANSOMWARE) - {prediction_proba[0]:.2%} confidence")
        
        with tab2:
            st.header("Upload PE File")
            uploaded_file = st.file_uploader("Choose PE file", type=['dll', 'exe'])
            
            if uploaded_file and st.button("🔍 Analyze File"):
                with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(uploaded_file.name)[1]) as tmp_file:
                    tmp_file.write(uploaded_file.getvalue())
                    temp_path = tmp_file.name
                
                try:
                    with st.spinner("Extracting features..."):
                        logger.info(f"Analyzing uploaded file: {uploaded_file.name}")
                        file_features = extract_pe_features(temp_path)
                        
                        if file_features:
                            logger.info(f"Features extracted successfully for {uploaded_file.name}")
                            logger.info("Making prediction with Random Forest model...")
                            
                            input_df = pd.DataFrame([file_features])
                            prediction = model.predict(input_df)[0]
                            prediction_proba = model.predict_proba(input_df)[0]
                            confidence = prediction_proba[1] if prediction == 1 else prediction_proba[0]
                            
                            result_text = "BENIGN" if prediction == 1 else "MALICIOUS (RANSOMWARE)"
                            logger.info(f"Prediction complete for {uploaded_file.name}: {result_text} with {confidence:.2%} confidence")
                            
                            arduino_manager.send_command("RANSOMWARE" if prediction == 0 else "BENIGN")
                            db_manager.log_detection(uploaded_file.name, prediction, confidence, file_features)
                            
                            if prediction == 1:
                                st.success(f"✅ BENIGN - {prediction_proba[1]:.2%} confidence")
                            else:
                                st.error(f"⚠️ MALICIOUS (RANSOMWARE) - {prediction_proba[0]:.2%} confidence")
                            
                            with st.expander("📋 Feature Details"):
                                st.dataframe(input_df)
                        else:
                            logger.error(f"Failed to extract features from {uploaded_file.name}")
                            st.error("Failed to extract features from the uploaded file. Please ensure it's a valid PE file.")
                finally:
                    try:
                        os.unlink(temp_path)
                    except:
                        pass
        
        with tab3:
            st.header("Batch CSV Analysis")
            csv_file = st.file_uploader("Choose CSV file", type=['csv'])
            
            if csv_file:
                try:
                    df = pd.read_csv(csv_file)
                    missing_cols = [col for col in features if col not in df.columns]
                    
                    if missing_cols:
                        st.error(f"Missing columns: {', '.join(missing_cols)}")
                    else:
                        st.success(f"📊 {len(df)} samples loaded")
                        
                        if st.button("🚀 Analyze Batch"):
                            batch_id = f"batch_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
                            logger.info(f"Starting batch analysis with ID: {batch_id} ({len(df)} samples)")
                            
                            with st.spinner(f"Processing {len(df)} samples..."):
                                input_df = df[features]
                                
                                logger.info("Making batch predictions with Random Forest model...")
                                predictions = model.predict(input_df)
                                prediction_probas = model.predict_proba(input_df)
                                
                                malicious_count = sum(predictions == 0)
                                benign_count = len(df) - malicious_count
                                logger.info(f"Batch prediction complete: {benign_count} benign, {malicious_count} malicious")
                                
                                arduino_manager.send_batch_result(len(df), malicious_count)
                                
                                results_df = pd.DataFrame({
                                    'Sample': range(1, len(df) + 1),
                                    'Prediction': ["BENIGN" if p == 1 else "MALICIOUS" for p in predictions],
                                    'Confidence': [prediction_probas[i][1] if predictions[i] == 1 else prediction_probas[i][0] 
                                                  for i in range(len(predictions))]
                                })
                                
                                logger.info(f"Logging {len(df)} detection results to database...")
                                for i, row in df.iterrows():
                                    confidence = prediction_probas[i][1] if predictions[i] == 1 else prediction_probas[i][0]
                                    db_manager.log_detection(f"sample_{i+1}", predictions[i], confidence, 
                                                           row[features].to_dict(), batch_id)
                                
                                logger.info(f"Batch analysis complete for {batch_id}")
                                st.success(f"✅ Analysis complete: {benign_count} benign, {malicious_count} malicious")
                                st.dataframe(results_df)
                                
                                csv_data = results_df.to_csv(index=False)
                                st.download_button("📥 Download Results", csv_data, 
                                                 "results.csv", "text/csv")
                
                except Exception as e:
                    st.error(f"CSV processing error: {str(e)}")
    
    elif page == "Logs":
        st.header("📊 Detection Logs")
        
        logs_df = db_manager.get_logs()
        
        if logs_df.empty:
            st.info("No logs found")
        else:
            logs_df['prediction_text'] = logs_df['prediction'].apply(lambda x: "BENIGN" if x == 1 else "MALICIOUS")
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total Files", len(logs_df))
            with col2:
                benign_count = sum(logs_df['prediction'] == 1)
                st.metric("Benign Files", benign_count)
            with col3:
                st.metric("Malicious Files", len(logs_df) - benign_count)
            
            create_visualizations(logs_df)
            
            st.subheader("📋 Recent Logs")
            display_cols = ['id', 'filename', 'detection_time', 'prediction_text', 'confidence']
            st.dataframe(logs_df[display_cols].head(50))
            
            if st.button("📥 Export Logs"):
                csv_data = logs_df.to_csv(index=False)
                st.download_button("Download", csv_data, 
                                 f"logs_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                                 "text/csv")
    
    elif page == "About":
        st.header("ℹ️ About")
        st.markdown("""
        ### 🛡️ Ransomware Detection System
        
        **Features:**
        - 🔍 PE file analysis using Random Forest ML model
        - 🔔 Arduino-based alert system (LED + Buzzer)
        - 💾 SQLite database with advanced analytics
        - 🚀 Optimized batch processing
        - 📈 Multiple visualization options
        
        **Arduino Connections:**
        - Green LED (Pin 10): Benign files
        - Red LED (Pin 11): Ransomware detected  
        - Buzzer (Pin 12): Audio alert
        
        **Detection Features:**
        - PE header analysis
        - Import/Export tables
        - Section characteristics  
        - Bitcoin address detection
        - Debug information analysis
        
        **Database:** SQLite (ransomware_detector.db)
        """)

if __name__ == "__main__":
    main()