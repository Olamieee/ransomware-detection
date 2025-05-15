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

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("ransomware_detector.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("ransomware-detector")

# Load the trained model
try:
    logger.info("Attempting to load model from ransomware_rf_model.pkl")
    model = joblib.load('ransomware_rf_model.pkl')
    logger.info("Model loaded successfully from pkl file")
except:
    logger.info("Attempting to load model from rf_ransomware_model.joblib")
    model = joblib.load('rf_ransomware_model.joblib')
    logger.info("Model loaded successfully from joblib file")

# Initialize database
def init_db():
    logger.info("Initializing database")
    conn = sqlite3.connect('ransomware_detection.db')
    c = conn.cursor()
    c.execute('''
    CREATE TABLE IF NOT EXISTS detection_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT,
        detection_time TIMESTAMP,
        prediction INTEGER,
        confidence REAL,
        features TEXT
    )
    ''')
    conn.commit()
    conn.close()
    logger.info("Database initialized successfully")

# Log detection to database
def log_detection(filename, prediction, confidence, features):
    logger.info(f"Logging detection for {filename}: prediction={prediction}, confidence={confidence:.2f}")
    conn = sqlite3.connect('ransomware_detection.db')
    c = conn.cursor()
    c.execute(
        "INSERT INTO detection_logs (filename, detection_time, prediction, confidence, features) VALUES (?, ?, ?, ?, ?)",
        (filename, datetime.datetime.now(), int(prediction), float(confidence), str(features))
    )
    conn.commit()
    conn.close()

# Initialize the database on startup
init_db()

# Set page config
st.set_page_config(page_title="Ransomware Detection", layout="wide")

# Title
st.title("Ransomware Detection System")

# Create sidebar navigation
page = st.sidebar.radio(
    "Navigation",
    ["Detection", "Logs", "About"]
)

if page == "Detection":
    # Create tabs for the different input methods
    tab1, tab2, tab3 = st.tabs(["Manual Input", "File Upload", "CSV Upload"])

    # Define the features required for prediction
    features = ['Machine', 'DebugSize', 'DebugRVA', 'MajorImageVersion', 
                'MajorOSVersion', 'ExportRVA', 'ExportSize', 'IatVRA', 
                'MajorLinkerVersion', 'MinorLinkerVersion', 'NumberOfSections', 
                'SizeOfStackReserve', 'DllCharacteristics', 'ResourceSize', 
                'BitcoinAddresses']

    with tab1:
        st.header("Enter File Characteristics Manually")
        
        # Create form for manual input
        with st.form("manual_input_form"):
            # Create 3 columns to organize the form fields
            col1, col2, col3 = st.columns(3)
            
            # Create form fields
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
            
            submit_manual = st.form_submit_button("Analyze")
        
        # When form is submitted
        if submit_manual:
            logger.info("Manual analysis submitted")
            # Create DataFrame from input values
            input_df = pd.DataFrame([input_values])
            
            # Make prediction
            prediction = model.predict(input_df)[0]
            prediction_proba = model.predict_proba(input_df)[0]
            confidence = prediction_proba[1] if prediction == 1 else prediction_proba[0]
            
            # Log to database
            log_detection("manual_input", prediction, confidence, input_values)
            
            # Display result
            st.subheader("Prediction Result")
            
            if prediction == 1:
                st.success(f"The file is BENIGN with {prediction_proba[1]:.2%} confidence")
                logger.info(f"Prediction: BENIGN with {prediction_proba[1]:.2%} confidence")
            else:
                st.error(f"The file is MALICIOUS (RANSOMWARE) with {prediction_proba[0]:.2%} confidence")
                logger.info(f"Prediction: MALICIOUS with {prediction_proba[0]:.2%} confidence")

    def extract_pe_features(file_path):
        """Extract features from a PE file for ransomware detection"""
        logger.info(f"Extracting features from {file_path}")
        try:
            pe = pefile.PE(file_path)
            
            # Extract debug info
            debug_size = 0
            debug_rva = 0
            if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG') and len(pe.DIRECTORY_ENTRY_DEBUG) > 0:
                debug_size = pe.DIRECTORY_ENTRY_DEBUG[0].struct.SizeOfData
                debug_rva = pe.DIRECTORY_ENTRY_DEBUG[0].struct.AddressOfRawData
                logger.debug(f"Debug info: size={debug_size}, rva={debug_rva}")
            
            # Extract export info
            export_rva = 0
            export_size = 0
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                export_rva = pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].VirtualAddress
                export_size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].Size
                logger.debug(f"Export info: rva={export_rva}, size={export_size}")
            
            # Extract IAT info
            iat_vra = 0
            if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > 12:
                iat_vra = pe.OPTIONAL_HEADER.DATA_DIRECTORY[12].VirtualAddress
                logger.debug(f"IAT VRA: {iat_vra}")
            
            # Extract resource info
            resource_size = 0
            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                resource_size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[2].Size
                logger.debug(f"Resource size: {resource_size}")
            
            # Check for Bitcoin addresses by looking for potential patterns
            bitcoin_addresses = 0
            raw_data = ' '.join([section.get_data().decode('latin-1', errors='ignore') for section in pe.sections])
            bitcoin_pattern = re.compile(r'[13][a-km-zA-HJ-NP-Z1-9]{25,34}')
            bitcoin_matches = bitcoin_pattern.findall(raw_data)
            bitcoin_addresses = len(bitcoin_matches)
            logger.debug(f"Bitcoin addresses found: {bitcoin_addresses}")
            
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
            logger.info("Features extracted successfully")
            return features
        except Exception as e:
            logger.error(f"Error extracting features from file: {str(e)}")
            st.error(f"Error extracting features from file: {str(e)}")
            return None

    with tab2:
        st.header("Upload a File for Analysis")
        
        uploaded_file = st.file_uploader("Choose a PE file (DLL/EXE)", type=['dll', 'exe'])
        
        if uploaded_file is not None:
            logger.info(f"File uploaded: {uploaded_file.name}")
            # Save uploaded file temporarily
            with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(uploaded_file.name)[1]) as tmp_file:
                tmp_file.write(uploaded_file.getvalue())
                temp_file_path = tmp_file.name
            
            st.info(f"File '{uploaded_file.name}' uploaded successfully")
            
            if st.button("Extract Features and Analyze"):
                try:
                    with st.spinner("Extracting features..."):
                        # Extract features from the PE file
                        file_features = extract_pe_features(temp_file_path)
                        
                        if file_features:
                            # Convert to DataFrame
                            input_df = pd.DataFrame([file_features])
                            
                            # Make prediction
                            prediction = model.predict(input_df)[0]
                            prediction_proba = model.predict_proba(input_df)[0]
                            confidence = prediction_proba[1] if prediction == 1 else prediction_proba[0]
                            
                            # Log to database
                            log_detection(uploaded_file.name, prediction, confidence, file_features)
                            
                            # Display result
                            st.subheader("Prediction Result")
                            
                            if prediction == 1:
                                st.success(f"The file is BENIGN with {prediction_proba[1]:.2%} confidence")
                                logger.info(f"Prediction for {uploaded_file.name}: BENIGN with {prediction_proba[1]:.2%} confidence")
                            else:
                                st.error(f"The file is MALICIOUS (RANSOMWARE) with {prediction_proba[0]:.2%} confidence")
                                logger.info(f"Prediction for {uploaded_file.name}: MALICIOUS with {prediction_proba[0]:.2%} confidence")
                            
                            # Display extracted features
                            with st.expander("View Extracted Features"):
                                st.dataframe(input_df)
                    
                except Exception as e:
                    logger.error(f"Error analyzing file: {str(e)}")
                    st.error(f"Error analyzing file: {str(e)}")
                
                finally:
                    # Close the file handle and wait a moment before trying to delete
                    try:
                        logger.debug(f"Cleaning up temporary file: {temp_file_path}")
                        # Give some time for file handles to be released
                        time.sleep(1)
                        if os.path.exists(temp_file_path):
                            os.unlink(temp_file_path)
                            logger.debug("Temporary file deleted successfully")
                    except Exception as e:
                        logger.warning(f"Could not delete temporary file {temp_file_path}: {str(e)}")
                        # Not critical, so don't show error to user

    with tab3:
        st.header("Upload CSV with Multiple Samples")
        
        st.info("Upload a CSV file with samples to analyze in batch. The CSV should contain the same features as the manual input form.")
        
        csv_file = st.file_uploader("Choose a CSV file", type=['csv'])
        
        if csv_file is not None:
            logger.info(f"CSV file uploaded: {csv_file.name}")
            try:
                # Read CSV
                df = pd.read_csv(csv_file)
                
                # Check if required columns exist
                missing_columns = [col for col in features if col not in df.columns]
                
                if missing_columns:
                    st.error(f"The CSV is missing these required columns: {', '.join(missing_columns)}")
                    logger.error(f"CSV missing columns: {missing_columns}")
                else:
                    st.success(f"CSV file loaded successfully with {len(df)} samples")
                    logger.info(f"CSV file loaded with {len(df)} samples")
                    
                    if st.button("Analyze All Samples"):
                        with st.spinner(f"Analyzing {len(df)} samples..."):
                            # Only use the required features
                            input_df = df[features]
                            
                            # Make predictions
                            predictions = model.predict(input_df)
                            prediction_probas = model.predict_proba(input_df)
                            
                            # Create results dataframe
                            results_df = pd.DataFrame({
                                'Sample': range(1, len(df) + 1),
                                'Prediction': ["BENIGN" if p == 1 else "MALICIOUS" for p in predictions],
                                'Confidence': [prediction_probas[i][1] if predictions[i] == 1 else prediction_probas[i][0] 
                                              for i in range(len(predictions))]
                            })
                            
                            # Display results
                            st.subheader("Prediction Results")
                            st.dataframe(results_df)
                            
                            # Log each prediction
                            for i, row in df.iterrows():
                                sample_name = f"csv_sample_{i+1}"
                                confidence = prediction_probas[i][1] if predictions[i] == 1 else prediction_probas[i][0]
                                log_detection(sample_name, predictions[i], confidence, row[features].to_dict())
                            
                            # Create download link for results
                            csv = results_df.to_csv(index=False)
                            st.download_button(
                                label="Download Results as CSV",
                                data=csv,
                                file_name="ransomware_detection_results.csv",
                                mime="text/csv",
                            )
                            logger.info(f"CSV analysis complete. Results: {sum(predictions == 1)} benign, {sum(predictions == 0)} malicious")
            
            except Exception as e:
                logger.error(f"Error processing CSV file: {str(e)}")
                st.error(f"Error processing CSV file: {str(e)}")

elif page == "Logs":
    st.header("Detection Logs")
    
    try:
        conn = sqlite3.connect('ransomware_detection.db')
        logs_df = pd.read_sql_query("SELECT * FROM detection_logs ORDER BY detection_time DESC", conn)
        conn.close()
        
        if logs_df.empty:
            st.info("No detection logs found. Analyze some files first.")
        else:
            # Clean up the dataframe for display
            logs_df['detection_time'] = pd.to_datetime(logs_df['detection_time'])
            logs_df['prediction_text'] = logs_df['prediction'].apply(lambda x: "BENIGN" if x == 1 else "MALICIOUS")
            logs_df['confidence'] = logs_df['confidence'].apply(lambda x: f"{x:.2%}")
            
            # Display stats
            col1, col2 = st.columns(2)
            with col1:
                st.metric("Total Files Analyzed", len(logs_df))
            with col2:
                benign_count = sum(logs_df['prediction'] == 1)
                st.metric("Benign / Malicious", f"{benign_count} / {len(logs_df) - benign_count}")
            
            # Add a line chart to display recent prediction attempts
            st.subheader("Recent Prediction Timeline")
            
            # Create a DataFrame for plotting
            plot_df = logs_df.copy()
            plot_df['confidence_value'] = pd.to_numeric(plot_df['confidence'].str.rstrip('%')) / 100
            
            # Create two separate dataframes - one for benign and one for malicious
            benign_df = plot_df[plot_df['prediction'] == 1].copy()
            malicious_df = plot_df[plot_df['prediction'] == 0].copy()
            
            # Create the line chart using plotly
            fig = px.line(
                plot_df,
                x="detection_time",
                y="confidence_value",
                color="prediction_text",
                markers=True,
                title="Recent Prediction Confidence Timeline",
                labels={"detection_time": "Time", "confidence_value": "Confidence", "prediction_text": "Prediction"},
                color_discrete_map={"BENIGN": "green", "MALICIOUS": "red"}
            )
            
            fig.update_layout(
                xaxis_title="Detection Time",
                yaxis_title="Confidence",
                yaxis_tickformat=".0%",
                legend_title="Prediction Result",
                hovermode="closest"
            )
            
            st.plotly_chart(fig, use_container_width=True)
            
            # Display the logs
            st.subheader("Detection Log Entries")
            st.dataframe(logs_df[['id', 'filename', 'detection_time', 'prediction_text', 'confidence']])
            
            # Export option
            if st.button("Export Logs to CSV"):
                csv = logs_df.to_csv(index=False)
                st.download_button(
                    label="Download Logs",
                    data=csv,
                    file_name=f"ransomware_detection_logs_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv",
                )
    
    except Exception as e:
        logger.error(f"Error accessing logs: {str(e)}")
        st.error(f"Error accessing logs: {str(e)}")

elif page == "About":
    st.header("About")
    st.info("""
    This application detects ransomware by analyzing PE file characteristics.
    
    Features:
    - Manual input of file characteristics
    - Direct file upload and analysis
    - CSV batch processing
    - Logging and history tracking
    """)
    
    st.subheader("How It Works")
    st.markdown("""
    The detection system uses a Random Forest model trained on various PE file characteristics
    to identify potential ransomware. Key indicators include:
    
    1. PE Header information
    2. Import/Export tables
    3. Section characteristics
    4. Presence of Bitcoin addresses
    5. Debug information
    
    The model has been trained on a dataset of known ransomware and benign files.
    """)
    
    st.subheader("Debug Information")
    if st.button("Show Debug Log"):
        try:
            with open("ransomware_detector.log", "r") as log_file:
                log_content = log_file.read()
                st.text_area("Log Content", log_content, height=300)
        except Exception as e:
            st.error(f"Error reading log file: {str(e)}")
