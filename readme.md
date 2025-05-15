# Ransomware Detection System

A machine learning-powered application for detecting ransomware through analysis of PE file characteristics, built with Streamlit, Python, and a Random Forest model.

## Overview

This application provides a user-friendly interface for detecting potential ransomware threats by analyzing executable files (PE files). It leverages a trained Random Forest model to identify suspicious patterns commonly found in ransomware, helping security professionals and system administrators protect their systems from malicious software.

## Features

- **Multiple Input Methods**
  - Manual feature input
  - Direct file upload and analysis
  - Batch processing via CSV upload

- **Detailed Analysis**
  - Extracts key PE file characteristics
  - Provides confidence scores for predictions
  - Displays detailed feature information

- **Visualization & Logging**
  - Real-time prediction timeline
  - Complete detection history
  - Exportable logs and results

### Setup

1. Clone the repository:
```bash
git clone https://github.com/Olamieee/ransomware-detection.git
cd ransomware-detection
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Download the pre-trained model (if not included):
```bash
# Either place ransomware_rf_model.pkl in the root directory
# or obtain the model file from the project maintainer
```

## Usage

1. Start the Streamlit application:
```bash
streamlit run streamlit_app_updated.py
```

2. Navigate to the provided local URL (typically http://localhost:8501)

3. Choose one of the three detection methods:
   - **Manual Input**: Enter PE file characteristics directly
   - **File Upload**: Upload a .dll or .exe file for analysis
   - **CSV Upload**: Process multiple samples via CSV

4. View results and detection logs in the application

## Technical Details

### Machine Learning Model

The application uses a Random Forest classifier trained on a dataset of known ransomware and benign files. The model analyzes several key features from PE files, including:

- PE Header information
- Debug directory characteristics
- Import/Export tables
- Section properties
- Resource information
- Presence of Bitcoin addresses (common in ransomware)

### Feature Extraction

For direct file analysis, the system:
1. Parses the PE file structure
2. Extracts relevant features using the pefile library
3. Normalizes the data for the model
4. Returns prediction results with confidence scores

### Database

Detection results are stored in an SQLite database with the following schema:
- File identification
- Detection timestamp
- Prediction result
- Confidence score
- Feature values

## Security Considerations

- This tool is intended as a supplementary security measure and should not replace comprehensive anti-virus solutions
- False positives and negatives can occur; always verify suspicious files through multiple methods
- The model is trained on known ransomware patterns and may not detect novel or highly obfuscated threats

## Requirements

```
streamlit>=1.17.0
pandas>=1.3.5
numpy>=1.21.5
joblib>=1.1.0
pefile>=2022.5.30
plotly>=5.10.0
scikit-learn>=1.0.2
sqlite3
```

## License

[MIT License](LICENSE)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.