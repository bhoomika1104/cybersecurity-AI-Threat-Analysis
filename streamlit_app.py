import streamlit as st
import pandas as pd
import os
import sys
import tempfile

# Add the parent directory to sys.path to import main.py
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from main import CybersecurityThreatDetector

st.set_page_config(page_title="AI-Powered Cybersecurity Threat Detection", layout="wide")

@st.cache_resource
def load_detector():
    detector = CybersecurityThreatDetector()
    try:
        detector.load_models()
    except Exception as e:
        st.error(f"Error loading models: {e}")
    return detector

detector = load_detector()

st.title("AI-Powered Cybersecurity Threat Detection System")

menu = ["Home", "Network Threat Detection", "Malware Detection", "Phishing Detection", "Dashboard"]
choice = st.sidebar.selectbox("Select Functionality", menu)

if choice == "Home":
    st.write("Welcome to the AI-Powered Cybersecurity Threat Detection System.")
    st.write("Use the sidebar to navigate between different threat detection modules.")
    st.subheader("Sample Inputs and Instructions")

    st.markdown("""
    ### Network Threat Detection
    - Paste CSV data with columns: `bytes_sent, bytes_received, duration, port, protocol_type, service, flag, src_ip`
    - Example:
    ```
    bytes_sent,bytes_received,duration,port,protocol_type,service,flag,src_ip
    5000,8000,60,80,tcp,http,SF,192.168.1.1
    10000,15000,120,443,tcp,https,SF,10.0.0.1
    ```

    ### Malware Detection
    - Upload executable files (.exe) for malware detection.
    - You can use the provided `sample_malware_test.exe` file in the project directory.

    ### Phishing Detection
    - Enter email text to check for phishing.
    - Example:
    ```
    Dear user,

    Your account has been compromised. Please click the link below to reset your password immediately:
    http://fake-website.com/reset-password

    Thank you,
    Support Team
    ```
    """)

elif choice == "Network Threat Detection":
    st.header("Network Threat Detection")
    st.write("Paste your network CSV data below (with columns like bytes_sent, bytes_received, duration, port, protocol_type, service, flag).")
    csv_data = st.text_area("Network CSV Data", height=200)
    if st.button("Detect Network Threats"):
        if not csv_data.strip():
            st.error("Please enter network CSV data.")
        else:
            try:
                from io import StringIO
                df = pd.read_csv(StringIO(csv_data))
                results = detector.detect_network_threats(df)
                if results and isinstance(results, dict) and 'anomalies' in results and 'scores' in results:
                    st.success(f"Detected {results['num_anomalies']} anomalies out of {len(df)} records ({results['anomaly_percentage']:.2f}%).")
                    st.dataframe(pd.DataFrame({'Anomaly': results['anomalies'], 'Score': results['scores']}))
                else:
                    st.warning("No results returned or missing expected keys. Ensure models are loaded and data is correct.")
            except Exception as e:
                import traceback
                st.error(f"Error processing network data: {e}")
                st.text(traceback.format_exc())

elif choice == "Malware Detection":
    st.header("Malware Detection")
    uploaded_files = st.file_uploader("Upload executable files for malware detection", accept_multiple_files=True, type=['exe'])
    if st.button("Detect Malware"):
        if not uploaded_files:
            st.error("Please upload at least one executable file.")
        else:
            results = []
            with tempfile.TemporaryDirectory() as temp_dir:
                for uploaded_file in uploaded_files:
                    temp_file_path = os.path.join(temp_dir, uploaded_file.name)
                    with open(temp_file_path, "wb") as f:
                        f.write(uploaded_file.getbuffer())
                    results.append(detector.detect_malware([temp_file_path])[0])
                for res in results:
                    if 'error' in res:
                        st.error(f"File {res['file_path']}: {res['error']}")
                    else:
                        status = "MALWARE" if res['is_malware'] else "BENIGN"
                        st.write(f"File {res['file_path']}: {status} (Confidence: {res['malware_probability']*100:.1f}%)")

elif choice == "Phishing Detection":
    st.header("Phishing Detection")
    email_text = st.text_area("Enter email text for phishing detection", height=200)
    if st.button("Detect Phishing"):
        if not email_text.strip():
            st.error("Please enter email text.")
        else:
            try:
                results = detector.detect_phishing([email_text])
                if results:
                    res = results[0]
                    if 'error' in res:
                        st.error(f"Error: {res['error']}")
                    else:
                        status = "PHISHING" if res['is_phishing'] else "LEGITIMATE"
                        st.write(f"Email is classified as: {status} (Confidence: {res['phishing_probability']*100:.1f}%)")
                else:
                    st.warning("No results returned. Ensure models are loaded and input is correct.")
            except Exception as e:
                st.error(f"Error during phishing detection: {e}")

elif choice == "Dashboard":
    st.header("Dashboard")
    st.write("Summary of detection results will be shown here.")

    # For demonstration, show dummy summary stats
    st.subheader("Threat Detection Summary")
    st.write("- Total network anomalies detected: 42")
    st.write("- Total malware files scanned: 10")
    st.write("- Total malware detected: 3")
    st.write("- Total phishing emails analyzed: 5")
    st.write("- Total phishing emails detected: 1")

    st.write("You can extend this dashboard to show detailed analytics, charts, and trends.")
