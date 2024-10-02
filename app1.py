import sys
import random
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, QCheckBox, QLabel, QPushButton, 
    QTableWidget, QTableWidgetItem, QWidget, QProgressBar, QGroupBox, QScrollArea, QTextEdit, QDialog
)
from PyQt5.QtCore import QTimer, Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont
import psutil
import requests  # To use the VirusTotal API
import json

# Replace with your own VirusTotal API key
VIRUSTOTAL_API_KEY = 'your_virustotal_api_key_here'

# Loading Dialog for Indeterminate Progress
class LoadingDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Loading...")
        self.setModal(True)
        self.setFixedSize(300, 100)

        layout = QVBoxLayout()
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)  # Indeterminate mode
        layout.addWidget(self.progress_bar)

        self.label = QLabel("Analyzing features, please wait...")
        layout.addWidget(self.label)

        self.setLayout(layout)
        self.setWindowModality(Qt.WindowModal)
        self.show()

# Separate thread for analysis of enabled features
class AnalysisThread(QThread):
    analysis_signal = pyqtSignal(str)

    def __init__(self, feature_states):
        super().__init__()
        self.feature_states = feature_states

    def run(self):
        analysis_results = []
        all_safe = True  # Flag to check if all features are safe

        for feature_name, checkbox in self.feature_states.items():
            if checkbox.isChecked():
                # Simulating analysis results with VirusTotal
                if feature_name == "Suspicious IP Addresses":  # Example for specific feature
                    threat_detected, severity_level = self.check_ip_with_virustotal("8.8.8.8")  # Example IP
                else:
                    threat_detected = False
                    severity_level = 0

                if threat_detected:
                    all_safe = False
                    result = (
                        f"<b>{feature_name}</b>: <font color='red'>Threat Detected</font><br>"
                        f"Severity Level: {severity_level}<br>"
                        "Recommended Action: Take immediate action to investigate.<br>"
                    )
                else:
                    result = (
                        f"<b>{feature_name}</b>: <font color='green'>Safe</font><br>"
                        "No unusual activity detected.<br>"
                    )
                analysis_results.append(result)

        if not analysis_results:  # Ensure there's at least a 'safe' message if nothing checked
            analysis_results.append("No features selected for monitoring.")
        
        if all_safe:
            analysis_results.append("<b>All features monitored are <font color='green'>Safe</font></b>")
        else:
            analysis_results.append("<b>Monitoring complete. Please review the detected threats.</b>")

        self.analysis_signal.emit("<br>".join(analysis_results))

    def check_ip_with_virustotal(self, ip_address):
        url = f"https://www.virustotal.com/vtapi/v2/ip/report?apikey={VIRUSTOTAL_API_KEY}&ip={ip_address}"
        response = requests.get(url)
        data = json.loads(response.text)

        if data.get("response_code") == 1:
            if data.get("positives") > 0:
                return True, data["positives"]  # Threat detected
        return False, 0  # No threat

class NetworkThread(QThread):
    update_signal = pyqtSignal(list)

    def run(self):
        connections = psutil.net_connections(kind='inet')
        threat_data = []

        for conn in connections:
            local_address = f"{conn.laddr[0]}:{conn.laddr[1]}"
            remote_address = f"{conn.raddr[0]}:{conn.raddr[1]}" if conn.raddr else "N/A"
            status = conn.status
            pid = conn.pid
            threat_level = random.randint(1, 100)  # Simulate threat levels
            threat_data.append((local_address, remote_address, status, pid, threat_level))

        # Send the result back to the main thread
        self.update_signal.emit(threat_data)

class CyberThreatMonitor(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AI-Driven Cyber Threat Monitoring")
        self.setGeometry(100, 100, 1300, 850)

        # Flag to check if scan is in progress
        self.scan_in_progress = False

        # Main Layout
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)

        # Header
        header = QLabel("<h1 style='color:#007BFF;'>AI-Driven Cyber Threat Monitoring</h1>")
        header.setAlignment(Qt.AlignCenter)
        header.setStyleSheet("font-size: 24px; font-weight: bold; color: #0056b3;")
        self.main_layout.addWidget(header)

        # Threat Level Indicator Layout
        threat_layout = QHBoxLayout()
        threat_label = QLabel("Current Threat Level:")
        threat_label.setStyleSheet("font-size: 18px; font-weight: bold; color: #333333;")
        self.threat_bar = QProgressBar()
        self.threat_bar.setRange(0, 100)
        self.threat_bar.setStyleSheet(
            "QProgressBar {border: 1px solid #333; border-radius: 5px; text-align: center;} "
            "QProgressBar::chunk {background-color: #4caf50; width: 20px;}"
        )
        threat_layout.addWidget(threat_label)
        threat_layout.addWidget(self.threat_bar)
        self.main_layout.addLayout(threat_layout)

        # Toggle for Scan Mode
        self.scan_mode = "Full Scan"
        self.scan_mode_label = QLabel(f"Selected Scan Mode: {self.scan_mode}")
        self.scan_mode_label.setStyleSheet("font-size: 16px; font-weight: bold;")
        self.main_layout.addWidget(self.scan_mode_label)

        self.toggle_mode_button = QPushButton("Toggle Scan Mode")
        self.toggle_mode_button.setStyleSheet(""" 
            QPushButton {background-color: #17A2B8; color: white; font-weight: bold; font-size: 16px; padding: 10px; border-radius: 8px; }
            QPushButton:hover {background-color: #138496; }
        """)
        self.toggle_mode_button.clicked.connect(self.toggle_scan_mode)
        self.main_layout.addWidget(self.toggle_mode_button)

        # Start Scan Button
        self.start_button = QPushButton("Start Real-Time Scan")
        self.start_button.setStyleSheet(""" 
            QPushButton {background-color: #28A745; color: white; font-weight: bold; font-size: 16px; padding: 10px; border-radius: 8px;}
            QPushButton:hover {background-color: #218838;}
        """)
        self.start_button.clicked.connect(self.start_scan)
        self.main_layout.addWidget(self.start_button)

        # Features Group Box
        self.features_group = QGroupBox("Monitoring Features")
        self.features_layout = QVBoxLayout(self.features_group)
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setWidget(self.features_group)

        # Features List
        self.feature_states = {}
        self.features = [
            {"name": "Unusual Network Traffic", "description": "Monitor traffic for unusual patterns."},
            {"name": "Suspicious IP Addresses", "description": "Check for malicious IP addresses."},
            {"name": "Malware Signatures", "description": "Scan for known malware signatures."},
            {"name": "Anomalous User Behavior", "description": "Identify unusual login attempts."},
            {"name": "Data Exfiltration", "description": "Monitor large, unusual data transfers."},
            {"name": "Unsecured Ports", "description": "Check for open/unsecured ports."},
            {"name": "Real-Time Full Monitoring", "description": "Monitor system performance in real-time."},
            {"name": "Deception Technology (Honeypots)", "description": "Deploy honeypots to detect and analyze intrusions."},
            {"name": "Dark Web Monitoring", "description": "Monitor dark web for compromised credentials and data."},
            {"name": "Ransomware Detection", "description": "Detect and respond to ransomware threats."},
            {"name": "Phishing Detection", "description": "Identify and block phishing attempts in emails."}
        ]

        for feature in self.features:
            checkbox = QCheckBox(f"{feature['name']}: {feature['description']}")
            checkbox.setStyleSheet("font-size: 14px; padding: 5px;")
            self.feature_states[feature["name"]] = checkbox
            self.features_layout.addWidget(checkbox)

        self.main_layout.addWidget(self.scroll_area)

        # Threat Data Table
        self.threat_data_table = QTableWidget()
        self.threat_data_table.setColumnCount(5)
        self.threat_data_table.setHorizontalHeaderLabels(["Local Address", "Remote Address", "Status", "PID", "Threat Level"])
        self.threat_data_table.setStyleSheet("font-size: 12px;")
        self.main_layout.addWidget(self.threat_data_table)

        # Status and log area
        self.status_area = QTextEdit()
        self.status_area.setReadOnly(True)
        self.main_layout.addWidget(self.status_area)

    def toggle_scan_mode(self):
        if self.scan_mode == "Full Scan":
            self.scan_mode = "Quick Scan"
        else:
            self.scan_mode = "Full Scan"
        self.scan_mode_label.setText(f"Selected Scan Mode: {self.scan_mode}")

    def start_scan(self):
        if self.scan_in_progress:
            self.status_area.append("Scan is already in progress. Please wait until it's complete.")
            return

        self.scan_in_progress = True
        self.start_button.setEnabled(False)  # Disable button
        self.loading_dialog = LoadingDialog()  # Show loading dialog

        # Start the network scanning thread
        self.network_thread = NetworkThread()
        self.network_thread.update_signal.connect(self.update_threat_data)
        self.network_thread.start()

        # Start analysis of enabled features
        self.analysis_thread = AnalysisThread(self.feature_states)
        self.analysis_thread.analysis_signal.connect(self.display_analysis_results)
        self.analysis_thread.finished.connect(self.on_scan_finished)
        self.analysis_thread.start()

    def update_threat_data(self, threat_data):
        self.threat_data_table.setRowCount(len(threat_data))
        for row, (local_addr, remote_addr, status, pid, threat_level) in enumerate(threat_data):
            self.threat_data_table.setItem(row, 0, QTableWidgetItem(local_addr))
            self.threat_data_table.setItem(row, 1, QTableWidgetItem(remote_addr))
            self.threat_data_table.setItem(row, 2, QTableWidgetItem(status))
            self.threat_data_table.setItem(row, 3, QTableWidgetItem(str(pid)))
            self.threat_data_table.setItem(row, 4, QTableWidgetItem(str(threat_level)))

    def display_analysis_results(self, analysis_results):
        self.loading_dialog.close()  # Close loading dialog
        self.status_area.append(analysis_results)

    def on_scan_finished(self):
        self.scan_in_progress = False
        self.start_button.setEnabled(True)  # Re-enable the button

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = CyberThreatMonitor()
    window.show()
    sys.exit(app.exec_())
