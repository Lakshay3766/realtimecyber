import sys
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, QCheckBox, QLabel, QPushButton, 
    QTableWidget, QTableWidgetItem, QWidget, QProgressBar, QGroupBox, QScrollArea
)
from PyQt5.QtCore import QTimer, Qt
import psutil
import requests
import random  # For generating fake threat levels in the example

class CyberThreatMonitor(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AI-Driven Cyber Threat Monitoring")
        self.setGeometry(100, 100, 1200, 800)

        # Main Layout
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)

        # Header
        header = QLabel("<h1 style='color:#007BFF;'>AI-Driven Cyber Threat Monitoring</h1>")
        header.setAlignment(Qt.AlignCenter)
        self.main_layout.addWidget(header)

        # Threat Level Indicator Layout
        threat_layout = QHBoxLayout()
        threat_label = QLabel("Current Threat Level:")
        self.threat_bar = QProgressBar()
        self.threat_bar.setRange(0, 100)
        threat_layout.addWidget(threat_label)
        threat_layout.addWidget(self.threat_bar)
        self.main_layout.addLayout(threat_layout)

        # Start Scan Button
        self.start_button = QPushButton("Start Real-Time Scan")
        self.start_button.setStyleSheet("background-color: #28A745; color: white; font-weight: bold;")
        self.start_button.clicked.connect(self.start_scan)
        self.main_layout.addWidget(self.start_button)

        # Features Group Box (with Scroll Area)
        self.features_group = QGroupBox("Monitoring Features")
        self.features_layout = QVBoxLayout(self.features_group)
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setWidget(self.features_group)

        # Features List (Checkboxes)
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
            self.feature_states[feature["name"]] = checkbox
            self.features_layout.addWidget(checkbox)

        self.main_layout.addWidget(self.scroll_area)

        # Network Connections Monitoring Layout
        self.network_table = QTableWidget()
        self.network_table.setColumnCount(5)
        self.network_table.setHorizontalHeaderLabels(["Local Address", "Remote Address", "Status", "PID", "Threat Level"])
        self.main_layout.addWidget(QLabel("<h3>Network Connections Monitoring</h3>"))
        self.main_layout.addWidget(self.network_table)

        # Timer for Real-Time Monitoring
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.real_time_threat_detection)

    def start_scan(self):
        # Start real-time scanning
        self.timer.start(3000)  # 3-second interval
        self.network_table.setRowCount(0)  # Clear previous rows
        connections = psutil.net_connections(kind='inet')

        for conn in connections:
            local_address = f"{conn.laddr[0]}:{conn.laddr[1]}"
            remote_address = f"{conn.raddr[0]}:{conn.raddr[1]}" if conn.raddr else "N/A"
            status = conn.status
            pid = conn.pid
            threat_level = random.randint(1, 100)  # Simulate threat levels (for illustration)

            row_position = self.network_table.rowCount()
            self.network_table.insertRow(row_position)
            self.network_table.setItem(row_position, 0, QTableWidgetItem(local_address))
            self.network_table.setItem(row_position, 1, QTableWidgetItem(remote_address))
            self.network_table.setItem(row_position, 2, QTableWidgetItem(status))
            self.network_table.setItem(row_position, 3, QTableWidgetItem(str(pid)))
            self.network_table.setItem(row_position, 4, QTableWidgetItem(str(threat_level)))

        # Check suspicious IPs with VirusTotal
        self.check_suspicious_ips()

    def check_suspicious_ips(self):
        # Example VirusTotal integration for IP checking
        api_key = "YOUR_VIRUSTOTAL_API_KEY"
        for i in range(self.network_table.rowCount()):
            remote_ip = self.network_table.item(i, 1).text().split(':')[0]
            if remote_ip != "N/A" and not remote_ip.startswith('192.168'):
                url = f"https://www.virustotal.com/vtapi/v2/ip-address/report?ip={remote_ip}&apikey={api_key}"
                response = requests.get(url)
                if response.status_code == 200:
                    result = response.json()
                    positives = result.get("positives", 0)
                    if positives > 0:
                        self.network_table.setItem(i, 2, QTableWidgetItem("Suspicious"))

    def real_time_threat_detection(self):
        # Simulate AI-driven threat detection
        threat_level = random.randint(1, 100)  # Simulated threat level
        self.threat_bar.setValue(threat_level)

        if threat_level > 70:
            self.threat_bar.setStyleSheet("QProgressBar::chunk {background-color: red;}")
        elif 30 < threat_level <= 70:
            self.threat_bar.setStyleSheet("QProgressBar::chunk {background-color: orange;}")
        else:
            self.threat_bar.setStyleSheet("QProgressBar::chunk {background-color: green;}")

# Main function to run the application
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = CyberThreatMonitor()
    window.show()
    sys.exit(app.exec_())
