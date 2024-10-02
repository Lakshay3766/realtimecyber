import requests
import hashlib

API_KEY = "a4724718edc205f481b113d5040c53cfd1dd83056bf6f63aa8a9068e45ad68f4"  # Replace with your VirusTotal API key

def check_suspicious_ips(network_table):
    for i in range(network_table.rowCount()):
        remote_ip = network_table.item(i, 1).text().split(':')[0]
        if remote_ip != "N/A" and not remote_ip.startswith('192.168'):
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{remote_ip}"
            headers = {"x-apikey": API_KEY}
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                result = response.json()
                malicious = result['data']['attributes']['last_analysis_stats']['malicious']
                if malicious > 0:
                    network_table.setItem(i, 2, QTableWidgetItem("Suspicious"))

def scan_file_with_virustotal(file_path):
    # Compute the SHA256 hash of the file
    sha256_hash = compute_sha256(file_path)
    # First, check if the file has been scanned before
    url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
    headers = {"x-apikey": API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        # File has been scanned before
        result = response.json()
        stats = result['data']['attributes']['last_analysis_stats']
        detection_ratio = f"{stats['malicious']}/{stats['harmless'] + stats['malicious'] + stats['suspicious'] + stats['undetected']}"
        return detection_ratio, "Scanned Previously"
    else:
        # Upload the file for scanning
        files = {'file': open(file_path, 'rb')}
        url = "https://www.virustotal.com/api/v3/files"
        response = requests.post(url, headers=headers, files=files)
        if response.status_code == 200:
            # File uploaded successfully, get the analysis ID
            result = response.json()
            analysis_id = result['data']['id']
            # Poll for the analysis report
            report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            while True:
                report_response = requests.get(report_url, headers=headers)
                if report_response.status_code == 200:
                    report_result = report_response.json()
                    status = report_result['data']['attributes']['status']
                    if status == "completed":
                        stats = report_result['data']['attributes']['stats']
                        detection_ratio = f"{stats['malicious']}/{stats['harmless'] + stats['malicious'] + stats['suspicious'] + stats['undetected']}"
                        return detection_ratio, "Scan Completed"
                else:
                    break
        else:
            return "Error", "Could not upload file"

def compute_sha256(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path,"rb") as f:
        # Read and update hash in chunks
        for byte_block in iter(lambda: f.read(4096),b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()
