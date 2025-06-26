import requests
import time

class ThreatIntelFeed:
    def __init__(self, update_interval=3600):
        self.update_interval = update_interval  # seconds
        self.last_update = 0
        self.threat_data = set()

    def fetch_threat_data(self):
        # Example: Fetch IP blacklist from a public source
        url = "https://www.blocklist.de/downloads/export-ips_all.txt"
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                ips = response.text.splitlines()
                self.threat_data = set(ip.strip() for ip in ips if ip and not ip.startswith("#"))
                self.last_update = time.time()
                print(f"Threat intelligence feed updated: {len(self.threat_data)} entries")
            else:
                print(f"Failed to fetch threat data, status code: {response.status_code}")
        except Exception as e:
            print(f"Error fetching threat data: {e}")

    def get_threat_data(self):
        current_time = time.time()
        if current_time - self.last_update > self.update_interval:
            self.fetch_threat_data()
        return self.threat_data
