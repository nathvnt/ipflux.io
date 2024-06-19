import os
import re
import requests
import folium
import sys
import json
import time
import psutil
from datetime import datetime
from collections import defaultdict
from scapy.all import sniff, IP, UDP, conf
import logging
import shutil

# Load configuration
with open('config.json', 'r') as f:
    config = json.load(f)

LOG_DIR = config.get("log_dir", "NetworkLogs")
TIMEOUT = config.get("timeout", 15)

# Constants
BACKUP_LOG_DIR = os.path.join(LOG_DIR, 'backup')
CURRENT_LOG_FILE = os.path.join(LOG_DIR, 'network_traffic.log')
HISTORY_LOG_FILE = os.path.join(LOG_DIR, 'network_traffic_history.json')
IP_CACHE_FILE = os.path.join(LOG_DIR, 'ip_cache.json')
ANALYSIS_LOG_FILE = os.path.join(LOG_DIR, 'analysis.log')
NA_LOG_FILE = os.path.join(LOG_DIR, 'network_traffic_na.log')
MAP_FILE = os.path.join(LOG_DIR, 'network_traffic_map.html')
ANOMALOUS_IPS_FILE = os.path.join(LOG_DIR, 'anomalous_ips.json')
TRUSTED_IPS_FILE = os.path.join(LOG_DIR, 'trusted_ips.json')
PATTERN = re.compile(r'Packet: (\d+\.\d+\.\d+\.\d+) -> (\d+\.\d+\.\d+\.\d+)')

# Protocol number to name mapping
protocol_map = {
    1: 'ICMP',
    6: 'TCP',
    17: 'UDP',
    41: 'IPv6',
    89: 'OSPF'
}

# Ensure directories exist
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(BACKUP_LOG_DIR, exist_ok=True)

# Clear analysis log at the start of each run
if os.path.exists(ANALYSIS_LOG_FILE):
    os.remove(ANALYSIS_LOG_FILE)

# Delete and replace the network_traffic.log at the start of each run
if os.path.exists(CURRENT_LOG_FILE):
    os.remove(CURRENT_LOG_FILE)

# Delete the map HTML file at the start of each run
if os.path.exists(MAP_FILE):
    os.remove(MAP_FILE)

# Create a fresh network_traffic.log file
with open(CURRENT_LOG_FILE, 'w') as file:
    pass

# Setup logging for capturing packets
logging.basicConfig(
    filename=CURRENT_LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

logging.info("Logging setup complete. Starting packet capture.")

# Setup logging for NA packets (append mode)
na_logger = logging.getLogger('na_logger')
na_handler = logging.FileHandler(NA_LOG_FILE, mode='a')
na_formatter = logging.Formatter('%(asctime)s - %(message)s')
na_handler.setFormatter(na_formatter)
na_logger.addHandler(na_handler)
na_logger.setLevel(logging.INFO)


def get_process_info(ip):
    connections = psutil.net_connections()
    for conn in connections:
        if conn.laddr.ip == ip or (conn.raddr and conn.raddr.ip == ip):
            try:
                proc = psutil.Process(conn.pid)
                return proc.name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                return "N/A"
    return "N/A"


def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        process_src = get_process_info(ip_src)
        process_dst = get_process_info(ip_dst)
        log_entry = f"Packet: {ip_src} -> {ip_dst}, Protocol: {protocol} ({protocol_map.get(protocol, 'Unknown')}), Process Src: {process_src}, Process Dst: {process_dst}"
        logging.info(log_entry)
        if process_src == "N/A" and process_dst == "N/A":
            if UDP in packet and packet[UDP].dport == 1900:
                na_logger.info(
                    f"SSDP Packet: {log_entry}\nComplete Packet: {packet.summary()}")
            else:
                na_logger.info(
                    f"{log_entry}\nComplete Packet: {packet.summary()}")


# Configure Scapy to use Npcap
conf.use_pcap = True

# Capture packets for a specified timeout
sniff(prn=packet_callback, store=0, timeout=TIMEOUT)

logging.info("Packet capture complete. Check the log file for entries.")

# Setup logging for analysis
analysis_logger = logging.getLogger('analysis')
analysis_handler = logging.FileHandler(ANALYSIS_LOG_FILE)
analysis_formatter = logging.Formatter('%(asctime)s - %(message)s')
analysis_handler.setFormatter(analysis_formatter)
analysis_logger.addHandler(analysis_handler)
analysis_logger.setLevel(logging.INFO)

# Geolocation Providers
providers = [
    {"name": "ipinfo.io", "url": "https://ipinfo.io/{ip}/json"},
    {"name": "freegeoip.app", "url": "https://freegeoip.app/json/{ip}"},
    {"name": "ip-api", "url": "http://ip-api.com/json/{ip}"},
    {"name": "geoplugin", "url": "http://www.geoplugin.net/json.gp?ip={ip}"}
]
current_provider_index = 0


def run_analysis_script():
    global current_provider_index
    traffic_data = []
    ip_cache = {}
    ip_counts = defaultdict(lambda: {'inbound': 0, 'outbound': 0, 'process_src': set(
    ), 'process_dst': set(), 'protocols': set(), 'coordinates': None})
    history_data = defaultdict(list)
    trusted_ips = set()
    anomalous_ips = defaultdict(list)

    # Load historical data, trusted IPs, IP cache, and anomalous IPs
    if os.path.exists(HISTORY_LOG_FILE):
        with open(HISTORY_LOG_FILE, 'r') as file:
            history_data = json.load(file)
        analysis_logger.info("Loaded historical data.")
    if os.path.exists(TRUSTED_IPS_FILE):
        with open(TRUSTED_IPS_FILE, 'r') as file:
            trusted_ips = set(json.load(file))
        analysis_logger.info("Loaded trusted IPs.")
    if os.path.exists(IP_CACHE_FILE):
        with open(IP_CACHE_FILE, 'r') as file:
            ip_cache = json.load(file)
        analysis_logger.info("Loaded IP cache.")
    if os.path.exists(ANOMALOUS_IPS_FILE):
        with open(ANOMALOUS_IPS_FILE, 'r') as file:
            anomalous_ips = json.load(file)
        analysis_logger.info("Loaded anomalous IPs.")

    # Step 1: Parse the Log File
    def parse_log_file():
        with open(CURRENT_LOG_FILE, 'r') as file:
            for line in file:
                match = PATTERN.search(line)
                if match:
                    ip_src, ip_dst = match.groups()
                    protocol = int(line.split("Protocol: ")[1].split(" ")[0])
                    process_src = get_process_info(ip_src)
                    process_dst = get_process_info(ip_dst)
                    traffic_data.append(
                        (ip_src, ip_dst, process_src, process_dst, protocol))
                    ip_counts[ip_src]['outbound'] += 1
                    ip_counts[ip_src]['process_src'].add(process_src)
                    ip_counts[ip_src]['protocols'].add(
                        protocol_map.get(protocol, 'Unknown'))
                    ip_counts[ip_dst]['inbound'] += 1
                    ip_counts[ip_dst]['process_dst'].add(process_dst)
                    ip_counts[ip_dst]['protocols'].add(
                        protocol_map.get(protocol, 'Unknown'))
        analysis_logger.info("Parsed log file.")

        # Step 2: Geolocate IP Addresses with Caching and Retry Mechanism
    def geolocate_ip(ip):
        global current_provider_index
        if ip in ip_cache:
            return ip_cache[ip]
        while current_provider_index < len(providers):
            try:
                provider = providers[current_provider_index]
                response = requests.get(provider["url"].format(ip=ip))
                response.raise_for_status()
                data = response.json()
                if 'loc' in data:
                    coords = tuple(map(float, data['loc'].split(',')))
                elif 'latitude' in data and 'longitude' in data:
                    coords = (data['latitude'], data['longitude'])
                elif 'lat' in data and 'lon' in data:
                    coords = (data['lat'], data['lon'])
                elif 'geoplugin_latitude' in data and 'geoplugin_longitude' in data:
                    coords = (data['geoplugin_latitude'],
                              data['geoplugin_longitude'])
                else:
                    raise ValueError("No location data found")

                if coords == (0, 0):
                    raise ValueError("Invalid location data")

                ip_cache[ip] = coords
                analysis_logger.info(f"Geolocated IP {ip}: {coords}")
                return coords
            except requests.RequestException as e:
                if response.status_code == 429:  # Rate limit error
                    analysis_logger.warning(
                        f"Rate limited by {provider['name']}. Switching to next provider...")
                    current_provider_index += 1
                else:
                    analysis_logger.error(
                        f"Error geolocating IP {ip} with {provider['name']}: {e}")
                    break
            except ValueError as ve:
                analysis_logger.warning(
                    f"Invalid location data for IP {ip}: {ve}")
                break
        return None

    def geolocate_traffic():
        unique_ips = set(ip for ip, _, _, _, _ in traffic_data)
        coordinates = {}
        for ip in unique_ips:
            coords = geolocate_ip(ip)
            if coords:
                coordinates[ip] = coords
        analysis_logger.info("Geolocated traffic.")
        return coordinates

    # Step 3: Visualize on a Map
    def create_map(coordinates):
        map_ = folium.Map(location=[0, 0], zoom_start=2)
        for coord in coordinates.values():
            if coord:
                folium.Marker(location=coord).add_to(map_)
        map_.save(MAP_FILE)
        analysis_logger.info(f"Map created and saved to {MAP_FILE}.")

        # Backup the map file
        backup_map_file = os.path.join(
            BACKUP_LOG_DIR, f"network_traffic_map_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
        shutil.copy(MAP_FILE, backup_map_file)
        analysis_logger.info(f"Map file backed up to {backup_map_file}.")

    # Step 4: Manage Logs
    def backup_log_file():
        if os.path.exists(CURRENT_LOG_FILE):
            backup_file = os.path.join(
                BACKUP_LOG_DIR, f"network_traffic_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
            shutil.copy(CURRENT_LOG_FILE, backup_file)
            analysis_logger.info(f"Log file backed up to {backup_file}.")

    def update_history():
        timestamp = datetime.now().isoformat()
        # Convert sets to lists for JSON serialization
        for ip in ip_counts:
            ip_counts[ip]['process_src'] = list(ip_counts[ip]['process_src'])
            ip_counts[ip]['process_dst'] = list(ip_counts[ip]['process_dst'])
            ip_counts[ip]['protocols'] = list(ip_counts[ip]['protocols'])
            ip_counts[ip]['coordinates'] = ip_cache.get(ip)
        history_data[timestamp] = ip_counts
        with open(HISTORY_LOG_FILE, 'w') as file:
            json.dump(history_data, file, indent=4)
        analysis_logger.info("History updated.")

    def update_trusted_ips():
        for ip in ip_counts:
            # Example threshold for trust
            if ip_counts[ip]['inbound'] + ip_counts[ip]['outbound'] > 10:
                trusted_ips.add(ip)
        with open(TRUSTED_IPS_FILE, 'w') as file:
            json.dump(list(trusted_ips), file, indent=4)
        analysis_logger.info("Trusted IPs updated.")

    def analyze_traffic():
        new_ips = [ip for ip in ip_counts if ip not in trusted_ips]
        if new_ips:
            analysis_logger.warning(f"Anomalous IPs detected: {new_ips}")
            timestamp = datetime.now().isoformat()
            if timestamp not in anomalous_ips:
                anomalous_ips[timestamp] = []
            for ip in new_ips:
                anomalous_ips[timestamp].append(ip)
            with open(ANOMALOUS_IPS_FILE, 'w') as file:
                json.dump(anomalous_ips, file, indent=4)
            analysis_logger.info("Anomalous IPs updated.")

    def save_ip_cache():
        with open(IP_CACHE_FILE, 'w') as file:
            json.dump(ip_cache, file, indent=4)
        analysis_logger.info("IP cache saved.")

    # Main script execution
    parse_log_file()
    coordinates = geolocate_traffic()
    create_map(coordinates)
    update_history()
    update_trusted_ips()
    analyze_traffic()
    save_ip_cache()
    backup_log_file()


# Run the analysis script
run_analysis_script()
analysis_logger.info("Analysis complete. Check the log file for details.")
