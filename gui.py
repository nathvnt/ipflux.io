import sys
import os
import json
import folium
import requests
from datetime import datetime
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from PyQt5.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QWidget, QSpinBox,
                             QLabel, QPushButton, QSizePolicy, QButtonGroup, QRadioButton,
                             QComboBox, QProgressBar, QTableWidget, QTableWidgetItem, QHeaderView,
                             QScrollArea, QCheckBox, QFrame, QHBoxLayout, QTabWidget, QTextEdit,
                             QAction, QMenu)
from PyQt5.QtWebEngineWidgets import QWebEngineView
from PyQt5.QtCore import QUrl, QThread, pyqtSignal, Qt

# Load configuration
with open('config.json', 'r') as f:
    config = json.load(f)

LOG_DIR = config.get("log_dir", "NetworkLogs")
TRUSTED_IPS_PATH = os.path.join(LOG_DIR, config.get(
    "trusted_ips_path", "trusted_ips.json"))
FLAGGED_IPS_PATH = os.path.join(LOG_DIR, config.get(
    "flagged_ips_path", "anomalous_ips.json"))
IP_CACHE_PATH = os.path.join(
    LOG_DIR, config.get("ip_cache_path", "ip_cache.json"))
HISTORY_LOG_FILE = os.path.join(LOG_DIR, config.get(
    "history_log_file", "network_traffic_history.json"))
MAP_FILE = os.path.join(LOG_DIR, config.get(
    "map_file", "network_traffic_map.html"))

VIRUSTOTAL_API_KEY = config.get("virustotal_api_key", "")
ABUSEIPDB_API_KEY = config.get("abuseipdb_api_key", "")


class ScanThread(QThread):
    progress = pyqtSignal(int)
    completed = pyqtSignal()

    def __init__(self, duration):
        super().__init__()
        self.duration = duration

    def run(self):
        for i in range(self.duration):
            self.sleep(1)  # Simulate scan progress
            self.progress.emit(int((i + 1) / self.duration * 100))
        os.system("python packetcapture.py")  # Run the scan script
        self.completed.emit()


class HistogramWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.figure = plt.figure(figsize=(12, 6))
        self.canvas = FigureCanvas(self.figure)

        self.scroll_area = QScrollArea(self)
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setSizePolicy(
            QSizePolicy.Expanding, QSizePolicy.Expanding)

        self.scroll_area_widget = QWidget()
        self.scroll_area.setWidget(self.scroll_area_widget)

        layout = QVBoxLayout(self.scroll_area_widget)
        layout.addWidget(self.canvas)

        main_layout = QVBoxLayout()
        main_layout.addWidget(self.scroll_area)
        self.setLayout(main_layout)

    def plot_histogram(self, data):
        self.figure.clear()
        ax = self.figure.add_subplot(111)
        ip_addresses = list(data.keys())
        inbound = [data[ip]['inbound'] for ip in ip_addresses]
        outbound = [data[ip]['outbound'] for ip in ip_addresses]

        x = range(len(ip_addresses))
        ax.bar(x, inbound, width=0.4, label='Inbound', align='center')
        ax.bar(x, outbound, width=0.4, label='Outbound', align='edge')
        ax.set_xlabel('IP Addresses')
        ax.set_ylabel('Number of Packets')
        ax.set_title('Inbound and Outbound Packets per IP Address')
        ax.set_xticks(x)
        ax.set_xticklabels(ip_addresses, rotation=90)
        ax.legend()
        self.canvas.draw()


class NetworkMonitorGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.selected_scans = []
        self.selected_packet = None
        self.protocols_to_include = set()
        self.hide_private_ips = True
        self.initUI()

    def initUI(self):
        self.setWindowTitle('ipflux.io')
        self.setGeometry(100, 100, 1600, 800)

        # Main layout
        main_layout = QVBoxLayout()
        settings_layout = QHBoxLayout()

        # Settings button
        self.settings_button = QPushButton("Settings", self)
        self.settings_button.setFixedWidth(100)
        self.settings_button.clicked.connect(self.show_settings_menu)
        settings_layout.addWidget(self.settings_button)
        settings_layout.addStretch()  # Add stretch to push the button to the left

        main_layout.addLayout(settings_layout)

        content_layout = QHBoxLayout()

        # Left layout for controls and scan history
        left_layout = QVBoxLayout()

        # Duration input
        self.duration_label = QLabel('Scan Duration (seconds):', self)
        left_layout.addWidget(self.duration_label)

        self.duration_input = QSpinBox(self)
        self.duration_input.setRange(1, 3600)
        self.duration_input.setValue(15)  # Default value
        left_layout.addWidget(self.duration_input)

        # Start button
        self.start_button = QPushButton('Start New Scan', self)
        self.start_button.clicked.connect(self.start_scan)
        left_layout.addWidget(self.start_button)

        # Progress bar
        self.progress_bar = QProgressBar(self)
        self.progress_bar.setValue(0)
        left_layout.addWidget(self.progress_bar)

        # Tabs for Scan History, Trusted, Flagged, and IP Cache
        self.left_tabs = QTabWidget()
        self.left_tabs.addTab(self.create_scan_history_tab(), "Scan History")
        self.left_tabs.addTab(self.create_trusted_tab(), "Trusted")
        self.left_tabs.addTab(self.create_flagged_tab(), "Flagged")
        self.left_tabs.addTab(self.create_ip_cache_tab(), "Geo Cache")

        # Make sure the left_tabs widget expands properly
        self.left_tabs.setSizePolicy(
            QSizePolicy.Expanding, QSizePolicy.Expanding)
        left_layout.addWidget(self.left_tabs, stretch=1)
        left_layout.addStretch()

        # Map view, packet inspector, and histogram view on the right side
        self.tabs = QTabWidget()
        self.map_view = QWebEngineView()
        self.map_view.setWindowTitle("Network Traffic Map")

        self.packet_inspector_layout = QVBoxLayout()
        self.packet_inspector_header = QTextEdit()
        self.packet_inspector_header.setReadOnly(True)
        self.packet_inspector_header.setWordWrapMode(3)
        self.packet_inspector_header.setMaximumHeight(80)
        self.packet_inspector_layout.addWidget(self.packet_inspector_header)
        self.inspect_button = QPushButton('Inspect IP')
        self.inspect_button.clicked.connect(self.inspect_ip)
        self.packet_inspector_layout.addWidget(self.inspect_button)
        self.packet_inspector_result = QTextEdit()
        self.packet_inspector_result.setReadOnly(True)
        self.packet_inspector_layout.addWidget(self.packet_inspector_result)
        packet_inspector_widget = QWidget()
        packet_inspector_widget.setLayout(self.packet_inspector_layout)

        self.histogram_widget = HistogramWidget()

        self.tabs.addTab(self.map_view, "Map View")
        self.tabs.addTab(packet_inspector_widget, "Packet Inspector")
        self.tabs.addTab(self.histogram_widget, "Histograms")

        content_layout.addLayout(left_layout, 1)
        content_layout.addWidget(self.tabs, 1)

        main_layout.addLayout(content_layout)
        container = QWidget()
        container.setLayout(main_layout)
        self.setCentralWidget(container)

        # Initialize protocols to include and hide private IPs
        self.protocols_to_include = {"TCP", "UDP", "ICMP", "HTTP", "HTTPS"}
        self.hide_private_ips = True

        # Create the settings menu
        self.create_settings_menu()

        # Load scan history on startup
        self.load_scan_history()

    def create_settings_menu(self):
        self.settings_menu = QMenu(self)
        self.settings_menu.setTearOffEnabled(
            True)  # Allow the menu to stay open

        self.hide_private_ips_action = QAction(
            "Hide Private IPs", self, checkable=True)
        self.hide_private_ips_action.setChecked(True)
        self.hide_private_ips_action.triggered.connect(
            self.toggle_hide_private_ips)
        self.settings_menu.addAction(self.hide_private_ips_action)

        self.protocol_actions = {}
        protocols = ["TCP", "UDP", "ICMP", "HTTP", "HTTPS"]
        for protocol in protocols:
            action = QAction(protocol, self, checkable=True)
            action.setChecked(True)
            action.triggered.connect(self.update_protocol_selection)
            self.protocol_actions[protocol] = action
            self.settings_menu.addAction(action)

        self.settings_button.setMenu(self.settings_menu)

    def show_settings_menu(self):
        self.settings_menu.exec_(self.settings_button.mapToGlobal(
            self.settings_button.rect().bottomLeft()))

    def toggle_hide_private_ips(self):
        self.hide_private_ips = self.hide_private_ips_action.isChecked()
        self.apply_settings()

    def update_protocol_selection(self):
        self.protocols_to_include = {
            protocol for protocol, action in self.protocol_actions.items() if action.isChecked()}
        self.apply_settings()

    def apply_settings(self, data=None):
        if data is None:
            if os.path.exists(HISTORY_LOG_FILE):
                with open(HISTORY_LOG_FILE, 'r') as file:
                    data = json.load(file)
        filtered_data = self.filter_data(
            data, self.hide_private_ips, self.protocols_to_include)
        self.display_scan_history(filtered_data)
        self.generate_map(filtered_data)
        self.generate_histogram(filtered_data)

    def create_scan_history_tab(self):
        self.scan_history_widget = QWidget()
        self.scan_history_layout = QVBoxLayout(self.scan_history_widget)

        self.scroll_area = QScrollArea(self)
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setSizePolicy(
            QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.scroll_area_widget = QWidget()
        self.scroll_area.setWidget(self.scroll_area_widget)
        self.scroll_area_layout = QVBoxLayout(self.scroll_area_widget)
        self.scan_history_layout.addWidget(self.scroll_area)
        return self.scan_history_widget

    def create_trusted_tab(self):
        self.trusted_widget = QWidget()
        self.trusted_layout = QVBoxLayout(self.trusted_widget)
        self.trusted_table = QTableWidget()
        self.trusted_table.setColumnCount(3)
        self.trusted_table.setHorizontalHeaderLabels(
            ['Timestamp', 'IP', 'Actions'])
        self.trusted_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.load_trusted_ips()
        self.trusted_layout.addWidget(self.trusted_table)
        return self.trusted_widget

    def create_flagged_tab(self):
        self.flagged_widget = QWidget()
        self.flagged_layout = QVBoxLayout(self.flagged_widget)
        self.flagged_table = QTableWidget()
        self.flagged_table.setColumnCount(3)
        self.flagged_table.setHorizontalHeaderLabels(
            ['Timestamp', 'IP', 'Actions'])
        self.flagged_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.load_flagged_ips()
        self.flagged_layout.addWidget(self.flagged_table)
        return self.flagged_widget

    def create_ip_cache_tab(self):
        self.ip_cache_widget = QWidget()
        self.ip_cache_layout = QVBoxLayout(self.ip_cache_widget)
        self.ip_cache_table = QTableWidget()
        self.ip_cache_table.setColumnCount(2)
        self.ip_cache_table.setHorizontalHeaderLabels(
            ['IP Cache', 'Coordinates'])
        self.ip_cache_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.load_ip_cache()
        self.ip_cache_layout.addWidget(self.ip_cache_table)
        return self.ip_cache_widget

    def load_trusted_ips(self):
        if os.path.exists(TRUSTED_IPS_PATH):
            with open(TRUSTED_IPS_PATH, 'r') as file:
                trusted_ips = json.load(file)
                self.trusted_table.setRowCount(0)
                for ip in trusted_ips:
                    row_position = self.trusted_table.rowCount()
                    self.trusted_table.insertRow(row_position)
                    self.trusted_table.setItem(
                        row_position, 1, QTableWidgetItem(ip))
                    timestamp = datetime.now().isoformat()
                    self.trusted_table.setItem(
                        row_position, 0, QTableWidgetItem(timestamp))
                    remove_button = QPushButton('Remove')
                    remove_button.clicked.connect(
                        lambda _, r=row_position, t=self.trusted_table: self.remove_ip_from_table(r, t))
                    self.trusted_table.setCellWidget(
                        row_position, 2, remove_button)

    def load_flagged_ips(self):
        if os.path.exists(FLAGGED_IPS_PATH):
            with open(FLAGGED_IPS_PATH, 'r') as file:
                flagged_data = json.load(file)
                self.flagged_table.setRowCount(0)
                for timestamp, ip_list in flagged_data.items():
                    for ip in ip_list:
                        row_position = self.flagged_table.rowCount()
                        self.flagged_table.insertRow(row_position)
                        self.flagged_table.setItem(
                            row_position, 0, QTableWidgetItem(timestamp))
                        self.flagged_table.setItem(
                            row_position, 1, QTableWidgetItem(ip))
                        remove_button = QPushButton('Remove')
                        remove_button.clicked.connect(
                            lambda _, r=row_position, t=self.flagged_table: self.remove_ip_from_table(r, t))
                        self.flagged_table.setCellWidget(
                            row_position, 2, remove_button)

    def load_ip_cache(self):
        if os.path.exists(IP_CACHE_PATH):
            with open(IP_CACHE_PATH, 'r') as file:
                ip_cache = json.load(file)
                self.update_ip_cache_table(ip_cache)

    def update_ip_cache_table(self, ip_cache):
        self.ip_cache_table.setRowCount(0)
        for ip, data in ip_cache.items():
            row_position = self.ip_cache_table.rowCount()
            self.ip_cache_table.insertRow(row_position)
            self.ip_cache_table.setItem(row_position, 0, QTableWidgetItem(ip))
            self.ip_cache_table.setItem(
                row_position, 1, QTableWidgetItem(json.dumps(data)))

    def remove_ip_from_table(self, row, table):
        ip_address = table.item(row, 1).text()
        if table == self.trusted_table:
            self.modify_ip_list(TRUSTED_IPS_PATH, ip_address, remove=True)
        elif table == self.flagged_table:
            self.modify_ip_list(FLAGGED_IPS_PATH, ip_address, remove=True)
        table.removeRow(row)
        self.load_scan_history()

    def add_ip_to_trusted(self):
        if self.selected_packet:
            ip_address = self.selected_packet['ip']
            self.modify_ip_list(TRUSTED_IPS_PATH, ip_address)

    def add_ip_to_flagged(self):
        if self.selected_packet:
            ip_address = self.selected_packet['ip']
            self.modify_ip_list(FLAGGED_IPS_PATH, ip_address)

    def modify_ip_list(self, file_path, ip_address, remove=False):
        if os.path.exists(file_path):
            with open(file_path, 'r') as file:
                ip_data = json.load(file)
        else:
            ip_data = {} if file_path == FLAGGED_IPS_PATH else []

        if remove:
            if file_path == TRUSTED_IPS_PATH:
                if ip_address in ip_data:
                    ip_data.remove(ip_address)
            elif file_path == FLAGGED_IPS_PATH:
                for timestamp in list(ip_data.keys()):
                    if ip_address in ip_data[timestamp]:
                        ip_data[timestamp].remove(ip_address)
                        # Remove the timestamp if no IPs are left
                        if not ip_data[timestamp]:
                            del ip_data[timestamp]
        else:
            current_timestamp = datetime.now().isoformat()
            if file_path == TRUSTED_IPS_PATH:
                if ip_address not in ip_data:
                    ip_data.append(ip_address)
            elif file_path == FLAGGED_IPS_PATH:
                if current_timestamp not in ip_data:
                    ip_data[current_timestamp] = []
                if ip_address not in ip_data[current_timestamp]:
                    ip_data[current_timestamp].append(ip_address)

        with open(file_path, 'w') as file:
            json.dump(ip_data, file, indent=4)

        if file_path == TRUSTED_IPS_PATH:
            self.load_trusted_ips()
        elif file_path == FLAGGED_IPS_PATH:
            self.load_flagged_ips()

    def start_scan(self):
        duration = self.duration_input.value()
        self.progress_bar.setValue(0)

        self.start_button.setEnabled(False)
        self.start_button.setText('Scan in Progress')

        self.scan_thread = ScanThread(duration)
        self.scan_thread.progress.connect(self.update_progress)
        self.scan_thread.completed.connect(self.scan_completed)
        self.scan_thread.start()

    def update_progress(self, value):
        self.progress_bar.setValue(value)

    def scan_completed(self):
        self.load_scan_history()
        self.apply_settings()  # Apply settings to filter data after scan completion
        self.progress_bar.setValue(0)
        self.start_button.setEnabled(True)
        self.start_button.setText('Start New Scan')

    def load_scan_history(self):
        if os.path.exists(HISTORY_LOG_FILE):
            with open(HISTORY_LOG_FILE, 'r') as file:
                data = json.load(file)
                if data:
                    # Select the most recent scan
                    most_recent_scan = list(data.keys())[-1]
                    self.selected_scans = [most_recent_scan]
                    self.apply_settings(data)  # Apply settings to filter data

    def display_scan_history(self, data):
        for i in reversed(range(self.scroll_area_layout.count())):
            widget = self.scroll_area_layout.itemAt(i).widget()
            if widget is not None:
                widget.deleteLater()

        self.radio_group = QButtonGroup()
        for index, (timestamp, details) in enumerate(reversed(data.items())):
            frame = QFrame()
            frame.setFrameShape(QFrame.StyledPanel)
            frame_layout = QVBoxLayout()

            header_layout = QHBoxLayout()
            checkbox = QCheckBox("Add Table To Map/Histogram")
            checkbox.setChecked(index == 0)
            checkbox.stateChanged.connect(
                lambda state, ts=timestamp: self.update_selected_scans(state, ts))
            header_layout.addWidget(checkbox)

            toggle_button = QPushButton(f'Scan at {timestamp}')
            toggle_button.setCheckable(True)
            toggle_button.setChecked(index == 0)
            toggle_button.clicked.connect(
                lambda checked, frame_layout=frame_layout: self.toggle_table_visibility(checked, frame_layout))
            header_layout.addWidget(toggle_button)

            header_widget = QWidget()
            header_widget.setLayout(header_layout)
            frame_layout.addWidget(header_widget)

            table = QTableWidget()
            table.setColumnCount(9)
            table.setHorizontalHeaderLabels(
                ['', 'Timestamp', 'IP', 'Inbound', 'Outbound', 'Processes', 'Protocols', 'Coordinates', 'Action'])
            table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
            table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
            table.setMinimumHeight(int(self.height() * 0.4))

            for ip, info in details.items():
                row_position = table.rowCount()
                table.insertRow(row_position)
                radio_button = QRadioButton()
                self.radio_group.addButton(radio_button)
                table.setCellWidget(row_position, 0, radio_button)
                table.setItem(row_position, 1, QTableWidgetItem(timestamp))
                table.setItem(row_position, 2, QTableWidgetItem(ip))
                table.setItem(row_position, 3, QTableWidgetItem(
                    str(info['inbound'])))
                table.setItem(row_position, 4, QTableWidgetItem(
                    str(info['outbound'])))
                processes = ', '.join(
                    info['process_src'] + info['process_dst'])
                table.setItem(row_position, 5, QTableWidgetItem(processes))
                protocols = ', '.join(info['protocols'])
                table.setItem(row_position, 6, QTableWidgetItem(protocols))
                coordinates = str(info['coordinates']
                                  ) if info['coordinates'] else 'None'
                table.setItem(row_position, 7, QTableWidgetItem(coordinates))

                # Add dropdown for Flag/Trust action
                action_dropdown = QComboBox()
                action_dropdown.addItems(["Select", "Flag", "Trust"])
                action_dropdown.currentIndexChanged.connect(
                    lambda index, ip=ip: self.handle_action(index, ip))
                table.setCellWidget(row_position, 8, action_dropdown)

                radio_button.clicked.connect(
                    lambda _, r=row_position, t=table: self.show_packet_details(r, t))

            table.setVisible(index == 0)
            frame_layout.addWidget(table)
            frame.setLayout(frame_layout)
            self.scroll_area_layout.addWidget(frame)

    def handle_action(self, index, ip):
        if index == 1:  # Flag
            self.modify_ip_list(FLAGGED_IPS_PATH, ip)
            self.modify_ip_list(TRUSTED_IPS_PATH, ip, remove=True)
        elif index == 2:  # Trust
            self.modify_ip_list(TRUSTED_IPS_PATH, ip)
            self.modify_ip_list(FLAGGED_IPS_PATH, ip, remove=True)
        self.load_scan_history()

    def toggle_table_visibility(self, checked, frame_layout):
        for i in range(1, frame_layout.count()):
            widget = frame_layout.itemAt(i).widget()
            if widget is not None:
                widget.setVisible(checked)

    def update_selected_scans(self, state, timestamp):
        if state == Qt.Checked:
            self.selected_scans.append(timestamp)
        else:
            if timestamp in self.selected_scans:
                self.selected_scans.remove(timestamp)
        self.generate_map()
        self.generate_histogram()

    def generate_map(self, filtered_data=None):
        if filtered_data is None:
            if os.path.exists(HISTORY_LOG_FILE):
                with open(HISTORY_LOG_FILE, 'r') as file:
                    filtered_data = json.load(file)
        map_ = folium.Map(location=[0, 0], zoom_start=2)
        for timestamp in self.selected_scans:
            if timestamp in filtered_data:
                for ip, info in filtered_data[timestamp].items():
                    coordinates = info['coordinates']
                    if coordinates:
                        folium.Marker(location=coordinates,
                                      popup=ip).add_to(map_)
        map_.save(MAP_FILE)
        self.map_view.load(QUrl.fromLocalFile(os.path.abspath(MAP_FILE)))

    def generate_histogram(self, filtered_data=None):
        if filtered_data is None:
            if os.path.exists(HISTORY_LOG_FILE):
                with open(HISTORY_LOG_FILE, 'r') as file:
                    filtered_data = json.load(file)
        selected_data = {timestamp: filtered_data[timestamp]
                         for timestamp in self.selected_scans if timestamp in filtered_data}
        histogram_data = {}
        for timestamp, details in selected_data.items():
            for ip, info in details.items():
                if ip not in histogram_data:
                    histogram_data[ip] = {'inbound': 0, 'outbound': 0}
                histogram_data[ip]['inbound'] += info['inbound']
                histogram_data[ip]['outbound'] += info['outbound']
        self.histogram_widget.plot_histogram(histogram_data)

    def show_packet_details(self, row, table):
        timestamp = table.item(row, 1).text()
        ip_address = table.item(row, 2).text()
        inbound = table.item(row, 3).text()
        outbound = table.item(row, 4).text()
        processes = table.item(row, 5).text()
        protocols = table.item(row, 6).text()
        coordinates = table.item(row, 7).text()

        self.selected_packet = {
            'timestamp': timestamp,
            'ip': ip_address,
            'inbound': inbound,
            'outbound': outbound,
            'processes': processes,
            'protocols': protocols,
            'coordinates': coordinates
        }

        # Ensure the packet details section does not expand beyond half the width of the GUI
        wrapped_details = self.wrap_text(
            f"Selected packet: {self.selected_packet}", 80)
        self.packet_inspector_header.setPlainText(wrapped_details)
        self.packet_inspector_result.clear()

        # Check if the packet has already been inspected
        ip_info_path = os.path.join(LOG_DIR, "ip_info.json")
        ip_info = {}
        if os.path.exists(ip_info_path):
            with open(ip_info_path, 'r') as file:
                ip_info = json.load(file)

        if ip_address in ip_info:
            self.packet_inspector_result.setPlainText(
                self.format_ip_info(ip_info[ip_address]))

    def wrap_text(self, text, max_length):
        return '\n'.join([text[i:i + max_length] for i in range(0, len(text), max_length)])

    def inspect_ip(self):
        if not self.selected_packet:
            self.packet_inspector_result.setPlainText("No packet selected.")
            return

        ip_address = self.selected_packet['ip']
        self.packet_inspector_result.setPlainText(
            f"Inspecting IP: {ip_address}...")

        ip_info_path = os.path.join(LOG_DIR, "ip_info.json")
        ip_info = {}

        if os.path.exists(ip_info_path):
            with open(ip_info_path, 'r') as file:
                ip_info = json.load(file)

        if ip_address in ip_info:
            self.packet_inspector_result.setPlainText(
                self.format_ip_info(ip_info[ip_address]))
            return

        virustotal_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
        abuseipdb_url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip_address}"

        headers_virustotal = {"x-apikey": VIRUSTOTAL_API_KEY}
        headers_abuseipdb = {"Key": ABUSEIPDB_API_KEY,
                             "Accept": "application/json"}

        virustotal_response = requests.get(
            virustotal_url, headers=headers_virustotal).json()
        abuseipdb_response = requests.get(
            abuseipdb_url, headers=headers_abuseipdb).json()

        ip_info[ip_address] = {
            "virustotal": virustotal_response, "abuseipdb": abuseipdb_response}

        with open(ip_info_path, 'w') as file:
            json.dump(ip_info, file, indent=4)

        self.packet_inspector_result.setPlainText(
            self.format_ip_info(ip_info[ip_address]))

    def format_ip_info(self, info):
        formatted_info = ""
        if "virustotal" in info:
            vt_info = info["virustotal"]
            formatted_info += "VirusTotal Information:\n"
            formatted_info += f"IP: {vt_info['data']['id']}\n"
            if 'asn' in vt_info['data']['attributes']:
                formatted_info += f"ASN: {vt_info['data']['attributes']['asn']}\n"
            formatted_info += "Last Analysis Results:\n"
            for engine, result in vt_info['data']['attributes']['last_analysis_results'].items():
                formatted_info += f"  {engine}: {result['result']}\n"
            formatted_info += "\n"

        if "abuseipdb" in info:
            ab_info = info["abuseipdb"]
            formatted_info += "AbuseIPDB Information:\n"
            formatted_info += f"IP: {ab_info['data']['ipAddress']}\n"
            formatted_info += f"ISP: {ab_info['data']['isp']}\n"
            formatted_info += f"Country: {ab_info['data']['countryCode']}\n"
            formatted_info += f"Usage Type: {ab_info['data']['usageType']}\n"
            formatted_info += f"Total Reports: {ab_info['data']['totalReports']}\n"
            formatted_info += f"Last Reported At: {ab_info['data']['lastReportedAt']}\n"
            formatted_info += "\n"

        return formatted_info

    def filter_data(self, data, hide_private_ips, protocols_to_include):
        filtered_data = {}
        for timestamp, details in data.items():
            filtered_details = {}
            for ip, info in details.items():
                if hide_private_ips and self.is_private_ip(ip):
                    continue
                if protocols_to_include and not protocols_to_include.intersection(info['protocols']):
                    continue
                filtered_details[ip] = info
            if filtered_details:
                filtered_data[timestamp] = filtered_details
        return filtered_data

    def is_private_ip(self, ip):
        private_ranges = [
            ("10.0.0.0", "10.255.255.255"),
            ("172.16.0.0", "172.31.255.255"),
            ("192.168.0.0", "192.168.255.255"),
            ("127.0.0.0", "127.255.255.255"),  # Loopback
        ]

        ip_parts = list(map(int, ip.split(".")))
        ip_as_int = (ip_parts[0] << 24) + (ip_parts[1] <<
                                           16) + (ip_parts[2] << 8) + ip_parts[3]

        for start, end in private_ranges:
            start_parts = list(map(int, start.split(".")))
            end_parts = list(map(int, end.split(".")))
            start_as_int = (start_parts[0] << 24) + (start_parts[1]
                                                     << 16) + (start_parts[2] << 8) + start_parts[3]
            end_as_int = (end_parts[0] << 24) + (end_parts[1]
                                                 << 16) + (end_parts[2] << 8) + end_parts[3]

            if start_as_int <= ip_as_int <= end_as_int:
                return True

        return False


if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = NetworkMonitorGUI()
    ex.show()
    sys.exit(app.exec_())
