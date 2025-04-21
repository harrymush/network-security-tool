from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                            QLineEdit, QPushButton, QComboBox, QTextEdit,
                            QGroupBox, QFileDialog, QMessageBox, QProgressBar,
                            QTableWidget, QTableWidgetItem, QHeaderView,
                            QSpinBox, QCheckBox, QFrame, QFormLayout)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
import socket
import threading
import queue
import time
import re
from typing import List, Dict, Optional
import nmap
import logging

class PortScannerThread(QThread):
    """Thread for running port scans in the background."""
    progress = pyqtSignal(dict)
    finished = pyqtSignal(list)
    error = pyqtSignal(str)

    def __init__(self, targets: List[str], port_ranges: List[str], scan_type: str,
                 timeout: int, delay: float, max_threads: int):
        super().__init__()
        self.targets = targets
        self.port_ranges = port_ranges
        self.scan_type = scan_type
        self.timeout = timeout
        self.delay = delay
        self.max_threads = max_threads
        self._is_running = True
        self._queue = queue.Queue()
        self._threads = []

    def run(self):
        try:
            # Initialize scan
            self._queue.put(("Initializing scan...", "info"))
            
            # Create scanner
            scanner = nmap.PortScanner()
            
            # Process each target
            for target in self.targets:
                if not self._is_running:
                    break
                    
                # Process each port range
                for port_range in self.port_ranges:
                    if not self._is_running:
                        break
                        
                    # Format scan type argument correctly
                    scan_arg = {
                        "TCP Connect": "-sT",
                        "SYN": "-sS",
                        "Stealth": "-sS -f"
                    }.get(self.scan_type, "-sT")
                    
                    # Perform scan
                    scanner.scan(
                        target,
                        port_range,
                        arguments=f'{scan_arg} -T4 --max-rtt-timeout {self.timeout}ms'
                    )
                    
                    # Process results
                    for host in scanner.all_hosts():
                        for proto in scanner[host].all_protocols():
                            ports = scanner[host][proto].keys()
                            for port in ports:
                                state = scanner[host][proto][port]['state']
                                if state == 'open':
                                    self.progress.emit({
                                        'target': host,
                                        'port': port,
                                        'state': state,
                                        'service': scanner[host][proto][port].get('name', 'unknown'),
                                        'version': scanner[host][proto][port].get('version', ''),
                                        'protocol': proto.upper()
                                    })
                                    
                                if self.delay > 0:
                                    time.sleep(self.delay)
            
            self.finished.emit([])
            
        except Exception as e:
            self.error.emit(str(e))

    def stop(self):
        self._is_running = False

class PortScannerTab(QWidget):
    """Port Scanner tab for scanning open ports on targets."""
    def __init__(self):
        super().__init__()
        self.scanner_thread = None
        self.init_ui()

    def init_ui(self):
        """Initialize the user interface."""
        layout = QVBoxLayout()
        self.setLayout(layout)

        # Target input
        target_group = QGroupBox("Target")
        target_layout = QFormLayout()
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("IP address, hostname, or subnet (e.g., 192.168.1.1, scanme.nmap.org, 192.168.1.0/24)")
        self.target_input.setMinimumWidth(400)  # Make the input box longer
        target_layout.addRow("Target:", self.target_input)
        target_group.setLayout(target_layout)
        layout.addWidget(target_group)

        # Scan options
        options_group = QGroupBox("Scan Options")
        options_layout = QFormLayout()
        
        # Port range selection
        self.port_range = QComboBox()
        self.port_range.addItems([
            "Well-known (0-1023)",
            "Registered (1024-49151)",
            "All ports (0-65535)",
            "Common Services",
            "Custom Range"
        ])
        options_layout.addRow("Port Range:", self.port_range)
        
        # Custom range input
        self.custom_range = QLineEdit()
        self.custom_range.setPlaceholderText("e.g., 20-25, 80, 443, 8080")
        self.custom_range.setEnabled(False)
        options_layout.addRow("Custom Range:", self.custom_range)
        
        # Scan type selection
        self.scan_type = QComboBox()
        self.scan_type.addItems(["TCP Connect", "SYN", "Stealth"])
        options_layout.addRow("Scan Type:", self.scan_type)
        
        # Timeout setting
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(100, 5000)
        self.timeout_spin.setValue(1000)
        self.timeout_spin.setSuffix(" ms")
        options_layout.addRow("Timeout:", self.timeout_spin)
        
        # Delay setting
        self.delay_spin = QSpinBox()
        self.delay_spin.setRange(0, 1000)
        self.delay_spin.setValue(0)
        self.delay_spin.setSuffix(" ms")
        options_layout.addRow("Delay:", self.delay_spin)
        
        # Max threads
        self.max_threads_input = QSpinBox()
        self.max_threads_input.setRange(1, 50)
        self.max_threads_input.setValue(10)
        options_layout.addRow("Max Threads:", self.max_threads_input)
        
        # Service detection
        self.service_detection = QCheckBox("Enable Service Detection")
        self.service_detection.setChecked(True)
        options_layout.addRow("", self.service_detection)
        
        # Banner grabbing
        self.banner_grabbing = QCheckBox("Enable Banner Grabbing")
        self.banner_grabbing.setChecked(True)
        options_layout.addRow("", self.banner_grabbing)
        
        options_group.setLayout(options_layout)
        layout.addWidget(options_group)

        # Control buttons
        button_layout = QHBoxLayout()
        self.start_button = QPushButton("Start Scan")
        self.start_button.clicked.connect(self.start_scan)
        self.stop_button = QPushButton("Stop Scan")
        self.stop_button.clicked.connect(self.stop_scan)
        self.stop_button.setEnabled(False)
        self.clear_button = QPushButton("Clear Results")
        self.clear_button.clicked.connect(self.clear_results)
        self.save_button = QPushButton("Save Results")
        self.save_button.clicked.connect(self.save_results)
        
        button_layout.addWidget(self.start_button)
        button_layout.addWidget(self.stop_button)
        button_layout.addWidget(self.clear_button)
        button_layout.addWidget(self.save_button)
        layout.addLayout(button_layout)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        layout.addWidget(self.progress_bar)

        # Results table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(6)
        self.results_table.setHorizontalHeaderLabels(["Target", "Port", "State", "Service", "Version", "Banner"])
        self.results_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.results_table)

        # Status messages
        self.status_text = QTextEdit()
        self.status_text.setReadOnly(True)
        self.status_text.setMaximumHeight(100)
        layout.addWidget(self.status_text)

        # Connect signals
        self.port_range.currentTextChanged.connect(self.handle_port_range_change)

    def handle_port_range_change(self, text: str):
        """Handle port range selection change."""
        self.custom_range.setEnabled(text == "Custom Range")

    def validate_target(self, target: str) -> bool:
        """Validate the target format."""
        try:
            # Check for subnet notation
            if '/' in target:
                parts = target.split('/')
                if len(parts) != 2:
                    return False
                ip, mask = parts
                if not (0 <= int(mask) <= 32):
                    return False
                socket.inet_aton(ip)
                return True
                
            # Check for comma-separated list
            if ',' in target:
                for t in target.split(','):
                    socket.gethostbyname(t.strip())
                return True
                
            # Single target
            socket.gethostbyname(target)
            return True
        except (socket.gaierror, socket.error):
            return False

    def validate_port_range(self, range_str: str) -> bool:
        """Validate the port range format."""
        if not range_str:
            return False
        try:
            # Split by commas and process each part
            for part in range_str.split(','):
                part = part.strip()
                if '-' in part:
                    start, end = map(int, part.split('-'))
                    if not (0 <= start <= end <= 65535):
                        return False
                else:
                    port = int(part)
                    if not (0 <= port <= 65535):
                        return False
            return True
        except ValueError:
            return False

    def start_scan(self):
        """Start the port scan."""
        target = self.target_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Error", "Please enter a target")
            return

        if not self.validate_target(target):
            QMessageBox.warning(self, "Error", "Invalid target format")
            return

        # Parse targets
        targets = [t.strip() for t in target.split(',')]

        # Get port range
        port_range = self.port_range.currentText()
        if port_range == "Well-known (0-1023)":
            port_ranges = ["0-1023"]
        elif port_range == "Registered (1024-49151)":
            port_ranges = ["1024-49151"]
        elif port_range == "All ports (0-65535)":
            port_ranges = ["0-65535"]
        elif port_range == "Common Services":
            port_ranges = ["21,22,23,25,53,80,110,143,443,445,3306,3389,5432,8080"]
        else:
            custom_range = self.custom_range.text().strip()
            if not self.validate_port_range(custom_range):
                QMessageBox.warning(self, "Error", "Invalid port range format")
                return
            port_ranges = [custom_range]

        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.clear_button.setEnabled(False)
        self.progress_bar.setValue(0)
        self.status_text.clear()
        self.results_table.setRowCount(0)

        self.scanner_thread = PortScannerThread(
            targets,
            port_ranges,
            self.scan_type.currentText(),
            self.timeout_spin.value(),
            self.delay_spin.value() / 1000.0,  # Convert to seconds
            self.max_threads_input.value()
        )
        self.scanner_thread.progress.connect(self.update_progress)
        self.scanner_thread.finished.connect(self.scan_finished)
        self.scanner_thread.error.connect(self.scan_error)
        self.scanner_thread.start()

    def stop_scan(self):
        """Stop the current scan."""
        if self.scanner_thread:
            self.scanner_thread.stop()
            self.scanner_thread.wait()
            self.status_text.append("Scan stopped by user")
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            self.clear_button.setEnabled(True)

    def clear_results(self):
        """Clear the scan results."""
        self.results_table.setRowCount(0)
        self.status_text.clear()
        self.progress_bar.setValue(0)

    def save_results(self):
        """Save scan results to a file."""
        if self.results_table.rowCount() == 0:
            QMessageBox.warning(self, "Error", "No results to save")
            return

        file_name, _ = QFileDialog.getSaveFileName(
            self,
            "Save Scan Results",
            "",
            "Text Files (*.txt);;All Files (*)"
        )

        if file_name:
            try:
                with open(file_name, 'w') as f:
                    f.write("Port Scan Results\n")
                    f.write("=" * 50 + "\n\n")
                    
                    for row in range(self.results_table.rowCount()):
                        target = self.results_table.item(row, 0).text()
                        port = self.results_table.item(row, 1).text()
                        state = self.results_table.item(row, 2).text()
                        service = self.results_table.item(row, 3).text()
                        version = self.results_table.item(row, 4).text()
                        banner = self.results_table.item(row, 5).text()
                        
                        f.write(f"Target: {target}\n")
                        f.write(f"Port: {port}\n")
                        f.write(f"State: {state}\n")
                        f.write(f"Service: {service}\n")
                        f.write(f"Version: {version}\n")
                        f.write(f"Banner: {banner}\n")
                        f.write("-" * 50 + "\n")
                        
                QMessageBox.information(self, "Success", "Results saved successfully")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save results: {str(e)}")

    def update_progress(self, result: dict):
        """Update the progress with new scan results."""
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)
        
        # Add items to the table
        self.results_table.setItem(row, 0, QTableWidgetItem(result.get('target', '')))
        self.results_table.setItem(row, 1, QTableWidgetItem(str(result.get('port', ''))))
        self.results_table.setItem(row, 2, QTableWidgetItem(result.get('state', '')))
        self.results_table.setItem(row, 3, QTableWidgetItem(result.get('service', '')))
        self.results_table.setItem(row, 4, QTableWidgetItem(result.get('version', '')))
        self.results_table.setItem(row, 5, QTableWidgetItem(result.get('banner', '')))

        # Update status
        self.status_text.append(
            f"Found open port on {result.get('target')}: {result.get('port')} "
            f"({result.get('service')})"
        )

    def scan_finished(self, results: list):
        """Handle scan completion."""
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.clear_button.setEnabled(True)
        self.progress_bar.setValue(100)
        self.status_text.append("\nScan completed successfully")

    def scan_error(self, error_message: str):
        """Handle scan errors."""
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.clear_button.setEnabled(True)
        self.status_text.append(f"Error: {error_message}")
        QMessageBox.critical(self, "Error", f"Scan failed: {error_message}") 