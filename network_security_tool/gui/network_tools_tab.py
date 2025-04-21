from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                            QLineEdit, QPushButton, QComboBox, QTextEdit,
                            QGroupBox, QFileDialog, QMessageBox, QProgressBar,
                            QTableWidget, QTableWidgetItem, QHeaderView,
                            QSpinBox, QCheckBox, QFrame, QTabWidget, QFormLayout)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from network_security_tool.scanner.network_scanner import NetworkScanner
from network_security_tool.scanner.port_scanner import PortScanner
from network_security_tool.scanner.ssl_analyzer import SSLAnalyzer
from network_security_tool.scanner.dns_tools import DNSTools
import threading
import queue
import time
import socket
import dns.resolver
import dns.reversename
import whois
import nmap
import logging
import re

class NetworkToolsTab(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Create tab widget for different network tools
        self.tab_widget = QTabWidget()
        
        # Add Network Scanner Tab
        self.tab_widget.addTab(self.create_network_scanner_tab(), "Network Scanner")
        
        # Add DNS Tools Tab
        self.tab_widget.addTab(self.create_dns_tools_tab(), "DNS Tools")
        
        layout.addWidget(self.tab_widget)
        self.setLayout(layout)
        
    def create_network_scanner_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        
        # Input section
        input_group = QGroupBox("Scan Settings")
        input_layout = QVBoxLayout()
        
        # Network range input
        range_layout = QHBoxLayout()
        range_label = QLabel("Network Range:")
        self.range_input = QLineEdit()
        self.range_input.setPlaceholderText("e.g., 192.168.1.0/24")
        range_layout.addWidget(range_label)
        range_layout.addWidget(self.range_input)
        input_layout.addLayout(range_layout)
        
        # Timeout setting
        timeout_layout = QHBoxLayout()
        timeout_label = QLabel("Timeout (seconds):")
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(1, 60)
        self.timeout_spin.setValue(5)
        timeout_layout.addWidget(timeout_label)
        timeout_layout.addWidget(self.timeout_spin)
        input_layout.addLayout(timeout_layout)
        
        # Scan options
        options_layout = QHBoxLayout()
        self.quick_scan_check = QCheckBox("Quick Scan (Ping Only)")
        self.quick_scan_check.setChecked(False)
        self.quick_scan_check.setToolTip("Only perform ping scan without port scanning")
        options_layout.addWidget(self.quick_scan_check)
        options_layout.addStretch()
        input_layout.addLayout(options_layout)
        
        input_group.setLayout(input_layout)
        layout.addWidget(input_group)
        
        # Control buttons
        button_layout = QHBoxLayout()
        self.start_scan_btn = QPushButton("Start Scan")
        self.start_scan_btn.clicked.connect(self.start_network_scan)
        self.stop_scan_btn = QPushButton("Stop")
        self.stop_scan_btn.clicked.connect(self.stop_network_scan)
        self.stop_scan_btn.setEnabled(False)
        
        button_layout.addWidget(self.start_scan_btn)
        button_layout.addWidget(self.stop_scan_btn)
        layout.addLayout(button_layout)
        
        # Progress section
        progress_group = QGroupBox("Progress")
        progress_layout = QVBoxLayout()
        
        # Main progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        progress_layout.addWidget(self.progress_bar)
        
        # Status text
        self.status_label = QLabel("Ready")
        progress_layout.addWidget(self.status_label)
        
        # Detailed progress
        self.detailed_progress = QTextEdit()
        self.detailed_progress.setReadOnly(True)
        self.detailed_progress.setMaximumHeight(100)
        self.detailed_progress.setStyleSheet("font-family: monospace;")
        progress_layout.addWidget(self.detailed_progress)
        
        # Stats display
        stats_layout = QHBoxLayout()
        self.hosts_scanned_label = QLabel("Hosts Scanned: 0")
        self.active_hosts_label = QLabel("Active Hosts: 0")
        self.open_ports_label = QLabel("Open Ports: 0")
        stats_layout.addWidget(self.hosts_scanned_label)
        stats_layout.addWidget(self.active_hosts_label)
        stats_layout.addWidget(self.open_ports_label)
        stats_layout.addStretch()
        progress_layout.addLayout(stats_layout)
        
        progress_group.setLayout(progress_layout)
        layout.addWidget(progress_group)
        
        # Results section
        results_group = QGroupBox("Results")
        results_layout = QVBoxLayout()
        
        # Add filter controls
        filter_layout = QHBoxLayout()
        self.show_active_check = QCheckBox("Show Active Hosts")
        self.show_active_check.setChecked(True)
        self.show_active_check.stateChanged.connect(self.filter_results)
        
        self.show_inactive_check = QCheckBox("Show Inactive Hosts")
        self.show_inactive_check.setChecked(True)
        self.show_inactive_check.stateChanged.connect(self.filter_results)
        
        filter_layout.addWidget(self.show_active_check)
        filter_layout.addWidget(self.show_inactive_check)
        filter_layout.addStretch()
        results_layout.addLayout(filter_layout)
        
        # Results table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(4)
        self.results_table.setHorizontalHeaderLabels(["IP Address", "Hostname", "Status", "Open Ports"])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        results_layout.addWidget(self.results_table)
        
        results_group.setLayout(results_layout)
        layout.addWidget(results_group)
        
        # Store original results and stats
        self.original_results = []
        self.scan_stats = {
            'hosts_scanned': 0,
            'active_hosts': 0,
            'open_ports': 0
        }
        
        tab.setLayout(layout)
        return tab
        
    def create_dns_tools_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        
        # Query input
        query_group = QGroupBox("DNS Query")
        query_layout = QVBoxLayout()
        
        # Domain input
        domain_layout = QHBoxLayout()
        domain_label = QLabel("Domain:")
        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText("e.g., example.com")
        domain_layout.addWidget(domain_label)
        domain_layout.addWidget(self.domain_input)
        query_layout.addLayout(domain_layout)
        
        # Record type selection
        record_type_layout = QHBoxLayout()
        record_type_label = QLabel("Record Type:")
        self.record_type_combo = QComboBox()
        self.record_type_combo.addItems(["A", "AAAA", "CNAME", "MX", "NS", "TXT"])
        record_type_layout.addWidget(record_type_label)
        record_type_layout.addWidget(self.record_type_combo)
        query_layout.addLayout(record_type_layout)
        
        query_group.setLayout(query_layout)
        layout.addWidget(query_group)
        
        # Query button
        query_btn = QPushButton("Query DNS")
        query_btn.clicked.connect(self.query_dns)
        layout.addWidget(query_btn)
        
        # Results section
        results_group = QGroupBox("Query Results")
        results_layout = QVBoxLayout()
        
        self.dns_results = QTextEdit()
        self.dns_results.setReadOnly(True)
        results_layout.addWidget(self.dns_results)
        
        results_group.setLayout(results_layout)
        layout.addWidget(results_group)
        
        tab.setLayout(layout)
        return tab
        
    def start_network_scan(self):
        network_range = self.range_input.text()
        if not network_range:
            QMessageBox.warning(self, "Warning", "Please enter a network range")
            return
            
        # Reset stats and display
        self.scan_stats = {'hosts_scanned': 0, 'active_hosts': 0, 'open_ports': 0}
        self.detailed_progress.clear()
        self.results_table.setRowCount(0)
        self.original_results = []
        
        timeout = self.timeout_spin.value()
        quick_scan = self.quick_scan_check.isChecked()
        
        self.start_scan_btn.setEnabled(False)
        self.stop_scan_btn.setEnabled(True)
        self.progress_bar.setValue(0)
        self.status_label.setText("Starting scan...")
        
        # Start scan in a separate thread
        self.scan_thread = NetworkScanThread(network_range, timeout, quick_scan)
        self.scan_thread.progress_updated.connect(self.update_network_scan_progress)
        self.scan_thread.result_received.connect(self.handle_scan_result)
        self.scan_thread.scan_complete.connect(self.handle_network_scan_complete)
        self.scan_thread.start()
        
    def stop_network_scan(self):
        if hasattr(self, 'scan_thread'):
            self.scan_thread.stop()
            self.start_scan_btn.setEnabled(True)
            self.stop_scan_btn.setEnabled(False)
            self.status_label.setText("Scan stopped")
            
    def update_network_scan_progress(self, value, message):
        """Update the progress display with detailed information"""
        self.progress_bar.setValue(value)
        self.status_label.setText(message)
        
        # Add timestamp to detailed progress
        timestamp = time.strftime("%H:%M:%S")
        self.detailed_progress.append(f"[{timestamp}] {message}")
        
        # Auto-scroll to bottom
        self.detailed_progress.verticalScrollBar().setValue(
            self.detailed_progress.verticalScrollBar().maximum()
        )
        
    def update_scan_stats(self, result):
        """Update the scan statistics display"""
        if 'error' not in result:
            self.scan_stats['hosts_scanned'] += 1
            if result.get('status') == 'up':
                self.scan_stats['active_hosts'] += 1
                self.scan_stats['open_ports'] += len(result.get('open_ports', []))
                
        self.hosts_scanned_label.setText(f"Hosts Scanned: {self.scan_stats['hosts_scanned']}")
        self.active_hosts_label.setText(f"Active Hosts: {self.scan_stats['active_hosts']}")
        self.open_ports_label.setText(f"Open Ports: {self.scan_stats['open_ports']}")
        
    def handle_scan_result(self, result):
        """Handle individual scan results as they come in"""
        self.original_results.append(result)
        self.update_scan_stats(result)
        self.filter_results()  # Update the filtered view
        
    def filter_results(self):
        """Filter the results table based on the checkbox states"""
        if not self.original_results:
            return
            
        # Clear the table
        self.results_table.setRowCount(0)
        
        # Filter results based on checkbox states
        filtered_results = []
        for result in self.original_results:
            if 'error' in result:
                continue
                
            status = result.get('status', '')
            if status == 'up' and self.show_active_check.isChecked():
                filtered_results.append(result)
            elif status == 'down' and self.show_inactive_check.isChecked():
                filtered_results.append(result)
                
        # Update the table with filtered results
        self.results_table.setRowCount(len(filtered_results))
        for i, result in enumerate(filtered_results):
            self.results_table.setItem(i, 0, QTableWidgetItem(result['ip']))
            self.results_table.setItem(i, 1, QTableWidgetItem(result.get('hostname', '')))
            self.results_table.setItem(i, 2, QTableWidgetItem(result['status']))
            
            # Format open ports
            ports = result.get('open_ports', [])
            if ports:
                port_text = ', '.join(str(p['port']) for p in ports)
            else:
                port_text = ''
            self.results_table.setItem(i, 3, QTableWidgetItem(port_text))
            
    def handle_network_scan_complete(self, results):
        self.start_scan_btn.setEnabled(True)
        self.stop_scan_btn.setEnabled(False)
        self.progress_bar.setValue(100)
        self.status_label.setText("Scan complete")
        self.detailed_progress.append("\nScan completed successfully")
        
    def query_dns(self):
        domain = self.domain_input.text()
        if not domain:
            QMessageBox.warning(self, "Warning", "Please enter a domain")
            return
            
        record_type = self.record_type_combo.currentText()
        
        self.dns_results.clear()
        self.dns_results.append(f"Querying {record_type} records for {domain}...")
        
        # Start query in a separate thread
        self.dns_query_thread = DNSQueryThread(domain, record_type)
        self.dns_query_thread.result_received.connect(self.handle_dns_result)
        self.dns_query_thread.query_complete.connect(self.handle_dns_query_complete)
        self.dns_query_thread.start()
        
    def handle_dns_result(self, result):
        """Handle DNS query results."""
        if "error" in result:
            self.dns_results.append(f"Error: {result['error']}")
            return
            
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)
        
        # Add record type
        self.results_table.setItem(row, 0, QTableWidgetItem(result.get('type', '')))
        
        # Format the result value
        value = result.get('value', '')
        if isinstance(value, list):
            value = '\n'.join(str(v) for v in value)
        self.results_table.setItem(row, 1, QTableWidgetItem(str(value)))
        
        # Add any additional information
        if 'ttl' in result:
            self.results_table.setItem(row, 2, QTableWidgetItem(str(result['ttl'])))
            
        self.dns_results.append(f"Found {result.get('type', '')} record: {value}")

    def handle_dns_query_complete(self):
        self.dns_results.append("\nQuery complete")

class NetworkScanThread(QThread):
    progress_updated = pyqtSignal(int, str)
    scan_complete = pyqtSignal(list)
    result_received = pyqtSignal(dict)
    
    def __init__(self, network_range, timeout, quick_scan):
        super().__init__()
        self.network_range = network_range
        self.timeout = timeout
        self.quick_scan = quick_scan
        self._is_running = True
        
    def run(self):
        try:
            scanner = NetworkScanner()
            results = scanner.scan_network(
                self.network_range,
                self.timeout,
                self.progress_callback,
                self.quick_scan,
                self.result_callback
            )
            self.scan_complete.emit(results)
        except Exception as e:
            self.progress_updated.emit(0, f"Error: {str(e)}")
            
    def stop(self):
        self._is_running = False
        
    def progress_callback(self, progress, message):
        if self._is_running:
            self.progress_updated.emit(progress, message)
            
    def result_callback(self, result):
        """Callback for individual scan results"""
        if self._is_running:
            self.result_received.emit(result)
            
    def handle_scan_result(self, result):
        """Handle individual scan results as they come in"""
        self.original_results.append(result)
        self.update_scan_stats(result)
        self.filter_results()  # Update the filtered view

class DNSQueryThread(QThread):
    result_received = pyqtSignal(dict)
    query_complete = pyqtSignal()
    
    def __init__(self, domain, record_type):
        super().__init__()
        self.domain = domain
        self.record_type = record_type
        
    def run(self):
        try:
            dns_tools = DNSTools()
            results = dns_tools.query_dns(self.domain, self.record_type)
            for result in results:
                self.result_received.emit(result)
            self.query_complete.emit()
        except Exception as e:
            self.result_received.emit({"error": str(e)}) 