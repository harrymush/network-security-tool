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
        
        # Add SSL/TLS Analyzer Tab
        self.tab_widget.addTab(self.create_ssl_analyzer_tab(), "SSL/TLS Analyzer")
        
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
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        progress_layout.addWidget(self.progress_bar)
        
        self.status_label = QLabel("Ready")
        progress_layout.addWidget(self.status_label)
        
        progress_group.setLayout(progress_layout)
        layout.addWidget(progress_group)
        
        # Results section
        results_group = QGroupBox("Results")
        results_layout = QVBoxLayout()
        
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(3)
        self.results_table.setHorizontalHeaderLabels(["IP Address", "Hostname", "Status"])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        results_layout.addWidget(self.results_table)
        
        results_group.setLayout(results_layout)
        layout.addWidget(results_group)
        
        tab.setLayout(layout)
        return tab
        
    def create_ssl_analyzer_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        
        # Target input
        target_group = QGroupBox("Target Settings")
        target_layout = QVBoxLayout()
        
        target_input_layout = QHBoxLayout()
        target_label = QLabel("Host:")
        self.ssl_host_input = QLineEdit()
        self.ssl_host_input.setPlaceholderText("e.g., example.com")
        target_input_layout.addWidget(target_label)
        target_input_layout.addWidget(self.ssl_host_input)
        target_layout.addLayout(target_input_layout)
        
        port_layout = QHBoxLayout()
        port_label = QLabel("Port:")
        self.ssl_port_spin = QSpinBox()
        self.ssl_port_spin.setRange(1, 65535)
        self.ssl_port_spin.setValue(443)
        port_layout.addWidget(port_label)
        port_layout.addWidget(self.ssl_port_spin)
        target_layout.addLayout(port_layout)
        
        target_group.setLayout(target_layout)
        layout.addWidget(target_group)
        
        # Analyze button
        analyze_btn = QPushButton("Analyze SSL/TLS")
        analyze_btn.clicked.connect(self.analyze_ssl)
        layout.addWidget(analyze_btn)
        
        # Results section
        results_group = QGroupBox("Analysis Results")
        results_layout = QVBoxLayout()
        
        self.ssl_results = QTextEdit()
        self.ssl_results.setReadOnly(True)
        results_layout.addWidget(self.ssl_results)
        
        results_group.setLayout(results_layout)
        layout.addWidget(results_group)
        
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
            
        timeout = self.timeout_spin.value()
        
        self.start_scan_btn.setEnabled(False)
        self.stop_scan_btn.setEnabled(True)
        self.progress_bar.setValue(0)
        self.status_label.setText("Starting scan...")
        
        # Start scan in a separate thread
        self.scan_thread = NetworkScanThread(network_range, timeout)
        self.scan_thread.progress_updated.connect(self.update_network_scan_progress)
        self.scan_thread.scan_complete.connect(self.handle_network_scan_complete)
        self.scan_thread.start()
        
    def stop_network_scan(self):
        if hasattr(self, 'scan_thread'):
            self.scan_thread.stop()
            self.start_scan_btn.setEnabled(True)
            self.stop_scan_btn.setEnabled(False)
            self.status_label.setText("Scan stopped")
            
    def update_network_scan_progress(self, value, message):
        self.progress_bar.setValue(value)
        self.status_label.setText(message)
        
    def handle_network_scan_complete(self, results):
        self.start_scan_btn.setEnabled(True)
        self.stop_scan_btn.setEnabled(False)
        self.progress_bar.setValue(100)
        
        self.results_table.setRowCount(len(results))
        for i, result in enumerate(results):
            self.results_table.setItem(i, 0, QTableWidgetItem(result['ip']))
            self.results_table.setItem(i, 1, QTableWidgetItem(result.get('hostname', '')))
            self.results_table.setItem(i, 2, QTableWidgetItem(result['status']))
            
    def analyze_ssl(self):
        host = self.ssl_host_input.text()
        if not host:
            QMessageBox.warning(self, "Warning", "Please enter a host")
            return
            
        port = self.ssl_port_spin.value()
        
        self.ssl_results.clear()
        self.ssl_results.append("Analyzing SSL/TLS configuration...")
        
        # Start analysis in a separate thread
        self.ssl_analyzer_thread = SSLAnalyzerThread(host, port)
        self.ssl_analyzer_thread.result_received.connect(self.handle_ssl_result)
        self.ssl_analyzer_thread.analysis_complete.connect(self.handle_ssl_analysis_complete)
        self.ssl_analyzer_thread.start()
        
    def handle_ssl_result(self, result):
        """Handle SSL/TLS analysis results."""
        if "error" in result:
            self.ssl_results.append(f"Error: {result['error']}")
            return
            
        # Format the result based on its type
        if result.get('type') == 'certificate':
            self.ssl_results.append("\nCertificate Information:")
            self.ssl_results.append(f"Subject: {result.get('subject', '')}")
            self.ssl_results.append(f"Issuer: {result.get('issuer', '')}")
            self.ssl_results.append(f"Valid From: {result.get('valid_from', '')}")
            self.ssl_results.append(f"Valid Until: {result.get('valid_until', '')}")
            self.ssl_results.append(f"Serial Number: {result.get('serial_number', '')}")
        elif result.get('type') == 'protocol':
            self.ssl_results.append("\nSupported Protocols:")
            for proto in result.get('protocols', []):
                self.ssl_results.append(f"- {proto}")
        elif result.get('type') == 'cipher':
            self.ssl_results.append("\nSupported Cipher Suites:")
            for cipher in result.get('ciphers', []):
                self.ssl_results.append(f"- {cipher}")
        elif result.get('type') == 'security':
            self.ssl_results.append("\nSecurity Analysis:")
            for issue in result.get('issues', []):
                self.ssl_results.append(f"- {issue}")
            for strength in result.get('strengths', []):
                self.ssl_results.append(f"+ {strength}")

    def handle_ssl_analysis_complete(self):
        """Handle completion of SSL/TLS analysis."""
        self.ssl_results.append("\nAnalysis complete")
        
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
    
    def __init__(self, network_range, timeout):
        super().__init__()
        self.network_range = network_range
        self.timeout = timeout
        self._is_running = True
        
    def run(self):
        try:
            scanner = NetworkScanner()
            results = scanner.scan_network(
                self.network_range,
                self.timeout,
                self.progress_callback
            )
            self.scan_complete.emit(results)
        except Exception as e:
            self.progress_updated.emit(0, f"Error: {str(e)}")
            
    def stop(self):
        self._is_running = False
        
    def progress_callback(self, progress, message):
        if self._is_running:
            self.progress_updated.emit(progress, message)

class SSLAnalyzerThread(QThread):
    result_received = pyqtSignal(dict)
    analysis_complete = pyqtSignal()
    
    def __init__(self, host, port):
        super().__init__()
        self.host = host
        self.port = port
        
    def run(self):
        try:
            analyzer = SSLAnalyzer()
            results = analyzer.analyze_ssl(self.host, self.port)
            for result in results:
                self.result_received.emit(result)
            self.analysis_complete.emit()
        except Exception as e:
            self.result_received.emit({"error": str(e)})

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