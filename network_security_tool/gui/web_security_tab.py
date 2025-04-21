from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                            QLineEdit, QPushButton, QTableWidget,
                            QTableWidgetItem, QHeaderView, QFrame, QTextEdit,
                            QMessageBox, QComboBox, QGroupBox, QSplitter,
                            QCheckBox, QSpinBox)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
import requests
import threading
import socket
import re
from typing import Dict, List
from urllib.parse import urlparse
import json
import time

class WebSecurityThread(QThread):
    scan_complete = pyqtSignal(dict)
    progress_updated = pyqtSignal(int, str)
    error_occurred = pyqtSignal(str)
    request_captured = pyqtSignal(dict)
    
    def __init__(self, url: str, scan_type: str, proxy_port: int = None):
        super().__init__()
        self.url = url
        self.scan_type = scan_type
        self.proxy_port = proxy_port
        self._is_running = True
        
    def run(self):
        try:
            if self.scan_type == "vulnerability_scan":
                self._run_vulnerability_scan()
            elif self.scan_type == "proxy":
                self._run_proxy()
                
        except Exception as e:
            self.error_occurred.emit(str(e))
            
    def _run_vulnerability_scan(self):
        results = {
            "vulnerabilities": [],
            "headers": {},
            "error": None
        }
        
        try:
            # Parse URL
            parsed_url = urlparse(self.url)
            if not parsed_url.scheme:
                self.url = "http://" + self.url
                parsed_url = urlparse(self.url)
                
            # Check for common vulnerabilities
            self.progress_updated.emit(10, "Checking for SQL injection vulnerabilities...")
            if self._check_sql_injection():
                results["vulnerabilities"].append({
                    "type": "SQL Injection",
                    "severity": "High",
                    "description": "Potential SQL injection vulnerability detected",
                    "details": "The application may be vulnerable to SQL injection attacks"
                })
                
            self.progress_updated.emit(30, "Checking for XSS vulnerabilities...")
            if self._check_xss():
                results["vulnerabilities"].append({
                    "type": "Cross-Site Scripting (XSS)",
                    "severity": "High",
                    "description": "Potential XSS vulnerability detected",
                    "details": "The application may be vulnerable to cross-site scripting attacks"
                })
                
            self.progress_updated.emit(50, "Analyzing HTTP headers...")
            headers = self._analyze_headers()
            results["headers"] = headers
            
            self.progress_updated.emit(70, "Checking for directory traversal...")
            if self._check_directory_traversal():
                results["vulnerabilities"].append({
                    "type": "Directory Traversal",
                    "severity": "Medium",
                    "description": "Potential directory traversal vulnerability detected",
                    "details": "The application may be vulnerable to directory traversal attacks"
                })
                
            self.progress_updated.emit(90, "Checking for sensitive information exposure...")
            if self._check_sensitive_info():
                results["vulnerabilities"].append({
                    "type": "Sensitive Information Exposure",
                    "severity": "Medium",
                    "description": "Potential sensitive information exposure detected",
                    "details": "The application may be exposing sensitive information"
                })
                
            self.progress_updated.emit(100, "Scan complete")
            self.scan_complete.emit(results)
            
        except Exception as e:
            results["error"] = str(e)
            self.scan_complete.emit(results)
            
    def _run_proxy(self):
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind(('127.0.0.1', self.proxy_port))
            server_socket.listen(5)
            
            while self._is_running:
                client_socket, addr = server_socket.accept()
                request = client_socket.recv(4096).decode()
                
                if request:
                    # Parse request
                    request_lines = request.split('\r\n')
                    method, path, version = request_lines[0].split()
                    
                    # Extract headers
                    headers = {}
                    for line in request_lines[1:]:
                        if ': ' in line:
                            key, value = line.split(': ', 1)
                            headers[key] = value
                            
                    # Capture request
                    self.request_captured.emit({
                        "method": method,
                        "path": path,
                        "version": version,
                        "headers": headers,
                        "raw": request
                    })
                    
                    # Forward request
                    try:
                        response = requests.request(
                            method,
                            path,
                            headers=headers,
                            verify=False
                        )
                        
                        # Send response back to client
                        client_socket.sendall(response.content)
                        
                    except Exception as e:
                        self.error_occurred.emit(str(e))
                        
                client_socket.close()
                
        except Exception as e:
            self.error_occurred.emit(str(e))
            
    def _check_sql_injection(self) -> bool:
        test_payloads = [
            "' OR '1'='1",
            "1' OR '1'='1",
            "admin'--",
            "1; DROP TABLE users--"
        ]
        
        for payload in test_payloads:
            try:
                response = requests.get(
                    self.url + "?id=" + payload,
                    verify=False,
                    timeout=5
                )
                if "error" in response.text.lower() or "sql" in response.text.lower():
                    return True
            except:
                continue
        return False
        
    def _check_xss(self) -> bool:
        test_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>"
        ]
        
        for payload in test_payloads:
            try:
                response = requests.get(
                    self.url + "?q=" + payload,
                    verify=False,
                    timeout=5
                )
                if payload in response.text:
                    return True
            except:
                continue
        return False
        
    def _analyze_headers(self) -> Dict:
        headers = {}
        try:
            response = requests.get(self.url, verify=False, timeout=5)
            security_headers = [
                "X-Frame-Options",
                "X-Content-Type-Options",
                "X-XSS-Protection",
                "Content-Security-Policy",
                "Strict-Transport-Security"
            ]
            
            for header in security_headers:
                headers[header] = response.headers.get(header, "Not Set")
                
        except:
            pass
        return headers
        
    def _check_directory_traversal(self) -> bool:
        test_paths = [
            "../../../../etc/passwd",
            "..\\..\\..\\..\\windows\\win.ini",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        ]
        
        for path in test_paths:
            try:
                response = requests.get(
                    self.url + "/" + path,
                    verify=False,
                    timeout=5
                )
                if "root:" in response.text or "[extensions]" in response.text:
                    return True
            except:
                continue
        return False
        
    def _check_sensitive_info(self) -> bool:
        sensitive_patterns = [
            r"password\s*=\s*['\"].*['\"]",
            r"api_key\s*=\s*['\"].*['\"]",
            r"secret\s*=\s*['\"].*['\"]",
            r"token\s*=\s*['\"].*['\"]"
        ]
        
        try:
            response = requests.get(self.url, verify=False, timeout=5)
            for pattern in sensitive_patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    return True
        except:
            pass
        return False
        
    def stop(self):
        self._is_running = False

class WebSecurityTab(QWidget):
    def __init__(self):
        super().__init__()
        self.scanner_thread = None
        self.proxy_thread = None
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Input section
        input_frame = QFrame()
        input_frame.setFrameStyle(QFrame.Shape.StyledPanel | QFrame.Shadow.Raised)
        input_layout = QVBoxLayout(input_frame)
        
        # URL input
        url_layout = QHBoxLayout()
        url_label = QLabel("URL:")
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("e.g., http://example.com")
        url_layout.addWidget(url_label)
        url_layout.addWidget(self.url_input)
        input_layout.addLayout(url_layout)
        
        # Proxy settings
        proxy_layout = QHBoxLayout()
        proxy_label = QLabel("Proxy Port:")
        self.proxy_port_input = QSpinBox()
        self.proxy_port_input.setRange(1024, 65535)
        self.proxy_port_input.setValue(8080)
        self.proxy_enabled = QCheckBox("Enable Proxy")
        proxy_layout.addWidget(proxy_label)
        proxy_layout.addWidget(self.proxy_port_input)
        proxy_layout.addWidget(self.proxy_enabled)
        input_layout.addLayout(proxy_layout)
        
        layout.addWidget(input_frame)
        
        # Control buttons
        button_layout = QHBoxLayout()
        self.scan_btn = QPushButton("Start Scan")
        self.scan_btn.clicked.connect(self.start_scan)
        self.stop_btn = QPushButton("Stop")
        self.stop_btn.clicked.connect(self.stop_scan)
        self.stop_btn.setEnabled(False)
        self.clear_btn = QPushButton("Clear")
        self.clear_btn.clicked.connect(self.clear_results)
        button_layout.addWidget(self.scan_btn)
        button_layout.addWidget(self.stop_btn)
        button_layout.addWidget(self.clear_btn)
        layout.addLayout(button_layout)
        
        # Splitter for results
        splitter = QSplitter(Qt.Orientation.Vertical)
        
        # Request/Response viewer
        traffic_frame = QFrame()
        traffic_frame.setFrameStyle(QFrame.Shape.StyledPanel | QFrame.Shadow.Raised)
        traffic_layout = QVBoxLayout(traffic_frame)
        
        traffic_label = QLabel("Captured Traffic:")
        self.traffic_table = QTableWidget()
        self.traffic_table.setColumnCount(4)
        self.traffic_table.setHorizontalHeaderLabels(["Method", "Path", "Status", "Length"])
        self.traffic_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        traffic_layout.addWidget(traffic_label)
        traffic_layout.addWidget(self.traffic_table)
        
        splitter.addWidget(traffic_frame)
        
        # Results section
        results_frame = QFrame()
        results_frame.setFrameStyle(QFrame.Shape.StyledPanel | QFrame.Shadow.Raised)
        results_layout = QVBoxLayout(results_frame)
        
        # Vulnerabilities table
        vuln_label = QLabel("Vulnerabilities:")
        self.vuln_table = QTableWidget()
        self.vuln_table.setColumnCount(4)
        self.vuln_table.setHorizontalHeaderLabels(["Type", "Severity", "Description", "Details"])
        self.vuln_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        results_layout.addWidget(vuln_label)
        results_layout.addWidget(self.vuln_table)
        
        # Headers information
        headers_label = QLabel("Security Headers:")
        self.headers_text = QTextEdit()
        self.headers_text.setReadOnly(True)
        results_layout.addWidget(headers_label)
        results_layout.addWidget(self.headers_text)
        
        splitter.addWidget(results_frame)
        
        layout.addWidget(splitter)
        
        self.setLayout(layout)
        
    def start_scan(self):
        url = self.url_input.text().strip()
        if not url:
            QMessageBox.warning(self, "Warning", "Please enter a URL")
            return
            
        try:
            # Clean up any existing threads
            if self.scanner_thread and self.scanner_thread.isRunning():
                self.scanner_thread.stop()
                self.scanner_thread.wait(1000)
                if self.scanner_thread.isRunning():
                    self.scanner_thread.terminate()
                    
            if self.proxy_thread and self.proxy_thread.isRunning():
                self.proxy_thread.stop()
                self.proxy_thread.wait(1000)
                if self.proxy_thread.isRunning():
                    self.proxy_thread.terminate()
                    
            self.scan_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
            self.clear_results()
            
            # Start proxy if enabled
            if self.proxy_enabled.isChecked():
                self.proxy_thread = WebSecurityThread(
                    url,
                    "proxy",
                    self.proxy_port_input.value()
                )
                self.proxy_thread.request_captured.connect(self.handle_request)
                self.proxy_thread.error_occurred.connect(self.handle_error)
                self.proxy_thread.start()
                
            # Start vulnerability scan
            self.scanner_thread = WebSecurityThread(url, "vulnerability_scan")
            self.scanner_thread.scan_complete.connect(self.handle_results)
            self.scanner_thread.progress_updated.connect(self.update_progress)
            self.scanner_thread.error_occurred.connect(self.handle_error)
            self.scanner_thread.start()
            
        except Exception as e:
            self.handle_error(str(e))
            
    def stop_scan(self):
        if self.scanner_thread and self.scanner_thread.isRunning():
            self.scanner_thread.stop()
        if self.proxy_thread and self.proxy_thread.isRunning():
            self.proxy_thread.stop()
        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        
    def update_progress(self, value, message):
        self.scan_btn.setText(message)
        
    def handle_request(self, request):
        row = self.traffic_table.rowCount()
        self.traffic_table.insertRow(row)
        self.traffic_table.setItem(row, 0, QTableWidgetItem(request["method"]))
        self.traffic_table.setItem(row, 1, QTableWidgetItem(request["path"]))
        self.traffic_table.setItem(row, 2, QTableWidgetItem("200"))  # Default status
        self.traffic_table.setItem(row, 3, QTableWidgetItem(str(len(request["raw"]))))
        
    def handle_results(self, results):
        try:
            if results["error"]:
                self.handle_error(results["error"])
                return
                
            # Update vulnerabilities table
            self.vuln_table.setRowCount(0)
            for vuln in results["vulnerabilities"]:
                row = self.vuln_table.rowCount()
                self.vuln_table.insertRow(row)
                self.vuln_table.setItem(row, 0, QTableWidgetItem(vuln["type"]))
                self.vuln_table.setItem(row, 1, QTableWidgetItem(vuln["severity"]))
                self.vuln_table.setItem(row, 2, QTableWidgetItem(vuln["description"]))
                self.vuln_table.setItem(row, 3, QTableWidgetItem(vuln["details"]))
                
            # Update headers information
            headers_text = []
            for header, value in results["headers"].items():
                headers_text.append(f"{header}: {value}")
            self.headers_text.setText("\n".join(headers_text))
            
            self.scan_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            self.scan_btn.setText("Start Scan")
            
        except Exception as e:
            self.handle_error(str(e))
            
    def handle_error(self, error_message):
        QMessageBox.critical(self, "Error", f"An error occurred: {error_message}")
        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.scan_btn.setText("Start Scan")
        
    def clear_results(self):
        self.traffic_table.setRowCount(0)
        self.vuln_table.setRowCount(0)
        self.headers_text.clear() 