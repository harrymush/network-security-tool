from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                            QLineEdit, QPushButton, QTableWidget,
                            QTableWidgetItem, QHeaderView, QFrame, QTextEdit,
                            QMessageBox, QComboBox, QProgressBar, QGroupBox)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
import socket
import threading
import time
from typing import List, Dict

class PortScannerThread(QThread):
    scan_complete = pyqtSignal(dict)
    progress_updated = pyqtSignal(int, str)
    error_occurred = pyqtSignal(str)
    
    def __init__(self, host: str, start_port: int, end_port: int, timeout: float = 1.0):
        super().__init__()
        self.host = host
        self.start_port = start_port
        self.end_port = end_port
        self.timeout = timeout
        self._is_running = True
        
    def run(self):
        try:
            results = {
                "open_ports": [],
                "closed_ports": [],
                "filtered_ports": [],
                "error": None
            }
            
            total_ports = self.end_port - self.start_port + 1
            scanned_ports = 0
            
            for port in range(self.start_port, self.end_port + 1):
                if not self._is_running:
                    break
                    
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(self.timeout)
                    result = sock.connect_ex((self.host, port))
                    
                    if result == 0:
                        results["open_ports"].append(port)
                    else:
                        results["closed_ports"].append(port)
                        
                    sock.close()
                    
                except socket.timeout:
                    results["filtered_ports"].append(port)
                except Exception as e:
                    results["error"] = str(e)
                    break
                    
                scanned_ports += 1
                progress = int((scanned_ports / total_ports) * 100)
                self.progress_updated.emit(progress, f"Scanning port {port}")
                
            self.scan_complete.emit(results)
            
        except Exception as e:
            self.error_occurred.emit(str(e))
            
    def stop(self):
        self._is_running = False

class PortScannerTab(QWidget):
    def __init__(self):
        super().__init__()
        self.scanner_thread = None
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Target input section
        target_frame = QFrame()
        target_frame.setFrameStyle(QFrame.Shape.StyledPanel | QFrame.Shadow.Raised)
        target_layout = QVBoxLayout(target_frame)
        
        # Host input
        host_layout = QHBoxLayout()
        host_label = QLabel("Host:")
        self.host_input = QLineEdit()
        self.host_input.setPlaceholderText("e.g., example.com or 192.168.1.1")
        host_layout.addWidget(host_label)
        host_layout.addWidget(self.host_input)
        target_layout.addLayout(host_layout)
        
        # Port range input
        port_range_layout = QHBoxLayout()
        port_range_label = QLabel("Port Range:")
        self.start_port_input = QLineEdit()
        self.start_port_input.setPlaceholderText("Start port")
        self.start_port_input.setText("1")
        self.end_port_input = QLineEdit()
        self.end_port_input.setPlaceholderText("End port")
        self.end_port_input.setText("1024")
        port_range_layout.addWidget(port_range_label)
        port_range_layout.addWidget(self.start_port_input)
        port_range_layout.addWidget(QLabel("to"))
        port_range_layout.addWidget(self.end_port_input)
        target_layout.addLayout(port_range_layout)
        
        # Timeout input
        timeout_layout = QHBoxLayout()
        timeout_label = QLabel("Timeout (seconds):")
        self.timeout_input = QLineEdit()
        self.timeout_input.setPlaceholderText("Timeout in seconds")
        self.timeout_input.setText("1.0")
        timeout_layout.addWidget(timeout_label)
        timeout_layout.addWidget(self.timeout_input)
        target_layout.addLayout(timeout_layout)
        
        layout.addWidget(target_frame)
        
        # Control buttons
        button_layout = QHBoxLayout()
        self.start_btn = QPushButton("Start Scan")
        self.start_btn.clicked.connect(self.start_scan)
        self.stop_btn = QPushButton("Stop")
        self.stop_btn.clicked.connect(self.stop_scan)
        self.stop_btn.setEnabled(False)
        self.clear_btn = QPushButton("Clear")
        self.clear_btn.clicked.connect(self.clear_results)
        button_layout.addWidget(self.start_btn)
        button_layout.addWidget(self.stop_btn)
        button_layout.addWidget(self.clear_btn)
        layout.addLayout(button_layout)
        
        # Progress section
        progress_frame = QFrame()
        progress_frame.setFrameStyle(QFrame.Shape.StyledPanel | QFrame.Shadow.Raised)
        progress_layout = QVBoxLayout(progress_frame)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setTextVisible(True)
        self.progress_label = QLabel("Ready")
        progress_layout.addWidget(self.progress_label)
        progress_layout.addWidget(self.progress_bar)
        layout.addWidget(progress_frame)
        
        # Results section
        results_frame = QFrame()
        results_frame.setFrameStyle(QFrame.Shape.StyledPanel | QFrame.Shadow.Raised)
        results_layout = QVBoxLayout(results_frame)
        
        # Results table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(2)
        self.results_table.setHorizontalHeaderLabels(["Port", "Status"])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        results_layout.addWidget(self.results_table)
        
        # Summary text
        self.summary_text = QTextEdit()
        self.summary_text.setReadOnly(True)
        results_layout.addWidget(self.summary_text)
        
        layout.addWidget(results_frame)
        
        self.setLayout(layout)
        
    def start_scan(self):
        host = self.host_input.text().strip()
        if not host:
            QMessageBox.warning(self, "Warning", "Please enter a host")
            return
            
        try:
            start_port = int(self.start_port_input.text().strip())
            end_port = int(self.end_port_input.text().strip())
            timeout = float(self.timeout_input.text().strip())
            
            if start_port < 1 or start_port > 65535:
                raise ValueError("Start port must be between 1 and 65535")
            if end_port < 1 or end_port > 65535:
                raise ValueError("End port must be between 1 and 65535")
            if start_port > end_port:
                raise ValueError("Start port must be less than or equal to end port")
            if timeout <= 0:
                raise ValueError("Timeout must be greater than 0")
                
        except ValueError as e:
            QMessageBox.warning(self, "Warning", str(e))
            return
            
        try:
            # Clean up any existing thread
            if self.scanner_thread and self.scanner_thread.isRunning():
                self.scanner_thread.stop()
                self.scanner_thread.wait(1000)
                if self.scanner_thread.isRunning():
                    self.scanner_thread.terminate()
                    
            self.start_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
            self.clear_results()
            self.progress_bar.setValue(0)
            self.progress_label.setText("Starting scan...")
            
            self.scanner_thread = PortScannerThread(host, start_port, end_port, timeout)
            self.scanner_thread.scan_complete.connect(self.handle_results)
            self.scanner_thread.progress_updated.connect(self.update_progress)
            self.scanner_thread.error_occurred.connect(self.handle_error)
            self.scanner_thread.start()
            
        except Exception as e:
            self.handle_error(str(e))
            
    def stop_scan(self):
        if self.scanner_thread and self.scanner_thread.isRunning():
            self.scanner_thread.stop()
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            self.progress_label.setText("Scan stopped")
            
    def update_progress(self, value, message):
        self.progress_label.setText(message)
        self.progress_bar.setValue(value)
        
    def handle_results(self, results):
        try:
            if results["error"]:
                self.handle_error(results["error"])
                return
                
            # Update results table
            self.results_table.setRowCount(0)
            for port in sorted(results["open_ports"]):
                row = self.results_table.rowCount()
                self.results_table.insertRow(row)
                self.results_table.setItem(row, 0, QTableWidgetItem(str(port)))
                self.results_table.setItem(row, 1, QTableWidgetItem("Open"))
                
            # Update summary
            summary = []
            summary.append(f"Scan completed for {self.host_input.text()}")
            summary.append(f"Open ports: {len(results['open_ports'])}")
            summary.append(f"Closed ports: {len(results['closed_ports'])}")
            summary.append(f"Filtered ports: {len(results['filtered_ports'])}")
            
            if results["open_ports"]:
                summary.append("\nOpen ports:")
                for port in sorted(results["open_ports"]):
                    summary.append(f"- {port}")
                    
            self.summary_text.setText("\n".join(summary))
            
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            self.progress_label.setText("Scan complete")
            self.progress_bar.setValue(100)
            
        except Exception as e:
            self.handle_error(str(e))
            
    def handle_error(self, error_message):
        QMessageBox.critical(self, "Error", f"An error occurred: {error_message}")
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress_label.setText("Error occurred")
        self.progress_bar.setValue(0)
        
    def clear_results(self):
        self.results_table.setRowCount(0)
        self.summary_text.clear()
        self.progress_bar.setValue(0)
        self.progress_label.setText("Ready") 