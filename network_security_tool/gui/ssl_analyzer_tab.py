from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                            QLineEdit, QPushButton, QTableWidget,
                            QTableWidgetItem, QHeaderView, QFrame, QTextEdit,
                            QMessageBox, QComboBox, QProgressBar, QGroupBox)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from network_security_tool.scanner.ssl_analyzer import SSLAnalyzer
import sys

class SSLAnalyzerThread(QThread):
    analysis_complete = pyqtSignal(dict)
    progress_updated = pyqtSignal(int, str)
    error_occurred = pyqtSignal(str)
    status_updated = pyqtSignal(str)
    
    def __init__(self, analyzer, host, port):
        super().__init__()
        self.analyzer = analyzer
        self.host = host
        self.port = port
        self._is_running = True
        
    def run(self):
        try:
            if not self._is_running:
                return
                
            self.progress_updated.emit(20, "Connecting to host...")
            self.status_updated.emit(f"Starting SSL/TLS analysis for {self.host}:{self.port}")
            
            results = self.analyzer.analyze_host(self.host, self.port)
            
            if not self._is_running:
                return
                
            self.progress_updated.emit(60, "Analyzing SSL/TLS configuration...")
            self.status_updated.emit("Checking for vulnerabilities...")
            
            self.progress_updated.emit(100, "Analysis complete")
            self.status_updated.emit("Analysis completed successfully")
            self.analysis_complete.emit(results)
            
        except Exception as e:
            error_msg = f"Analysis failed: {str(e)}"
            print(f"Error during analysis: {error_msg}")
            self.error_occurred.emit(error_msg)
            self.status_updated.emit(f"Error: {error_msg}")
            self.analysis_complete.emit({"error": error_msg})
            
    def stop(self):
        self._is_running = False
        self.status_updated.emit("Analysis stopped by user")

class SSLAnalyzerTab(QWidget):
    def __init__(self):
        super().__init__()
        self.analyzer = SSLAnalyzer()
        self.analyzer_thread = None
        self.progress_timer = QTimer()
        self.progress_timer.timeout.connect(self.update_progress_animation)
        self.progress_direction = 1
        self.progress_value = 0
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
        
        # Port input
        port_layout = QHBoxLayout()
        port_label = QLabel("Port:")
        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("e.g., 443")
        self.port_input.setText("443")  # Default HTTPS port
        port_layout.addWidget(port_label)
        port_layout.addWidget(self.port_input)
        target_layout.addLayout(port_layout)
        
        layout.addWidget(target_frame)
        
        # Control buttons
        button_layout = QHBoxLayout()
        self.start_btn = QPushButton("Start Analysis")
        self.start_btn.clicked.connect(self.start_analysis)
        self.stop_btn = QPushButton("Stop")
        self.stop_btn.clicked.connect(self.stop_analysis)
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
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setTextVisible(True)
        self.progress_label = QLabel("Ready")
        progress_layout.addWidget(self.progress_label)
        progress_layout.addWidget(self.progress_bar)
        
        # Status window
        status_group = QGroupBox("Analysis Status")
        status_layout = QVBoxLayout(status_group)
        self.status_text = QTextEdit()
        self.status_text.setReadOnly(True)
        self.status_text.setMaximumHeight(100)
        status_layout.addWidget(self.status_text)
        progress_layout.addWidget(status_group)
        
        layout.addWidget(progress_frame)
        
        # Results section
        results_frame = QFrame()
        results_frame.setFrameStyle(QFrame.Shape.StyledPanel | QFrame.Shadow.Raised)
        results_layout = QVBoxLayout(results_frame)
        
        # Vulnerabilities table
        vuln_label = QLabel("Vulnerabilities:")
        self.vuln_table = QTableWidget()
        self.vuln_table.setColumnCount(4)
        self.vuln_table.setHorizontalHeaderLabels([
            "Type", "Severity", "Description", "Details"
        ])
        self.vuln_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        results_layout.addWidget(vuln_label)
        results_layout.addWidget(self.vuln_table)
        
        # Certificate details
        cert_label = QLabel("Certificate Details:")
        self.cert_text = QTextEdit()
        self.cert_text.setReadOnly(True)
        results_layout.addWidget(cert_label)
        results_layout.addWidget(self.cert_text)
        
        # Protocol and cipher info
        info_label = QLabel("Protocol and Cipher Information:")
        self.info_text = QTextEdit()
        self.info_text.setReadOnly(True)
        results_layout.addWidget(info_label)
        results_layout.addWidget(self.info_text)
        
        layout.addWidget(results_frame)
        
        self.setLayout(layout)
        
    def update_progress_animation(self):
        """Update progress bar animation during analysis"""
        if self.progress_value >= 100:
            self.progress_direction = -1
        elif self.progress_value <= 0:
            self.progress_direction = 1
            
        self.progress_value += self.progress_direction
        self.progress_bar.setValue(self.progress_value)
        
    def start_analysis(self):
        host = self.host_input.text().strip()
        if not host:
            QMessageBox.warning(self, "Warning", "Please enter a host")
            return
            
        try:
            port = int(self.port_input.text().strip())
        except ValueError:
            QMessageBox.warning(self, "Warning", "Please enter a valid port number")
            return
            
        try:
            # Clean up any existing thread
            if self.analyzer_thread and self.analyzer_thread.isRunning():
                self.analyzer_thread.stop()
                self.analyzer_thread.wait(1000)
                if self.analyzer_thread.isRunning():
                    self.analyzer_thread.terminate()
                    
            self.start_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
            self.clear_results()
            self.progress_bar.setValue(0)
            self.progress_label.setText("Starting analysis...")
            self.status_text.clear()
            self.status_text.append(f"Starting SSL/TLS analysis for {host}:{port}")
            
            # Start progress animation
            self.progress_timer.start(50)
            
            self.analyzer_thread = SSLAnalyzerThread(
                self.analyzer,
                host,
                port
            )
            
            self.analyzer_thread.analysis_complete.connect(self.handle_results)
            self.analyzer_thread.progress_updated.connect(self.update_progress)
            self.analyzer_thread.error_occurred.connect(self.handle_error)
            self.analyzer_thread.status_updated.connect(self.update_status)
            self.analyzer_thread.start()
            
        except Exception as e:
            self.handle_error(str(e))
            
    def stop_analysis(self):
        """Stop the current analysis"""
        if self.analyzer_thread and self.analyzer_thread.isRunning():
            try:
                # Stop the progress animation
                self.progress_timer.stop()
                
                # Signal the thread to stop
                self.analyzer_thread.stop()
                
                # Update UI immediately
                self.start_btn.setEnabled(True)
                self.stop_btn.setEnabled(False)
                self.progress_label.setText("Stopping analysis...")
                self.status_text.append("Stopping analysis...")
                
                # Use a timer to check if the thread has stopped
                check_timer = QTimer()
                check_timer.timeout.connect(lambda: self.check_thread_status(check_timer))
                check_timer.start(100)
                
            except Exception as e:
                print(f"Error stopping analysis: {e}")
                self.handle_error(f"Error stopping analysis: {e}")
                
    def check_thread_status(self, timer):
        """Check if the analyzer thread has stopped"""
        if not self.analyzer_thread.isRunning():
            timer.stop()
            self.progress_label.setText("Analysis stopped")
            self.progress_bar.setValue(0)
            self.status_text.append("Analysis stopped by user")
            
    def update_status(self, message):
        """Update the status window with a new message"""
        self.status_text.append(message)
        self.status_text.verticalScrollBar().setValue(
            self.status_text.verticalScrollBar().maximum()
        )
        
    def update_progress(self, value, message):
        """Update progress bar and label"""
        self.progress_label.setText(message)
        if value == 100:
            self.progress_timer.stop()
            self.progress_bar.setValue(100)
        elif value == 0:
            self.progress_timer.start(50)
            
    def handle_results(self, results):
        """Handle and display analysis results"""
        try:
            if "error" in results:
                self.handle_error(results["error"])
                return
                
            # Update vulnerabilities table
            for vuln in results["vulnerabilities"]:
                row = self.vuln_table.rowCount()
                self.vuln_table.insertRow(row)
                self.vuln_table.setItem(row, 0, QTableWidgetItem(vuln["type"]))
                self.vuln_table.setItem(row, 1, QTableWidgetItem(vuln["severity"]))
                self.vuln_table.setItem(row, 2, QTableWidgetItem(vuln["description"]))
                self.vuln_table.setItem(row, 3, QTableWidgetItem(vuln["details"]))
                
            # Update certificate details
            cert_details = []
            cert_details.append("=== Certificate Information ===")
            for key, value in results["certificate"].items():
                if isinstance(value, dict):
                    cert_details.append(f"\n{key}:")
                    for k, v in value.items():
                        cert_details.append(f"  {k}: {v}")
                else:
                    cert_details.append(f"{key}: {value}")
            self.cert_text.setText("\n".join(cert_details))
            
            # Update protocol and cipher info
            info_details = []
            info_details.append("=== Protocol Information ===")
            info_details.append("Supported Protocols:")
            for protocol in results["protocols"]:
                info_details.append(f"- {protocol}")
                
            info_details.append("\n=== Cipher Information ===")
            for cipher in results["ciphers"]:
                info_details.append(f"\nCipher Suite: {cipher['name']}")
                info_details.append(f"Version: {cipher['version']}")
                info_details.append(f"Key Length: {cipher['bits']} bits")
                
            self.info_text.setText("\n".join(info_details))
            
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            self.progress_label.setText("Analysis complete")
            self.progress_bar.setValue(100)
            
        except Exception as e:
            self.handle_error(str(e))
            
    def handle_error(self, error_message):
        """Handle and display error messages"""
        print(f"Error in analyzer: {error_message}")
        QMessageBox.critical(
            self,
            "Analysis Error",
            f"An error occurred during the analysis:\n\n{error_message}\n\n"
            "Please check:\n"
            "1. The host is reachable\n"
            "2. The port is correct\n"
            "3. The host supports SSL/TLS"
        )
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress_label.setText("Error occurred")
        self.progress_bar.setValue(0)
        
    def clear_results(self):
        """Clear all results"""
        self.vuln_table.setRowCount(0)
        self.cert_text.clear()
        self.info_text.clear()
        self.status_text.clear() 