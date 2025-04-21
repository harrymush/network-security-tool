from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                            QLineEdit, QPushButton, QComboBox, QProgressBar,
                            QTextEdit, QFrame, QSpinBox, QTableWidget,
                            QTableWidgetItem, QHeaderView)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from network_security_tool.scanner.network_scanner import NetworkScanner

class ScannerThread(QThread):
    progress_updated = pyqtSignal(float)
    scan_completed = pyqtSignal(list)
    
    def __init__(self, scanner, network, timeout, max_threads):
        super().__init__()
        self.scanner = scanner
        self.network = network
        self.timeout = timeout
        self.max_threads = max_threads
        
    def run(self):
        def progress_callback(progress):
            self.progress_updated.emit(progress)
            
        results = self.scanner.scan_network(
            self.network,
            self.timeout,
            self.max_threads,
            progress_callback
        )
        self.scan_completed.emit(results)

class NetworkScannerTab(QWidget):
    def __init__(self):
        super().__init__()
        self.scanner = NetworkScanner()
        self.scanner_thread = None
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Network input section
        network_frame = QFrame()
        network_frame.setFrameStyle(QFrame.Shape.StyledPanel | QFrame.Shadow.Raised)
        network_layout = QVBoxLayout(network_frame)
        
        # Network address input
        network_input_layout = QHBoxLayout()
        network_label = QLabel("Network Address:")
        self.network_input = QLineEdit()
        self.network_input.setPlaceholderText("e.g., 192.168.1.0/24")
        network_input_layout.addWidget(network_label)
        network_input_layout.addWidget(self.network_input)
        network_layout.addLayout(network_input_layout)
        
        # Scan options
        options_layout = QHBoxLayout()
        
        # Timeout
        timeout_layout = QHBoxLayout()
        timeout_label = QLabel("Timeout (s):")
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(1, 10)
        self.timeout_spin.setValue(1)
        timeout_layout.addWidget(timeout_label)
        timeout_layout.addWidget(self.timeout_spin)
        options_layout.addLayout(timeout_layout)
        
        # Max threads
        threads_layout = QHBoxLayout()
        threads_label = QLabel("Max Threads:")
        self.threads_spin = QSpinBox()
        self.threads_spin.setRange(1, 500)
        self.threads_spin.setValue(100)
        threads_layout.addWidget(threads_label)
        threads_layout.addWidget(self.threads_spin)
        options_layout.addLayout(threads_layout)
        
        network_layout.addLayout(options_layout)
        layout.addWidget(network_frame)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        layout.addWidget(self.progress_bar)
        
        # Control buttons
        button_layout = QHBoxLayout()
        self.start_btn = QPushButton("Start Scan")
        self.start_btn.clicked.connect(self.start_scan)
        self.stop_btn = QPushButton("Stop")
        self.stop_btn.clicked.connect(self.stop_scan)
        self.stop_btn.setEnabled(False)
        button_layout.addWidget(self.start_btn)
        button_layout.addWidget(self.stop_btn)
        layout.addLayout(button_layout)
        
        # Results table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(3)
        self.results_table.setHorizontalHeaderLabels(["IP Address", "Port", "Service"])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.results_table)
        
        self.setLayout(layout)
        
    def start_scan(self):
        network = self.network_input.text().strip()
        if not network:
            return
            
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress_bar.setValue(0)
        self.results_table.setRowCount(0)
        
        self.scanner_thread = ScannerThread(
            self.scanner,
            network,
            self.timeout_spin.value(),
            self.threads_spin.value()
        )
        
        self.scanner_thread.progress_updated.connect(self.update_progress)
        self.scanner_thread.scan_completed.connect(self.display_results)
        self.scanner_thread.start()
        
    def stop_scan(self):
        if self.scanner_thread and self.scanner_thread.isRunning():
            self.scanner.stop_scan()
            self.scanner_thread.wait()
            
    def update_progress(self, progress):
        self.progress_bar.setValue(int(progress))
        
    def display_results(self, results):
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        
        if not results:
            return
            
        if "error" in results[0]:
            self.results_table.setRowCount(1)
            self.results_table.setItem(0, 0, QTableWidgetItem(results[0]["error"]))
            return
            
        row = 0
        for host in results:
            for port_info in host["ports"]:
                self.results_table.insertRow(row)
                self.results_table.setItem(row, 0, QTableWidgetItem(host["ip"]))
                self.results_table.setItem(row, 1, QTableWidgetItem(str(port_info["port"])))
                self.results_table.setItem(row, 2, QTableWidgetItem(port_info["service"]))
                row += 1 