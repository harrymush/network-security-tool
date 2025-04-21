from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                            QLineEdit, QPushButton, QComboBox, QTableWidget,
                            QTableWidgetItem, QHeaderView, QFrame, QTextEdit,
                            QMessageBox)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from network_security_tool.sniffer.packet_sniffer import PacketSniffer
import netifaces
import sys

class SnifferThread(QThread):
    packet_received = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)
    status_updated = pyqtSignal(dict)
    
    def __init__(self, sniffer, interface, filter):
        super().__init__()
        self.sniffer = sniffer
        self.interface = interface
        self.filter = filter
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_status)
        self.timer.start(1000)  # Update status every second
        
    def run(self):
        result = self.sniffer.start_sniffing(
            self.interface,
            self.filter,
            self.packet_received.emit
        )
        if result and "error" in result:
            self.error_occurred.emit(result["error"])
            
    def update_status(self):
        if self.sniffer:
            stats = self.sniffer.get_statistics()
            self.status_updated.emit(stats)
            
    def cleanup(self):
        """Clean up resources"""
        self.timer.stop()
        if self.sniffer:
            self.sniffer.stop_sniffing()

class PacketSnifferTab(QWidget):
    def __init__(self):
        super().__init__()
        self.sniffer = PacketSniffer()
        self.sniffer_thread = None
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Interface selection section
        interface_frame = QFrame()
        interface_frame.setFrameStyle(QFrame.Shape.StyledPanel | QFrame.Shadow.Raised)
        interface_layout = QVBoxLayout(interface_frame)
        
        # Interface selection
        interface_input_layout = QHBoxLayout()
        interface_label = QLabel("Network Interface:")
        self.interface_combo = QComboBox()
        self.load_interfaces()
        interface_input_layout.addWidget(interface_label)
        interface_input_layout.addWidget(self.interface_combo)
        interface_layout.addLayout(interface_input_layout)
        
        # Filter input
        filter_layout = QHBoxLayout()
        filter_label = QLabel("BPF Filter:")
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("e.g., tcp port 80")
        filter_layout.addWidget(filter_label)
        filter_layout.addWidget(self.filter_input)
        interface_layout.addLayout(filter_layout)
        
        layout.addWidget(interface_frame)
        
        # Control buttons
        button_layout = QHBoxLayout()
        self.start_btn = QPushButton("Start Capture")
        self.start_btn.clicked.connect(self.start_capture)
        self.stop_btn = QPushButton("Stop")
        self.stop_btn.clicked.connect(self.stop_capture)
        self.stop_btn.setEnabled(False)
        self.clear_btn = QPushButton("Clear")
        self.clear_btn.clicked.connect(self.clear_capture)
        button_layout.addWidget(self.start_btn)
        button_layout.addWidget(self.stop_btn)
        button_layout.addWidget(self.clear_btn)
        layout.addLayout(button_layout)
        
        # Status and Statistics
        stats_frame = QFrame()
        stats_frame.setFrameStyle(QFrame.Shape.StyledPanel | QFrame.Shadow.Raised)
        stats_layout = QVBoxLayout(stats_frame)
        
        # Status label
        self.status_label = QLabel("Status: Ready")
        stats_layout.addWidget(self.status_label)
        
        # Statistics
        stats_row = QHBoxLayout()
        self.packets_label = QLabel("Packets: 0")
        self.duration_label = QLabel("Duration: 0s")
        self.rate_label = QLabel("Rate: 0 pps")
        
        stats_row.addWidget(self.packets_label)
        stats_row.addWidget(self.duration_label)
        stats_row.addWidget(self.rate_label)
        stats_layout.addLayout(stats_row)
        
        layout.addWidget(stats_frame)
        
        # Packet table
        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(7)
        self.packet_table.setHorizontalHeaderLabels([
            "Time", "Source", "Destination", "Protocol",
            "Length", "Source Port", "Info"
        ])
        self.packet_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.packet_table)
        
        # Packet details
        details_frame = QFrame()
        details_frame.setFrameStyle(QFrame.Shape.StyledPanel | QFrame.Shadow.Raised)
        details_layout = QVBoxLayout(details_frame)
        
        details_label = QLabel("Packet Details:")
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        details_layout.addWidget(details_label)
        details_layout.addWidget(self.details_text)
        
        layout.addWidget(details_frame)
        
        self.setLayout(layout)
        
    def load_interfaces(self):
        """Load available network interfaces"""
        try:
            interfaces = netifaces.interfaces()
            for iface in interfaces:
                self.interface_combo.addItem(iface)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load network interfaces: {str(e)}")
            
    def start_capture(self):
        interface = self.interface_combo.currentText()
        if not interface:
            QMessageBox.warning(self, "Warning", "Please select a network interface")
            return
            
        try:
            # Ensure any previous capture is stopped
            if self.sniffer_thread and self.sniffer_thread.isRunning():
                self.stop_capture()
                
            self.start_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
            self.packet_table.setRowCount(0)
            self.details_text.clear()
            self.status_label.setText("Status: Starting capture...")
            
            self.sniffer_thread = SnifferThread(
                self.sniffer,
                interface,
                self.filter_input.text().strip()
            )
            
            self.sniffer_thread.packet_received.connect(self.add_packet)
            self.sniffer_thread.error_occurred.connect(self.handle_error)
            self.sniffer_thread.status_updated.connect(self.update_status)
            self.sniffer_thread.start()
            
        except Exception as e:
            self.handle_error(str(e))
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            
    def stop_capture(self):
        if self.sniffer_thread:
            self.status_label.setText("Status: Stopping capture...")
            self.sniffer_thread.cleanup()
            self.sniffer_thread.wait(2000)  # Wait up to 2 seconds for thread to stop
            if self.sniffer_thread.isRunning():
                self.sniffer_thread.terminate()  # Force stop if not responding
            self.sniffer_thread = None
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            self.status_label.setText("Status: Ready")
            
    def clear_capture(self):
        self.packet_table.setRowCount(0)
        self.details_text.clear()
        
    def add_packet(self, packet_info):
        """Add a new packet to the table"""
        try:
            row = self.packet_table.rowCount()
            self.packet_table.insertRow(row)
            
            self.packet_table.setItem(row, 0, QTableWidgetItem(packet_info["timestamp"]))
            self.packet_table.setItem(row, 1, QTableWidgetItem(packet_info["source"]))
            self.packet_table.setItem(row, 2, QTableWidgetItem(packet_info["destination"]))
            self.packet_table.setItem(row, 3, QTableWidgetItem(packet_info["protocol"]))
            self.packet_table.setItem(row, 4, QTableWidgetItem(str(packet_info["length"])))
            
            source_port = str(packet_info.get("source_port", ""))
            self.packet_table.setItem(row, 5, QTableWidgetItem(source_port))
            
            self.packet_table.setItem(row, 6, QTableWidgetItem(packet_info["info"]))
            
            # Auto-scroll to the new packet
            self.packet_table.scrollToBottom()
        except Exception as e:
            print(f"Error adding packet to table: {e}", file=sys.stderr)
            
    def update_status(self, stats):
        """Update the status and statistics display"""
        try:
            self.packets_label.setText(f"Packets: {stats['packets_captured']}")
            self.duration_label.setText(f"Duration: {stats['duration']:.1f}s")
            self.rate_label.setText(f"Rate: {stats['packets_per_second']:.1f} pps")
            
            if stats['is_running']:
                self.status_label.setText("Status: Capturing...")
            else:
                self.status_label.setText("Status: Ready")
        except Exception as e:
            print(f"Error updating status: {e}", file=sys.stderr)
            
    def handle_error(self, error_message):
        """Handle errors from the sniffer thread"""
        QMessageBox.critical(self, "Error", error_message)
        self.stop_capture()
        
    def show_packet_details(self, row, column):
        """Show detailed information about the selected packet"""
        try:
            packet_info = {
                "Time": self.packet_table.item(row, 0).text(),
                "Source": self.packet_table.item(row, 1).text(),
                "Destination": self.packet_table.item(row, 2).text(),
                "Protocol": self.packet_table.item(row, 3).text(),
                "Length": self.packet_table.item(row, 4).text(),
                "Source Port": self.packet_table.item(row, 5).text(),
                "Info": self.packet_table.item(row, 6).text()
            }
            
            details = "\n".join(f"{key}: {value}" for key, value in packet_info.items())
            self.details_text.setText(details)
        except Exception as e:
            print(f"Error showing packet details: {e}", file=sys.stderr) 