from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QComboBox,
    QPushButton, QLineEdit, QTableWidget, QTableWidgetItem,
    QHeaderView, QTextEdit, QGroupBox, QFormLayout, QMessageBox
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from network_security_tool.sniffer.packet_sniffer import PacketSniffer
import logging
import re

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PacketSnifferThread(QThread):
    """Thread for running packet sniffing in the background."""
    packet_received = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)
    finished = pyqtSignal()

    def __init__(self, interface: str, filter_text: str):
        super().__init__()
        self.interface = interface
        self.filter_text = filter_text
        self.sniffer = PacketSniffer()
        self.running = False

    def run(self):
        try:
            logger.debug(f"Starting sniffing on interface {self.interface} with filter {self.filter_text}")
            self.running = True
            self.sniffer.start_sniffing(
                interface=self.interface,
                filter_text=self.filter_text,
                callback=self._packet_callback
            )
        except Exception as e:
            logger.error(f"Error in sniffer thread: {str(e)}")
            self.error_occurred.emit(str(e))
        finally:
            self.finished.emit()

    def _packet_callback(self, packet_info):
        if self.running:
            self.packet_received.emit(packet_info)

    def stop(self):
        logger.debug("Stopping sniffer thread")
        self.running = False
        self.sniffer.stop_sniffing()

class PacketSnifferTab(QWidget):
    """GUI tab for the packet sniffer."""
    def __init__(self):
        super().__init__()
        self.sniffer_thread = None
        self.sniffer = PacketSniffer()
        self.setup_ui()
        self.update_interfaces()

    def setup_ui(self):
        """Initialize the user interface."""
        layout = QVBoxLayout()
        self.setLayout(layout)

        # Interface selection
        interface_group = QGroupBox("Interface Selection")
        interface_layout = QFormLayout()
        
        self.interface_combo = QComboBox()
        self.interface_combo.setMinimumWidth(200)
        interface_layout.addRow("Network Interface:", self.interface_combo)
        
        self.filter_input = QTextEdit()
        self.filter_input.setMaximumHeight(50)
        self.filter_input.setPlaceholderText("Enter BPF filter (e.g., tcp port 80)")
        interface_layout.addRow("Filter:", self.filter_input)
        
        interface_group.setLayout(interface_layout)
        layout.addWidget(interface_group)

        # Control buttons
        button_layout = QHBoxLayout()
        self.start_button = QPushButton("Start Sniffing")
        self.start_button.clicked.connect(self.start_sniffing)
        self.stop_button = QPushButton("Stop Sniffing")
        self.stop_button.clicked.connect(self.stop_sniffing)
        self.stop_button.setEnabled(False)
        self.clear_button = QPushButton("Clear Results")
        self.clear_button.clicked.connect(self.clear_results)
        self.refresh_button = QPushButton("Refresh Interfaces")
        self.refresh_button.clicked.connect(self.update_interfaces)
        
        button_layout.addWidget(self.start_button)
        button_layout.addWidget(self.stop_button)
        button_layout.addWidget(self.clear_button)
        button_layout.addWidget(self.refresh_button)
        layout.addLayout(button_layout)

        # Statistics
        stats_group = QGroupBox("Statistics")
        stats_layout = QFormLayout()
        self.packets_label = QLabel("Packets: 0")
        self.duration_label = QLabel("Duration: 0s")
        self.rate_label = QLabel("Rate: 0 pps")
        
        stats_layout.addRow("Packets Captured:", self.packets_label)
        stats_layout.addRow("Capture Duration:", self.duration_label)
        stats_layout.addRow("Capture Rate:", self.rate_label)
        
        stats_group.setLayout(stats_layout)
        layout.addWidget(stats_group)

        # Results table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(5)
        self.results_table.setHorizontalHeaderLabels([
            "Time", "Source", "Destination", "Protocol", "Length"
        ])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.results_table)

        # Status messages
        self.status_text = QTextEdit()
        self.status_text.setReadOnly(True)
        self.status_text.setMaximumHeight(100)
        layout.addWidget(self.status_text)

    def update_interfaces(self):
        """Update the list of available network interfaces."""
        self.interface_combo.clear()
        self.status_text.append("Refreshing interface list...")
        
        try:
            interfaces = self.sniffer.get_interfaces()
            
            logger.debug(f"Found interfaces: {interfaces}")
            self.status_text.append(f"Found {len(interfaces)} interfaces")
            
            for interface in interfaces:
                self.interface_combo.addItem(interface)
                self.status_text.append(f"Added interface: {interface}")
            
            if not interfaces:
                self.status_text.append("Warning: No interfaces found!")
                logger.warning("No interfaces found")
            else:
                self.status_text.append("Interface list updated successfully")
                
        except Exception as e:
            error_msg = f"Error updating interfaces: {str(e)}"
            logger.error(error_msg)
            self.status_text.append(error_msg)
            QMessageBox.critical(self, "Error", error_msg)

    def validate_filter(self, filter_str: str) -> bool:
        """Validate the BPF filter syntax."""
        if not filter_str:
            return True
        # Basic validation - more complex validation would require BPF parser
        return bool(re.match(r'^[a-zA-Z0-9\s\.\:\=\>\<\!\&\|\-\+\*\(\)]+$', filter_str))

    def start_sniffing(self):
        """Start the packet capture."""
        interface = self.interface_combo.currentText()
        filter_text = self.filter_input.toPlainText()
        
        if not interface:
            QMessageBox.warning(self, "Warning", "Please select a network interface")
            return

        if not self.validate_filter(filter_text):
            QMessageBox.warning(self, "Warning", "Invalid filter syntax")
            return

        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.clear_button.setEnabled(False)
        self.status_text.clear()

        self.sniffer_thread = PacketSnifferThread(interface, filter_text)
        self.sniffer_thread.packet_received.connect(self.add_packet)
        self.sniffer_thread.error_occurred.connect(self.handle_error)
        self.sniffer_thread.finished.connect(self.sniffing_finished)
        
        self.status_text.append(f"Started sniffing on {interface}")
        if filter_text:
            self.status_text.append(f"Using filter: {filter_text}")

        self.sniffer_thread.start()

    def stop_sniffing(self):
        """Stop the packet capture."""
        if self.sniffer_thread:
            self.sniffer_thread.stop()
            self.status_text.append("Stopped sniffing")
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            self.clear_button.setEnabled(True)

    def clear_results(self):
        """Clear the capture results."""
        self.results_table.setRowCount(0)
        self.status_text.clear()
        self.packets_label.setText("Packets: 0")
        self.duration_label.setText("Duration: 0s")
        self.rate_label.setText("Rate: 0 pps")

    def add_packet(self, packet_info):
        """Update the UI with a new packet."""
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)
        
        self.results_table.setItem(row, 0, QTableWidgetItem(packet_info['time']))
        self.results_table.setItem(row, 1, QTableWidgetItem(packet_info['source']))
        self.results_table.setItem(row, 2, QTableWidgetItem(packet_info['destination']))
        self.results_table.setItem(row, 3, QTableWidgetItem(packet_info['protocol']))
        self.results_table.setItem(row, 4, QTableWidgetItem(str(packet_info['length'])))

        # Update statistics
        stats = self.sniffer_thread.sniffer.get_statistics()
        self.packets_label.setText(f"Packets: {stats['packets']}")
        self.duration_label.setText(f"Duration: {stats['duration']:.1f}s")
        self.rate_label.setText(f"Rate: {stats['packets_per_second']:.1f} pps")

    def handle_error(self, error_msg):
        """Handle capture errors."""
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.clear_button.setEnabled(True)
        self.status_text.append(f"Error: {error_msg}")
        QMessageBox.critical(self, "Error", f"Capture failed: {error_msg}")

    def sniffing_finished(self):
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.status_text.append("Sniffing finished") 