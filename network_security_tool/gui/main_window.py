from PyQt6.QtWidgets import QMainWindow, QTabWidget, QWidget, QVBoxLayout
from PyQt6.QtCore import Qt
from network_security_tool.gui.password_tools_tab import PasswordToolsTab
from network_security_tool.gui.web_cracker_tab import WebCrackerTab
from network_security_tool.gui.network_tools_tab import NetworkToolsTab
from network_security_tool.gui.packet_sniffer_tab import PacketSnifferTab
from network_security_tool.gui.vulnerability_scanner_tab import VulnerabilityScannerTab
from network_security_tool.gui.port_scanner_tab import PortScannerTab
import platform

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Security Tool")
        self.setGeometry(100, 100, 1200, 800)
        
        # Set keyboard input handling for macOS
        if platform.system() == 'Darwin':
            self.setAttribute(Qt.WidgetAttribute.WA_InputMethodEnabled, True)
        
        # Create central widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        
        # Create tab widget
        self.tab_widget = QTabWidget()
        layout.addWidget(self.tab_widget)
        
        # Add tabs
        self.add_tab("Network Tools", NetworkToolsTab())
        self.add_tab("Port Scanner", PortScannerTab())
        self.add_tab("Packet Sniffer", PacketSnifferTab())
        self.add_tab("Vulnerability Scanner", VulnerabilityScannerTab())
        self.add_tab("Password Tools", PasswordToolsTab())
        self.add_tab("Web Cracker", WebCrackerTab())
        
    def add_tab(self, name, widget):
        self.tab_widget.addTab(widget, name)
        
    def keyPressEvent(self, event):
        """Handle keyboard input events."""
        if platform.system() == 'Darwin':
            # Handle special characters for German keyboard
            if event.key() == Qt.Key.Key_At:
                self.handle_special_character('@')
            elif event.key() == Qt.Key.Key_NumberSign:
                self.handle_special_character('#')
            elif event.key() == Qt.Key.Key_QuoteLeft:
                self.handle_special_character('`')
            else:
                super().keyPressEvent(event)
        else:
            super().keyPressEvent(event)
            
    def handle_special_character(self, char):
        """Handle special character input."""
        # Get the current focused widget
        focused_widget = self.focusWidget()
        if focused_widget and hasattr(focused_widget, 'insert'):
            focused_widget.insert(char) 