from PyQt6.QtWidgets import (QMainWindow, QTabWidget, QWidget, QVBoxLayout,
                            QApplication)
from PyQt6.QtCore import Qt
from network_security_tool.gui.password_analysis_tab import PasswordAnalysisTab
from network_security_tool.gui.password_generator_tab import PasswordGeneratorTab
from network_security_tool.gui.passphrase_generator_tab import PassphraseGeneratorTab
from network_security_tool.gui.password_cracker_tab import PasswordCrackerTab
from network_security_tool.gui.network_scanner_tab import NetworkScannerTab
from network_security_tool.gui.packet_sniffer_tab import PacketSnifferTab
from network_security_tool.gui.vulnerability_scanner_tab import VulnerabilityScannerTab
from network_security_tool.gui.port_scanner_tab import PortScannerTab
from network_security_tool.gui.ssl_analyzer_tab import SSLAnalyzerTab
from network_security_tool.gui.dns_tools_tab import DNSToolsTab
from network_security_tool.gui.web_security_tab import WebSecurityTab
from network_security_tool.gui.web_cracker_tab import WebCrackerTab

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Security Tool")
        self.setMinimumSize(800, 600)
        
        # Create central widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        
        # Create tab widget
        self.tab_widget = QTabWidget()
        layout.addWidget(self.tab_widget)
        
        # Initialize tabs
        self.tabs = {}
        
        # Add Password Analysis tab
        self.add_tab("Password Analysis", PasswordAnalysisTab())
        
        # Add Password Generator tab
        self.add_tab("Password Generator", PasswordGeneratorTab())
        
        # Add Passphrase Generator tab
        self.add_tab("Passphrase Generator", PassphraseGeneratorTab())
        
        # Add Password Cracker tab
        self.add_tab("Password Cracker", PasswordCrackerTab())
        
        # Add Network Scanner tab
        self.add_tab("Network Scanner", NetworkScannerTab())
        
        # Add Packet Sniffer tab
        self.add_tab("Packet Sniffer", PacketSnifferTab())
        
        # Add Vulnerability Scanner tab
        self.add_tab("Vulnerability Scanner", VulnerabilityScannerTab())
        
        # Add Port Scanner tab
        self.add_tab("Port Scanner", PortScannerTab())
        
        # Add SSL/TLS Analyzer tab
        self.add_tab("SSL/TLS Analyzer", SSLAnalyzerTab())
        
        # Add DNS Tools tab
        self.add_tab("DNS Tools", DNSToolsTab())
        
        # Add Web Security tab
        self.add_tab("Web Security", WebSecurityTab())
        
        # Add Web Cracker tab
        self.add_tab("Web Cracker", WebCrackerTab())
        
    def add_tab(self, name, widget):
        """Add a new tab to the main window"""
        self.tabs[name] = widget
        self.tab_widget.addTab(widget, name) 