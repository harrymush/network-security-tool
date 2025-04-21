from PyQt6.QtWidgets import QMainWindow, QTabWidget, QApplication
from PyQt6.QtCore import Qt, QObject, QSettings
import sys
import platform
import os

# Import our tab modules
from .network_tools_tab import NetworkToolsTab
from .packet_sniffer_tab import PacketSnifferTab
from .vulnerability_scanner_tab import VulnerabilityScannerTab
from .password_tools_tab import PasswordToolsTab
from .web_cracker_tab import WebCrackerTab
from .ssl_analyzer_tab import SSLAnalyzerTab

class AppDelegate(QObject):
    def __init__(self):
        super().__init__()
        # Ensure we're not using state restoration
        if platform.system() == 'Darwin':
            settings = QSettings()
            settings.setValue("NSQuitAlwaysKeepsWindows", False)
            settings.sync()

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        
        self.setWindowTitle("Network Security Tool")
        self.setMinimumSize(800, 600)

        # Create tab widget
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        # Add tabs
        self.add_tab("Network Tools", NetworkToolsTab())
        self.add_tab("Packet Sniffer", PacketSnifferTab())
        self.add_tab("SSL/TLS Analyzer", SSLAnalyzerTab())
        self.add_tab("Vulnerability Scanner", VulnerabilityScannerTab())
        self.add_tab("Password Tools", PasswordToolsTab())
        self.add_tab("Web Cracker", WebCrackerTab())

    def add_tab(self, name, widget):
        self.tabs.addTab(widget, name)

def main():
    # Disable state restoration before creating QApplication
    if platform.system() == 'Darwin':
        os.environ['OBJC_DISABLE_APP_RESUME'] = 'YES'
        os.environ['OBJC_DISABLE_STATE_RESTORATION'] = 'YES'
    
    app = QApplication(sys.argv)
    
    # Set up application metadata
    app.setApplicationName("Network Security Tool")
    app.setOrganizationName("NetworkSecurity")
    app.setOrganizationDomain("networksecurity.tool")
    
    # Set up macOS specific configuration
    if platform.system() == 'Darwin':
        # Create and set application delegate
        delegate = AppDelegate()
        app.setProperty("NSApplicationDelegate", delegate)
        
        # Disable native menu bar and control/meta key swap
        app.setAttribute(Qt.ApplicationAttribute.AA_DontUseNativeMenuBar)
        app.setAttribute(Qt.ApplicationAttribute.AA_MacDontSwapCtrlAndMeta)
        
        # Disable automatic window tabbing
        if hasattr(app, 'setDesktopFileName'):
            app.setDesktopFileName('network-security-tool')
    
    # Create and show the main window
    window = MainWindow()
    window.show()
    
    sys.exit(app.exec()) 