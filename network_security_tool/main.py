import sys
from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QIcon
from network_security_tool.gui.main_window import MainWindow
import logging

def setup_logging():
    """Configure logging for the application"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(message)s',
        handlers=[
            logging.StreamHandler()
        ]
    )

def main():
    """Main entry point for the application"""
    # Setup logging
    setup_logging()
    
    # Create the application
    app = QApplication(sys.argv)
    app.setApplicationName("Network Security Tool")
    app.setApplicationDisplayName("Network Security Tool")
    app.setStyle("Fusion")  # Use Fusion style for consistent look across platforms
    
    # Set application-wide settings
    app.setAttribute(Qt.ApplicationAttribute.AA_UseHighDpiPixmaps)
    
    # Create and show the main window
    window = MainWindow()
    window.show()
    
    # Start the application event loop
    sys.exit(app.exec())

if __name__ == "__main__":
    main() 