from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                            QLineEdit, QPushButton, QTableWidget,
                            QTableWidgetItem, QHeaderView, QFrame, QTextEdit,
                            QMessageBox, QComboBox, QGroupBox)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
import dns.resolver
import dns.reversename
import socket
import whois
from typing import Dict, List
import ipaddress

class DNSToolsThread(QThread):
    lookup_complete = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)
    
    def __init__(self, domain: str, lookup_type: str):
        super().__init__()
        self.domain = domain
        self.lookup_type = lookup_type
        
    def run(self):
        try:
            results = {
                "records": [],
                "whois": {},
                "error": None
            }
            
            if self.lookup_type == "A":
                answers = dns.resolver.resolve(self.domain, 'A')
                for rdata in answers:
                    results["records"].append({
                        "type": "A",
                        "value": str(rdata)
                    })
            elif self.lookup_type == "AAAA":
                answers = dns.resolver.resolve(self.domain, 'AAAA')
                for rdata in answers:
                    results["records"].append({
                        "type": "AAAA",
                        "value": str(rdata)
                    })
            elif self.lookup_type == "MX":
                answers = dns.resolver.resolve(self.domain, 'MX')
                for rdata in answers:
                    results["records"].append({
                        "type": "MX",
                        "value": f"{rdata.exchange} (Priority: {rdata.preference})"
                    })
            elif self.lookup_type == "NS":
                answers = dns.resolver.resolve(self.domain, 'NS')
                for rdata in answers:
                    results["records"].append({
                        "type": "NS",
                        "value": str(rdata)
                    })
            elif self.lookup_type == "TXT":
                answers = dns.resolver.resolve(self.domain, 'TXT')
                for rdata in answers:
                    results["records"].append({
                        "type": "TXT",
                        "value": str(rdata)
                    })
            elif self.lookup_type == "PTR":
                try:
                    ip = ipaddress.ip_address(self.domain)
                    ptr_name = dns.reversename.from_address(str(ip))
                    answers = dns.resolver.resolve(ptr_name, 'PTR')
                    for rdata in answers:
                        results["records"].append({
                            "type": "PTR",
                            "value": str(rdata)
                        })
                except ValueError:
                    results["error"] = "Invalid IP address for PTR lookup"
            elif self.lookup_type == "WHOIS":
                try:
                    w = whois.whois(self.domain)
                    results["whois"] = {
                        "domain_name": w.domain_name,
                        "registrar": w.registrar,
                        "whois_server": w.whois_server,
                        "creation_date": str(w.creation_date),
                        "expiration_date": str(w.expiration_date),
                        "updated_date": str(w.updated_date),
                        "name_servers": w.name_servers,
                        "emails": w.emails,
                        "status": w.status
                    }
                except Exception as e:
                    results["error"] = str(e)
                    
            self.lookup_complete.emit(results)
            
        except dns.resolver.NXDOMAIN:
            self.error_occurred.emit(f"Domain {self.domain} does not exist")
        except dns.resolver.NoAnswer:
            self.error_occurred.emit(f"No {self.lookup_type} records found for {self.domain}")
        except dns.resolver.Timeout:
            self.error_occurred.emit("DNS lookup timed out")
        except Exception as e:
            self.error_occurred.emit(str(e))

class DNSToolsTab(QWidget):
    def __init__(self):
        super().__init__()
        self.lookup_thread = None
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Input section
        input_frame = QFrame()
        input_frame.setFrameStyle(QFrame.Shape.StyledPanel | QFrame.Shadow.Raised)
        input_layout = QVBoxLayout(input_frame)
        
        # Domain input
        domain_layout = QHBoxLayout()
        domain_label = QLabel("Domain/IP:")
        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText("e.g., example.com or 8.8.8.8")
        domain_layout.addWidget(domain_label)
        domain_layout.addWidget(self.domain_input)
        input_layout.addLayout(domain_layout)
        
        # Lookup type selection
        type_layout = QHBoxLayout()
        type_label = QLabel("Lookup Type:")
        self.type_combo = QComboBox()
        self.type_combo.addItems(["A", "AAAA", "MX", "NS", "TXT", "PTR", "WHOIS"])
        type_layout.addWidget(type_label)
        type_layout.addWidget(self.type_combo)
        input_layout.addLayout(type_layout)
        
        layout.addWidget(input_frame)
        
        # Control buttons
        button_layout = QHBoxLayout()
        self.lookup_btn = QPushButton("Lookup")
        self.lookup_btn.clicked.connect(self.start_lookup)
        self.clear_btn = QPushButton("Clear")
        self.clear_btn.clicked.connect(self.clear_results)
        button_layout.addWidget(self.lookup_btn)
        button_layout.addWidget(self.clear_btn)
        layout.addLayout(button_layout)
        
        # Results section
        results_frame = QFrame()
        results_frame.setFrameStyle(QFrame.Shape.StyledPanel | QFrame.Shadow.Raised)
        results_layout = QVBoxLayout(results_frame)
        
        # DNS records table
        records_group = QGroupBox("DNS Records")
        records_layout = QVBoxLayout(records_group)
        self.records_table = QTableWidget()
        self.records_table.setColumnCount(2)
        self.records_table.setHorizontalHeaderLabels(["Type", "Value"])
        self.records_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        records_layout.addWidget(self.records_table)
        results_layout.addWidget(records_group)
        
        # WHOIS information
        whois_group = QGroupBox("WHOIS Information")
        whois_layout = QVBoxLayout(whois_group)
        self.whois_text = QTextEdit()
        self.whois_text.setReadOnly(True)
        whois_layout.addWidget(self.whois_text)
        results_layout.addWidget(whois_group)
        
        layout.addWidget(results_frame)
        
        self.setLayout(layout)
        
    def start_lookup(self):
        domain = self.domain_input.text().strip()
        if not domain:
            QMessageBox.warning(self, "Warning", "Please enter a domain or IP address")
            return
            
        lookup_type = self.type_combo.currentText()
        
        try:
            # Clean up any existing thread
            if self.lookup_thread and self.lookup_thread.isRunning():
                self.lookup_thread.wait(1000)
                if self.lookup_thread.isRunning():
                    self.lookup_thread.terminate()
                    
            self.lookup_btn.setEnabled(False)
            self.clear_results()
            
            self.lookup_thread = DNSToolsThread(domain, lookup_type)
            self.lookup_thread.lookup_complete.connect(self.handle_results)
            self.lookup_thread.error_occurred.connect(self.handle_error)
            self.lookup_thread.start()
            
        except Exception as e:
            self.handle_error(str(e))
            
    def handle_results(self, results):
        try:
            if results["error"]:
                self.handle_error(results["error"])
                return
                
            # Update DNS records table
            self.records_table.setRowCount(0)
            for record in results["records"]:
                row = self.records_table.rowCount()
                self.records_table.insertRow(row)
                self.records_table.setItem(row, 0, QTableWidgetItem(record["type"]))
                self.records_table.setItem(row, 1, QTableWidgetItem(record["value"]))
                
            # Update WHOIS information
            if results["whois"]:
                whois_info = []
                for key, value in results["whois"].items():
                    if value:
                        if isinstance(value, list):
                            whois_info.append(f"{key}:")
                            for item in value:
                                whois_info.append(f"  - {item}")
                        else:
                            whois_info.append(f"{key}: {value}")
                self.whois_text.setText("\n".join(whois_info))
            else:
                self.whois_text.clear()
                
            self.lookup_btn.setEnabled(True)
            
        except Exception as e:
            self.handle_error(str(e))
            
    def handle_error(self, error_message):
        QMessageBox.critical(self, "Error", f"An error occurred: {error_message}")
        self.lookup_btn.setEnabled(True)
        
    def clear_results(self):
        self.records_table.setRowCount(0)
        self.whois_text.clear() 