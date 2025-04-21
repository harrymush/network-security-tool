from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QLineEdit, QPushButton, QTextEdit, QComboBox,
                            QGroupBox, QFormLayout, QCheckBox, QFileDialog,
                            QProgressBar, QMessageBox)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
import socket
import ssl
import json
import csv
import datetime
from OpenSSL import SSL, crypto
import requests
from urllib.parse import urlparse
import concurrent.futures
import re
import os

class SSLScannerThread(QThread):
    progress = pyqtSignal(int)
    result = pyqtSignal(dict)
    error = pyqtSignal(str)
    log = pyqtSignal(str)

    def __init__(self, target, port, options):
        super().__init__()
        self.target = target
        self.port = port
        self.options = options

    def _create_ssl_context(self):
        context = ssl.create_default_context()
        if not self.options.get("verify_cert", True):
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        return context

    def run(self):
        try:
            self.log.emit(f"Starting SSL/TLS analysis for {self.target}:{self.port}")
            
            # Create SSL context with verification settings
            context = self._create_ssl_context()
            if not self.options.get("verify_cert", True):
                self.log.emit("Warning: Certificate verification is disabled")
            
            with socket.create_connection((self.target, self.port)) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    # Get certificate details
                    cert_info = self._get_certificate_details(ssock)
                    
                    # Perform security checks
                    security_checks = self._perform_security_checks()
                    
                    # Advanced features
                    advanced_info = self._get_advanced_info(ssock)
                    
                    # Combine all results
                    results = {
                        "basic_info": {
                            "hostname": self.target,
                            "ip": socket.gethostbyname(self.target),
                            "port": self.port,
                            "protocol": ssock.version(),
                            "cipher_suite": cipher[0],
                            "cipher_bits": cipher[2],
                            "certificate_verified": self.options.get("verify_cert", True)
                        },
                        "certificate": cert_info,
                        "security_checks": security_checks,
                        "advanced_info": advanced_info
                    }
                    
                    self.result.emit(results)
                    
        except Exception as e:
            if "CERTIFICATE_VERIFY_FAILED" in str(e):
                self.log.emit("Certificate verification failed. Try disabling certificate verification in the options.")
            self.error.emit(str(e))

    def _get_certificate_details(self, ssock):
        cert = ssock.getpeercert()
        x509 = ssock.getpeercert(binary_form=True)
        x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, x509)
        
        return {
            "subject": dict(x509.get_subject().get_components()),
            "issuer": dict(x509.get_issuer().get_components()),
            "valid_from": datetime.datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z').isoformat(),
            "valid_until": datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z').isoformat(),
            "serial_number": hex(x509.get_serial_number())[2:],
            "signature_algorithm": x509.get_signature_algorithm().decode(),
            "version": x509.get_version() + 1,
            "extensions": self._get_certificate_extensions(x509)
        }

    def _get_certificate_extensions(self, x509):
        extensions = {}
        for i in range(x509.get_extension_count()):
            ext = x509.get_extension(i)
            extensions[ext.get_short_name().decode()] = ext.__str__()
        return extensions

    def _perform_security_checks(self):
        checks = {
            "tls_versions": self._check_tls_versions(),
            "weak_ciphers": self._check_weak_ciphers(),
            "forward_secrecy": self._check_forward_secrecy(),
            "known_vulnerabilities": self._check_known_vulnerabilities()
        }
        return checks

    def _check_tls_versions(self):
        versions = {}
        for version in [ssl.PROTOCOL_TLSv1, ssl.PROTOCOL_TLSv1_1, ssl.PROTOCOL_TLSv1_2, ssl.PROTOCOL_TLSv1_3]:
            try:
                context = self._create_ssl_context()
                context.protocol = version
                with socket.create_connection((self.target, self.port)) as sock:
                    with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                        versions[ssock.version()] = True
            except:
                versions[version] = False
        return versions

    def _check_weak_ciphers(self):
        weak_ciphers = []
        context = self._create_ssl_context()
        context.set_ciphers('ALL')
        try:
            with socket.create_connection((self.target, self.port)) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cipher = ssock.cipher()
                    if cipher[0] in ['RC4', 'NULL', 'EXPORT']:
                        weak_ciphers.append(cipher[0])
        except:
            pass
        return weak_ciphers

    def _check_forward_secrecy(self):
        try:
            context = self._create_ssl_context()
            with socket.create_connection((self.target, self.port)) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    return 'ECDHE' in ssock.cipher()[0] or 'DHE' in ssock.cipher()[0]
        except:
            return False

    def _check_known_vulnerabilities(self):
        vulnerabilities = {
            "heartbleed": self._check_heartbleed(),
            "poodle": self._check_poodle(),
            "beast": self._check_beast()
        }
        return vulnerabilities

    def _check_heartbleed(self):
        try:
            context = self._create_ssl_context()
            with socket.create_connection((self.target, self.port)) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    return ssock.version() != 'TLSv1.2' and ssock.version() != 'TLSv1.3'
        except:
            return False

    def _check_poodle(self):
        try:
            context = self._create_ssl_context()
            with socket.create_connection((self.target, self.port)) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    return 'CBC' in ssock.cipher()[0]
        except:
            return False

    def _check_beast(self):
        try:
            context = self._create_ssl_context()
            with socket.create_connection((self.target, self.port)) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    return 'CBC' in ssock.cipher()[0] and ssock.version() in ['TLSv1.0', 'SSLv3']
        except:
            return False

    def _get_advanced_info(self, ssock):
        return {
            "session_resumption": self._check_session_resumption(),
            "ocsp_stapling": self._check_ocsp_stapling(),
            "http_headers": self._get_http_headers(),
            "client_cert_support": self._check_client_cert_support()
        }

    def _check_session_resumption(self):
        try:
            context = self._create_ssl_context()
            with socket.create_connection((self.target, self.port)) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    session = ssock.session
                    return session is not None
        except:
            return False

    def _check_ocsp_stapling(self):
        try:
            context = self._create_ssl_context()
            context.verify_mode = ssl.CERT_REQUIRED
            with socket.create_connection((self.target, self.port)) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    return ssock.getpeercert().get('ocsp', []) != []
        except:
            return False

    def _get_http_headers(self):
        try:
            verify = self.options.get("verify_cert", True)
            response = requests.get(f"https://{self.target}:{self.port}", verify=verify, timeout=5)
            return dict(response.headers)
        except:
            return {}

    def _check_client_cert_support(self):
        try:
            context = self._create_ssl_context()
            context.verify_mode = ssl.CERT_REQUIRED
            with socket.create_connection((self.target, self.port)) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    return True
        except:
            return False

class SSLAnalyzerTab(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.scanner_thread = None

    def init_ui(self):
        layout = QVBoxLayout()
        
        # Input section
        input_group = QGroupBox("Target Information")
        input_layout = QFormLayout()
        
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("example.com")
        input_layout.addRow("Target Hostname:", self.target_input)
        
        self.port_input = QLineEdit()
        self.port_input.setText("443")
        input_layout.addRow("Port:", self.port_input)
        
        # Add verify certificate checkbox
        self.verify_cert_check = QCheckBox("Verify Certificate")
        self.verify_cert_check.setChecked(True)
        self.verify_cert_check.setToolTip("Disable this if you encounter certificate verification errors")
        input_layout.addRow("", self.verify_cert_check)
        
        input_group.setLayout(input_layout)
        layout.addWidget(input_group)
        
        # Options section
        options_group = QGroupBox("Scan Options")
        options_layout = QVBoxLayout()
        
        self.check_tls_versions = QCheckBox("Check TLS Version Support")
        self.check_tls_versions.setChecked(True)
        options_layout.addWidget(self.check_tls_versions)
        
        self.check_ciphers = QCheckBox("Check Cipher Suites")
        self.check_ciphers.setChecked(True)
        options_layout.addWidget(self.check_ciphers)
        
        self.check_vulnerabilities = QCheckBox("Check Known Vulnerabilities")
        self.check_vulnerabilities.setChecked(True)
        options_layout.addWidget(self.check_vulnerabilities)
        
        self.check_advanced = QCheckBox("Advanced Features")
        self.check_advanced.setChecked(True)
        options_layout.addWidget(self.check_advanced)
        
        options_group.setLayout(options_layout)
        layout.addWidget(options_group)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        self.scan_button = QPushButton("Start Scan")
        self.scan_button.clicked.connect(self.start_scan)
        button_layout.addWidget(self.scan_button)
        
        self.export_button = QPushButton("Export Results")
        self.export_button.clicked.connect(self.export_results)
        self.export_button.setEnabled(False)
        button_layout.addWidget(self.export_button)
        
        layout.addLayout(button_layout)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # Results display
        self.results_display = QTextEdit()
        self.results_display.setReadOnly(True)
        layout.addWidget(self.results_display)
        
        self.setLayout(layout)
        self.results = None

    def start_scan(self):
        target = self.target_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Error", "Please enter a target hostname")
            return
            
        try:
            port = int(self.port_input.text())
        except ValueError:
            QMessageBox.warning(self, "Error", "Invalid port number")
            return
            
        options = {
            "check_tls_versions": self.check_tls_versions.isChecked(),
            "check_ciphers": self.check_ciphers.isChecked(),
            "check_vulnerabilities": self.check_vulnerabilities.isChecked(),
            "check_advanced": self.check_advanced.isChecked(),
            "verify_cert": self.verify_cert_check.isChecked()
        }
        
        self.scan_button.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.results_display.clear()
        
        self.scanner_thread = SSLScannerThread(target, port, options)
        self.scanner_thread.progress.connect(self.update_progress)
        self.scanner_thread.result.connect(self.display_results)
        self.scanner_thread.error.connect(self.display_error)
        self.scanner_thread.log.connect(self.log_message)
        self.scanner_thread.start()

    def update_progress(self, value):
        self.progress_bar.setValue(value)

    def display_results(self, results):
        self.results = results
        self.scan_button.setEnabled(True)
        self.export_button.setEnabled(True)
        self.progress_bar.setVisible(False)
        
        # Format and display results
        output = "SSL/TLS Analysis Results\n"
        output += "=" * 50 + "\n\n"
        
        # Basic Info
        output += "Basic Information:\n"
        output += "-" * 20 + "\n"
        for key, value in results["basic_info"].items():
            output += f"{key.replace('_', ' ').title()}: {value}\n"
        output += "\n"
        
        # Certificate Details
        output += "Certificate Details:\n"
        output += "-" * 20 + "\n"
        cert = results["certificate"]
        output += f"Subject: {cert['subject']}\n"
        output += f"Issuer: {cert['issuer']}\n"
        output += f"Valid From: {cert['valid_from']}\n"
        output += f"Valid Until: {cert['valid_until']}\n"
        output += f"Signature Algorithm: {cert['signature_algorithm']}\n"
        output += f"Version: {cert['version']}\n"
        output += "\n"
        
        # Security Checks
        output += "Security Checks:\n"
        output += "-" * 20 + "\n"
        checks = results["security_checks"]
        output += "TLS Version Support:\n"
        for version, supported in checks["tls_versions"].items():
            output += f"  {version}: {'Supported' if supported else 'Not Supported'}\n"
        
        if checks["weak_ciphers"]:
            output += "\nWeak Ciphers Detected:\n"
            for cipher in checks["weak_ciphers"]:
                output += f"  - {cipher}\n"
        
        output += f"\nForward Secrecy: {'Supported' if checks['forward_secrecy'] else 'Not Supported'}\n"
        
        vulns = checks["known_vulnerabilities"]
        output += "\nKnown Vulnerabilities:\n"
        for vuln, present in vulns.items():
            output += f"  {vuln}: {'Vulnerable' if present else 'Not Vulnerable'}\n"
        output += "\n"
        
        # Advanced Info
        output += "Advanced Information:\n"
        output += "-" * 20 + "\n"
        advanced = results["advanced_info"]
        output += f"Session Resumption: {'Supported' if advanced['session_resumption'] else 'Not Supported'}\n"
        output += f"OCSP Stapling: {'Supported' if advanced['ocsp_stapling'] else 'Not Supported'}\n"
        output += f"Client Certificate Support: {'Supported' if advanced['client_cert_support'] else 'Not Supported'}\n"
        
        if advanced["http_headers"]:
            output += "\nHTTP Headers:\n"
            for header, value in advanced["http_headers"].items():
                output += f"  {header}: {value}\n"
        
        self.results_display.setText(output)

    def display_error(self, error_message):
        self.scan_button.setEnabled(True)
        self.progress_bar.setVisible(False)
        QMessageBox.critical(self, "Error", f"Scan failed: {error_message}")

    def log_message(self, message):
        current_text = self.results_display.toPlainText()
        self.results_display.setText(current_text + message + "\n")

    def export_results(self):
        if not self.results:
            QMessageBox.warning(self, "Error", "No results to export")
            return
            
        file_dialog = QFileDialog()
        file_dialog.setAcceptMode(QFileDialog.AcceptMode.AcceptSave)
        file_dialog.setNameFilter("JSON Files (*.json);;CSV Files (*.csv);;HTML Files (*.html)")
        
        if file_dialog.exec():
            file_path = file_dialog.selectedFiles()[0]
            file_type = file_dialog.selectedNameFilter()
            
            if "JSON" in file_type:
                with open(file_path, 'w') as f:
                    json.dump(self.results, f, indent=4)
            elif "CSV" in file_type:
                self._export_csv(file_path)
            else:  # HTML
                self._export_html(file_path)
                
            QMessageBox.information(self, "Success", "Results exported successfully")

    def _export_csv(self, file_path):
        with open(file_path, 'w', newline='') as f:
            writer = csv.writer(f)
            
            # Basic Info
            writer.writerow(["Category", "Property", "Value"])
            for key, value in self.results["basic_info"].items():
                writer.writerow(["Basic Info", key, value])
            
            # Certificate Details
            cert = self.results["certificate"]
            writer.writerow(["Certificate", "Subject", str(cert["subject"])])
            writer.writerow(["Certificate", "Issuer", str(cert["issuer"])])
            writer.writerow(["Certificate", "Valid From", cert["valid_from"]])
            writer.writerow(["Certificate", "Valid Until", cert["valid_until"]])
            
            # Security Checks
            checks = self.results["security_checks"]
            for version, supported in checks["tls_versions"].items():
                writer.writerow(["TLS Versions", version, "Supported" if supported else "Not Supported"])
            
            for cipher in checks["weak_ciphers"]:
                writer.writerow(["Weak Ciphers", cipher, "Detected"])
            
            writer.writerow(["Forward Secrecy", "Support", "Supported" if checks["forward_secrecy"] else "Not Supported"])
            
            for vuln, present in checks["known_vulnerabilities"].items():
                writer.writerow(["Vulnerabilities", vuln, "Vulnerable" if present else "Not Vulnerable"])

    def _export_html(self, file_path):
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>SSL/TLS Analysis Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                h1 { color: #333; }
                h2 { color: #444; margin-top: 20px; }
                table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
                .vulnerable { color: red; }
                .secure { color: green; }
            </style>
        </head>
        <body>
        """
        
        html += f"<h1>SSL/TLS Analysis Report for {self.results['basic_info']['hostname']}</h1>"
        html += f"<p>Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>"
        
        # Basic Info
        html += "<h2>Basic Information</h2><table>"
        for key, value in self.results["basic_info"].items():
            html += f"<tr><th>{key.replace('_', ' ').title()}</th><td>{value}</td></tr>"
        html += "</table>"
        
        # Certificate Details
        html += "<h2>Certificate Details</h2><table>"
        cert = self.results["certificate"]
        html += f"<tr><th>Subject</th><td>{cert['subject']}</td></tr>"
        html += f"<tr><th>Issuer</th><td>{cert['issuer']}</td></tr>"
        html += f"<tr><th>Valid From</th><td>{cert['valid_from']}</td></tr>"
        html += f"<tr><th>Valid Until</th><td>{cert['valid_until']}</td></tr>"
        html += f"<tr><th>Signature Algorithm</th><td>{cert['signature_algorithm']}</td></tr>"
        html += f"<tr><th>Version</th><td>{cert['version']}</td></tr>"
        html += "</table>"
        
        # Security Checks
        html += "<h2>Security Checks</h2>"
        checks = self.results["security_checks"]
        
        html += "<h3>TLS Version Support</h3><table>"
        for version, supported in checks["tls_versions"].items():
            status = "Supported" if supported else "Not Supported"
            html += f"<tr><th>{version}</th><td class='{status.lower().replace(' ', '-')}'>{status}</td></tr>"
        html += "</table>"
        
        if checks["weak_ciphers"]:
            html += "<h3>Weak Ciphers Detected</h3><ul>"
            for cipher in checks["weak_ciphers"]:
                html += f"<li class='vulnerable'>{cipher}</li>"
            html += "</ul>"
        
        html += f"<p>Forward Secrecy: <span class='{'secure' if checks['forward_secrecy'] else 'vulnerable'}'>{'Supported' if checks['forward_secrecy'] else 'Not Supported'}</span></p>"
        
        html += "<h3>Known Vulnerabilities</h3><table>"
        for vuln, present in checks["known_vulnerabilities"].items():
            status = "Vulnerable" if present else "Not Vulnerable"
            html += f"<tr><th>{vuln}</th><td class='{status.lower()}'>{status}</td></tr>"
        html += "</table>"
        
        # Advanced Info
        html += "<h2>Advanced Information</h2><table>"
        advanced = self.results["advanced_info"]
        html += f"<tr><th>Session Resumption</th><td>{'Supported' if advanced['session_resumption'] else 'Not Supported'}</td></tr>"
        html += f"<tr><th>OCSP Stapling</th><td>{'Supported' if advanced['ocsp_stapling'] else 'Not Supported'}</td></tr>"
        html += f"<tr><th>Client Certificate Support</th><td>{'Supported' if advanced['client_cert_support'] else 'Not Supported'}</td></tr>"
        html += "</table>"
        
        if advanced["http_headers"]:
            html += "<h3>HTTP Headers</h3><table>"
            for header, value in advanced["http_headers"].items():
                html += f"<tr><th>{header}</th><td>{value}</td></tr>"
            html += "</table>"
        
        html += "</body></html>"
        
        with open(file_path, 'w') as f:
            f.write(html) 