from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                            QLineEdit, QPushButton, QComboBox, QProgressBar,
                            QTextEdit, QFileDialog, QFrame, QApplication,
                            QCheckBox, QSpinBox)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from network_security_tool.cracker.password_cracker import PasswordCracker
import os

class CrackerThread(QThread):
    progress_updated = pyqtSignal(float)
    finished = pyqtSignal(bool, str, float)
    
    def __init__(self, cracker, hash_value, hash_type, dictionary_path,
                 max_length, use_brute_force):
        super().__init__()
        self.cracker = cracker
        self.hash_value = hash_value
        self.hash_type = hash_type
        self.dictionary_path = dictionary_path
        self.max_length = max_length
        self.use_brute_force = use_brute_force
        
    def run(self):
        def progress_callback(progress):
            self.progress_updated.emit(progress)
            
        result = self.cracker.crack_password(
            self.hash_value,
            self.hash_type,
            self.dictionary_path,
            self.max_length,
            self.use_brute_force,
            progress_callback
        )
        self.finished.emit(*result)

class PasswordCrackerTab(QWidget):
    def __init__(self):
        super().__init__()
        self.cracker = PasswordCracker()
        self.cracker_thread = None
        self.dictionaries_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'dictionaries')
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Hash input section
        hash_frame = QFrame()
        hash_frame.setFrameStyle(QFrame.Shape.StyledPanel | QFrame.Shadow.Raised)
        hash_layout = QVBoxLayout(hash_frame)
        
        # Hash value input
        hash_input_layout = QHBoxLayout()
        hash_label = QLabel("Hash Value:")
        self.hash_input = QLineEdit()
        self.hash_input.setPlaceholderText("Enter the hash to crack")
        hash_input_layout.addWidget(hash_label)
        hash_input_layout.addWidget(self.hash_input)
        hash_layout.addLayout(hash_input_layout)
        
        # Hash type selection
        hash_type_layout = QHBoxLayout()
        hash_type_label = QLabel("Hash Type:")
        self.hash_type_combo = QComboBox()
        self.hash_type_combo.addItems(["MD5", "SHA1", "SHA256", "SHA512"])
        hash_type_layout.addWidget(hash_type_label)
        hash_type_layout.addWidget(self.hash_type_combo)
        hash_layout.addLayout(hash_type_layout)
        
        layout.addWidget(hash_frame)
        
        # Attack options section
        options_frame = QFrame()
        options_frame.setFrameStyle(QFrame.Shape.StyledPanel | QFrame.Shadow.Raised)
        options_layout = QVBoxLayout(options_frame)
        
        # Dictionary selection
        dictionary_layout = QHBoxLayout()
        dictionary_label = QLabel("Dictionary:")
        self.dictionary_combo = QComboBox()
        self.load_dictionaries()
        self.dictionary_combo.currentTextChanged.connect(self.on_dictionary_changed)
        dictionary_layout.addWidget(dictionary_label)
        dictionary_layout.addWidget(self.dictionary_combo)
        options_layout.addLayout(dictionary_layout)
        
        # Custom dictionary file selection
        custom_dict_layout = QHBoxLayout()
        self.dictionary_path = QLineEdit()
        self.dictionary_path.setReadOnly(True)
        dictionary_btn = QPushButton("Select Custom Dictionary")
        dictionary_btn.clicked.connect(self.select_dictionary)
        custom_dict_layout.addWidget(QLabel("Custom Dictionary:"))
        custom_dict_layout.addWidget(self.dictionary_path)
        custom_dict_layout.addWidget(dictionary_btn)
        options_layout.addLayout(custom_dict_layout)
        
        # Brute force options
        brute_force_layout = QHBoxLayout()
        self.use_brute_force = QCheckBox("Use Brute Force")
        self.max_length_spin = QSpinBox()
        self.max_length_spin.setRange(1, 10)
        self.max_length_spin.setValue(6)
        brute_force_layout.addWidget(self.use_brute_force)
        brute_force_layout.addWidget(QLabel("Max Length:"))
        brute_force_layout.addWidget(self.max_length_spin)
        options_layout.addLayout(brute_force_layout)
        
        layout.addWidget(options_frame)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        layout.addWidget(self.progress_bar)
        
        # Control buttons
        button_layout = QHBoxLayout()
        self.start_btn = QPushButton("Start Cracking")
        self.start_btn.clicked.connect(self.start_cracking)
        self.stop_btn = QPushButton("Stop")
        self.stop_btn.clicked.connect(self.stop_cracking)
        self.stop_btn.setEnabled(False)
        button_layout.addWidget(self.start_btn)
        button_layout.addWidget(self.stop_btn)
        layout.addLayout(button_layout)
        
        # Results area
        self.results_area = QTextEdit()
        self.results_area.setReadOnly(True)
        self.results_area.setMinimumHeight(200)
        layout.addWidget(self.results_area)
        
        self.setLayout(layout)
        
    def load_dictionaries(self):
        """Load available dictionaries from the dictionaries directory"""
        if os.path.exists(self.dictionaries_dir):
            for file in os.listdir(self.dictionaries_dir):
                if file.endswith('.txt'):
                    self.dictionary_combo.addItem(file)
            self.dictionary_combo.addItem("Custom Dictionary")
            
    def on_dictionary_changed(self, text):
        """Handle dictionary selection change"""
        if text == "Custom Dictionary":
            self.dictionary_path.setEnabled(True)
        else:
            self.dictionary_path.setEnabled(False)
            self.dictionary_path.setText(os.path.join(self.dictionaries_dir, text))
            
    def select_dictionary(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Dictionary File",
            "",
            "Text Files (*.txt);;All Files (*)"
        )
        if file_path:
            self.dictionary_path.setText(file_path)
            self.dictionary_combo.setCurrentText("Custom Dictionary")
            
    def start_cracking(self):
        hash_value = self.hash_input.text().strip()
        if not hash_value:
            self.results_area.setText("Please enter a hash value")
            return
            
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress_bar.setValue(0)
        self.results_area.clear()
        
        dictionary_path = self.dictionary_path.text() if self.dictionary_combo.currentText() == "Custom Dictionary" else os.path.join(self.dictionaries_dir, self.dictionary_combo.currentText())
        
        self.cracker_thread = CrackerThread(
            self.cracker,
            hash_value,
            self.hash_type_combo.currentText().lower(),
            dictionary_path,
            self.max_length_spin.value() if self.use_brute_force.isChecked() else 0,
            self.use_brute_force.isChecked()
        )
        
        self.cracker_thread.progress_updated.connect(self.update_progress)
        self.cracker_thread.finished.connect(self.cracking_finished)
        self.cracker_thread.start()
        
    def stop_cracking(self):
        if self.cracker_thread and self.cracker_thread.isRunning():
            self.cracker.stop_cracking()
            self.cracker_thread.wait()
            
    def update_progress(self, progress):
        self.progress_bar.setValue(int(progress))
        
    def cracking_finished(self, success, result, time_taken):
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        
        if success:
            self.results_area.setText(
                f"Password found: {result}\n"
                f"Time taken: {time_taken:.2f} seconds"
            )
        else:
            self.results_area.setText(
                f"{result}\n"
                f"Time taken: {time_taken:.2f} seconds"
            ) 