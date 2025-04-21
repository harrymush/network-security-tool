from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                            QLineEdit, QPushButton, QComboBox, QTextEdit,
                            QGroupBox, QFileDialog, QMessageBox, QProgressBar,
                            QTableWidget, QTableWidgetItem, QHeaderView,
                            QSpinBox, QCheckBox, QFrame, QTabWidget, QApplication,
                            QFormLayout)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from network_security_tool.analysis.password_analyzer import PasswordAnalyzer
from network_security_tool.generator.password_generator import PasswordGenerator
from network_security_tool.generator.passphrase_generator import PassphraseGenerator
from network_security_tool.cracker.password_cracker import PasswordCracker
import threading
import queue
import time
import hashlib
from pathlib import Path

class PasswordToolsTab(QWidget):
    def __init__(self):
        super().__init__()
        # Initialize UI elements that need to be accessed across methods
        self.password_input = None
        self.analysis_results = None
        self.length_spin = None
        self.uppercase_check = None
        self.lowercase_check = None
        self.numbers_check = None
        self.symbols_check = None
        self.exclude_similar = None
        self.exclude_ambiguous = None
        self.generated_password = None
        self.word_count_spin = None
        self.separator_input = None
        self.generated_passphrase = None
        self.hash_input = None
        self.hash_type_combo = None
        self.dictionary_path = None
        self.brute_force_check = None
        self.max_length_spin = None
        self.progress_bar = None
        self.status_label = None
        self.results_table = None
        self.text_input = None
        self.hash_results = None
        
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Create tab widget for different password tools
        self.tab_widget = QTabWidget()
        
        # Add Analysis Tab
        self.tab_widget.addTab(self.create_analysis_tab(), "Password Analysis")
        
        # Add Generator Tab
        self.tab_widget.addTab(self.create_generator_tab(), "Password Generator")
        
        # Add Passphrase Tab
        self.tab_widget.addTab(self.create_passphrase_tab(), "Passphrase Generator")
        
        # Add Cracker Tab
        self.tab_widget.addTab(self.create_cracker_tab(), "Password Cracker")
        
        # Add Hash Converter Tab
        self.tab_widget.addTab(self.create_hash_converter_tab(), "Hash Converter")
        
        layout.addWidget(self.tab_widget)
        self.setLayout(layout)
        
    def create_analysis_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        
        # Input section
        input_group = QGroupBox("Password Input")
        input_layout = QVBoxLayout()
        
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter password to analyze")
        input_layout.addWidget(self.password_input)
        
        analyze_btn = QPushButton("Analyze Password")
        analyze_btn.clicked.connect(self.analyze_password)
        input_layout.addWidget(analyze_btn)
        
        input_group.setLayout(input_layout)
        layout.addWidget(input_group)
        
        # Results section
        results_group = QGroupBox("Analysis Results")
        results_layout = QVBoxLayout()
        
        self.analysis_results = QTextEdit()
        self.analysis_results.setReadOnly(True)
        results_layout.addWidget(self.analysis_results)
        
        results_group.setLayout(results_layout)
        layout.addWidget(results_group)
        
        tab.setLayout(layout)
        return tab
        
    def create_generator_tab(self):
        tab = QWidget()
        main_layout = QVBoxLayout()
        main_layout.setSpacing(10)  # Reduce spacing between elements
        
        # Create a central widget to contain everything
        central_widget = QWidget()
        central_layout = QVBoxLayout()
        central_layout.setSpacing(15)  # Spacing between major sections
        central_widget.setLayout(central_layout)
        
        # Length control section
        length_widget = QWidget()
        length_layout = QHBoxLayout()
        length_layout.setContentsMargins(0, 0, 0, 0)
        
        length_label = QLabel("Password Length:")
        length_label.setMinimumWidth(120)
        self.length_spin = QSpinBox()
        self.length_spin.setRange(8, 128)
        self.length_spin.setValue(16)
        self.length_spin.setMinimumWidth(80)
        
        length_layout.addWidget(length_label)
        length_layout.addWidget(self.length_spin)
        length_layout.addStretch()
        length_widget.setLayout(length_layout)
        central_layout.addWidget(length_widget)
        
        # Character sets section
        char_sets_group = QGroupBox("Character Sets")
        char_sets_layout = QVBoxLayout()
        char_sets_layout.setSpacing(8)  # Reduce spacing between checkboxes
        
        self.uppercase_check = QCheckBox("Uppercase letters (A-Z)")
        self.uppercase_check.setChecked(True)
        self.lowercase_check = QCheckBox("Lowercase letters (a-z)")
        self.lowercase_check.setChecked(True)
        self.numbers_check = QCheckBox("Numbers (0-9)")
        self.numbers_check.setChecked(True)
        self.symbols_check = QCheckBox("Symbols (!@#$%^&*(),.?\":{}|<>)")
        self.symbols_check.setChecked(True)
        
        char_sets_layout.addWidget(self.uppercase_check)
        char_sets_layout.addWidget(self.lowercase_check)
        char_sets_layout.addWidget(self.numbers_check)
        char_sets_layout.addWidget(self.symbols_check)
        char_sets_group.setLayout(char_sets_layout)
        central_layout.addWidget(char_sets_group)
        
        # Additional options section
        options_group = QGroupBox("Additional Options")
        options_layout = QVBoxLayout()
        options_layout.setSpacing(8)
        
        self.exclude_similar = QCheckBox("Exclude similar characters (l, 1, I, O, 0)")
        self.exclude_ambiguous = QCheckBox("Exclude ambiguous symbols ({}, [], (), /\\)")
        
        options_layout.addWidget(self.exclude_similar)
        options_layout.addWidget(self.exclude_ambiguous)
        options_group.setLayout(options_layout)
        central_layout.addWidget(options_group)
        
        # Generate section
        generate_widget = QWidget()
        generate_layout = QVBoxLayout()
        generate_layout.setSpacing(10)
        
        # Buttons
        button_widget = QWidget()
        button_layout = QHBoxLayout()
        button_layout.setContentsMargins(0, 0, 0, 0)
        
        self.generate_btn = QPushButton("Generate Password")
        self.generate_btn.clicked.connect(self.generate_password)
        self.generate_btn.setMinimumWidth(150)
        self.generate_btn.setFixedHeight(32)
        
        self.copy_btn = QPushButton("Copy to Clipboard")
        self.copy_btn.clicked.connect(self.copy_password)
        self.copy_btn.setMinimumWidth(150)
        self.copy_btn.setFixedHeight(32)
        
        button_layout.addStretch()
        button_layout.addWidget(self.generate_btn)
        button_layout.addWidget(self.copy_btn)
        button_layout.addStretch()
        button_widget.setLayout(button_layout)
        generate_layout.addWidget(button_widget)
        
        # Password display
        self.generated_password = QLineEdit()
        self.generated_password.setReadOnly(True)
        self.generated_password.setMinimumHeight(36)
        self.generated_password.setAlignment(Qt.AlignmentFlag.AlignCenter)
        font = self.generated_password.font()
        font.setPointSize(12)
        self.generated_password.setFont(font)
        generate_layout.addWidget(self.generated_password)
        
        generate_widget.setLayout(generate_layout)
        central_layout.addWidget(generate_widget)
        
        # Add note about password strength
        note_label = QLabel("Note: A strong password should be at least 12 characters long and include a mix of character types.")
        note_label.setWordWrap(True)
        note_label.setStyleSheet("color: #666; font-style: italic;")
        note_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        central_layout.addWidget(note_label)
        
        # Set maximum width for the central widget to keep everything compact
        central_widget.setMaximumWidth(600)
        
        # Add the central widget to the main layout with stretches to center it
        main_layout.addStretch()
        main_layout.addWidget(central_widget, alignment=Qt.AlignmentFlag.AlignCenter)
        main_layout.addStretch()
        
        tab.setLayout(main_layout)
        return tab
        
    def create_passphrase_tab(self):
        tab = QWidget()
        main_layout = QVBoxLayout()
        main_layout.setSpacing(10)
        
        # Create a central widget to contain everything
        central_widget = QWidget()
        central_layout = QVBoxLayout()
        central_layout.setSpacing(15)
        central_widget.setLayout(central_layout)
        
        # Word count section
        word_count_widget = QWidget()
        word_count_layout = QHBoxLayout()
        word_count_layout.setContentsMargins(0, 0, 0, 0)
        
        word_count_label = QLabel("Number of Words:")
        word_count_label.setMinimumWidth(120)
        self.word_count_spin = QSpinBox()
        self.word_count_spin.setRange(2, 12)
        self.word_count_spin.setValue(4)
        self.word_count_spin.setMinimumWidth(80)
        
        word_count_layout.addWidget(word_count_label)
        word_count_layout.addWidget(self.word_count_spin)
        word_count_layout.addStretch()
        word_count_widget.setLayout(word_count_layout)
        central_layout.addWidget(word_count_widget)
        
        # Options section
        options_group = QGroupBox("Options")
        options_layout = QVBoxLayout()
        options_layout.setSpacing(8)
        
        self.capitalize_check = QCheckBox("Capitalize First Letter")
        self.capitalize_check.setChecked(True)
        
        self.numbers_check = QCheckBox("Include Numbers")
        self.numbers_check.setChecked(True)
        
        self.special_check = QCheckBox("Include Symbols")
        self.special_check.setChecked(True)
        
        # Separator section
        separator_widget = QWidget()
        separator_layout = QHBoxLayout()
        separator_layout.setContentsMargins(0, 0, 0, 0)
        
        separator_label = QLabel("Separator:")
        separator_label.setMinimumWidth(70)
        
        self.separator_combo = QComboBox()
        self.separator_combo.addItems(["-", "_", ".", " ", "Custom"])
        self.separator_combo.setMinimumWidth(80)
        
        self.separator_input = QLineEdit()
        self.separator_input.setText("-")
        self.separator_input.setMaximumWidth(50)
        self.separator_input.setEnabled(False)
        
        separator_layout.addWidget(separator_label)
        separator_layout.addWidget(self.separator_combo)
        separator_layout.addWidget(self.separator_input)
        separator_layout.addStretch()
        separator_widget.setLayout(separator_layout)
        
        options_layout.addWidget(self.capitalize_check)
        options_layout.addWidget(self.numbers_check)
        options_layout.addWidget(self.special_check)
        options_layout.addWidget(separator_widget)
        
        options_group.setLayout(options_layout)
        central_layout.addWidget(options_group)
        
        # Generate section
        generate_widget = QWidget()
        generate_layout = QVBoxLayout()
        generate_layout.setSpacing(10)
        
        # Buttons
        button_widget = QWidget()
        button_layout = QHBoxLayout()
        button_layout.setContentsMargins(0, 0, 0, 0)
        
        self.generate_passphrase_btn = QPushButton("Generate Passphrase")
        self.generate_passphrase_btn.clicked.connect(self.generate_passphrase)
        self.generate_passphrase_btn.setMinimumWidth(150)
        self.generate_passphrase_btn.setFixedHeight(32)
        
        self.copy_passphrase_btn = QPushButton("Copy to Clipboard")
        self.copy_passphrase_btn.clicked.connect(self.copy_passphrase)
        self.copy_passphrase_btn.setMinimumWidth(150)
        self.copy_passphrase_btn.setFixedHeight(32)
        
        button_layout.addStretch()
        button_layout.addWidget(self.generate_passphrase_btn)
        button_layout.addWidget(self.copy_passphrase_btn)
        button_layout.addStretch()
        button_widget.setLayout(button_layout)
        generate_layout.addWidget(button_widget)
        
        # Passphrase display
        self.generated_passphrase = QLineEdit()
        self.generated_passphrase.setReadOnly(True)
        self.generated_passphrase.setMinimumHeight(36)
        self.generated_passphrase.setAlignment(Qt.AlignmentFlag.AlignCenter)
        font = self.generated_passphrase.font()
        font.setPointSize(12)
        self.generated_passphrase.setFont(font)
        generate_layout.addWidget(self.generated_passphrase)
        
        generate_widget.setLayout(generate_layout)
        central_layout.addWidget(generate_widget)
        
        # Add note about passphrase strength
        note_label = QLabel("Note: A passphrase with 4 or more words provides excellent security while remaining memorable.")
        note_label.setWordWrap(True)
        note_label.setStyleSheet("color: #666; font-style: italic;")
        note_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        central_layout.addWidget(note_label)
        
        # Set maximum width for the central widget to keep everything compact
        central_widget.setMaximumWidth(600)
        
        # Add the central widget to the main layout with stretches to center it
        main_layout.addStretch()
        main_layout.addWidget(central_widget, alignment=Qt.AlignmentFlag.AlignCenter)
        main_layout.addStretch()
        
        tab.setLayout(main_layout)
        return tab
        
    def create_cracker_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        
        # Input section
        input_group = QGroupBox("Hash Input")
        input_layout = QVBoxLayout()
        
        self.hash_input = QLineEdit()
        self.hash_input.setPlaceholderText("Enter hash to crack")
        input_layout.addWidget(self.hash_input)
        
        # Hash type selection
        hash_type_layout = QHBoxLayout()
        hash_type_label = QLabel("Hash Type:")
        self.hash_type_combo = QComboBox()
        self.hash_type_combo.addItems(["MD5", "SHA1", "SHA256", "SHA512"])
        hash_type_layout.addWidget(hash_type_label)
        hash_type_layout.addWidget(self.hash_type_combo)
        input_layout.addLayout(hash_type_layout)
        
        input_group.setLayout(input_layout)
        layout.addWidget(input_group)
        
        # Attack options
        attack_group = QGroupBox("Attack Options")
        attack_layout = QVBoxLayout()
        
        # Dictionary attack
        dictionary_layout = QVBoxLayout()
        
        # Dictionary selection
        dictionary_select_layout = QHBoxLayout()
        dictionary_label = QLabel("Dictionary:")
        self.dictionary_combo = QComboBox()
        self.dictionary_combo.addItems(["rockyou.txt", "common_passwords.txt", "custom"])
        self.dictionary_combo.currentTextChanged.connect(self.handle_dictionary_selection)
        dictionary_select_layout.addWidget(dictionary_label)
        dictionary_select_layout.addWidget(self.dictionary_combo)
        dictionary_layout.addLayout(dictionary_select_layout)
        
        # Custom dictionary path
        custom_dict_layout = QHBoxLayout()
        self.dictionary_btn = QPushButton("Select Custom Dictionary")
        self.dictionary_btn.clicked.connect(self.select_dictionary)
        self.dictionary_btn.setEnabled(False)
        self.dictionary_path = QLineEdit()
        self.dictionary_path.setReadOnly(True)
        self.dictionary_path.setEnabled(False)
        custom_dict_layout.addWidget(self.dictionary_btn)
        custom_dict_layout.addWidget(self.dictionary_path)
        dictionary_layout.addLayout(custom_dict_layout)
        
        attack_layout.addLayout(dictionary_layout)
        
        # Brute force options
        brute_force_layout = QHBoxLayout()
        self.brute_force_check = QCheckBox("Brute Force Attack")
        self.brute_force_check.setChecked(True)
        brute_force_layout.addWidget(self.brute_force_check)
        
        self.max_length_spin = QSpinBox()
        self.max_length_spin.setRange(1, 8)
        self.max_length_spin.setValue(4)
        brute_force_layout.addWidget(QLabel("Max Length:"))
        brute_force_layout.addWidget(self.max_length_spin)
        
        attack_layout.addLayout(brute_force_layout)
        
        attack_group.setLayout(attack_layout)
        layout.addWidget(attack_group)
        
        # Progress section
        progress_group = QGroupBox("Progress")
        progress_layout = QVBoxLayout()
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        progress_layout.addWidget(self.progress_bar)
        
        self.status_label = QLabel("Ready")
        progress_layout.addWidget(self.status_label)
        
        progress_group.setLayout(progress_layout)
        layout.addWidget(progress_group)
        
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
        
        # Results section
        results_group = QGroupBox("Results")
        results_layout = QVBoxLayout()
        
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(2)
        self.results_table.setHorizontalHeaderLabels(["Hash", "Password"])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        results_layout.addWidget(self.results_table)
        
        results_group.setLayout(results_layout)
        layout.addWidget(results_group)
        
        tab.setLayout(layout)
        return tab
        
    def create_hash_converter_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        
        # Input section
        input_group = QGroupBox("Text Input")
        input_layout = QVBoxLayout()
        
        self.text_input = QLineEdit()
        self.text_input.setPlaceholderText("Enter text to hash")
        input_layout.addWidget(self.text_input)
        
        # Hash type selection
        hash_type_layout = QHBoxLayout()
        hash_type_label = QLabel("Hash Type:")
        self.hash_type_combo = QComboBox()
        self.hash_type_combo.addItems(["MD5", "SHA1", "SHA256", "SHA512"])
        hash_type_layout.addWidget(hash_type_label)
        hash_type_layout.addWidget(self.hash_type_combo)
        input_layout.addLayout(hash_type_layout)
        
        # Convert button
        convert_btn = QPushButton("Convert to Hash")
        convert_btn.clicked.connect(self.convert_to_hash)
        input_layout.addWidget(convert_btn)
        
        input_group.setLayout(input_layout)
        layout.addWidget(input_group)
        
        # Results section
        results_group = QGroupBox("Hash Results")
        results_layout = QVBoxLayout()
        
        self.hash_results = QTextEdit()
        self.hash_results.setReadOnly(True)
        results_layout.addWidget(self.hash_results)
        
        # Copy button
        copy_btn = QPushButton("Copy Hash")
        copy_btn.clicked.connect(self.copy_hash)
        results_layout.addWidget(copy_btn)
        
        results_group.setLayout(results_layout)
        layout.addWidget(results_group)
        
        tab.setLayout(layout)
        return tab
        
    def analyze_password(self):
        password = self.password_input.text()
        if not password:
            QMessageBox.warning(self, "Warning", "Please enter a password to analyze")
            return
            
        analyzer = PasswordAnalyzer()
        results = analyzer.analyze_password(password)
        
        # Display results
        self.analysis_results.clear()
        self.analysis_results.append(f"Password: {password}")
        self.analysis_results.append(f"Length: {results['length']}")
        self.analysis_results.append(f"Entropy: {results['entropy']:.2f} bits")
        self.analysis_results.append(f"Strength Score: {results['strength_score']}/100")
        self.analysis_results.append("\nCharacter Types:")
        self.analysis_results.append(f"- Numbers: {'Yes' if results['has_numbers'] else 'No'}")
        self.analysis_results.append(f"- Lowercase Letters: {'Yes' if results['has_lowercase'] else 'No'}")
        self.analysis_results.append(f"- Uppercase Letters: {'Yes' if results['has_uppercase'] else 'No'}")
        self.analysis_results.append(f"- Special Characters: {'Yes' if results['has_special'] else 'No'}")
        self.analysis_results.append("\nCommon Patterns:")
        for pattern in results['common_patterns']:
            self.analysis_results.append(f"- {pattern}")
            
    def generate_password(self):
        length = self.length_spin.value()
        use_uppercase = self.uppercase_check.isChecked()
        use_lowercase = self.lowercase_check.isChecked()
        use_digits = self.numbers_check.isChecked()
        use_special = self.symbols_check.isChecked()
        exclude_similar = self.exclude_similar.isChecked()
        exclude_ambiguous = self.exclude_ambiguous.isChecked()
        
        if not any([use_uppercase, use_lowercase, use_digits, use_special]):
            QMessageBox.warning(self, "Warning", "Please select at least one character set")
            return
            
        if length < 12:
            response = QMessageBox.warning(
                self,
                "Warning",
                "The selected password length is less than the recommended minimum of 12 characters. "
                "Do you want to continue anyway?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
            if response == QMessageBox.StandardButton.No:
                return
        
        generator = PasswordGenerator()
        try:
            password = generator.generate_password(
                length=length,
                use_uppercase=use_uppercase,
                use_lowercase=use_lowercase,
                use_digits=use_digits,
                use_special=use_special,
                exclude_similar=exclude_similar,
                exclude_ambiguous=exclude_ambiguous
            )
            self.generated_password.setText(password)
        except ValueError as e:
            QMessageBox.warning(self, "Error", str(e))
        
    def generate_passphrase(self):
        word_count = self.word_count_spin.value()
        separator = self.separator_input.text()
        use_numbers = self.numbers_check.isChecked()
        use_special = self.special_check.isChecked()
        capitalize = self.capitalize_check.isChecked()
        
        generator = PassphraseGenerator()
        passphrase = generator.generate_passphrase(
            word_count=word_count,
            separator=separator,
            use_numbers=use_numbers,
            use_special=use_special,
            capitalize=capitalize
        )
        
        self.generated_passphrase.setText(passphrase)
        
    def select_dictionary(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Dictionary File",
            "",
            "Text Files (*.txt);;All Files (*)"
        )
        if file_path:
            self.dictionary_path.setText(file_path)
            
    def handle_dictionary_selection(self, text):
        """Handle dictionary selection from dropdown"""
        if text == "custom":
            self.dictionary_btn.setEnabled(True)
            self.dictionary_path.setEnabled(True)
        else:
            self.dictionary_btn.setEnabled(False)
            self.dictionary_path.setEnabled(False)
            self.dictionary_path.clear()
            
    def start_cracking(self):
        hash_value = self.hash_input.text().strip()
        if not hash_value:
            QMessageBox.warning(self, "Warning", "Please enter a hash to crack")
            return
            
        hash_type = self.hash_type_combo.currentText().lower()
        
        # Get dictionary path
        selected_dict = self.dictionary_combo.currentText()
        dictionary_path = None
        
        if selected_dict == "custom":
            dictionary_path = self.dictionary_path.text()
            if not dictionary_path:
                QMessageBox.warning(self, "Warning", "Please select a custom dictionary file")
                return
        else:
            # Use built-in dictionary
            dictionary_path = str(Path(__file__).parent.parent / "dictionaries" / selected_dict)
            if not Path(dictionary_path).exists():
                QMessageBox.warning(self, "Warning", f"Dictionary file {selected_dict} not found")
                return
                
        if not dictionary_path and not self.brute_force_check.isChecked():
            QMessageBox.warning(self, "Warning", "Please select a dictionary or enable brute force")
            return
            
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress_bar.setValue(0)
        self.status_label.setText("Starting...")
        
        # Start cracking in a separate thread
        self.cracker_thread = CrackerThread(
            hash_value,
            hash_type,
            dictionary_path,
            self.brute_force_check.isChecked(),
            self.max_length_spin.value()
        )
        self.cracker_thread.progress_updated.connect(self.update_progress)
        self.cracker_thread.crack_complete.connect(self.handle_crack_complete)
        self.cracker_thread.error_occurred.connect(self.handle_error)
        self.cracker_thread.start()
        
    def stop_cracking(self):
        if hasattr(self, 'cracker_thread'):
            self.cracker_thread.stop()
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            self.status_label.setText("Stopped")
            
    def update_progress(self, value, message):
        self.progress_bar.setValue(value)
        self.status_label.setText(message)
        
    def handle_crack_complete(self, results):
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        
        if results['success']:  # Password found
            self.status_label.setText(f"Password found: {results['password']}")
            self.progress_bar.setValue(100)
            QMessageBox.information(self, "Success", f"Password found: {results['password']}\nTime taken: {results['time_taken']:.2f} seconds")
        else:
            self.status_label.setText("Password not found")
            self.progress_bar.setValue(100)
            QMessageBox.information(self, "Result", "Password not found")
            
    def handle_error(self, error_message):
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_label.setText("Error occurred")
        QMessageBox.critical(self, "Error", f"An error occurred: {error_message}")
        
    def convert_to_hash(self):
        text = self.text_input.text()
        if not text:
            QMessageBox.warning(self, "Warning", "Please enter text to hash")
            return
            
        hash_type = self.hash_type_combo.currentText().lower()
        
        # Create hash object based on selected type
        if hash_type == "md5":
            hash_obj = hashlib.md5()
        elif hash_type == "sha1":
            hash_obj = hashlib.sha1()
        elif hash_type == "sha256":
            hash_obj = hashlib.sha256()
        elif hash_type == "sha512":
            hash_obj = hashlib.sha512()
            
        # Update hash with text
        hash_obj.update(text.encode('utf-8'))
        
        # Get hex digest
        hash_result = hash_obj.hexdigest()
        
        # Display results
        self.hash_results.clear()
        self.hash_results.append(f"Text: {text}")
        self.hash_results.append(f"Hash Type: {hash_type.upper()}")
        self.hash_results.append(f"Hash: {hash_result}")
        
    def copy_hash(self):
        # Get the last line (the hash) from the results
        text = self.hash_results.toPlainText()
        lines = text.split('\n')
        if len(lines) >= 3:  # Ensure we have at least 3 lines (text, type, hash)
            hash_line = lines[-1]  # Get the last line
            hash_value = hash_line.split(': ')[-1]  # Get the part after "Hash: "
            
            # Copy to clipboard
            clipboard = QApplication.clipboard()
            clipboard.setText(hash_value)
            
            QMessageBox.information(self, "Success", "Hash copied to clipboard")
        else:
            QMessageBox.warning(self, "Warning", "No hash to copy")
            
    def copy_password(self):
        """Copy the generated password to clipboard."""
        if self.generated_password.text():
            clipboard = QApplication.clipboard()
            clipboard.setText(self.generated_password.text())
            QMessageBox.information(self, "Success", "Password copied to clipboard")
        else:
            QMessageBox.warning(self, "Warning", "No password to copy")
            
    def copy_passphrase(self):
        """Copy the generated passphrase to clipboard."""
        if self.generated_passphrase.text():
            clipboard = QApplication.clipboard()
            clipboard.setText(self.generated_passphrase.text())
            QMessageBox.information(self, "Success", "Passphrase copied to clipboard")
        else:
            QMessageBox.warning(self, "Warning", "No passphrase to copy")
            
class CrackerThread(QThread):
    progress_updated = pyqtSignal(int, str)
    crack_complete = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)
    
    def __init__(self, hash_value, hash_type, dictionary_path, use_brute_force, max_length):
        super().__init__()
        self.hash_value = hash_value
        self.hash_type = hash_type
        self.dictionary_path = dictionary_path
        self.use_brute_force = use_brute_force
        self.max_length = max_length
        self._is_running = True
        
    def run(self):
        try:
            cracker = PasswordCracker()
            success, result, time_taken = cracker.crack_password(
                self.hash_value,
                self.hash_type,
                self.dictionary_path,
                self.max_length,
                self.use_brute_force,
                self.progress_callback
            )
            
            # Convert tuple result to dictionary
            results_dict = {
                'success': success,
                'password': result if success else None,
                'time_taken': time_taken,
                'message': result if not success else 'Password found'
            }
            
            self.crack_complete.emit(results_dict)
        except Exception as e:
            self.progress_updated.emit(0, f"Error: {str(e)}")
            self.error_occurred.emit(str(e))
            
    def stop(self):
        self._is_running = False
        
    def progress_callback(self, progress, message):
        if self._is_running:
            self.progress_updated.emit(progress, message) 