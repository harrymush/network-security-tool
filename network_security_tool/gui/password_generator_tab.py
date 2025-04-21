from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                            QLineEdit, QPushButton, QSpinBox, QCheckBox,
                            QTextEdit, QScrollArea, QFrame, QApplication)
from PyQt6.QtCore import Qt
from network_security_tool.generator.password_generator import PasswordGenerator

class PasswordGeneratorTab(QWidget):
    def __init__(self):
        super().__init__()
        self.generator = PasswordGenerator()
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Options section
        options_frame = QFrame()
        options_frame.setFrameStyle(QFrame.Shape.StyledPanel | QFrame.Shadow.Raised)
        options_layout = QVBoxLayout(options_frame)
        
        # Password length
        length_layout = QHBoxLayout()
        length_label = QLabel("Password Length:")
        self.length_spin = QSpinBox()
        self.length_spin.setRange(4, 100)
        self.length_spin.setValue(12)
        length_layout.addWidget(length_label)
        length_layout.addWidget(self.length_spin)
        length_layout.addStretch()
        options_layout.addLayout(length_layout)
        
        # Character options
        self.lowercase_check = QCheckBox("Include Lowercase (a-z)")
        self.uppercase_check = QCheckBox("Include Uppercase (A-Z)")
        self.digits_check = QCheckBox("Include Numbers (0-9)")
        self.special_check = QCheckBox("Include Special Characters (!@#$%^&*)")
        self.similar_check = QCheckBox("Exclude Similar Characters (1, l, I, 0, O)")
        self.ambiguous_check = QCheckBox("Exclude Ambiguous Characters ({, }, |)")
        
        # Set default checked state
        for checkbox in [self.lowercase_check, self.uppercase_check,
                        self.digits_check, self.special_check]:
            checkbox.setChecked(True)
            options_layout.addWidget(checkbox)
            
        options_layout.addWidget(self.similar_check)
        options_layout.addWidget(self.ambiguous_check)
        
        layout.addWidget(options_frame)
        
        # Generate button
        generate_layout = QHBoxLayout()
        self.password_count_spin = QSpinBox()
        self.password_count_spin.setRange(1, 20)
        self.password_count_spin.setValue(5)
        generate_layout.addWidget(QLabel("Number of passwords:"))
        generate_layout.addWidget(self.password_count_spin)
        
        generate_btn = QPushButton("Generate Passwords")
        generate_btn.clicked.connect(self.generate_passwords)
        generate_layout.addWidget(generate_btn)
        generate_layout.addStretch()
        layout.addLayout(generate_layout)
        
        # Results area
        self.results_area = QTextEdit()
        self.results_area.setReadOnly(True)
        self.results_area.setMinimumHeight(200)
        layout.addWidget(self.results_area)
        
        # Copy button
        copy_btn = QPushButton("Copy to Clipboard")
        copy_btn.clicked.connect(self.copy_to_clipboard)
        layout.addWidget(copy_btn)
        
        self.setLayout(layout)
        
    def generate_passwords(self):
        try:
            passwords = self.generator.generate_multiple_passwords(
                count=self.password_count_spin.value(),
                length=self.length_spin.value(),
                use_lowercase=self.lowercase_check.isChecked(),
                use_uppercase=self.uppercase_check.isChecked(),
                use_digits=self.digits_check.isChecked(),
                use_special=self.special_check.isChecked(),
                exclude_similar=self.similar_check.isChecked(),
                exclude_ambiguous=self.ambiguous_check.isChecked()
            )
            
            # Format results
            results = []
            for i, password in enumerate(passwords, 1):
                entropy = self.generator.estimate_strength(password)
                results.append(f"Password {i}:")
                results.append(f"{password}")
                results.append(f"Entropy: {entropy}")
                results.append("")  # Empty line for spacing
                
            self.results_area.setText("\n".join(results))
            
        except ValueError as e:
            self.results_area.setText(f"Error: {str(e)}")
            
    def copy_to_clipboard(self):
        text = self.results_area.toPlainText()
        if text:
            clipboard = QApplication.clipboard()
            clipboard.setText(text) 