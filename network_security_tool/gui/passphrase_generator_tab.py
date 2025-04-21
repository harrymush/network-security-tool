from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                            QPushButton, QSpinBox, QCheckBox, QTextEdit,
                            QFrame, QComboBox, QApplication)
from PyQt6.QtCore import Qt
from network_security_tool.generator.passphrase_generator import PassphraseGenerator

class PassphraseGeneratorTab(QWidget):
    def __init__(self):
        super().__init__()
        self.generator = PassphraseGenerator()
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Options section
        options_frame = QFrame()
        options_frame.setFrameStyle(QFrame.Shape.StyledPanel | QFrame.Shadow.Raised)
        options_layout = QVBoxLayout(options_frame)
        
        # Word count
        word_layout = QHBoxLayout()
        word_label = QLabel("Number of Words:")
        self.word_count_spin = QSpinBox()
        self.word_count_spin.setRange(2, 10)
        self.word_count_spin.setValue(4)
        word_layout.addWidget(word_label)
        word_layout.addWidget(self.word_count_spin)
        word_layout.addStretch()
        options_layout.addLayout(word_layout)
        
        # Separator
        separator_layout = QHBoxLayout()
        separator_label = QLabel("Word Separator:")
        self.separator_combo = QComboBox()
        self.separator_combo.addItems(["-", "_", ".", " ", ""])
        separator_layout.addWidget(separator_label)
        separator_layout.addWidget(self.separator_combo)
        separator_layout.addStretch()
        options_layout.addLayout(separator_layout)
        
        # Additional options
        self.capitalize_check = QCheckBox("Capitalize Words")
        self.capitalize_check.setChecked(True)
        self.numbers_check = QCheckBox("Add Random Number")
        self.numbers_check.setChecked(True)
        self.special_check = QCheckBox("Add Special Character")
        self.special_check.setChecked(True)
        
        options_layout.addWidget(self.capitalize_check)
        options_layout.addWidget(self.numbers_check)
        options_layout.addWidget(self.special_check)
        
        layout.addWidget(options_frame)
        
        # Generate button
        generate_layout = QHBoxLayout()
        self.passphrase_count_spin = QSpinBox()
        self.passphrase_count_spin.setRange(1, 20)
        self.passphrase_count_spin.setValue(5)
        generate_layout.addWidget(QLabel("Number of passphrases:"))
        generate_layout.addWidget(self.passphrase_count_spin)
        
        generate_btn = QPushButton("Generate Passphrases")
        generate_btn.clicked.connect(self.generate_passphrases)
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
        
    def generate_passphrases(self):
        try:
            passphrases = self.generator.generate_multiple_passphrases(
                count=self.passphrase_count_spin.value(),
                word_count=self.word_count_spin.value(),
                use_numbers=self.numbers_check.isChecked(),
                use_special=self.special_check.isChecked(),
                capitalize=self.capitalize_check.isChecked(),
                separator=self.separator_combo.currentText()
            )
            
            # Format results
            results = []
            for i, passphrase in enumerate(passphrases, 1):
                entropy = self.generator.estimate_strength(passphrase)
                results.append(f"Passphrase {i}:")
                results.append(f"{passphrase}")
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