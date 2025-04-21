from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                            QLineEdit, QPushButton, QProgressBar, QTextEdit)
from PyQt6.QtCore import Qt
from network_security_tool.analysis.password_analyzer import PasswordAnalyzer

class PasswordAnalysisTab(QWidget):
    def __init__(self):
        super().__init__()
        self.analyzer = PasswordAnalyzer()
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Password input
        input_layout = QHBoxLayout()
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter password to analyze")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        input_layout.addWidget(self.password_input)
        
        analyze_btn = QPushButton("Analyze")
        analyze_btn.clicked.connect(self.analyze_password)
        input_layout.addWidget(analyze_btn)
        
        layout.addLayout(input_layout)
        
        # Strength meter
        self.strength_label = QLabel("Password Strength:")
        layout.addWidget(self.strength_label)
        
        self.strength_bar = QProgressBar()
        self.strength_bar.setRange(0, 100)
        layout.addWidget(self.strength_bar)
        
        # Analysis results
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        layout.addWidget(self.results_text)
        
        self.setLayout(layout)
        
    def analyze_password(self):
        password = self.password_input.text()
        analysis = self.analyzer.analyze_password(password)
        
        if "error" in analysis:
            self.results_text.setText(analysis["error"])
            self.strength_bar.setValue(0)
            return
            
        # Update strength bar
        self.strength_bar.setValue(analysis["strength_score"])
        
        # Format results
        results = []
        results.append(f"Length: {analysis['length']} characters")
        results.append(f"Contains numbers: {'Yes' if analysis['has_numbers'] else 'No'}")
        results.append(f"Contains lowercase: {'Yes' if analysis['has_lowercase'] else 'No'}")
        results.append(f"Contains uppercase: {'Yes' if analysis['has_uppercase'] else 'No'}")
        results.append(f"Contains special characters: {'Yes' if analysis['has_special'] else 'No'}")
        results.append(f"Entropy: {analysis['entropy']}")
        results.append(f"Strength Score: {analysis['strength_score']}/100")
        
        if analysis['common_patterns']:
            results.append("\nCommon patterns found:")
            for pattern in analysis['common_patterns']:
                results.append(f"- {pattern}")
                
        self.results_text.setText("\n".join(results)) 