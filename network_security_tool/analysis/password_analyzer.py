import re
from typing import Dict, List, Tuple

class PasswordAnalyzer:
    def __init__(self):
        self.common_patterns = [
            r'\d+',  # Numbers
            r'[a-z]+',  # Lowercase letters
            r'[A-Z]+',  # Uppercase letters
            r'[!@#$%^&*(),.?":{}|<>]',  # Special characters
        ]
        
    def analyze_password(self, password: str) -> Dict:
        """Analyze a password and return its characteristics"""
        if not password:
            return {"error": "Password cannot be empty"}
            
        analysis = {
            "length": len(password),
            "has_numbers": bool(re.search(r'\d', password)),
            "has_lowercase": bool(re.search(r'[a-z]', password)),
            "has_uppercase": bool(re.search(r'[A-Z]', password)),
            "has_special": bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password)),
            "common_patterns": self._find_common_patterns(password),
            "entropy": self._calculate_entropy(password),
            "strength_score": self._calculate_strength_score(password)
        }
        
        return analysis
    
    def _find_common_patterns(self, password: str) -> List[str]:
        """Find common patterns in the password"""
        patterns = []
        for pattern in self.common_patterns:
            if re.search(pattern, password):
                patterns.append(pattern)
        return patterns
    
    def _calculate_entropy(self, password: str) -> float:
        """Calculate password entropy"""
        char_set = 0
        if re.search(r'[a-z]', password):
            char_set += 26
        if re.search(r'[A-Z]', password):
            char_set += 26
        if re.search(r'\d', password):
            char_set += 10
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            char_set += 32
            
        if char_set == 0:
            return 0
            
        entropy = len(password) * (char_set ** 0.5)
        return round(entropy, 2)
    
    def _calculate_strength_score(self, password: str) -> int:
        """Calculate a strength score from 0 to 100"""
        score = 0
        
        # Length score (max 40 points)
        length = len(password)
        if length >= 12:
            score += 40
        elif length >= 8:
            score += 30
        elif length >= 6:
            score += 20
        else:
            score += 10
            
        # Character variety score (max 60 points)
        if re.search(r'[a-z]', password):
            score += 10
        if re.search(r'[A-Z]', password):
            score += 10
        if re.search(r'\d', password):
            score += 10
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 10
        if len(set(password)) >= len(password) * 0.8:  # High uniqueness
            score += 20
            
        return min(score, 100)  # Cap at 100 