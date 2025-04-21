import random
import string
from typing import List

class PasswordGenerator:
    def __init__(self):
        self.lowercase = string.ascii_lowercase
        self.uppercase = string.ascii_uppercase
        self.digits = string.digits
        self.special_chars = "!@#$%^&*(),.?\":{}|<>"
        
    def generate_password(self, length: int = 12, use_lowercase: bool = True,
                         use_uppercase: bool = True, use_digits: bool = True,
                         use_special: bool = True, exclude_similar: bool = False,
                         exclude_ambiguous: bool = False) -> str:
        """Generate a password based on specified criteria"""
        if length < 4:
            raise ValueError("Password length must be at least 4 characters")
            
        # Initialize character pool
        char_pool = ""
        required_chars = []
        
        if use_lowercase:
            chars = self.lowercase
            if exclude_similar:
                chars = chars.replace('l', '').replace('i', '').replace('o', '')
            char_pool += chars
            required_chars.append(random.choice(chars))
            
        if use_uppercase:
            chars = self.uppercase
            if exclude_similar:
                chars = chars.replace('I', '').replace('O', '')
            char_pool += chars
            required_chars.append(random.choice(chars))
            
        if use_digits:
            chars = self.digits
            if exclude_similar:
                chars = chars.replace('0', '').replace('1', '')
            char_pool += chars
            required_chars.append(random.choice(chars))
            
        if use_special:
            chars = self.special_chars
            if exclude_ambiguous:
                chars = chars.replace('{', '').replace('}', '').replace('|', '')
            char_pool += chars
            required_chars.append(random.choice(chars))
            
        if not char_pool:
            raise ValueError("At least one character type must be selected")
            
        # Generate the password
        password_chars = required_chars
        remaining_length = length - len(required_chars)
        
        if remaining_length > 0:
            password_chars.extend(random.choices(char_pool, k=remaining_length))
            
        # Shuffle the password
        random.shuffle(password_chars)
        return ''.join(password_chars)
        
    def generate_multiple_passwords(self, count: int = 5, **kwargs) -> List[str]:
        """Generate multiple passwords with the same criteria"""
        return [self.generate_password(**kwargs) for _ in range(count)]
        
    def estimate_strength(self, password: str) -> float:
        """Estimate the entropy (randomness) of a password"""
        char_space = 0
        if any(c in string.ascii_lowercase for c in password):
            char_space += 26
        if any(c in string.ascii_uppercase for c in password):
            char_space += 26
        if any(c in string.digits for c in password):
            char_space += 10
        if any(c in self.special_chars for c in password):
            char_space += len(self.special_chars)
            
        if char_space == 0:
            return 0
            
        entropy = len(password) * (char_space ** 0.5)
        return round(entropy, 2) 