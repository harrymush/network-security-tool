import random
import string
from typing import List, Optional
import requests
from pathlib import Path

class PassphraseGenerator:
    def __init__(self):
        self.word_list = self._load_word_list()
        self.special_chars = "!@#$%^&*(),.?\":{}|<>"
        
    def _load_word_list(self) -> List[str]:
        """Load a list of common words for passphrase generation"""
        # Try to load from local file first
        word_file = Path(__file__).parent / "wordlist.txt"
        if word_file.exists():
            with open(word_file, 'r') as f:
                return [line.strip() for line in f if line.strip()]
                
        # If no local file, use a basic list
        return [
            "apple", "banana", "carrot", "dog", "elephant", "fish", "giraffe",
            "house", "igloo", "jacket", "kangaroo", "lion", "monkey", "nest",
            "orange", "penguin", "queen", "rabbit", "snake", "tiger", "umbrella",
            "violin", "whale", "xylophone", "yacht", "zebra"
        ]
        
    def generate_passphrase(self, word_count: int = 4, use_numbers: bool = True,
                          use_special: bool = True, capitalize: bool = True,
                          separator: str = "-") -> str:
        """Generate a passphrase based on specified criteria"""
        if word_count < 2:
            raise ValueError("Word count must be at least 2")
            
        # Select random words
        words = random.sample(self.word_list, word_count)
        
        # Apply transformations
        if capitalize:
            words = [word.capitalize() for word in words]
            
        # Add numbers if requested
        if use_numbers:
            # Add a random number between 0-999
            words.append(str(random.randint(0, 999)))
            
        # Add special character if requested
        if use_special:
            words.append(random.choice(self.special_chars))
            
        # Join words with separator
        return separator.join(words)
        
    def generate_multiple_passphrases(self, count: int = 5, **kwargs) -> List[str]:
        """Generate multiple passphrases with the same criteria"""
        return [self.generate_passphrase(**kwargs) for _ in range(count)]
        
    def estimate_strength(self, passphrase: str) -> float:
        """Estimate the entropy (randomness) of a passphrase"""
        # Count the number of words
        words = passphrase.split('-')
        word_count = len([w for w in words if w.lower() in self.word_list])
        
        # Calculate entropy based on word count and character types
        entropy = 0
        
        # Word entropy (assuming 1000 possible words)
        if word_count > 0:
            entropy += word_count * 10  # log2(1000) ≈ 10
            
        # Character entropy
        if any(c.isupper() for c in passphrase):
            entropy += 1
        if any(c.isdigit() for c in passphrase):
            entropy += 4
        if any(c in self.special_chars for c in passphrase):
            entropy += 5
            
        return round(entropy, 2)
        
    def get_word_count(self) -> int:
        """Get the number of available words in the word list"""
        return len(self.word_list) 