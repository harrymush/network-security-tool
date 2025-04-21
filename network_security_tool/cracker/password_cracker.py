import hashlib
import itertools
import string
from typing import List, Optional, Tuple, Callable
from pathlib import Path
import threading
import queue
import time
import logging

class PasswordCracker:
    def __init__(self):
        self.stop_event = threading.Event()
        self.progress_queue = queue.Queue()
        self.logger = logging.getLogger(__name__)
        
    def crack_password(self, hash_value: str, hash_type: str = "md5",
                      dictionary_path: Optional[str] = None,
                      max_length: int = 8, use_brute_force: bool = False,
                      progress_callback: Optional[Callable] = None) -> Tuple[bool, str, float]:
        """Attempt to crack a password hash using dictionary and/or brute force"""
        self.stop_event.clear()
        start_time = time.time()
        
        # Validate hash type
        hash_func = self._get_hash_function(hash_type)
        if not hash_func:
            return False, f"Unsupported hash type: {hash_type}", 0
            
        # Try dictionary attack first if dictionary is provided
        if dictionary_path:
            if not Path(dictionary_path).exists():
                return False, f"Dictionary file not found: {dictionary_path}", 0
            try:
                result = self._dictionary_attack(hash_value, hash_func, dictionary_path, progress_callback)
                if result[0]:  # If password found
                    return True, result[1], time.time() - start_time
            except Exception as e:
                self.logger.error(f"Dictionary attack failed: {str(e)}")
                return False, f"Dictionary attack failed: {str(e)}", 0
                
        # If dictionary attack failed and brute force is enabled
        if use_brute_force:
            try:
                result = self._brute_force_attack(hash_value, hash_func, max_length, progress_callback)
                if result[0]:  # If password found
                    return True, result[1], time.time() - start_time
            except Exception as e:
                self.logger.error(f"Brute force attack failed: {str(e)}")
                return False, f"Brute force attack failed: {str(e)}", 0
                
        return False, "Password not found", time.time() - start_time
        
    def stop_cracking(self):
        """Stop the current cracking operation"""
        self.stop_event.set()
        
    def _get_hash_function(self, hash_type: str) -> Optional[Callable]:
        """Get the appropriate hash function based on hash type"""
        hash_functions = {
            "md5": hashlib.md5,
            "sha1": hashlib.sha1,
            "sha256": hashlib.sha256,
            "sha512": hashlib.sha512
        }
        return hash_functions.get(hash_type.lower())
        
    def _dictionary_attack(self, hash_value: str, hash_func: Callable,
                         dictionary_path: str,
                         progress_callback: Optional[Callable]) -> Tuple[bool, str]:
        """Attempt to crack password using dictionary attack"""
        try:
            # Count total lines efficiently
            with open(dictionary_path, 'r', encoding='utf-8', errors='ignore') as f:
                total_lines = sum(1 for _ in f)
            
            processed_lines = 0
            with open(dictionary_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    if self.stop_event.is_set():
                        return False, "Operation stopped"
                        
                    password = line.strip()
                    if not password:  # Skip empty lines
                        continue
                        
                    if self._check_password(password, hash_value, hash_func):
                        return True, password
                        
                    processed_lines += 1
                    if progress_callback and processed_lines % 1000 == 0:
                        progress = (processed_lines / total_lines) * 100
                        progress_callback(progress)
                        
            return False, "Password not found in dictionary"
        except Exception as e:
            self.logger.error(f"Error in dictionary attack: {str(e)}")
            raise
            
    def _brute_force_attack(self, hash_value: str, hash_func: Callable,
                          max_length: int,
                          progress_callback: Optional[Callable]) -> Tuple[bool, str]:
        """Attempt to crack password using brute force attack"""
        try:
            chars = string.ascii_letters + string.digits + string.punctuation
            # Calculate total combinations more efficiently
            total_combinations = sum(len(chars) ** i for i in range(1, min(max_length + 1, 5)))
            processed_combinations = 0
            
            for length in range(1, max_length + 1):
                for combination in itertools.product(chars, repeat=length):
                    if self.stop_event.is_set():
                        return False, "Operation stopped"
                        
                    password = ''.join(combination)
                    if self._check_password(password, hash_value, hash_func):
                        return True, password
                        
                    processed_combinations += 1
                    if progress_callback and processed_combinations % 1000 == 0:
                        # Use a more accurate progress calculation for longer passwords
                        if length <= 4:
                            progress = (processed_combinations / total_combinations) * 100
                        else:
                            # For longer passwords, use a simpler progress indicator
                            progress = (length / max_length) * 100
                        progress_callback(progress)
                        
            return False, "Password not found"
        except Exception as e:
            self.logger.error(f"Error in brute force attack: {str(e)}")
            raise
            
    def _check_password(self, password: str, hash_value: str,
                       hash_func: Callable) -> bool:
        """Check if a password matches the given hash"""
        try:
            # Handle potential encoding issues
            password_bytes = password.encode('utf-8', errors='ignore')
            return hash_func(password_bytes).hexdigest().lower() == hash_value.lower()
        except UnicodeEncodeError:
            return False
        except Exception as e:
            self.logger.error(f"Error checking password: {str(e)}")
            return False 