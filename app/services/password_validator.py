from typing import Dict, List, Optional, Tuple
import re
import hashlib
import requests
from passlib.context import CryptContext
import structlog

from app.core.config import settings

logger = structlog.get_logger()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class PasswordValidator:
    """
    Advanced password validation with strength requirements and breach detection
    """
    
    def __init__(self):
        self.min_length = settings.PASSWORD_MIN_LENGTH if hasattr(settings, 'PASSWORD_MIN_LENGTH') else 8
        self.max_length = settings.PASSWORD_MAX_LENGTH if hasattr(settings, 'PASSWORD_MAX_LENGTH') else 128
        self.require_uppercase = settings.PASSWORD_REQUIRE_UPPERCASE if hasattr(settings, 'PASSWORD_REQUIRE_UPPERCASE') else True
        self.require_lowercase = settings.PASSWORD_REQUIRE_LOWERCASE if hasattr(settings, 'PASSWORD_REQUIRE_LOWERCASE') else True
        self.require_numbers = settings.PASSWORD_REQUIRE_NUMBERS if hasattr(settings, 'PASSWORD_REQUIRE_NUMBERS') else True
        self.require_special = settings.PASSWORD_REQUIRE_SPECIAL if hasattr(settings, 'PASSWORD_REQUIRE_SPECIAL') else True
        self.check_breach = settings.PASSWORD_CHECK_BREACH if hasattr(settings, 'PASSWORD_CHECK_BREACH') else True
        self.min_entropy = settings.PASSWORD_MIN_ENTROPY if hasattr(settings, 'PASSWORD_MIN_ENTROPY') else 30
        
        # Common passwords list (can be loaded from file)
        self.common_passwords = {
            "password", "123456", "123456789", "12345678", "12345", "1234567",
            "password123", "Password1", "qwerty", "abc123", "111111", "123123",
            "admin", "letmein", "welcome", "monkey", "dragon", "master", "admin123"
        }
        
        # Special characters
        self.special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?/~`"
    
    def validate_password(
        self, 
        password: str, 
        email: Optional[str] = None,
        username: Optional[str] = None,
        first_name: Optional[str] = None,
        last_name: Optional[str] = None
    ) -> Tuple[bool, List[str]]:
        """
        Validate password against configured requirements
        Returns (is_valid, list_of_errors)
        """
        errors = []
        
        # Basic length validation
        if len(password) < self.min_length:
            errors.append(f"Password must be at least {self.min_length} characters long")
        
        if len(password) > self.max_length:
            errors.append(f"Password must not exceed {self.max_length} characters")
        
        # Character requirements
        if self.require_uppercase and not re.search(r'[A-Z]', password):
            errors.append("Password must contain at least one uppercase letter")
        
        if self.require_lowercase and not re.search(r'[a-z]', password):
            errors.append("Password must contain at least one lowercase letter")
        
        if self.require_numbers and not re.search(r'\d', password):
            errors.append("Password must contain at least one number")
        
        if self.require_special and not any(char in self.special_chars for char in password):
            errors.append("Password must contain at least one special character")
        
        # Check common passwords
        if password.lower() in self.common_passwords:
            errors.append("Password is too common. Please choose a more unique password")
        
        # Check password doesn't contain user information
        if email and email.split('@')[0].lower() in password.lower():
            errors.append("Password should not contain your email address")
        
        if username and username.lower() in password.lower():
            errors.append("Password should not contain your username")
        
        if first_name and len(first_name) > 2 and first_name.lower() in password.lower():
            errors.append("Password should not contain your first name")
        
        if last_name and len(last_name) > 2 and last_name.lower() in password.lower():
            errors.append("Password should not contain your last name")
        
        # Check for repetitive characters
        if self._has_repetitive_chars(password):
            errors.append("Password contains too many repetitive characters")
        
        # Check for sequential characters
        if self._has_sequential_chars(password):
            errors.append("Password contains too many sequential characters")
        
        # Calculate entropy
        entropy = self._calculate_entropy(password)
        if entropy < self.min_entropy:
            errors.append(f"Password is not complex enough (entropy: {entropy:.1f}, required: {self.min_entropy})")
        
        # Check against breach database if enabled
        if self.check_breach and not errors:
            is_breached, breach_count = self._check_haveibeenpwned(password)
            if is_breached:
                if breach_count > 0:
                    errors.append(f"This password has been found in {breach_count:,} data breaches. Please choose a different password")
                else:
                    errors.append("This password has been compromised in a data breach. Please choose a different password")
        
        return (len(errors) == 0, errors)
    
    def _has_repetitive_chars(self, password: str, max_repeat: int = 3) -> bool:
        """Check if password has too many repetitive characters"""
        for i in range(len(password) - max_repeat + 1):
            if password[i:i+max_repeat] == password[i] * max_repeat:
                return True
        return False
    
    def _has_sequential_chars(self, password: str, max_sequence: int = 3) -> bool:
        """Check if password has too many sequential characters"""
        sequences = [
            "abcdefghijklmnopqrstuvwxyz",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "0123456789",
            "qwertyuiop",
            "asdfghjkl",
            "zxcvbnm"
        ]
        
        password_lower = password.lower()
        for seq in sequences:
            for i in range(len(seq) - max_sequence + 1):
                if seq[i:i+max_sequence] in password_lower or seq[i:i+max_sequence][::-1] in password_lower:
                    return True
        return False
    
    def _calculate_entropy(self, password: str) -> float:
        """Calculate password entropy (measure of randomness)"""
        charset_size = 0
        
        if re.search(r'[a-z]', password):
            charset_size += 26
        if re.search(r'[A-Z]', password):
            charset_size += 26
        if re.search(r'\d', password):
            charset_size += 10
        if any(char in self.special_chars for char in password):
            charset_size += len(self.special_chars)
        
        if charset_size == 0:
            return 0
        
        import math
        entropy = len(password) * math.log2(charset_size)
        return entropy
    
    def _check_haveibeenpwned(self, password: str) -> Tuple[bool, int]:
        """
        Check if password has been compromised using HaveIBeenPwned API
        Uses k-anonymity to protect the password
        """
        try:
            # Hash the password with SHA-1
            sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
            prefix = sha1_hash[:5]
            suffix = sha1_hash[5:]
            
            # Query the API with the first 5 characters
            response = requests.get(
                f"https://api.pwnedpasswords.com/range/{prefix}",
                headers={"User-Agent": "FastAPI-Clerk-Auth"},
                timeout=5
            )
            
            if response.status_code != 200:
                logger.warning(f"HaveIBeenPwned API returned status {response.status_code}")
                return (False, 0)
            
            # Check if our hash suffix is in the response
            for line in response.text.splitlines():
                hash_suffix, count = line.split(':')
                if hash_suffix == suffix:
                    return (True, int(count))
            
            return (False, 0)
        
        except Exception as e:
            logger.error(f"Error checking password breach: {str(e)}")
            return (False, 0)
    
    def get_password_strength(self, password: str) -> Dict[str, any]:
        """
        Get detailed password strength analysis
        """
        strength_score = 0
        max_score = 100
        
        # Length scoring (max 25 points)
        if len(password) >= 8:
            strength_score += 10
        if len(password) >= 12:
            strength_score += 10
        if len(password) >= 16:
            strength_score += 5
        
        # Character diversity (max 25 points)
        if re.search(r'[a-z]', password):
            strength_score += 5
        if re.search(r'[A-Z]', password):
            strength_score += 5
        if re.search(r'\d', password):
            strength_score += 5
        if any(char in self.special_chars for char in password):
            strength_score += 10
        
        # Complexity (max 25 points)
        if not self._has_repetitive_chars(password):
            strength_score += 10
        if not self._has_sequential_chars(password):
            strength_score += 10
        if password.lower() not in self.common_passwords:
            strength_score += 5
        
        # Entropy (max 25 points)
        entropy = self._calculate_entropy(password)
        if entropy >= 30:
            strength_score += 10
        if entropy >= 40:
            strength_score += 10
        if entropy >= 50:
            strength_score += 5
        
        # Determine strength level
        if strength_score < 25:
            strength = "Very Weak"
            color = "red"
        elif strength_score < 50:
            strength = "Weak"
            color = "orange"
        elif strength_score < 75:
            strength = "Good"
            color = "yellow"
        elif strength_score < 90:
            strength = "Strong"
            color = "light-green"
        else:
            strength = "Very Strong"
            color = "green"
        
        return {
            "score": strength_score,
            "max_score": max_score,
            "percentage": (strength_score / max_score) * 100,
            "strength": strength,
            "color": color,
            "entropy": entropy,
            "length": len(password),
            "has_lowercase": bool(re.search(r'[a-z]', password)),
            "has_uppercase": bool(re.search(r'[A-Z]', password)),
            "has_numbers": bool(re.search(r'\d', password)),
            "has_special": any(char in self.special_chars for char in password),
            "suggestions": self._get_suggestions(password, strength_score)
        }
    
    def _get_suggestions(self, password: str, score: int) -> List[str]:
        """Get suggestions to improve password strength"""
        suggestions = []
        
        if len(password) < 12:
            suggestions.append("Use at least 12 characters for better security")
        
        if not re.search(r'[A-Z]', password):
            suggestions.append("Add uppercase letters")
        
        if not re.search(r'[a-z]', password):
            suggestions.append("Add lowercase letters")
        
        if not re.search(r'\d', password):
            suggestions.append("Include numbers")
        
        if not any(char in self.special_chars for char in password):
            suggestions.append("Add special characters (!@#$%^&*)")
        
        if self._has_repetitive_chars(password):
            suggestions.append("Avoid repetitive characters")
        
        if self._has_sequential_chars(password):
            suggestions.append("Avoid sequential characters")
        
        if score < 75:
            suggestions.append("Consider using a passphrase with random words")
        
        return suggestions
    
    def hash_password(self, password: str) -> str:
        """Hash a password for storing"""
        return pwd_context.hash(password)
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify a password against a hash"""
        return pwd_context.verify(plain_password, hashed_password)


# Singleton instance
password_validator = PasswordValidator()