from .base import TextEncryptionAlgorithm
from typing import Union
import math

class AffineCipher(TextEncryptionAlgorithm):
    def __init__(self):
        super().__init__("Affine")
        self.required_params = ['a', 'b']
    
    def _gcd(self, a: int, b: int) -> int:
        while b:
            a, b = b, a % b
        return a
    
    def _mod_inverse(self, a: int, m: int) -> int:
        if self._gcd(a, m) != 1:
            raise ValueError(f"{a} ve {m} aralarında asal değil, modüler ters bulunamaz")
        
        def extended_gcd(a, b):
            if a == 0:
                return b, 0, 1
            gcd, x1, y1 = extended_gcd(b % a, a)
            x = y1 - (b // a) * x1
            y = x1
            return gcd, x, y
        
        gcd, x, y = extended_gcd(a, m)
        return x % m
    
    def _validate_params(self, a: int, b: int) -> bool:
        if not (1 <= a <= 25):
            return False
        
        if not (0 <= b <= 25):
            return False
        
        return self._gcd(a, 26) == 1
    
    def encrypt(self, data: Union[str, bytes], **kwargs) -> Union[str, bytes]:
        if not self.validate_params(kwargs):
            raise ValueError("Gerekli parametreler eksik: a, b")
        
        a = int(kwargs['a'])
        b = int(kwargs['b'])
        
        if not self._validate_params(a, b):
            raise ValueError("Geçersiz parametreler: a ve 26 aralarında asal olmalı, b 0-25 arası olmalı")
        
        text = data if isinstance(data, str) else data.decode('utf-8')
        
        result = []
        for char in text:
            if char.isalpha():
                is_upper = char.isupper()
                base_char = char.upper()
                
                x = ord(base_char) - ord('A')
                encrypted_x = (a * x + b) % 26
                encrypted_char = chr(encrypted_x + ord('A'))
                
                if not is_upper:
                    encrypted_char = encrypted_char.lower()
                    
                result.append(encrypted_char)
            else:
                result.append(char)
        
        return ''.join(result)
    
    def decrypt(self, data: Union[str, bytes], **kwargs) -> Union[str, bytes]:
        if not self.validate_params(kwargs):
            raise ValueError("Gerekli parametreler eksik: a, b")
        
        a = int(kwargs['a'])
        b = int(kwargs['b'])
        
        if not self._validate_params(a, b):
            raise ValueError("Geçersiz parametreler: a ve 26 aralarında asal olmalı, b 0-25 arası olmalı")
        
        text = data if isinstance(data, str) else data.decode('utf-8')
        
        a_inverse = self._mod_inverse(a, 26)
        
        result = []
        for char in text:
            if char.isalpha():
                is_upper = char.isupper()
                base_char = char.upper()
                
                y = ord(base_char) - ord('A')
                decrypted_x = (a_inverse * (y - b)) % 26
                decrypted_char = chr(decrypted_x + ord('A'))
                
                if not is_upper:
                    decrypted_char = decrypted_char.lower()
                    
                result.append(decrypted_char)
            else:
                result.append(char)
        
        return ''.join(result)
    
    def get_info(self):
        info = super().get_info()
        info.update({
            'description': 'Matematiksel fonksiyon tabanlı şifreleme. E(x) = (ax + b) mod 26 formülü kullanır.',
            'required_params': ['a', 'b'],
            'param_descriptions': {
                'a': 'Çarpan katsayısı (1-25, 26 ile aralarında asal olmalı)',
                'b': 'Toplama katsayısı (0-25)'
            }
        })
        return info
