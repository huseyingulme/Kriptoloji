from .base import TextEncryptionAlgorithm
from typing import Union, Dict
import random
import string

class SubstitutionCipher(TextEncryptionAlgorithm):
    def __init__(self):
        super().__init__("Substitution")
        self.required_params = ['substitution_key']
    
    def _generate_random_key(self) -> str:
        alphabet = list(string.ascii_uppercase)
        random.shuffle(alphabet)
        return ''.join(alphabet)
    
    def _validate_substitution_key(self, key: str) -> bool:
        if len(key) != 26:
            return False
        
        if len(set(key.upper())) != 26:
            return False
        
        return all(c.isalpha() for c in key)
    
    def encrypt(self, data: Union[str, bytes], **kwargs) -> Union[str, bytes]:
        if not self.validate_params(kwargs):
            raise ValueError("Gerekli parametreler eksik: substitution_key")
        
        substitution_key = kwargs['substitution_key'].upper()
        
        if not self._validate_substitution_key(substitution_key):
            raise ValueError("Geçersiz yerine geçme anahtarı. 26 unique harf olmalı.")
        
        text = data if isinstance(data, str) else data.decode('utf-8')
        processed_text = self._prepare_text(text)
        
        result = []
        for char in processed_text:
            if char.isalpha():
                index = ord(char) - ord('A')
                result.append(substitution_key[index])
            else:
                result.append(char)
        
        return ''.join(result)
    
    def decrypt(self, data: Union[str, bytes], **kwargs) -> Union[str, bytes]:
        if not self.validate_params(kwargs):
            raise ValueError("Gerekli parametreler eksik: substitution_key")
        
        substitution_key = kwargs['substitution_key'].upper()
        
        if not self._validate_substitution_key(substitution_key):
            raise ValueError("Geçersiz yerine geçme anahtarı. 26 unique harf olmalı.")
        
        text = data if isinstance(data, str) else data.decode('utf-8')
        processed_text = self._prepare_text(text)
        
        reverse_mapping = {}
        for i, char in enumerate(substitution_key):
            reverse_mapping[char] = chr(i + ord('A'))
        
        result = []
        for char in processed_text:
            if char.isalpha():
                result.append(reverse_mapping[char])
            else:
                result.append(char)
        
        return ''.join(result)
    
    def generate_key(self) -> str:
        return self._generate_random_key()
    
    def get_info(self):
        info = super().get_info()
        info.update({
            'description': 'Harf yerine geçme tabanlı şifreleme. Her harf başka bir harfle değiştirilir.',
            'required_params': ['substitution_key'],
            'param_descriptions': {
                'substitution_key': '26 harfli yerine geçme anahtarı (A-Z harflerinin karışık sırası)'
            }
        })
        return info
