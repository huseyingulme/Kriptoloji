from .base import TextEncryptionAlgorithm
from typing import Union

class VigenereCipher(TextEncryptionAlgorithm):
    def __init__(self):
        super().__init__("Vigenere")
        self.required_params = ['keyword']
    
    def _prepare_keyword(self, keyword: str, length: int) -> str:
        clean_keyword = ''.join(c.upper() for c in keyword if c.isalpha())
        
        if len(clean_keyword) == 0:
            raise ValueError("Anahtar kelime en az bir harf içermelidir")
        
        repeated_keyword = (clean_keyword * ((length // len(clean_keyword)) + 1))[:length]
        return repeated_keyword
    
    def encrypt(self, data: Union[str, bytes], **kwargs) -> Union[str, bytes]:
        if not self.validate_params(kwargs):
            raise ValueError("Gerekli parametreler eksik: keyword")
        
        keyword = kwargs['keyword']
        text = data if isinstance(data, str) else data.decode('utf-8')
        
        alpha_chars = [c for c in text if c.isalpha()]
        prepared_keyword = self._prepare_keyword(keyword, len(alpha_chars))
        
        result = []
        key_index = 0
        for char in text:
            if char.isalpha():
                is_upper = char.isupper()
                base_char = char.upper()
                
                char_val = ord(base_char) - ord('A')
                key_val = ord(prepared_keyword[key_index]) - ord('A')
                
                encrypted_val = (char_val + key_val) % 26
                encrypted_char = chr(encrypted_val + ord('A'))
                
                if not is_upper:
                    encrypted_char = encrypted_char.lower()
                    
                result.append(encrypted_char)
                key_index += 1
            else:
                result.append(char)
        
        return ''.join(result)
    
    def decrypt(self, data: Union[str, bytes], **kwargs) -> Union[str, bytes]:
        if not self.validate_params(kwargs):
            raise ValueError("Gerekli parametreler eksik: keyword")
        
        keyword = kwargs['keyword']
        text = data if isinstance(data, str) else data.decode('utf-8')
        
        alpha_chars = [c for c in text if c.isalpha()]
        prepared_keyword = self._prepare_keyword(keyword, len(alpha_chars))
        
        result = []
        key_index = 0
        for char in text:
            if char.isalpha():
                is_upper = char.isupper()
                base_char = char.upper()
                
                char_val = ord(base_char) - ord('A')
                key_val = ord(prepared_keyword[key_index]) - ord('A')
                
                decrypted_val = (char_val - key_val) % 26
                decrypted_char = chr(decrypted_val + ord('A'))
                
                if not is_upper:
                    decrypted_char = decrypted_char.lower()
                    
                result.append(decrypted_char)
                key_index += 1
            else:
                result.append(char)
        
        return ''.join(result)
    
    def get_info(self):
        info = super().get_info()
        info.update({
            'description': 'Anahtar kelime tabanlı çoklu kaydırma şifrelemesi. Caesar\'ın gelişmiş versiyonu.',
            'required_params': ['keyword'],
            'param_descriptions': {
                'keyword': 'Anahtar kelime (sadece harflerden oluşmalı)'
            }
        })
        return info
