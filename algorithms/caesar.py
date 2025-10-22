from .base import TextEncryptionAlgorithm
from typing import Union


class CaesarCipher(TextEncryptionAlgorithm):
    def __init__(self):
        super().__init__("Caesar")
        self.required_params = ['shift']
    
    def encrypt(self, data: Union[str, bytes], **kwargs) -> Union[str, bytes]:
        if not self.validate_params(kwargs):
            raise ValueError("Gerekli parametreler eksik: shift")
        
        shift = kwargs['shift']
        text = data if isinstance(data, str) else data.decode('utf-8')
        
        result = []
        for char in text:
            if char.isalpha():
                is_upper = char.isupper()
                base_char = char.upper()
                
                ascii_val = ord(base_char) - ord('A')
                shifted = (ascii_val + shift) % 26
                
                shifted_char = chr(shifted + ord('A'))
                if not is_upper:
                    shifted_char = shifted_char.lower()
                    
                result.append(shifted_char)
            else:
                result.append(char)
        
        return ''.join(result)
    
    def decrypt(self, data: Union[str, bytes], **kwargs) -> Union[str, bytes]:
        if not self.validate_params(kwargs):
            raise ValueError("Gerekli parametreler eksik: shift")
        
        kwargs['shift'] = -kwargs['shift']
        return self.encrypt(data, **kwargs)
    
    def get_info(self):
        info = super().get_info()
        info.update({
            'description': 'Klasik kaydırma tabanlı şifreleme. Her harfi belirli bir sayı kadar kaydırır.',
            'required_params': ['shift'],
            'param_descriptions': {
                'shift': 'Kaydırma miktarı (0-25 arası tam sayı)'
            }
        })
        return info
