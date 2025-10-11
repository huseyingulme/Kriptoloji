"""
Caesar Şifreleme Algoritması
Klasik kaydırma tabanlı şifreleme yöntemi
"""

from .base import TextEncryptionAlgorithm
from typing import Union


class CaesarCipher(TextEncryptionAlgorithm):
    """
    Caesar şifreleme algoritması
    Her harfi belirli bir sayı kadar kaydırarak şifreleme yapar
    """
    
    def __init__(self):
        super().__init__("Caesar")
        self.required_params = ['shift']
    
    def encrypt(self, data: Union[str, bytes], **kwargs) -> Union[str, bytes]:
        """
        Metni Caesar algoritması ile şifreler
        
        Args:
            data: Şifrelenecek metin
            **kwargs: shift (kaydırma miktarı)
            
        Returns:
            Şifrelenmiş metin
        """
        if not self.validate_params(kwargs):
            raise ValueError("Gerekli parametreler eksik: shift")
        
        shift = kwargs['shift']
        text = data if isinstance(data, str) else data.decode('utf-8')
        
        result = []
        for char in text:
            if char.isalpha():
                # Büyük/küçük harf durumunu koru
                is_upper = char.isupper()
                base_char = char.upper()
                
                # ASCII değerini al, A=65'ten başlayarak hesapla
                ascii_val = ord(base_char) - ord('A')
                shifted = (ascii_val + shift) % 26
                
                shifted_char = chr(shifted + ord('A'))
                # Orijinal duruma göre büyük/küçük harf ayarla
                if not is_upper:
                    shifted_char = shifted_char.lower()
                    
                result.append(shifted_char)
            else:
                result.append(char)
        
        return ''.join(result)
    
    def decrypt(self, data: Union[str, bytes], **kwargs) -> Union[str, bytes]:
        """
        Caesar ile şifrelenmiş metni çözer
        
        Args:
            data: Şifrelenmiş metin
            **kwargs: shift (kaydırma miktarı)
            
        Returns:
            Çözülmüş metin
        """
        if not self.validate_params(kwargs):
            raise ValueError("Gerekli parametreler eksik: shift")
        
        # Çözme işlemi için shift değerini tersine çevir
        kwargs['shift'] = -kwargs['shift']
        return self.encrypt(data, **kwargs)
    
    def get_info(self):
        """
        Caesar algoritması hakkında bilgi döndürür
        """
        info = super().get_info()
        info.update({
            'description': 'Klasik kaydırma tabanlı şifreleme. Her harfi belirli bir sayı kadar kaydırır.',
            'required_params': ['shift'],
            'param_descriptions': {
                'shift': 'Kaydırma miktarı (0-25 arası tam sayı)'
            }
        })
        return info
