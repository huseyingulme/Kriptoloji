"""
Vigenere Şifreleme Algoritması
Anahtar kelime tabanlı çoklu kaydırma şifrelemesi
"""

from .base import TextEncryptionAlgorithm
from typing import Union


class VigenereCipher(TextEncryptionAlgorithm):
    """
    Vigenere şifreleme algoritması
    Anahtar kelimeye göre her harfi farklı miktarda kaydırır
    """
    
    def __init__(self):
        super().__init__("Vigenere")
        self.required_params = ['keyword']
    
    def _prepare_keyword(self, keyword: str, length: int) -> str:
        """
        Anahtar kelimeyi metin uzunluğuna göre hazırlar
        
        Args:
            keyword: Anahtar kelime
            length: Hedef uzunluk
            
        Returns:
            Hazırlanmış anahtar kelime
        """
        # Anahtar kelimeyi temizle ve büyük harfe çevir
        clean_keyword = ''.join(c.upper() for c in keyword if c.isalpha())
        
        # Anahtar kelimeyi gerekli uzunluğa kadar tekrarla
        if len(clean_keyword) == 0:
            raise ValueError("Anahtar kelime en az bir harf içermelidir")
        
        repeated_keyword = (clean_keyword * ((length // len(clean_keyword)) + 1))[:length]
        return repeated_keyword
    
    def encrypt(self, data: Union[str, bytes], **kwargs) -> Union[str, bytes]:
        """
        Metni Vigenere algoritması ile şifreler
        
        Args:
            data: Şifrelenecek metin
            **kwargs: keyword (anahtar kelime)
            
        Returns:
            Şifrelenmiş metin
        """
        if not self.validate_params(kwargs):
            raise ValueError("Gerekli parametreler eksik: keyword")
        
        keyword = kwargs['keyword']
        text = data if isinstance(data, str) else data.decode('utf-8')
        
        # Sadece alfabetik karakterleri say
        alpha_chars = [c for c in text if c.isalpha()]
        prepared_keyword = self._prepare_keyword(keyword, len(alpha_chars))
        
        result = []
        key_index = 0
        for char in text:
            if char.isalpha():
                # Büyük/küçük harf durumunu koru
                is_upper = char.isupper()
                base_char = char.upper()
                
                # Karakter ve anahtar kelime değerlerini al
                char_val = ord(base_char) - ord('A')
                key_val = ord(prepared_keyword[key_index]) - ord('A')
                
                # Vigenere formülü: (char + key) mod 26
                encrypted_val = (char_val + key_val) % 26
                encrypted_char = chr(encrypted_val + ord('A'))
                
                # Orijinal duruma göre büyük/küçük harf ayarla
                if not is_upper:
                    encrypted_char = encrypted_char.lower()
                    
                result.append(encrypted_char)
                key_index += 1
            else:
                result.append(char)
        
        return ''.join(result)
    
    def decrypt(self, data: Union[str, bytes], **kwargs) -> Union[str, bytes]:
        """
        Vigenere ile şifrelenmiş metni çözer
        
        Args:
            data: Şifrelenmiş metin
            **kwargs: keyword (anahtar kelime)
            
        Returns:
            Çözülmüş metin
        """
        if not self.validate_params(kwargs):
            raise ValueError("Gerekli parametreler eksik: keyword")
        
        keyword = kwargs['keyword']
        text = data if isinstance(data, str) else data.decode('utf-8')
        
        # Sadece alfabetik karakterleri say
        alpha_chars = [c for c in text if c.isalpha()]
        prepared_keyword = self._prepare_keyword(keyword, len(alpha_chars))
        
        result = []
        key_index = 0
        for char in text:
            if char.isalpha():
                # Büyük/küçük harf durumunu koru
                is_upper = char.isupper()
                base_char = char.upper()
                
                # Karakter ve anahtar kelime değerlerini al
                char_val = ord(base_char) - ord('A')
                key_val = ord(prepared_keyword[key_index]) - ord('A')
                
                # Vigenere çözme formülü: (char - key) mod 26
                decrypted_val = (char_val - key_val) % 26
                decrypted_char = chr(decrypted_val + ord('A'))
                
                # Orijinal duruma göre büyük/küçük harf ayarla
                if not is_upper:
                    decrypted_char = decrypted_char.lower()
                    
                result.append(decrypted_char)
                key_index += 1
            else:
                result.append(char)
        
        return ''.join(result)
    
    def get_info(self):
        """
        Vigenere algoritması hakkında bilgi döndürür
        """
        info = super().get_info()
        info.update({
            'description': 'Anahtar kelime tabanlı çoklu kaydırma şifrelemesi. Caesar\'ın gelişmiş versiyonu.',
            'required_params': ['keyword'],
            'param_descriptions': {
                'keyword': 'Anahtar kelime (sadece harflerden oluşmalı)'
            }
        })
        return info
