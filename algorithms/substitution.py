"""
Substitution Şifreleme Algoritması
Harf yerine geçme tabanlı şifreleme yöntemi
"""

from .base import TextEncryptionAlgorithm
from typing import Union, Dict
import random
import string


class SubstitutionCipher(TextEncryptionAlgorithm):
    """
    Substitution şifreleme algoritması
    Her harfi başka bir harfle değiştirerek şifreleme yapar
    """
    
    def __init__(self):
        super().__init__("Substitution")
        self.required_params = ['substitution_key']
    
    def _generate_random_key(self) -> str:
        """
        Rastgele bir yerine geçme anahtarı oluşturur
        
        Returns:
            26 harfli rastgele anahtar
        """
        alphabet = list(string.ascii_uppercase)
        random.shuffle(alphabet)
        return ''.join(alphabet)
    
    def _validate_substitution_key(self, key: str) -> bool:
        """
        Yerine geçme anahtarının geçerliliğini kontrol eder
        
        Args:
            key: Kontrol edilecek anahtar
            
        Returns:
            Anahtar geçerliyse True
        """
        if len(key) != 26:
            return False
        
        # Tüm harflerin unique olup olmadığını kontrol et
        if len(set(key.upper())) != 26:
            return False
        
        # Sadece harflerden oluşup oluşmadığını kontrol et
        return all(c.isalpha() for c in key)
    
    def encrypt(self, data: Union[str, bytes], **kwargs) -> Union[str, bytes]:
        """
        Metni Substitution algoritması ile şifreler
        
        Args:
            data: Şifrelenecek metin
            **kwargs: substitution_key (yerine geçme anahtarı)
            
        Returns:
            Şifrelenmiş metin
        """
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
                # A=0, B=1, ... indeksini hesapla ve yerine geç
                index = ord(char) - ord('A')
                result.append(substitution_key[index])
            else:
                result.append(char)
        
        return ''.join(result)
    
    def decrypt(self, data: Union[str, bytes], **kwargs) -> Union[str, bytes]:
        """
        Substitution ile şifrelenmiş metni çözer
        
        Args:
            data: Şifrelenmiş metin
            **kwargs: substitution_key (yerine geçme anahtarı)
            
        Returns:
            Çözülmüş metin
        """
        if not self.validate_params(kwargs):
            raise ValueError("Gerekli parametreler eksik: substitution_key")
        
        substitution_key = kwargs['substitution_key'].upper()
        
        if not self._validate_substitution_key(substitution_key):
            raise ValueError("Geçersiz yerine geçme anahtarı. 26 unique harf olmalı.")
        
        text = data if isinstance(data, str) else data.decode('utf-8')
        processed_text = self._prepare_text(text)
        
        # Çözme için ters mapping oluştur
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
        """
        Rastgele bir yerine geçme anahtarı oluşturur
        
        Returns:
            26 harfli rastgele anahtar
        """
        return self._generate_random_key()
    
    def get_info(self):
        """
        Substitution algoritması hakkında bilgi döndürür
        """
        info = super().get_info()
        info.update({
            'description': 'Harf yerine geçme tabanlı şifreleme. Her harf başka bir harfle değiştirilir.',
            'required_params': ['substitution_key'],
            'param_descriptions': {
                'substitution_key': '26 harfli yerine geçme anahtarı (A-Z harflerinin karışık sırası)'
            }
        })
        return info
