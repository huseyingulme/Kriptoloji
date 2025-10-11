"""
Affine Şifreleme Algoritması
Matematiksel fonksiyon tabanlı şifreleme yöntemi
"""

from .base import TextEncryptionAlgorithm
from typing import Union
import math


class AffineCipher(TextEncryptionAlgorithm):
    """
    Affine şifreleme algoritması
    E(x) = (ax + b) mod 26 formülü ile şifreleme yapar
    """
    
    def __init__(self):
        super().__init__("Affine")
        self.required_params = ['a', 'b']
    
    def _gcd(self, a: int, b: int) -> int:
        """
        İki sayının en büyük ortak bölenini hesaplar
        
        Args:
            a: İlk sayı
            b: İkinci sayı
            
        Returns:
            En büyük ortak bölen
        """
        while b:
            a, b = b, a % b
        return a
    
    def _mod_inverse(self, a: int, m: int) -> int:
        """
        a sayısının m modülüne göre tersini hesaplar
        
        Args:
            a: Tersi bulunacak sayı
            m: Modül değeri
            
        Returns:
            Modüler ters
        """
        if self._gcd(a, m) != 1:
            raise ValueError(f"{a} ve {m} aralarında asal değil, modüler ters bulunamaz")
        
        # Extended Euclidean Algorithm
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
        """
        Affine parametrelerinin geçerliliğini kontrol eder
        
        Args:
            a: Çarpan katsayısı
            b: Toplama katsayısı
            
        Returns:
            Parametreler geçerliyse True
        """
        if not (1 <= a <= 25):
            return False
        
        if not (0 <= b <= 25):
            return False
        
        # a ve 26 aralarında asal olmalı
        return self._gcd(a, 26) == 1
    
    def encrypt(self, data: Union[str, bytes], **kwargs) -> Union[str, bytes]:
        """
        Metni Affine algoritması ile şifreler
        
        Args:
            data: Şifrelenecek metin
            **kwargs: a (çarpan), b (toplama katsayısı)
            
        Returns:
            Şifrelenmiş metin
        """
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
                # Büyük/küçük harf durumunu koru
                is_upper = char.isupper()
                base_char = char.upper()
                
                # Harfi sayıya çevir (A=0, B=1, ...)
                x = ord(base_char) - ord('A')
                # Affine formülü: E(x) = (ax + b) mod 26
                encrypted_x = (a * x + b) % 26
                encrypted_char = chr(encrypted_x + ord('A'))
                
                # Orijinal duruma göre büyük/küçük harf ayarla
                if not is_upper:
                    encrypted_char = encrypted_char.lower()
                    
                result.append(encrypted_char)
            else:
                result.append(char)
        
        return ''.join(result)
    
    def decrypt(self, data: Union[str, bytes], **kwargs) -> Union[str, bytes]:
        """
        Affine ile şifrelenmiş metni çözer
        
        Args:
            data: Şifrelenmiş metin
            **kwargs: a (çarpan), b (toplama katsayısı)
            
        Returns:
            Çözülmüş metin
        """
        if not self.validate_params(kwargs):
            raise ValueError("Gerekli parametreler eksik: a, b")
        
        a = int(kwargs['a'])
        b = int(kwargs['b'])
        
        if not self._validate_params(a, b):
            raise ValueError("Geçersiz parametreler: a ve 26 aralarında asal olmalı, b 0-25 arası olmalı")
        
        text = data if isinstance(data, str) else data.decode('utf-8')
        
        # a'nın modüler tersini hesapla
        a_inverse = self._mod_inverse(a, 26)
        
        result = []
        for char in text:
            if char.isalpha():
                # Büyük/küçük harf durumunu koru
                is_upper = char.isupper()
                base_char = char.upper()
                
                # Şifrelenmiş harfi sayıya çevir
                y = ord(base_char) - ord('A')
                # Affine çözme formülü: D(y) = a^(-1)(y - b) mod 26
                decrypted_x = (a_inverse * (y - b)) % 26
                decrypted_char = chr(decrypted_x + ord('A'))
                
                # Orijinal duruma göre büyük/küçük harf ayarla
                if not is_upper:
                    decrypted_char = decrypted_char.lower()
                    
                result.append(decrypted_char)
            else:
                result.append(char)
        
        return ''.join(result)
    
    def get_info(self):
        """
        Affine algoritması hakkında bilgi döndürür
        """
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
