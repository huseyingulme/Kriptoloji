"""
Substitution Cipher - Alfabe Karıştırma Şifrelemesi

Her harf, önceden belirlenmiş bir alfabe karışımına göre başka bir harfle değiştirilir.
"""

from algorithms.BaseCipher import BaseCipher
import string


class SubstitutionCipher(BaseCipher):
    """
    Substitution Cipher - Alfabe karıştırma tabanlı şifreleme.
    
    Her harf, verilen alfabe karışımına göre değiştirilir.
    """
    
    def __init__(self):
        super().__init__()
        self.name = "Substitution Cipher"
        self.description = "Alfabe karıştırma tabanlı şifreleme - Her harf başka bir harfle değiştirilir"
        self.key_type = "string"
        self.min_key_length = 26
        self.max_key_length = 26
        self.key_description = "26 harflik alfabe karışımı (örn: 'QWERTYUIOPASDFGHJKLZXCVBNM')"
        self.supports_binary = False
    
    def validate_key(self, key: str) -> bool:
        """Anahtarın geçerli olup olmadığını kontrol eder."""
        if not key or len(key) != 26:
            return False
        
        # Tüm harflerin farklı olup olmadığını kontrol et
        if len(set(key.upper())) != 26:
            return False
        
        # Sadece harf içermeli
        if not key.replace(' ', '').isalpha():
            return False
        
        return True
    
    def encrypt(self, data: bytes, key: str) -> bytes:
        """
        Veriyi Substitution Cipher ile şifreler.
        
        Args:
            data: Şifrelenecek veri (bytes)
            key: 26 harflik alfabe karışımı
            
        Returns:
            bytes: Şifrelenmiş veri
        """
        try:
            if not self.validate_key(key):
                raise ValueError("Geçersiz anahtar: 26 harflik alfabe karışımı gerekli")
            
            # Anahtarı büyük harfe çevir
            key_upper = key.upper()
            
            # Normal alfabe
            alphabet = string.ascii_uppercase
            
            # Şifreleme tablosu oluştur
            substitution_map = str.maketrans(alphabet, key_upper)
            
            # Veriyi string'e çevir ve şifrele
            text = data.decode('utf-8', errors='ignore')
            encrypted_text = text.upper().translate(substitution_map)
            
            return encrypted_text.encode('utf-8')
        
        except Exception as e:
            raise Exception(f"Substitution şifreleme hatası: {str(e)}")
    
    def decrypt(self, data: bytes, key: str) -> bytes:
        """
        Substitution Cipher ile şifrelenmiş veriyi çözer.
        
        Args:
            data: Çözülecek veri (bytes)
            key: 26 harflik alfabe karışımı
            
        Returns:
            bytes: Çözülmüş veri
        """
        try:
            if not self.validate_key(key):
                raise ValueError("Geçersiz anahtar: 26 harflik alfabe karışımı gerekli")
            
            # Anahtarı büyük harfe çevir
            key_upper = key.upper()
            
            # Normal alfabe
            alphabet = string.ascii_uppercase
            
            # Çözme tablosu oluştur (ters mapping)
            decryption_map = str.maketrans(key_upper, alphabet)
            
            # Veriyi string'e çevir ve çöz
            text = data.decode('utf-8', errors='ignore')
            decrypted_text = text.upper().translate(decryption_map)
            
            return decrypted_text.encode('utf-8')
        
        except Exception as e:
            raise Exception(f"Substitution çözme hatası: {str(e)}")

