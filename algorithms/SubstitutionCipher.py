from algorithms.BaseCipher import BaseCipher
import string

class SubstitutionCipher(BaseCipher):
    """
    Substitution Cipher - Alfabe karıştırma tabanlı şifreleme.
    Her harf, verilen 26 harflik alfabe karışımına göre başka harfe dönüştürülür.
    """

    def __init__(self):
        super().__init__()
        self.name = "Substitution Cipher"
        self.supports_binary = False
        self.description = "Alfabe karıştırma tabanlı şifreleme - Her harf başka bir harfle değiştirilir"
        self.key_type = "string"
        self.min_key_length = 26
        self.max_key_length = 26
        self.key_description = "26 harflik alfabe karışımı (örn: QWERTYUIOPASDFGHJKLZXCVBNM)"
        self.supports_binary = False

    def validate_key(self, key: str) -> bool:
        """Girilen anahtarın geçerli olup olmadığını doğrular."""
        if not key or len(key) != 26:
            return False
        key = key.upper()
        if not key.isalpha():
            return False
        if len(set(key)) != 26:
            return False
        return True

    def encrypt(self, data: bytes, key: str) -> bytes:
        """Metni substitution cipher ile şifreler."""
        try:
            if not self.validate_key(key):
                raise ValueError("Geçersiz anahtar: 26 harflik benzersiz alfabe karışımı gerekli")

            alphabet = string.ascii_uppercase
            key = key.upper()
            text = data.decode('utf-8', errors='ignore').upper()

            # Şifreleme tablosu
            encrypt_map = str.maketrans(alphabet, key)
            encrypted = text.translate(encrypt_map)
            return encrypted.encode('utf-8')

        except Exception as e:
            raise Exception(f"Substitution şifreleme hatası: {str(e)}")

    def decrypt(self, data: bytes, key: str) -> bytes:
        """Substitution cipher ile şifrelenmiş metni çözer."""
        try:
            if not self.validate_key(key):
                raise ValueError("Geçersiz anahtar: 26 harflik benzersiz alfabe karışımı gerekli")

            alphabet = string.ascii_uppercase
            key = key.upper()
            text = data.decode('utf-8', errors='ignore').upper()

            # Çözme tablosu (ters çeviri)
            decrypt_map = str.maketrans(key, alphabet)
            decrypted = text.translate(decrypt_map)
            return decrypted.encode('utf-8')

        except Exception as e:
            raise Exception(f"Substitution çözme hatası: {str(e)}")