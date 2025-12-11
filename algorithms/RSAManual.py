"""
RSA Manual Implementation - Kütüphanesiz RSA Implementasyonu

RSA (Rivest–Shamir–Adleman) - Asimetrik Şifreleme
"""

from algorithms.BaseCipher import BaseCipher
import random
import math
from typing import Tuple, Optional, List


class RSAManual(BaseCipher):
    """
    Manuel RSA implementasyonu (kütüphanesiz).
    
    RSA Özellikleri:
    - Tür: Asimetrik Şifreleme
    - Anahtar Çifti: Public Key (e, n) ve Private Key (d, n)
    """

    def __init__(self, key_size: int = 1024):
        super().__init__()
        self.name = "RSA Manual (Kütüphanesiz)"
        self.description = "RSA Manuel Implementasyonu - Asimetrik Şifreleme (Anahtar Dağıtımı)"
        self.key_type = "keypair"
        self.min_key_length = 1
        self.max_key_length = 10000
        self.key_description = "Anahtar çifti (e,n ve d,n tamsayıları) veya 'generate'"
        self.supports_binary = True
        self.key_size = key_size
        self.public_key: Optional[Tuple[int, int]] = None
        self.private_key: Optional[Tuple[int, int]] = None
        self.generate_key_pair() # İlk anahtar çiftini başlat

    # --- Matematiksel Temeller ---

    def is_prime(self, n: int, k: int = 5) -> bool:
        """Miller-Rabin asallık testi."""
        if n < 2: return False
        if n == 2 or n == 3: return True
        if n % 2 == 0: return False

        r, s = 0, n - 1
        while s % 2 == 0:
            r += 1
            s //= 2
        
        for _ in range(k):
            a = random.randrange(2, n - 1)
            x = pow(a, s, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    def generate_large_prime(self, bits: int) -> int:
        """Büyük asal sayı üret."""
        lower_bound = 1 << (bits - 1)
        upper_bound = (1 << bits) - 1
        while True:
            # Sadece tek sayılarla başla
            num = random.randrange(lower_bound | 1, upper_bound | 1, 2)
            if self.is_prime(num):
                return num

    def gcd(self, a: int, b: int) -> int:
        """Euclidean algoritması ile GCD."""
        while b:
            a, b = b, a % b
        return a

    def mod_inverse(self, a: int, m: int) -> int:
        """Extended Euclidean algoritması ile modüler ters."""
        m0, x0, x1 = m, 0, 1
        while a > 1:
            q = a // m
            m, a = a % m, m
            x0, x1 = x1 - q * x0, x0
        if x1 < 0:
            x1 += m0
        return x1

    # --- RSA Anahtar Üretimi ---

    def generate_key_pair(self) -> Tuple[Tuple[int, int], Tuple[int, int]]:
        """RSA anahtar çifti üret: (e, n) ve (d, n)."""
        
        # Bits / 2, her asalın bit uzunluğu
        p_bits = self.key_size // 2
        q_bits = self.key_size // 2
        
        p = self.generate_large_prime(p_bits)
        q = self.generate_large_prime(q_bits)

        n = p * q
        phi = (p - 1) * (q - 1) # Euler's Totient function

        e = 65537 # Standart Public Exponent
        g = self.gcd(e, phi)
        while g != 1:
            # Gerekli değil ama teorik olarak e'yi yeniden seçme
            e = random.randrange(1, phi)
            g = self.gcd(e, phi)

        d = self.mod_inverse(e, phi) # Private Exponent

        self.public_key = (e, n)
        self.private_key = (d, n)
        return self.public_key, self.private_key
    
    # --- Çekirdek RSA İşlemleri ---

    @staticmethod
    def _encrypt_int(message_int: int, public_key: Tuple[int, int]) -> int:
        """Mesajı şifrele (integer): C = M^e mod n."""
        e, n = public_key
        # pow(base, exp, mod) -> Python'ın hızlı modüler üs alma fonksiyonu
        cipher_int = pow(message_int, e, n)
        return cipher_int

    @staticmethod
    def _decrypt_int(cipher_int: int, private_key: Tuple[int, int]) -> int:
        """Şifreli mesajı çöz (integer): M = C^d mod n."""
        d, n = private_key
        decrypted_int = pow(cipher_int, d, n)
        return decrypted_int

    # --- Şifreleme/Deşifreleme (Bytes) ---

    def _get_active_keys(self, key_string: str, operation: str) -> Tuple[int, int]:
        """İşlem için doğru anahtarı (e, n) veya (d, n) döndürür."""
        if key_string == 'generate' or not key_string:
            if operation == 'ENCRYPT' and self.public_key:
                return self.public_key
            elif operation == 'DECRYPT' and self.private_key:
                return self.private_key
            else:
                 # İlk kullanımda üretir
                self.generate_key_pair()
                return self.public_key if operation == 'ENCRYPT' else self.private_key

        try:
            parts = key_string.split(',')
            if len(parts) == 2:
                k_val = int(parts[0])
                n_val = int(parts[1])
                return (k_val, n_val)
            else:
                raise ValueError("Anahtar formatı: 'k,n' (k=e veya d)")
        except ValueError:
            raise ValueError(f"Geçersiz anahtar formatı: {key_string}")

    def encrypt(self, data: bytes, key: str) -> bytes:
        """RSA ile veriyi şifreler (Public Key ile)."""
        try:
            e, n = self._get_active_keys(key, 'ENCRYPT')
            
            # Şifrelenecek her tamsayı n'den küçük olmalıdır.
            # max_chunk_size: n'den bir byte küçük (padding uygulanmadığı için)
            max_chunk_size = (n.bit_length() - 1) // 8
            
            # RSA çıktısı (cipher_int), n'nin byte uzunluğuna eşittir (veya 1 byte daha az olabilir)
            output_byte_len = n.bit_length() // 8 + (1 if n.bit_length() % 8 != 0 else 0)
            
            encrypted_chunks: List[bytes] = []
            
            for i in range(0, len(data), max_chunk_size):
                chunk = data[i:i + max_chunk_size]
                
                # Mesajı tamsayıya çevir (Big Endian)
                message_int = int.from_bytes(chunk, 'big')
                
                # Şifrele
                cipher_int = self._encrypt_int(message_int, (e, n))
                
                # Tamsayıyı byte'a çevir, çıktıyı n'nin byte uzunluğuna eşitle (Öndeki sıfırları koru)
                cipher_bytes = cipher_int.to_bytes(output_byte_len, 'big')
                
                # Parça uzunluğu (4 byte) + Şifreli veri
                chunk_len_bytes = len(cipher_bytes).to_bytes(4, 'big')
                encrypted_chunks.append(chunk_len_bytes + cipher_bytes)
            
            return b''.join(encrypted_chunks)
        
        except Exception as e:
            raise Exception(f"RSA şifreleme hatası: {str(e)}")

    def decrypt(self, data: bytes, key: str) -> bytes:
        """RSA ile şifrelenmiş veriyi çözer (Private Key ile)."""
        try:
            d, n = self._get_active_keys(key, 'DECRYPT')

            decrypted_chunks: List[bytes] = []
            offset = 0
            
            # Şifreli tamsayının bayt cinsinden beklenen boyutu
            expected_input_len = n.bit_length() // 8 + (1 if n.bit_length() % 8 != 0 else 0)

            while offset < len(data):
                # 4 byte chunk uzunluğunu oku
                if offset + 4 > len(data): break
                chunk_len = int.from_bytes(data[offset:offset+4], 'big')
                offset += 4
                
                # Şifreli chunk'ı oku
                if offset + chunk_len > len(data): break
                cipher_bytes = data[offset:offset + chunk_len]
                offset += chunk_len
                
                # Kontrol: Şifreli parçanın uzunluğu n'nin byte uzunluğuna yakın olmalı
                if chunk_len != expected_input_len:
                    # Bu, anahtarın değiştiğini veya verinin bozuk olduğunu gösterebilir
                    raise ValueError("Şifreli blok uzunluğu anahtar boyutuna uymuyor.")
                
                # Integer'a çevir
                cipher_int = int.from_bytes(cipher_bytes, 'big')
                
                # Çöz
                decrypted_int = self._decrypt_int(cipher_int, (d, n))
                
                # Byte'a çevir (Orijinal *mesaj* chunk boyutu)
                # NOT: Bu manuel implementasyonda orijinal padding boyutu (max_chunk_size) bilinmediği için,
                # çözülen verinin minimum gerekli byte uzunluğuna dönüştürülmesi en iyi tahmindir.
                byte_len = (n.bit_length() - 1) // 8 # max_chunk_size
                decrypted_bytes = decrypted_int.to_bytes(byte_len, 'big').lstrip(b'\x00')
                
                # Orijinal sıfır padding'in kaybolması sorunu manuel RSA'da kaçınılmazdır.
                decrypted_chunks.append(decrypted_bytes)
            
            return b''.join(decrypted_chunks)
        
        except Exception as e:
            raise Exception(f"RSA çözme hatası: {str(e)}")

    def validate_key(self, key: str) -> bool:
        """Anahtarın geçerli olup olmadığını kontrol eder."""
        if not key or key == 'generate':
            return True
        try:
            parts = key.split(',')
            if len(parts) == 2:
                int(parts[0])
                int(parts[1])
                return True
        except:
            pass
        return False

    def get_public_key(self) -> Optional[Tuple[int, int]]:
        """Public key'i döndür."""
        return self.public_key

    def get_private_key(self) -> Optional[Tuple[int, int]]:
        """Private key'i döndür."""
        return self.private_key