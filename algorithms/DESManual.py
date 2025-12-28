from algorithms.BaseCipher import BaseCipher
import os
import hashlib
from typing import List, Tuple

class DESManual(BaseCipher):
    """
    🔐 [Algorithm Overview]
    Type: Symmetric Block Cipher (FIPS 46-3)
    Mode: DES / CBC (Cipher Block Chaining)
    Manual Implementation: All 16 rounds, S-Boxes, Permutations (IP, FP, E, P), 
    and Key Schedule are implemented manually.

    🔑 [Key Management]
    - Uses a 56-bit effective key.
    - Integrated with the centralized Security module for key distribution.

    🧮 [Mathematical Foundation]
    - Feistel Network structure.
    - Uses non-linear substitution boxes (S-Boxes) and bit-level permutations.
    """

    block_size = 8

    # --- DES Sabit Tabloları ---
    # Not: Tüm tablolar 1'den başlar, Python'da 0-bazlı hale getirilir.
    _IP = [
        58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7
    ]
    _FP = [
        40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25
    ]
    _E = [
        32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11,
        12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21,
        22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1
    ] # 32-bit'ten 48-bit'e genişletme
    _P = [
        16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
        2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25
    ] # 32-bit permütasyonu
    _S_BOXES = [ 
        # S-Box içeriği doğru kabul edilmiştir.
        [
             [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
             [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
             [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
             [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
        ],
        [
             [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
             [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
             [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
             [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
        ],
        [
             [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
             [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
             [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
             [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
        ],
        [
             [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
             [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
             [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
             [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
        ],
        [
             [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
             [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
             [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
             [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
        ],
        [
             [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
             [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
             [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
             [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
        ],
        [
             [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
             [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
             [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
             [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
        ],
        [
             [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
             [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
             [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
             [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
        ]
    ]
    _PC1 = [
        57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2,
        59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39,
        31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37,
        29, 21, 13, 5, 28, 20, 12, 4
    ] # 64-bit'ten 56-bit'e (Parite bitleri atılır)
    _PC2 = [
        14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4,
        26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40,
        51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
    ] # 56-bit'ten 48-bit'e (Round Key üretimi)
    _SHIFT_SCHEDULE = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1] # Tur başına sola kaydırma miktarı

    def __init__(self):
        super().__init__()
        self.name = "DES Manual (Kütüphanesiz)"
        self.description = "DES Manuel Implementasyonu - Feistel Ağı (CBC Modu)"
        self.key_type = "string"
        self.min_key_length = 1
        self.max_key_length = 200
        self.key_description = "Anahtar (MD5 ile 8 byte'a türetilir)"
        self.supports_binary = True

    # --- Yardımcı/Temel DES Metotları ---

    @staticmethod
    def _derive_key(key: str) -> bytes:
        """MD5 kullanarak anahtarı 8 byte'a türetir."""
        if not key:
            raise ValueError("DES için anahtar gerekli")
        digest = hashlib.md5(key.encode('utf-8')).digest()
        return digest[:8]

    @staticmethod
    def _permute(block: int, table: List[int], bits: int) -> int:
        """
        Bit tablosuna göre permütasyon uygular.
        Tablo 1'den başladığı için (bits - position) kullanılır.
        """
        permuted = 0
        for position in table:
            # Gerekli biti al
            bit_val = (block >> (bits - position)) & 1
            # Sonuca ekle
            permuted = (permuted << 1) | bit_val
        return permuted

    @classmethod
    def _generate_round_keys(cls, key: bytes) -> List[int]:
        """16 adet 48-bit tur anahtarını üretir (Key Schedule)."""
        key_int = int.from_bytes(key, 'big')
        
        # Adım 1: PC1 (64 -> 56 bit)
        permuted = cls._permute(key_int, cls._PC1, 64)
        
        # Adım 2: C (sol 28 bit) ve D (sağ 28 bit) ayır
        c = (permuted >> 28) & 0xFFFFFFF
        d = permuted & 0xFFFFFFF
        
        round_keys = []
        for shift in cls._SHIFT_SCHEDULE:
            # Adım 3: Sola Döngüsel Kaydırma
            c = ((c << shift) | (c >> (28 - shift))) & 0xFFFFFFF
            d = ((d << shift) | (d >> (28 - shift))) & 0xFFFFFFF
            
            # Adım 4: PC2 (C ve D'yi birleştir (56 bit) ve 48 bit'e indirge)
            cd = (c << 28) | d
            round_key = cls._permute(cd, cls._PC2, 56) # 48 bitlik sonuç
            round_keys.append(round_key)
            
        return round_keys
    
    @classmethod
    def _feistel(cls, right: int, round_key: int) -> int:
        """DES Feistel Fonksiyonu F(R, K)."""
        
        # Adım 1: Genişletme (E-box) (32 -> 48 bit)
        expanded = cls._permute(right, cls._E, 32)
        
        # Adım 2: XOR (Genişletilmiş R ^ K)
        xored = expanded ^ round_key # 48 bit
        
        # Adım 3: S-Box İkamesi (48 -> 32 bit)
        output = 0
        for i in range(8): # 8 adet S-Box
            six_bits = (xored >> (42 - 6 * i)) & 0x3F # 6 bitlik blok
            
            # Satır (Row): İlk ve son bit (6 bitin 5. ve 0. bitleri)
            row = ((six_bits & 0x20) >> 4) | (six_bits & 0x01)
            # Sütun (Column): Ortadaki 4 bit (6 bitin 4. - 1. bitleri)
            col = (six_bits >> 1) & 0x0F
            
            # S-Box'tan 4 bitlik değeri al
            s_box_output = cls._S_BOXES[i][row][col]
            
            # Sonuca ekle
            output = (output << 4) | s_box_output # 4 bit kaydır
            
        # Adım 4: P-Box Permütasyonu (32 -> 32 bit)
        final_output = cls._permute(output, cls._P, 32)
        return final_output

    @classmethod
    def _process_block(cls, block: bytes, round_keys: List[int], decrypt: bool = False) -> bytes:
        """Tek 64-bit bloğu şifreler/çözer."""
        
        block_int = int.from_bytes(block, 'big')
        
        # Adım 1: Initial Permutation (IP)
        permuted = cls._permute(block_int, cls._IP, 64)
        
        # Adım 2: Sol (L) ve Sağ (R) 32 bit'e ayır
        left = (permuted >> 32) & 0xFFFFFFFF
        right = permuted & 0xFFFFFFFF

        # Tur anahtarlarını ayarla (Çözme için ters sıra)
        keys = reversed(round_keys) if decrypt else round_keys
        
        # Adım 3: 16 Tur Feistel Ağı 
        for round_key in keys:
            # L_i = R_{i-1}
            # R_i = L_{i-1} XOR F(R_{i-1}, K_i)
            new_right = left ^ cls._feistel(right, round_key)
            left = right
            right = new_right

        # Adım 4: L ve R'yi birleştir (Swap: R16 || L16)
        pre_output = (right << 32) | left
        
        # Adım 5: Final Permutation (FP / IP^{-1})
        final = cls._permute(pre_output, cls._FP, 64)
        
        return final.to_bytes(8, 'big')

    # --- Blok Şifreleme Modu (CBC) ve Padding ---

    @staticmethod
    def _pkcs7_pad(data: bytes) -> bytes:
        """PKCS7 padding ekle (8 byte blok boyutu için)."""
        pad_len = 8 - (len(data) % 8)
        return data + bytes([pad_len] * pad_len)

    @staticmethod
    def _pkcs7_unpad(data: bytes) -> bytes:
        """PKCS7 padding kaldırır."""
        if not data:
            raise ValueError("Boş veri.")
        pad_len = data[-1]
        if pad_len < 1 or pad_len > 8 or len(data) < pad_len:
            raise ValueError(f"Geçersiz padding uzunluğu: {pad_len}")
        if any(data[i] != pad_len for i in range(len(data) - pad_len, len(data))):
            raise ValueError("Geçersiz padding içeriği.")
        return data[:-pad_len]

    def encrypt(self, data: bytes, key: str) -> bytes:
        """DES ile veriyi şifreler (CBC modu)."""
        try:
            key_bytes = self._derive_key(key)
            round_keys = self._generate_round_keys(key_bytes)
            iv = os.urandom(8) # 8 byte IV
            padded = self._pkcs7_pad(data)

            prev_block = iv
            blocks = []
            
            for i in range(0, len(padded), self.block_size):
                block = padded[i:i + self.block_size]
                # CBC Adım 1: Plaintext ^ Önceki Ciphertext (veya IV)
                xor_block = bytes(a ^ b for a, b in zip(block, prev_block))
                # CBC Adım 2: DES Şifreleme
                encrypted = self._process_block(xor_block, round_keys, decrypt=False)
                
                blocks.append(encrypted)
                prev_block = encrypted

            ciphertext = b''.join(blocks)
            return iv + ciphertext

        except Exception as e:
            raise Exception(f"DES şifreleme hatası: {str(e)}")

    def decrypt(self, data: bytes, key: str) -> bytes:
        """DES ile şifrelenmiş veriyi çözer (CBC modu)."""
        try:
            key_bytes = self._derive_key(key)
            round_keys = self._generate_round_keys(key_bytes)
            
            if len(data) < 8 or (len(data) - 8) % self.block_size != 0:
                raise ValueError("Geçersiz şifreli veri formatı.")
            
            iv = data[:8]
            ciphertext = data[8:]

            prev_block = iv
            blocks = []
            
            for i in range(0, len(ciphertext), self.block_size):
                block = ciphertext[i:i + self.block_size]
                if len(block) != self.block_size:
                    raise ValueError(f"Geçersiz blok uzunluğu: {len(block)}")
                
                # CBC Adım 1: DES Çözme
                decrypted = self._process_block(block, round_keys, decrypt=True)
                # CBC Adım 2: Çözülmüş blok ^ Önceki Ciphertext (veya IV)
                plain_block = bytes(a ^ b for a, b in zip(decrypted, prev_block))
                
                blocks.append(plain_block)
                prev_block = block # Bir sonraki tur için Prev C := C_i

            padded = b''.join(blocks)
            plaintext = self._pkcs7_unpad(padded)
            return plaintext

        except Exception as e:
            raise Exception(f"DES çözme hatası: {str(e)}")

    def validate_key(self, key: str) -> bool:
        """Anahtarın geçerli olup olmadığını kontrol eder."""
        return bool(key and len(key) >= 1)