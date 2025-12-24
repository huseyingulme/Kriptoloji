from algorithms.BaseCipher import BaseCipher
import os
import hashlib
from typing import List, Tuple

class AESManual(BaseCipher):
    """
    Kütüphanesiz (Manuel) AES Implementasyonu.
    
    Bu implementasyon, AES'in temel adımlarını (SubBytes, ShiftRows, MixColumns, AddRoundKey)
    ve Key Expansion sürecini FIPS 197 standardına göre manuel olarak kodlar.
    Varsayılan olarak AES-256 (32 byte key) ve CBC (Cipher Block Chaining) modunu kullanır.
    """

    block_size = 16  # 128 bit

    # --- AES Sabitleri (Constants) ---
    _S_BOX = [
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
    ]
    # S_BOX'ın tersi (InvSubBytes için)
    _INV_S_BOX = [0] * 256
    for idx, val in enumerate(_S_BOX):
        _INV_S_BOX[val] = idx

    # Rcon'un ilk 11 elemanı (AES-128 için Rcon[10]'a kadar)
    # Rcon değerleri 32-bit (4 byte) kelime formatında (Big-Endian) saklanır.
    _R_CON = [
        0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C,
        0xD8, 0xAB, 0x4D, 0x9A
    ]

    def __init__(self):
        super().__init__()
        self.name = "AES Manual (Kütüphanesiz)"
        self.description = "AES Manuel Implementasyonu (AES-256 / CBC)"
        self.key_type = "string"
        self.min_key_length = 1
        self.max_key_length = 200
        self.key_description = "Anahtar (SHA-256 ile 32 byte'a türetilir, AES-256 için)"
        self.supports_binary = True

    @staticmethod
    def _derive_key(key: str, key_size: int = 32) -> bytes:
        """SHA-256 ile anahtarı istenen boyuta türetir (Varsayılan: 32 byte)."""
        if not key:
            raise ValueError("AES için anahtar dizesi gerekli")
        digest = hashlib.sha256(key.encode('utf-8')).digest()
        return digest[:key_size]

    # --- Galois Field (GF(2^8)) Operasyonları ---

    @staticmethod
    def _g_multiply(a: int, b: int) -> int:
        """Galois Field çarpma (a * b) - MixColumns'un temeli."""
        p = 0
        hi_bit = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            hi_bit = a & 0x80
            a <<= 1
            a &= 0xFF # 8 bit sınırında tut
            if hi_bit:
                a ^= 0x1B # Polinom x^8 + x^4 + x^3 + x + 1 ile modül
            b >>= 1
        return p

    # --- AES Tur Adımları (Round Operations) ---

    @classmethod
    def _sub_bytes(cls, state: List[int]) -> None:
        """SubBytes işlemi (S-Box İkamesi)."""
        for i in range(16):
            state[i] = cls._S_BOX[state[i]]

    @classmethod
    def _inv_sub_bytes(cls, state: List[int]) -> None:
        """InvSubBytes işlemi (Ters S-Box İkamesi)."""
        for i in range(16):
            state[i] = cls._INV_S_BOX[state[i]]

    @staticmethod
    def _shift_rows(state: List[int]) -> None:
        """ShiftRows işlemi (Satır Kaydırma)."""
        # Satır 1: 1 byte sola kaydır
        state[1], state[5], state[9], state[13] = state[5], state[9], state[13], state[1]
        # Satır 2: 2 byte sola kaydır
        state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
        # Satır 3: 3 byte sola kaydır
        state[3], state[7], state[11], state[15] = state[15], state[3], state[7], state[11]

    @staticmethod
    def _inv_shift_rows(state: List[int]) -> None:
        """InvShiftRows işlemi (Sağa Kaydırma)."""
        # Satır 1: 1 byte sağa kaydır (3 sola kaydırma)
        state[1], state[5], state[9], state[13] = state[13], state[1], state[5], state[9]
        # Satır 2: 2 byte sağa kaydır (2 sola kaydırma)
        state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
        # Satır 3: 3 byte sağa kaydır (1 sola kaydırma)
        state[3], state[7], state[11], state[15] = state[7], state[11], state[15], state[3]

    @classmethod
    def _mix_columns(cls, state: List[int]) -> None:
        """MixColumns işlemi (Sütun Karıştırma)."""
        # Sabit matris: 02 03 01 01 / 01 02 03 01 / 01 01 02 03 / 03 01 01 02
        for i in range(4):
            col_start = i * 4
            s = [state[col_start + j] for j in range(4)]
            
            # Matris Çarpımı (Galois Field üzerinde)
            state[col_start + 0] = cls._g_multiply(0x02, s[0]) ^ cls._g_multiply(0x03, s[1]) ^ s[2] ^ s[3]
            state[col_start + 1] = s[0] ^ cls._g_multiply(0x02, s[1]) ^ cls._g_multiply(0x03, s[2]) ^ s[3]
            state[col_start + 2] = s[0] ^ s[1] ^ cls._g_multiply(0x02, s[2]) ^ cls._g_multiply(0x03, s[3])
            state[col_start + 3] = cls._g_multiply(0x03, s[0]) ^ s[1] ^ s[2] ^ cls._g_multiply(0x02, s[3])
            
    @classmethod
    def _inv_mix_columns(cls, state: List[int]) -> None:
        """InvMixColumns işlemi (Ters Sütun Karıştırma)."""
        # Ters Sabit matris: 0E 0B 0D 09 / 09 0E 0B 0D / 0D 09 0E 0B / 0B 0D 09 0E
        for i in range(4):
            col_start = i * 4
            s = [state[col_start + j] for j in range(4)]
            
            # Matris Çarpımı (Galois Field üzerinde)
            state[col_start + 0] = cls._g_multiply(0x0E, s[0]) ^ cls._g_multiply(0x0B, s[1]) ^ cls._g_multiply(0x0D, s[2]) ^ cls._g_multiply(0x09, s[3])
            state[col_start + 1] = cls._g_multiply(0x09, s[0]) ^ cls._g_multiply(0x0E, s[1]) ^ cls._g_multiply(0x0B, s[2]) ^ cls._g_multiply(0x0D, s[3])
            state[col_start + 2] = cls._g_multiply(0x0D, s[0]) ^ cls._g_multiply(0x09, s[1]) ^ cls._g_multiply(0x0E, s[2]) ^ cls._g_multiply(0x0B, s[3])
            state[col_start + 3] = cls._g_multiply(0x0B, s[0]) ^ cls._g_multiply(0x0D, s[1]) ^ cls._g_multiply(0x09, s[2]) ^ cls._g_multiply(0x0E, s[3])

    @classmethod
    def _add_round_key(cls, state: List[int], round_key: List[int]) -> None:
        """AddRoundKey işlemi (Tur Anahtarı Ekleme - XOR)."""
        for i in range(16):
            state[i] ^= round_key[i]

    # --- Anahtar Genişletme (Key Expansion) ---
    
    @classmethod
    def _rot_word(cls, word: int) -> int:
        """4 bytelik kelimeyi 1 byte sola döndürür."""
        # Kelime formatı: [b0, b1, b2, b3] -> [b1, b2, b3, b0]
        return ((word << 8) & 0xFFFFFFFF) | (word >> 24)

    @classmethod
    def _sub_word(cls, word: int) -> int:
        """4 bytelik kelimeye SubBytes uygular (S-Box)."""
        res = 0
        for i in range(4):
            byte = (word >> (24 - i * 8)) & 0xFF
            res |= (cls._S_BOX[byte] << (24 - i * 8))
        return res

    @classmethod
    def _key_expansion(cls, key: bytes) -> List[List[int]]:
        """AES Key Schedule: Tüm tur anahtarlarını üretir."""
        key_symbols = list(key)
        key_size = len(key_symbols) # 16, 24 veya 32
        
        # Anahtar Boyutuna Göre Tur Sayısı ve Kelime Sayısı
        Nk = key_size // 4 # Anahtar kelime sayısı (4, 6 veya 8)
        Nb = 4            # Blok kelime sayısı (AES için sabit 4)
        Nr = {4: 10, 6: 12, 8: 14}.get(Nk) # Tur sayısı (10, 12, 14)
        
        if Nr is None:
            raise ValueError("AES anahtarı 16, 24 veya 32 bayt olmalıdır.")

        # Toplam kelime sayısı: Nb * (Nr + 1)
        words: List[int] = [0] * (Nb * (Nr + 1))

        # İlk anahtar kelimeleri
        for i in range(Nk):
            words[i] = (key_symbols[4 * i] << 24) | \
                       (key_symbols[4 * i + 1] << 16) | \
                       (key_symbols[4 * i + 2] << 8) | \
                       key_symbols[4 * i + 3]

        # Anahtar genişletme döngüsü
        for i in range(Nk, Nb * (Nr + 1)):
            temp = words[i - 1]
            
            # Rcon ve Sub/Rot Word Uygulaması
            if i % Nk == 0:
                # RotWord
                temp = cls._rot_word(temp)
                # SubWord
                temp = cls._sub_word(temp)
                # Rcon XOR (Rcon sabiti yalnızca ilk byte'a uygulanır)
                rcon_byte = cls._R_CON[i // Nk]
                temp ^= (rcon_byte << 24)
            
            # AES-256 (Nk=8) için ek SubWord (Her 4 kelimede bir)
            elif Nk > 6 and i % Nk == 4:
                temp = cls._sub_word(temp)
                
            # Genişletilmiş kelimeyi hesapla
            words[i] = words[i - Nk] ^ temp

        # Kelimeleri (Words) 16 bytelık tur anahtarlarına dönüştür
        round_keys: List[List[int]] = []
        for r in range(Nr + 1):
            round_key: List[int] = []
            for i in range(4): # Her tur anahtarı 4 kelimedir (16 byte)
                word = words[r * 4 + i]
                # Kelimeyi (int) 4 byte'a (int listesi) ayır
                round_key.extend([
                    (word >> 24) & 0xFF,
                    (word >> 16) & 0xFF,
                    (word >> 8) & 0xFF,
                    word & 0xFF,
                ])
            round_keys.append(round_key)
        
        return round_keys
        
    # --- Blok İşleme (Cipher Mode: CBC) ---

    @staticmethod
    def _pkcs7_pad(data: bytes) -> bytes:
        """PKCS7 padding ekle (16 byte blok boyutu için)."""
        pad_len = 16 - (len(data) % 16)
        return data + bytes([pad_len] * pad_len)

    @staticmethod
    def _pkcs7_unpad(data: bytes) -> bytes:
        """PKCS7 padding kaldırır."""
        if not data:
            raise ValueError("Boş veri.")
        pad_len = data[-1]
        if pad_len < 1 or pad_len > 16 or len(data) < pad_len:
            raise ValueError(f"Geçersiz padding uzunluğu: {pad_len}")
        if any(data[i] != pad_len for i in range(len(data) - pad_len, len(data))):
            raise ValueError("Geçersiz padding içeriği.")
        return data[:-pad_len]

    # --- Çekirdek AES İşlemleri (Core Cipher) ---

    def _cipher(self, block: bytes, round_keys: List[List[int]]) -> bytes:
        """AES Şifreleme (Bir Blok)."""
        state = list(block)
        Nr = len(round_keys) - 1

        # Başlangıç RoundKey
        self._add_round_key(state, round_keys[0])

        # Ara Turlar (1 to Nr-1)
        for r in range(1, Nr):
            self._sub_bytes(state)
            self._shift_rows(state)
            self._mix_columns(state)
            self._add_round_key(state, round_keys[r])

        # Son Tur (Nr)
        self._sub_bytes(state)
        self._shift_rows(state)
        self._add_round_key(state, round_keys[Nr])

        return bytes(state)

    def _inv_cipher(self, block: bytes, round_keys: List[List[int]]) -> bytes:
        """AES Çözme (Bir Blok)."""
        state = list(block)
        Nr = len(round_keys) - 1

        # Başlangıç RoundKey (Ters sıra: round_keys[Nr])
        self._add_round_key(state, round_keys[Nr])

        # Ara Turlar (Nr-1 to 1) - Ters İşlemler
        for r in range(Nr - 1, 0, -1):
            self._inv_shift_rows(state)
            self._inv_sub_bytes(state)
            self._add_round_key(state, round_keys[r])
            self._inv_mix_columns(state)

        # Son Tur (0) - Ters İşlemler
        self._inv_shift_rows(state)
        self._inv_sub_bytes(state)
        self._add_round_key(state, round_keys[0])

        return bytes(state)

    def encrypt(self, data: bytes, key: str) -> bytes:
        """AES-CBC şifreleme."""
        try:
            # Not: Bu manuel implementasyon, varsayılan olarak AES-256 (32 byte) key kullanır.
            key_bytes = self._derive_key(key, key_size=32)
            round_keys = self._key_expansion(key_bytes)
            iv = os.urandom(16) # Rastgele 16 byte IV
            padded = self._pkcs7_pad(data)

            blocks = []
            prev_block = iv
            
            # CBC (Cipher Block Chaining) modu döngüsü
            for i in range(0, len(padded), self.block_size):
                block = padded[i:i + self.block_size]
                
                # CBC Adım 1: Plaintext ^ Önceki Ciphertext (veya IV)
                xor_block = bytes(a ^ b for a, b in zip(block, prev_block))
                
                # CBC Adım 2: AES Şifreleme
                encrypted = self._cipher(xor_block, round_keys)
                
                blocks.append(encrypted)
                prev_block = encrypted # Bir sonraki tur için Prev C := C_i

            ciphertext = b''.join(blocks)
            # IV (16 byte) + Ciphertext (veri) gönderilir
            return iv + ciphertext

        except Exception as e:
            raise Exception(f"AES şifreleme hatası: {str(e)}")

    def decrypt(self, data: bytes, key: str) -> bytes:
        """AES-CBC çözme."""
        try:
            key_bytes = self._derive_key(key, key_size=32)
            round_keys = self._key_expansion(key_bytes)
            
            if len(data) < 16 or (len(data) - 16) % self.block_size != 0:
                raise ValueError("Geçersiz şifreli veri formatı.")
            
            iv = data[:16]
            ciphertext = data[16:]

            blocks = []
            prev_block = iv
            
            # CBC (Cipher Block Chaining) modu çözme döngüsü
            for i in range(0, len(ciphertext), self.block_size):
                block = ciphertext[i:i + self.block_size]
                
                # CBC Adım 1: AES Çözme
                decrypted = self._inv_cipher(block, round_keys)
                
                # CBC Adım 2: Çözülmüş blok ^ Önceki Ciphertext (veya IV)
                plain_block = bytes(a ^ b for a, b in zip(decrypted, prev_block))
                
                blocks.append(plain_block)
                prev_block = block # Bir sonraki tur için Prev C := C_i

            padded = b''.join(blocks)
            plaintext = self._pkcs7_unpad(padded)
            return plaintext

        except Exception as e:
            raise Exception(f"AES çözme hatası: {str(e)}")

    def validate_key(self, key: str) -> bool:
        """Anahtar dizesinin geçerli olup olmadığını kontrol eder."""
        return bool(key and len(key) >= 1)