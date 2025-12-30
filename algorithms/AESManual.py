from algorithms.BaseCipher import BaseCipher
import os
import hashlib
from typing import List, Tuple
from algorithms.aes_manual import gf
from algorithms.aes_manual import sbox
from shared.utils import CryptoUtils

class AESManual(BaseCipher):
    """
    🔐 [Algorithm Overview]
    Type: Symmetric Block Cipher (Manual implementation)
    Mode: AES-256 / CBC
    
    🔒 KRİPTO FELSEFESİ:
    "AES bir ezber tablo değil, bir matematiksel dönüşümdür."
    - SubBytes adımı: Sabit S-Box yerine GF(2^8) multiplicative inverse kullanılır.
    - Tüm seans anahtarları random üretilir ve sadece RAM'de tutulur.

    🧮 [Mathematical Foundation]
    - Operations in Galois Field GF(2^8).
    - Polynomial: P(x) = x^8 + x^4 + x^3 + x + 1 (0x11B).
    """

    # --- AES Sabitleri (Constants) ---
    _R_CON = [
        0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C,
        0xD8, 0xAB, 0x4D, 0x9A
    ]

    def __init__(self):
        super().__init__()
        self.name = "AES Manual (Akademik)"
        self.description = "GF(2^8) tabanlı manuel AES-256 (Dinamik S-Box)"
        self.key_type = "string"
        self.min_key_length = 1
        self.max_key_length = 200
        self.key_description = "Anahtar (Dinamik S-Box ve Round Key üretimi için kullanılır)"
        self.supports_binary = True
        self.block_size = 16
        
        # S-Box'lar her seferinde anahtara göre üretilecek fakat 
        # varsayılan olarak standart S-Box yüklenebilir.
        self.current_sbox = sbox.generate_sbox()
        self.current_inv_sbox = sbox.generate_inverse_sbox(self.current_sbox)

    def _setup_dynamic_sbox(self, key_bytes: bytes):
        """Anahtara bağlı dinamik S-Box yapılandırması."""
        self.current_sbox = sbox.generate_dynamic_sbox(key_bytes)
        self.current_inv_sbox = sbox.generate_inverse_sbox(self.current_sbox)

    @staticmethod
    def _derive_key(key: str, key_size: int = 32) -> bytes:
        """Kullanıcı anahtarından kriptografik anahtar türetir."""
        if not key:
            raise ValueError("AES için anahtar dizesi gerekli")
            
        # 1. Akıllı Anahtar Tespiti (Hex, B64, Raw)
        derived_key = CryptoUtils.derive_key_robust(key, expected_sizes=[16, 24, 32])
        
        # Eğer zaten beklenen boyutlardaysa direkt döndür
        if len(derived_key) in [16, 24, 32]:
            return derived_key

        # 2. Aksi takdirde SHA256 ile türet
        digest = hashlib.sha256(derived_key).digest()
        return digest[:key_size]

    # --- AES Tur Adımları (Round Operations) ---

    def _sub_bytes(self, state: List[int]) -> None:
        """SubBytes işlemi (Dinamik S-Box İkamesi)."""
        for i in range(16):
            state[i] = self.current_sbox[state[i]]

    def _inv_sub_bytes(self, state: List[int]) -> None:
        """InvSubBytes işlemi (Ters Dinamik S-Box İkamesi)."""
        for i in range(16):
            state[i] = self.current_inv_sbox[state[i]]

    @staticmethod
    def _shift_rows(state: List[int]) -> None:
        """ShiftRows işlemi (Satır Kaydırma)."""
        state[1], state[5], state[9], state[13] = state[5], state[9], state[13], state[1]
        state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
        state[3], state[7], state[11], state[15] = state[15], state[3], state[7], state[11]

    @staticmethod
    def _inv_shift_rows(state: List[int]) -> None:
        """InvShiftRows işlemi (Ters Satır Kaydırma)."""
        state[1], state[5], state[9], state[13] = state[13], state[1], state[5], state[9]
        state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
        state[3], state[7], state[11], state[15] = state[7], state[11], state[15], state[3]

    @staticmethod
    def _mix_columns(state: List[int]) -> None:
        """MixColumns işlemi (GF(2^8) Sütun Karıştırma)."""
        for i in range(4):
            col_start = i * 4
            s = [state[col_start + j] for j in range(4)]
            state[col_start + 0] = gf.multiply(0x02, s[0]) ^ gf.multiply(0x03, s[1]) ^ s[2] ^ s[3]
            state[col_start + 1] = s[0] ^ gf.multiply(0x02, s[1]) ^ gf.multiply(0x03, s[2]) ^ s[3]
            state[col_start + 2] = s[0] ^ s[1] ^ gf.multiply(0x02, s[2]) ^ gf.multiply(0x03, s[3])
            state[col_start + 3] = gf.multiply(0x03, s[0]) ^ s[1] ^ s[2] ^ gf.multiply(0x02, s[3])
            
    @staticmethod
    def _inv_mix_columns(state: List[int]) -> None:
        """InvMixColumns işlemi (Ters GF(2^8) Sütun Karıştırma)."""
        for i in range(4):
            col_start = i * 4
            s = [state[col_start + j] for j in range(4)]
            state[col_start + 0] = gf.multiply(0x0E, s[0]) ^ gf.multiply(0x0B, s[1]) ^ gf.multiply(0x0D, s[2]) ^ gf.multiply(0x09, s[3])
            state[col_start + 1] = gf.multiply(0x09, s[0]) ^ gf.multiply(0x0E, s[1]) ^ gf.multiply(0x0B, s[2]) ^ gf.multiply(0x0D, s[3])
            state[col_start + 2] = gf.multiply(0x0D, s[0]) ^ gf.multiply(0x09, s[1]) ^ gf.multiply(0x0E, s[2]) ^ gf.multiply(0x0B, s[3])
            state[col_start + 3] = gf.multiply(0x0B, s[0]) ^ gf.multiply(0x0D, s[1]) ^ gf.multiply(0x09, s[2]) ^ gf.multiply(0x0E, s[3])

    @staticmethod
    def _add_round_key(state: List[int], round_key: List[int]) -> None:
        """AddRoundKey işlemi (XOR)."""
        for i in range(16):
            state[i] ^= round_key[i]

    # --- Anahtar Genişletme (Key Expansion) ---
    
    @staticmethod
    def _rot_word(word: int) -> int:
        return ((word << 8) & 0xFFFFFFFF) | (word >> 24)

    def _sub_word(self, word: int) -> int:
        res = 0
        for i in range(4):
            byte = (word >> (24 - i * 8)) & 0xFF
            res |= (self.current_sbox[byte] << (24 - i * 8))
        return res

    def _key_expansion(self, key: bytes) -> List[List[int]]:
        """AES Key Schedule."""
        key_symbols = list(key)
        key_size = len(key_symbols)
        Nk = key_size // 4
        Nb = 4
        Nr = {4: 10, 6: 12, 8: 14}.get(Nk)
        
        if Nr is None:
            raise ValueError("AES anahtarı 16, 24 veya 32 bayt olmalıdır.")

        words: List[int] = [0] * (Nb * (Nr + 1))

        for i in range(Nk):
            words[i] = (key_symbols[4 * i] << 24) | (key_symbols[4 * i + 1] << 16) | \
                       (key_symbols[4 * i + 2] << 8) | key_symbols[4 * i + 3]

        for i in range(Nk, Nb * (Nr + 1)):
            temp = words[i - 1]
            if i % Nk == 0:
                temp = self._rot_word(temp)
                temp = self._sub_word(temp)
                rcon_byte = self._R_CON[i // Nk]
                temp ^= (rcon_byte << 24)
            elif Nk > 6 and i % Nk == 4:
                temp = self._sub_word(temp)
            words[i] = words[i - Nk] ^ temp

        round_keys: List[List[int]] = []
        for r in range(Nr + 1):
            round_key: List[int] = []
            for i in range(4):
                word = words[r * 4 + i]
                round_key.extend([(word >> 24) & 0xFF, (word >> 16) & 0xFF, (word >> 8) & 0xFF, word & 0xFF])
            round_keys.append(round_key)
        
        return round_keys
        
    # --- Blok İşleme (Cipher Mode: CBC) ---

    @staticmethod
    def _pkcs7_pad(data: bytes) -> bytes:
        pad_len = 16 - (len(data) % 16)
        return data + bytes([pad_len] * pad_len)

    @staticmethod
    def _pkcs7_unpad(data: bytes) -> bytes:
        if not data: raise ValueError("Boş veri.")
        pad_len = data[-1]
        if pad_len < 1 or pad_len > 16 or len(data) < pad_len:
            raise ValueError(f"Geçersiz padding uzunluğu: {pad_len}")
        if any(data[i] != pad_len for i in range(len(data) - pad_len, len(data))):
            raise ValueError("Geçersiz padding içeriği.")
        return data[:-pad_len]

    def _cipher(self, block: bytes, round_keys: List[List[int]]) -> bytes:
        state = list(block)
        Nr = len(round_keys) - 1
        self._add_round_key(state, round_keys[0])
        for r in range(1, Nr):
            self._sub_bytes(state)
            self._shift_rows(state)
            self._mix_columns(state)
            self._add_round_key(state, round_keys[r])
        self._sub_bytes(state)
        self._shift_rows(state)
        self._add_round_key(state, round_keys[Nr])
        return bytes(state)

    def _inv_cipher(self, block: bytes, round_keys: List[List[int]]) -> bytes:
        state = list(block)
        Nr = len(round_keys) - 1
        self._add_round_key(state, round_keys[Nr])
        for r in range(Nr - 1, 0, -1):
            self._inv_shift_rows(state)
            self._inv_sub_bytes(state)
            self._add_round_key(state, round_keys[r])
            self._inv_mix_columns(state)
        self._inv_shift_rows(state)
        self._inv_sub_bytes(state)
        self._add_round_key(state, round_keys[0])
        return bytes(state)

    def encrypt(self, data: bytes, key: str) -> bytes:
        """AES-CBC şifreleme (Akademik Manuel)."""
        try:
            key_bytes = self._derive_key(key, key_size=32)
            self._setup_dynamic_sbox(key_bytes) # Anahtara bağlı S-Box
            round_keys = self._key_expansion(key_bytes)
            iv = os.urandom(16)
            padded = self._pkcs7_pad(data)
            blocks = []
            prev_block = iv
            for i in range(0, len(padded), self.block_size):
                block = padded[i:i + self.block_size]
                xor_block = bytes(a ^ b for a, b in zip(block, prev_block))
                encrypted = self._cipher(xor_block, round_keys)
                blocks.append(encrypted)
                prev_block = encrypted
            return iv + b''.join(blocks)
        except Exception as e:
            raise Exception(f"AES şifreleme hatası: {str(e)}")

    def decrypt(self, data: bytes, key: str) -> bytes:
        """AES-CBC çözme (Akademik Manuel)."""
        try:
            key_bytes = self._derive_key(key, key_size=32)
            self._setup_dynamic_sbox(key_bytes) # Aynı anahtarla aynı S-Box
            round_keys = self._key_expansion(key_bytes)
            if len(data) < 16 or (len(data) - 16) % self.block_size != 0:
                raise ValueError("Geçersiz şifreli veri formatı.")
            iv = data[:16]
            ciphertext = data[16:]
            blocks = []
            prev_block = iv
            for i in range(0, len(ciphertext), self.block_size):
                block = ciphertext[i:i + self.block_size]
                decrypted = self._inv_cipher(block, round_keys)
                plain_block = bytes(a ^ b for a, b in zip(decrypted, prev_block))
                blocks.append(plain_block)
                prev_block = block
            return self._pkcs7_unpad(b''.join(blocks))
        except Exception as e:
            raise Exception(f"AES çözme hatası: {str(e)}")

    def validate_key(self, key: str) -> bool:
        return bool(key and len(key) >= 1)
