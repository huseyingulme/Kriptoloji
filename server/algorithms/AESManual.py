"""
AES Manual Implementation - Kütüphanesiz AES-128 Implementasyonu

Bu dosya, kriptografik kütüphaneler kullanmadan AES-128 algoritmasının
manuel implementasyonunu içerir. Bu sayede round yapısı, S-box kullanımı,
permütasyonlar gibi temel kavramlar doğrudan deneyimlenmiş olur.

NOT: Bu implementasyon eğitim amaçlıdır ve gerçek üretim ortamlarında
kullanılmamalıdır. Güvenlik için kütüphaneli versiyon tercih edilmelidir.
"""

from server.algorithms.BaseCipher import BaseCipher
import os


class AESManual(BaseCipher):
    """
    Manuel AES-128 implementasyonu (kütüphanesiz).
    
    Bu implementasyon, AES algoritmasının temel yapısını gösterir:
    - SubBytes (S-box dönüşümü)
    - ShiftRows (satır kaydırma)
    - MixColumns (sütun karıştırma)
    - AddRoundKey (anahtar ekleme)
    """

    # AES S-box (Substitution Box)
    S_BOX = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    ]

    # Inverse S-box
    INV_S_BOX = [
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    ]

    # Rcon (Round Constant) - Key expansion için
    RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

    def __init__(self):
        super().__init__()
        self.name = "AES Manual (Kütüphanesiz)"
        self.description = "AES-128 Manuel Implementasyonu - Kütüphanesiz versiyon (Eğitim amaçlı)\n\nAdımlar:\n1. Key Expansion (Anahtar genişletme)\n2. Initial AddRoundKey\n3. 9 Round (SubBytes, ShiftRows, MixColumns, AddRoundKey)\n4. Final Round (SubBytes, ShiftRows, AddRoundKey - MixColumns yok)"
        self.key_type = "string"
        self.min_key_length = 16
        self.max_key_length = 16  # AES-128 için tam 16 byte
        self.key_description = "16 byte (128 bit) anahtar gerekir"
        self.supports_binary = True

    def _key_expansion(self, key: bytes) -> list:
        """AES anahtar genişletme (Key Expansion)"""
        # AES-128 için 11 round key gerekir (her biri 16 byte)
        w = []
        
        # İlk 4 word (ana anahtar)
        for i in range(4):
            w.append([key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]])
        
        # Kalan 40 word'ü oluştur
        for i in range(4, 44):
            temp = w[i-1][:]
            if i % 4 == 0:
                # RotWord + SubWord + Rcon
                temp = [temp[1], temp[2], temp[3], temp[0]]  # RotWord
                temp = [self.S_BOX[b] for b in temp]  # SubWord
                temp[0] ^= self.RCON[i//4 - 1]  # Rcon
            w.append([w[i-4][j] ^ temp[j] for j in range(4)])
        
        return w

    def _sub_bytes(self, state: list) -> list:
        """SubBytes dönüşümü - S-box kullanımı"""
        return [[self.S_BOX[state[i][j]] for j in range(4)] for i in range(4)]

    def _inv_sub_bytes(self, state: list) -> list:
        """Inverse SubBytes dönüşümü"""
        return [[self.INV_S_BOX[state[i][j]] for j in range(4)] for i in range(4)]

    def _shift_rows(self, state: list) -> list:
        """ShiftRows dönüşümü - Satır kaydırma"""
        new_state = [state[0][:]]  # İlk satır değişmez
        new_state.append([state[1][1], state[1][2], state[1][3], state[1][0]])  # 1 byte sola
        new_state.append([state[2][2], state[2][3], state[2][0], state[2][1]])  # 2 byte sola
        new_state.append([state[3][3], state[3][0], state[3][1], state[3][2]])  # 3 byte sola
        return new_state

    def _inv_shift_rows(self, state: list) -> list:
        """Inverse ShiftRows dönüşümü"""
        new_state = [state[0][:]]  # İlk satır değişmez
        new_state.append([state[1][3], state[1][0], state[1][1], state[1][2]])  # 1 byte sağa
        new_state.append([state[2][2], state[2][3], state[2][0], state[2][1]])  # 2 byte sağa
        new_state.append([state[3][1], state[3][2], state[3][3], state[3][0]])  # 3 byte sağa
        return new_state

    def _gf_multiply(self, a: int, b: int) -> int:
        """Galois Field (GF) çarpımı"""
        result = 0
        for i in range(8):
            if b & 1:
                result ^= a
            a <<= 1
            if a & 0x100:
                a ^= 0x11b  # AES irreducible polynomial
            b >>= 1
        return result & 0xff

    def _mix_columns(self, state: list) -> list:
        """MixColumns dönüşümü - Sütun karıştırma"""
        new_state = [[0] * 4 for _ in range(4)]
        for c in range(4):
            new_state[0][c] = self._gf_multiply(2, state[0][c]) ^ self._gf_multiply(3, state[1][c]) ^ state[2][c] ^ state[3][c]
            new_state[1][c] = state[0][c] ^ self._gf_multiply(2, state[1][c]) ^ self._gf_multiply(3, state[2][c]) ^ state[3][c]
            new_state[2][c] = state[0][c] ^ state[1][c] ^ self._gf_multiply(2, state[2][c]) ^ self._gf_multiply(3, state[3][c])
            new_state[3][c] = self._gf_multiply(3, state[0][c]) ^ state[1][c] ^ state[2][c] ^ self._gf_multiply(2, state[3][c])
        return new_state

    def _inv_mix_columns(self, state: list) -> list:
        """Inverse MixColumns dönüşümü"""
        new_state = [[0] * 4 for _ in range(4)]
        for c in range(4):
            new_state[0][c] = self._gf_multiply(0x0e, state[0][c]) ^ self._gf_multiply(0x0b, state[1][c]) ^ self._gf_multiply(0x0d, state[2][c]) ^ self._gf_multiply(0x09, state[3][c])
            new_state[1][c] = self._gf_multiply(0x09, state[0][c]) ^ self._gf_multiply(0x0e, state[1][c]) ^ self._gf_multiply(0x0b, state[2][c]) ^ self._gf_multiply(0x0d, state[3][c])
            new_state[2][c] = self._gf_multiply(0x0d, state[0][c]) ^ self._gf_multiply(0x09, state[1][c]) ^ self._gf_multiply(0x0e, state[2][c]) ^ self._gf_multiply(0x0b, state[3][c])
            new_state[3][c] = self._gf_multiply(0x0b, state[0][c]) ^ self._gf_multiply(0x0d, state[1][c]) ^ self._gf_multiply(0x09, state[2][c]) ^ self._gf_multiply(0x0e, state[3][c])
        return new_state

    def _add_round_key(self, state: list, round_key: list) -> list:
        """AddRoundKey - Anahtar ekleme (XOR)"""
        return [[state[i][j] ^ round_key[i*4 + j] for j in range(4)] for i in range(4)]

    def _bytes_to_state(self, data: bytes) -> list:
        """Bytes'ı state matrix'e dönüştür (column-major order)"""
        state = [[0] * 4 for _ in range(4)]
        for i in range(4):
            for j in range(4):
                state[j][i] = data[i * 4 + j]
        return state

    def _state_to_bytes(self, state: list) -> bytes:
        """State matrix'i bytes'a dönüştür"""
        data = bytearray(16)
        for i in range(4):
            for j in range(4):
                data[i * 4 + j] = state[j][i]
        return bytes(data)

    def _pad_data(self, data: bytes) -> bytes:
        """
        PKCS7 padding ekle
        
        AES 16 byte bloklar halinde çalışır.
        Padding: Eksik byte sayısı kadar, eksik byte sayısı değeri eklenir.
        Örnek: 10 byte veri varsa, 6 byte padding eklenir, her biri 0x06.
        """
        if len(data) == 0:
            return bytes([16] * 16)  # 16 byte padding
        
        pad_len = 16 - (len(data) % 16)
        return data + bytes([pad_len] * pad_len)

    def _unpad_data(self, data: bytes) -> bytes:
        """
        PKCS7 padding kaldır
        
        Son byte padding uzunluğunu gösterir.
        Son pad_len byte'ı kaldır.
        """
        if len(data) == 0:
            raise ValueError("Boş veri için padding kaldırılamaz")
        
        pad_len = data[-1]
        
        # Padding uzunluğu kontrolü
        if pad_len < 1 or pad_len > 16:
            raise ValueError(f"Geçersiz padding uzunluğu: {pad_len}")
        
        if len(data) < pad_len:
            raise ValueError("Veri uzunluğu padding uzunluğundan küçük")
        
        # Tüm padding byte'larının aynı olduğunu kontrol et
        for i in range(len(data) - pad_len, len(data)):
            if data[i] != pad_len:
                raise ValueError(f"Geçersiz padding: byte {i} beklenen {pad_len} ama {data[i]}")
        
        return data[:-pad_len]

    def encrypt(self, data: bytes, key: str) -> bytes:
        """
        AES-128 ile veriyi şifreler (manuel implementasyon).
        
        Args:
            data: Şifrelenecek veri
            key: 16 byte anahtar (string olarak verilirse hash'lenir)
            
        Returns:
            bytes: Şifrelenmiş veri (IV + ciphertext)
        """
        try:
            # Anahtarı hazırla
            if isinstance(key, str):
                # String anahtardan 16 byte türet
                key_bytes = key.encode()[:16].ljust(16, b'\0')
            else:
                key_bytes = key[:16].ljust(16, b'\0')
            
            if len(key_bytes) != 16:
                raise ValueError("AES-128 için tam 16 byte anahtar gerekir")
            
            # IV oluştur (CBC modu için)
            iv = os.urandom(16)
            
            # Anahtar genişletme
            expanded_key = self._key_expansion(key_bytes)
            round_keys = []
            for i in range(11):
                round_key = []
                for j in range(4):
                    round_key.extend(expanded_key[i*4 + j])
                round_keys.append(round_key)
            
            # Padding ekle
            padded_data = self._pad_data(data)
            
            # CBC modu ile şifreleme
            encrypted_blocks = []
            prev_block = iv
            
            for i in range(0, len(padded_data), 16):
                block = padded_data[i:i+16]
                
                # XOR with previous ciphertext (CBC)
                block = bytes([block[j] ^ prev_block[j] for j in range(16)])
                
                # State'e dönüştür
                state = self._bytes_to_state(block)
                
                # Initial round key ekle
                state = self._add_round_key(state, round_keys[0])
                
                # 9 round (her round: SubBytes, ShiftRows, MixColumns, AddRoundKey)
                for round_num in range(1, 10):
                    state = self._sub_bytes(state)
                    state = self._shift_rows(state)
                    state = self._mix_columns(state)
                    state = self._add_round_key(state, round_keys[round_num])
                
                # Final round (MixColumns yok)
                state = self._sub_bytes(state)
                state = self._shift_rows(state)
                state = self._add_round_key(state, round_keys[10])
                
                # State'ten bytes'a dönüştür
                encrypted_block = self._state_to_bytes(state)
                encrypted_blocks.append(encrypted_block)
                prev_block = encrypted_block
            
            # IV + tüm şifreli bloklar
            return iv + b''.join(encrypted_blocks)
        
        except Exception as e:
            raise Exception(f"AES manuel şifreleme hatası: {str(e)}")

    def decrypt(self, data: bytes, key: str) -> bytes:
        """
        AES-128 ile şifrelenmiş veriyi çözer (manuel implementasyon).
        
        Args:
            data: Şifrelenmiş veri (IV + ciphertext)
            key: 16 byte anahtar
            
        Returns:
            bytes: Çözülmüş veri
        """
        try:
            # Anahtarı hazırla
            if isinstance(key, str):
                key_bytes = key.encode()[:16].ljust(16, b'\0')
            else:
                key_bytes = key[:16].ljust(16, b'\0')
            
            if len(key_bytes) != 16:
                raise ValueError("AES-128 için tam 16 byte anahtar gerekir")
            
            # IV'yi ayır
            if len(data) < 16:
                raise ValueError("Geçersiz şifreli veri formatı: Veri çok kısa (IV yok)")
            
            # Veri uzunluğu 16'nın katı olmalı (IV + şifreli bloklar)
            if (len(data) - 16) % 16 != 0:
                raise ValueError("Geçersiz şifreli veri formatı: Veri uzunluğu 16'nın katı değil")
            
            iv = data[:16]
            encrypted_data = data[16:]
            
            # Anahtar genişletme
            expanded_key = self._key_expansion(key_bytes)
            round_keys = []
            for i in range(11):
                round_key = []
                for j in range(4):
                    round_key.extend(expanded_key[i*4 + j])
                round_keys.append(round_key)
            
            # CBC modu ile çözme
            decrypted_blocks = []
            prev_block = iv
            
            for i in range(0, len(encrypted_data), 16):
                block = encrypted_data[i:i+16]
                
                # State'e dönüştür
                state = self._bytes_to_state(block)
                
                # Final round key ekle
                state = self._add_round_key(state, round_keys[10])
                
                # 9 inverse round
                for round_num in range(9, 0, -1):
                    state = self._inv_shift_rows(state)
                    state = self._inv_sub_bytes(state)
                    state = self._add_round_key(state, round_keys[round_num])
                    state = self._inv_mix_columns(state)
                
                # Initial round
                state = self._inv_shift_rows(state)
                state = self._inv_sub_bytes(state)
                state = self._add_round_key(state, round_keys[0])
                
                # State'ten bytes'a dönüştür
                decrypted_block = self._state_to_bytes(state)
                
                # Blok uzunluğu kontrolü
                if len(decrypted_block) != 16:
                    raise ValueError(f"Geçersiz blok uzunluğu: {len(decrypted_block)} (16 olmalı)")
                
                # XOR with previous ciphertext (CBC)
                decrypted_block = bytes([decrypted_block[j] ^ prev_block[j] for j in range(16)])
                decrypted_blocks.append(decrypted_block)
                prev_block = block
            
            # Tüm blokları birleştir ve padding kaldır
            decrypted_data = b''.join(decrypted_blocks)
            return self._unpad_data(decrypted_data)
        
        except Exception as e:
            raise Exception(f"AES manuel çözme hatası: {str(e)}")

    def validate_key(self, key: str) -> bool:
        """Anahtarın geçerli olup olmadığını kontrol eder."""
        try:
            if isinstance(key, str):
                key_bytes = key.encode()[:16].ljust(16, b'\0')
            else:
                key_bytes = key[:16].ljust(16, b'\0')
            return len(key_bytes) == 16
        except:
            return False

