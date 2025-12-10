"""
DES Manual Implementation - Kütüphanesiz DES Implementasyonu

Bu dosya, kriptografik kütüphaneler kullanmadan DES algoritmasının
manuel implementasyonunu içerir. Bu sayede round yapısı, S-box kullanımı,
permütasyonlar gibi temel kavramlar doğrudan deneyimlenmiş olur.

NOT: Bu implementasyon eğitim amaçlıdır ve gerçek üretim ortamlarında
kullanılmamalıdır. Güvenlik için kütüphaneli versiyon tercih edilmelidir.
"""

from server.algorithms.BaseCipher import BaseCipher
import os


class DESManual(BaseCipher):
    """
    Manuel DES implementasyonu (kütüphanesiz).
    
    Bu implementasyon, DES algoritmasının temel yapısını gösterir:
    - Initial Permutation (IP)
    - 16 Round Feistel Network
    - S-box dönüşümleri
    - Final Permutation (FP)
    """

    # Initial Permutation (IP)
    IP = [
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    ]

    # Final Permutation (FP) - IP'nin tersi
    FP = [
        40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25
    ]

    # PC1 - Key Permutation Choice 1
    PC1 = [
        57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4
    ]

    # PC2 - Key Permutation Choice 2
    PC2 = [
        14, 17, 11, 24, 1, 5,
        3, 28, 15, 6, 21, 10,
        23, 19, 12, 4, 26, 8,
        16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32
    ]

    # Left shifts for key schedule
    SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

    # Expansion Permutation (E)
    E = [
        32, 1, 2, 3, 4, 5,
        4, 5, 6, 7, 8, 9,
        8, 9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1
    ]

    # Permutation (P)
    P = [
        16, 7, 20, 21,
        29, 12, 28, 17,
        1, 15, 23, 26,
        5, 18, 31, 10,
        2, 8, 24, 14,
        32, 27, 3, 9,
        19, 13, 30, 6,
        22, 11, 4, 25
    ]

    # S-boxes
    S_BOXES = [
        # S1
        [
            [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
            [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
            [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
            [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
        ],
        # S2
        [
            [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
            [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
            [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
            [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
        ],
        # S3
        [
            [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
            [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
            [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
            [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
        ],
        # S4
        [
            [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
            [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
            [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
            [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
        ],
        # S5
        [
            [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
            [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
            [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
            [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
        ],
        # S6
        [
            [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
            [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
            [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
            [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
        ],
        # S7
        [
            [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
            [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
            [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
            [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
        ],
        # S8
        [
            [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
            [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
            [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
            [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
        ]
    ]

    def __init__(self):
        super().__init__()
        self.name = "DES Manual (Kütüphanesiz)"
        self.description = "DES Manuel Implementasyonu - Kütüphanesiz versiyon (Eğitim amaçlı)\n\nAdımlar:\n1. Initial Permutation (IP)\n2. 16 Round Feistel Network\n3. Final Permutation (FP)\n\nHer round:\n- Sağ yarıyı F fonksiyonuna sok\n- Sol yarı ile XOR işlemi yap\n- Sağ ve sol yarıları yer değiştir"
        self.key_type = "string"
        self.min_key_length = 8
        self.max_key_length = 8  # DES için tam 8 byte
        self.key_description = "8 byte (64 bit) anahtar gerekir (56 bit efektif)"
        self.supports_binary = True

    def _permute(self, bits: list, table: list) -> list:
        """Permütasyon uygula"""
        return [bits[i - 1] for i in table]

    def _left_shift(self, bits: list, n: int) -> list:
        """Sola kaydır"""
        return bits[n:] + bits[:n]

    def _bytes_to_bits(self, data: bytes) -> list:
        """Bytes'ı bit listesine dönüştür"""
        bits = []
        for byte in data:
            for i in range(7, -1, -1):
                bits.append((byte >> i) & 1)
        return bits

    def _bits_to_bytes(self, bits: list) -> bytes:
        """Bit listesini bytes'a dönüştür"""
        bytes_list = []
        for i in range(0, len(bits), 8):
            byte = 0
            for j in range(8):
                if i + j < len(bits):
                    byte |= (bits[i + j] << (7 - j))
            bytes_list.append(byte)
        return bytes(bytes_list)

    def _key_schedule(self, key: bytes) -> list:
        """DES anahtar zamanlaması - 16 round key üret"""
        # 64-bit anahtarı 56-bit'e indir (PC1)
        key_bits = self._bytes_to_bits(key)
        key_56 = self._permute(key_bits, self.PC1)
        
        # C0 ve D0'ı ayır
        C = key_56[:28]
        D = key_56[28:]
        
        round_keys = []
        for i in range(16):
            # Sola kaydır
            C = self._left_shift(C, self.SHIFTS[i])
            D = self._left_shift(D, self.SHIFTS[i])
            
            # PC2 permütasyonu
            CD = C + D
            round_key = self._permute(CD, self.PC2)
            round_keys.append(round_key)
        
        return round_keys

    def _f_function(self, R: list, round_key: list) -> list:
        """DES F fonksiyonu"""
        # Expansion
        expanded = self._permute(R, self.E)
        
        # XOR with round key
        xor_result = [expanded[i] ^ round_key[i] for i in range(48)]
        
        # S-box substitution
        s_output = []
        for i in range(8):
            block = xor_result[i*6:(i+1)*6]
            row = block[0] * 2 + block[5]
            col = block[1] * 8 + block[2] * 4 + block[3] * 2 + block[4]
            s_value = self.S_BOXES[i][row][col]
            # 4-bit değeri bit listesine dönüştür
            for j in range(3, -1, -1):
                s_output.append((s_value >> j) & 1)
        
        # Permutation
        return self._permute(s_output, self.P)

    def _des_round(self, L: list, R: list, round_key: list) -> tuple:
        """
        DES tek round (Feistel Network)
        
        Feistel yapısı:
        - Li = Ri-1
        - Ri = Li-1 XOR F(Ri-1, Ki)
        
        Args:
            L: Sol yarı (32 bit)
            R: Sağ yarı (32 bit)
            round_key: Round anahtarı (48 bit)
            
        Returns:
            tuple: (Yeni L, Yeni R)
        """
        # F fonksiyonunu uygula
        f_result = self._f_function(R, round_key)
        
        # Li = Ri-1 (eski sağ yarı yeni sol yarı olur)
        new_L = R
        
        # Ri = Li-1 XOR F(Ri-1, Ki) (yeni sağ yarı)
        new_R = [L[i] ^ f_result[i] for i in range(32)]
        
        return new_L, new_R

    def _des_block_encrypt(self, block: bytes, round_keys: list) -> bytes:
        """DES tek blok şifreleme"""
        # Initial Permutation
        block_bits = self._bytes_to_bits(block)
        permuted = self._permute(block_bits, self.IP)
        
        # L0 ve R0'ı ayır
        L = permuted[:32]
        R = permuted[32:]
        
        # 16 round
        for i in range(16):
            L, R = self._des_round(L, R, round_keys[i])
        
        # Final swap
        LR = R + L
        
        # Final Permutation
        result_bits = self._permute(LR, self.FP)
        return self._bits_to_bytes(result_bits)

    def _des_block_decrypt(self, block: bytes, round_keys: list) -> bytes:
        """DES tek blok çözme"""
        # Initial Permutation
        block_bits = self._bytes_to_bits(block)
        permuted = self._permute(block_bits, self.IP)
        
        # L0 ve R0'ı ayır
        L = permuted[:32]
        R = permuted[32:]
        
        # 16 round (ters sırada)
        for i in range(15, -1, -1):
            L, R = self._des_round(L, R, round_keys[i])
        
        # Final swap
        LR = R + L
        
        # Final Permutation
        result_bits = self._permute(LR, self.FP)
        return self._bits_to_bytes(result_bits)

    def _pad_data(self, data: bytes) -> bytes:
        """
        PKCS7 padding ekle
        
        DES 8 byte bloklar halinde çalışır.
        Padding: Eksik byte sayısı kadar, eksik byte sayısı değeri eklenir.
        Örnek: 5 byte veri varsa, 3 byte padding eklenir, her biri 0x03.
        """
        if len(data) == 0:
            return bytes([8] * 8)  # 8 byte padding
        
        pad_len = 8 - (len(data) % 8)
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
        if pad_len < 1 or pad_len > 8:
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
        DES ile veriyi şifreler (manuel implementasyon).
        
        Args:
            data: Şifrelenecek veri
            key: 8 byte anahtar (string olarak verilirse hash'lenir)
            
        Returns:
            bytes: Şifrelenmiş veri (IV + ciphertext)
        """
        try:
            # Anahtarı hazırla
            if isinstance(key, str):
                key_bytes = key.encode()[:8].ljust(8, b'\0')
            else:
                key_bytes = key[:8].ljust(8, b'\0')
            
            if len(key_bytes) != 8:
                raise ValueError("DES için tam 8 byte anahtar gerekir")
            
            # IV oluştur (CBC modu için)
            iv = os.urandom(8)
            
            # Anahtar zamanlaması
            round_keys = self._key_schedule(key_bytes)
            
            # Padding ekle
            padded_data = self._pad_data(data)
            
            # CBC modu ile şifreleme
            encrypted_blocks = []
            prev_block = iv
            
            for i in range(0, len(padded_data), 8):
                block = padded_data[i:i+8]
                
                # XOR with previous ciphertext (CBC)
                block = bytes([block[j] ^ prev_block[j] for j in range(8)])
                
                # DES şifreleme
                encrypted_block = self._des_block_encrypt(block, round_keys)
                encrypted_blocks.append(encrypted_block)
                prev_block = encrypted_block
            
            # IV + tüm şifreli bloklar
            return iv + b''.join(encrypted_blocks)
        
        except Exception as e:
            raise Exception(f"DES manuel şifreleme hatası: {str(e)}")

    def decrypt(self, data: bytes, key: str) -> bytes:
        """
        DES ile şifrelenmiş veriyi çözer (manuel implementasyon).
        
        Args:
            data: Şifrelenmiş veri (IV + ciphertext)
            key: 8 byte anahtar
            
        Returns:
            bytes: Çözülmüş veri
        """
        try:
            # Anahtarı hazırla
            if isinstance(key, str):
                key_bytes = key.encode()[:8].ljust(8, b'\0')
            else:
                key_bytes = key[:8].ljust(8, b'\0')
            
            if len(key_bytes) != 8:
                raise ValueError("DES için tam 8 byte anahtar gerekir")
            
            # IV'yi ayır
            if len(data) < 8:
                raise ValueError("Geçersiz şifreli veri formatı: Veri çok kısa (IV yok)")
            
            # Veri uzunluğu 8'in katı olmalı (IV + şifreli bloklar)
            if (len(data) - 8) % 8 != 0:
                raise ValueError("Geçersiz şifreli veri formatı: Veri uzunluğu 8'in katı değil")
            
            iv = data[:8]
            encrypted_data = data[8:]
            
            # Anahtar zamanlaması
            round_keys = self._key_schedule(key_bytes)
            
            # CBC modu ile çözme
            decrypted_blocks = []
            prev_block = iv
            
            for i in range(0, len(encrypted_data), 8):
                block = encrypted_data[i:i+8]
                
                # Blok uzunluğu kontrolü
                if len(block) != 8:
                    raise ValueError(f"Geçersiz blok uzunluğu: {len(block)} (8 olmalı)")
                
                # DES çözme
                decrypted_block = self._des_block_decrypt(block, round_keys)
                
                # XOR with previous ciphertext (CBC)
                decrypted_block = bytes([decrypted_block[j] ^ prev_block[j] for j in range(8)])
                decrypted_blocks.append(decrypted_block)
                prev_block = block
            
            # Tüm blokları birleştir ve padding kaldır
            decrypted_data = b''.join(decrypted_blocks)
            return self._unpad_data(decrypted_data)
        
        except Exception as e:
            raise Exception(f"DES manuel çözme hatası: {str(e)}")

    def validate_key(self, key: str) -> bool:
        """Anahtarın geçerli olup olmadığını kontrol eder."""
        try:
            if isinstance(key, str):
                key_bytes = key.encode()[:8].ljust(8, b'\0')
            else:
                key_bytes = key[:8].ljust(8, b'\0')
            return len(key_bytes) == 8
        except:
            return False

