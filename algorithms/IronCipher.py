import os
import hashlib
from typing import List, Tuple
from algorithms.BaseCipher import BaseCipher

class IronCipher(BaseCipher):
    """
    🔐 [Algorithm Overview]
    Type: Feistel Block Cipher (Variation of IDEA)
    A custom Feistel-based block cipher designed for academic exploration.

    🔑 [Key Management]
    - Key-dependent round counts and dynamic round keys.

    🧮 [Mathematical Foundation]
    - Uses a Feistel structure.
    - Incorporates dynamic S-Box generation based on the key to frustrate linear cryptanalysis.
    
    IRON (International Data Encryption Algorithm - Feistel Variation)
    
    Bu algoritma kullanıcı tarafından sağlanan özel Feistel mimarisine dayanmaktadır.
    
    Özellikler:
    - Blok Boyutu: 64 bit (8 byte)
    - Anahtar Boyutu: 128 bit (16 byte)
    - Yapı: Feistel Network
    - Tur Sayısı: Anahtar bağımlı (16 veya 17)
    - S-Box: Anahtar bağımlı dinamik üretilen 4 adet 8x32 kutu
    """

    block_size = 8

    # Pi Sabitleri (Hex formatında Pi'nin ilk basamakları)
    P = [
        0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344, 0xa4093822, 0x299f31d0, 
        0x082efa98, 0xec4e6c89, 0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c, 
        0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917, 0x9216d5d9, 0x8979fb1b,
        0x111b111b, 0x222b222b, 0x333b333b, 0x444b444b, 0x555b555b, 0x666b666b,
        0x777b777b, 0x888b888b, 0x999b999b, 0xaaab222b, 0xbbbc222b, 0xcccd222b,
        0xddddeeee, 0xffff0000, 0x0000ffff, 0x12345678, 0x87654321, 0xabcdef01
    ]

    def __init__(self):
        super().__init__()
        self.name = "IRON"
        self.description = "IRON (Feistel based block cipher / Key Dependent)"
        self.key_type = "string"
        self.min_key_length = 1
        self.max_key_length = 200
        self.key_description = "128-bit anahtar (SHA-256 ile türetilir)"
        self.supports_binary = True

    @staticmethod
    def _derive_key(key: str) -> bytes:
        """Anahtarı 16 byte (128 bit) boyutuna türetir."""
        return hashlib.sha256(key.encode('utf-8')).digest()[:16]

    def _calculate_rounds(self, key_bytes: bytes) -> int:
        """Anahtar nibble'larının XOR sonucuna göre tur sayısını hesaplar."""
        xor_result = 0
        for b in key_bytes:
            xor_result ^= (b >> 4)  # Üst 4 bit
            xor_result ^= (b & 0x0F) # Alt 4 bit
        
        # Çift ise 16, tek ise 17 tur
        return 16 if xor_result % 2 == 0 else 17

    def _generate_subkeys(self, key_bytes: bytes, num_rounds: int) -> List[Tuple[int, int]]:
        """Alt anahtarları üretir."""
        k_left = int.from_bytes(key_bytes[0:8], 'big')
        k_right = int.from_bytes(key_bytes[8:16], 'big')
        
        subkeys = []
        for i in range(num_rounds):
            # 1 bit sola dairesel kaydır (64 bit üzerinden)
            k_left = ((k_left << 1) | (k_left >> 63)) & 0xFFFFFFFFFFFFFFFF
            k_right = ((k_right << 1) | (k_right >> 63)) & 0xFFFFFFFFFFFFFFFF
            
            # 32 + 32'ye ayır ve sabitlerle XORla
            # Her tur için 2 farklı sabit kullanalım
            p_idx = (i * 2) % len(self.P)
            sk_l = (k_left >> 32) ^ self.P[p_idx]
            sk_r = (k_left & 0xFFFFFFFF) ^ self.P[(p_idx + 1) % len(self.P)]
            
            # Subkey (SKL, SKR)
            subkeys.append((sk_l & 0xFFFFFFFF, sk_r & 0xFFFFFFFF))
            
            # Diğer 64 bitlik parçayı da döndürerek anahtarı güncellemeye devam ediyoruz
            # (Bir sonraki turda k_left ve k_right kullanılmış olacak)
        
        return subkeys

    def _generate_sboxes(self, key_bytes: bytes, first_subkey: Tuple[int, int]) -> List[List[int]]:
        """Anahtar bağımlı S-box'ları üretir."""
        k0 = int.from_bytes(key_bytes[0:4], 'big')
        k1 = int.from_bytes(key_bytes[4:8], 'big')
        k2 = int.from_bytes(key_bytes[8:12], 'big')
        k3 = int.from_bytes(key_bytes[12:16], 'big')
        
        skl, skr = first_subkey
        sk_product = (skl * skr) % 0x100000000
        
        sboxes = []
        # 4 adet S-box (S0, S1, S2, S3)
        for box_idx in range(4):
            box = [0] * 256
            # İlk eleman
            p_val = self.P[box_idx % len(self.P)]
            box[0] = (k0 + k1 + k2 + k3 + p_val) & 0xFFFFFFFF
            
            # Diğer 255 eleman
            for i in range(1, 256):
                # Önceki eleman * Pi + subkey çarpımı
                pi_val = self.P[(box_idx + i) % len(self.P)]
                box[i] = (box[i-1] * pi_val + sk_product) & 0xFFFFFFFF
            
            sboxes.append(box)
            
        return sboxes

    def _f_function(self, r: int, skl: int, skr: int, sboxes: List[List[int]]) -> int:
        """IRON F Fonksiyonu."""
        # R ^ SKL
        temp = r ^ skl
        
        # 4 adet 8 bitlik parçaya ayır
        b0 = (temp >> 24) & 0xFF
        b1 = (temp >> 16) & 0xFF
        b2 = (temp >> 8) & 0xFF
        b3 = temp & 0xFF
        
        # S-box lookup
        a0 = sboxes[0][b0]
        a1 = sboxes[1][b1]
        a2 = sboxes[2][b2]
        a3 = sboxes[3][b3]
        
        # A0 + A3, A1 + A2 (mod 2^32 + 1)
        # mod (2^32 + 1) için Python zaten büyük sayılarla başa çıkabilir
        mod_val = 0x100000001
        
        val1 = (a0 + a3) % mod_val
        val2 = (a1 + a2) % mod_val
        
        # (val1 ^ val2) ^ SKR
        # Not: bitwise XOR işlemi mod 2^32+1 sonucunda da 32 bit sınırında kalır
        res = (val1 ^ val2) ^ skr
        
        return res & 0xFFFFFFFF

    def _cipher(self, data: bytes, subkeys: List[Tuple[int, int]], sboxes: List[List[int]], decrypt: bool = False) -> bytes:
        """Çekirdek Feistel işlemi."""
        l = int.from_bytes(data[0:4], 'big')
        r = int.from_bytes(data[4:8], 'big')
        
        num_rounds = len(subkeys)
        
        if decrypt:
            # Deşifrelemede alt anahtarlar ters sırada
            current_subkeys = subkeys[::-1]
        else:
            current_subkeys = subkeys
            
        for i in range(num_rounds):
            skl, skr = current_subkeys[i]
            
            # Feistel formülü:
            # Li+1 = Ri
            # Ri+1 = Li ^ F(Ri, Ki)
            
            f_res = self._f_function(r, skl, skr, sboxes)
            new_r = l ^ f_res
            new_l = r
            
            l, r = new_l, new_r
            
        # Son turda yer değiştirme (swap) yapılmaz (Feistel standardı)
        # Ancak yukarıdaki döngü her turda swap yaptığı için geri almalıyız
        res = r.to_bytes(4, 'big') + l.to_bytes(4, 'big')
        return res

    def encrypt(self, data: bytes, key: str) -> bytes:
        """IRON-CBC Şifreleme."""
        try:
            key_bytes = self._derive_key(key)
            num_rounds = self._calculate_rounds(key_bytes)
            subkeys = self._generate_subkeys(key_bytes, num_rounds)
            sboxes = self._generate_sboxes(key_bytes, subkeys[0])
            
            iv = os.urandom(8)
            padded = self._pkcs7_pad(data)
            
            blocks = []
            prev_block = iv
            for i in range(0, len(padded), 8):
                block = padded[i:i+8]
                # CBC: Plaintext ^ Önceki Ciphertext
                xor_block = bytes(a ^ b for a, b in zip(block, prev_block))
                encrypted = self._cipher(xor_block, subkeys, sboxes, decrypt=False)
                blocks.append(encrypted)
                prev_block = encrypted
                
            return iv + b"".join(blocks)
        except Exception as e:
            raise Exception(f"IRON şifreleme hatası: {str(e)}")

    def decrypt(self, data: bytes, key: str) -> bytes:
        """IRON-CBC Deşifreleme."""
        try:
            if len(data) < 8:
                raise ValueError("Geçersiz şifreli veri (IV eksik)")
                
            key_bytes = self._derive_key(key)
            num_rounds = self._calculate_rounds(key_bytes)
            subkeys = self._generate_subkeys(key_bytes, num_rounds)
            sboxes = self._generate_sboxes(key_bytes, subkeys[0])
            
            iv = data[:8]
            ciphertext = data[8:]
            
            if len(ciphertext) % 8 != 0:
                raise ValueError("Şifreli veri blok boyutu hatası")
                
            blocks = []
            prev_block = iv
            for i in range(0, len(ciphertext), 8):
                block = ciphertext[i:i+8]
                decrypted = self._cipher(block, subkeys, sboxes, decrypt=True)
                # CBC: Decrypted ^ Önceki Ciphertext
                plain_block = bytes(a ^ b for a, b in zip(decrypted, prev_block))
                blocks.append(plain_block)
                prev_block = block
                
            return self._pkcs7_unpad(b"".join(blocks))
        except Exception as e:
            raise Exception(f"IRON deşifreleme hatası: {str(e)}")

    @staticmethod
    def _pkcs7_pad(data: bytes) -> bytes:
        pad_len = 8 - (len(data) % 8)
        return data + bytes([pad_len] * pad_len)

    @staticmethod
    def _pkcs7_unpad(data: bytes) -> bytes:
        if not data: return b""
        pad_len = data[-1]
        if not (1 <= pad_len <= 8): return data
        if data[-pad_len:] != bytes([pad_len] * pad_len):
            return data
        return data[:-pad_len]

    def validate_key(self, key: str) -> bool:
        return bool(key)
