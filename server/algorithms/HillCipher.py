Hill Cipher implementasyonu
import numpy as np
from server.algorithms.BaseCipher import BaseCipher
from typing import Union


class HillCipher(BaseCipher):
    
    def __init__(self):
        super().__init__()
        self.name = "Hill Cipher"
        self.description = "Hill matris tabanlı şifreleme algoritması"
        self.key_type = "matrix"
        self.min_key_length = 4
        self.max_key_length = 16
        self.key_description = "2x2 veya 3x3 matris (ör: 1,2,3,4)"
        self.matrix_size = 2  # Varsayılan 2x2 matris
    
    def encrypt(self, data: bytes, key: str) -> bytes:
        Hill şifreleme
        
        Args:
            data: Şifrelenecek veri
            key: Matris anahtarı (virgülle ayrılmış sayılar)
        
        Returns:
            Şifrelenmiş veri
        try:
            key_matrix = self._parse_key(key)
            
            data_str = data.decode('utf-8', errors='ignore')
            data_str = ''.join(c.upper() for c in data_str if c.isalpha())
            
            while len(data_str) % self.matrix_size != 0:
                data_str += 'X'
            
            result = ""
            
            for i in range(0, len(data_str), self.matrix_size):
                group = data_str[i:i + self.matrix_size]
                encrypted_group = self._encrypt_group(group, key_matrix)
                result += encrypted_group
            
            return result.encode('utf-8')
            
        except Exception as e:
            raise Exception(f"Şifreleme hatası: {str(e)}")
    
    def decrypt(self, data: bytes, key: str) -> bytes:
        Hill çözme
        
        Args:
            data: Çözülecek veri
            key: Matris anahtarı
        
        Returns:
            Çözülmüş veri
        try:
            key_matrix = self._parse_key(key)
            
            det = int(np.linalg.det(key_matrix)) % 26
            if det == 0:
                raise ValueError("Matris determinantı 0 olamaz")
            
            det_inv = self._mod_inverse(det, 26)
            if det_inv is None:
                raise ValueError("Matris tersi hesaplanamıyor")
            
            adj_matrix = np.linalg.inv(key_matrix) * np.linalg.det(key_matrix)
            adj_matrix = adj_matrix.astype(int)
            inverse_matrix = (adj_matrix * det_inv) % 26
            
            data_str = data.decode('utf-8', errors='ignore')
            data_str = ''.join(c.upper() for c in data_str if c.isalpha())
            
            result = ""
            
            for i in range(0, len(data_str), self.matrix_size):
                group = data_str[i:i + self.matrix_size]
                decrypted_group = self._decrypt_group(group, inverse_matrix)
                result += decrypted_group
            
            return result.encode('utf-8')
            
        except Exception as e:
            raise Exception(f"Çözme hatası: {str(e)}")
    
    def _parse_key(self, key: str) -> np.ndarray:
        try:
            key_values = [int(x.strip()) for x in key.split(',')]
            
            if len(key_values) == 4:
                self.matrix_size = 2
                matrix = np.array(key_values).reshape(2, 2)
            elif len(key_values) == 9:
                self.matrix_size = 3
                matrix = np.array(key_values).reshape(3, 3)
            else:
                raise ValueError("Anahtar 4 (2x2) veya 9 (3x3) sayı içermeli")
            
            det = int(np.linalg.det(matrix)) % 26
            if det == 0:
                raise ValueError("Matris determinantı 0 olamaz")
            
            return matrix
            
        except ValueError as e:
            raise ValueError(f"Geçersiz anahtar formatı: {str(e)}")
    
    def _encrypt_group(self, group: str, matrix: np.ndarray) -> str:
        vector = np.array([ord(c) - ord('A') for c in group])
        
        result_vector = np.dot(matrix, vector) % 26
        
        return ''.join(chr(int(x) + ord('A')) for x in result_vector)
    
    def _decrypt_group(self, group: str, inverse_matrix: np.ndarray) -> str:
        vector = np.array([ord(c) - ord('A') for c in group])
        
        result_vector = np.dot(inverse_matrix, vector) % 26
        
        result = ''.join(chr(int(x) + ord('A')) for x in result_vector)
        
        while result.endswith('X'):
            result = result[:-1]
        
        return result
    
    def _mod_inverse(self, a: int, m: int) -> int:
        for i in range(1, m):
            if (a * i) % m == 1:
                return i
        return None
    
    def validate_key(self, key: str) -> bool:
        Hill anahtar geçerliliğini kontrol eder
        
        Args:
            key: Kontrol edilecek anahtar
        
        Returns:
            Anahtar geçerliliği
        try:
            key_values = [int(x.strip()) for x in key.split(',')]
            
            if len(key_values) not in [4, 9]:
                return False
            
            if len(key_values) == 4:
                matrix = np.array(key_values).reshape(2, 2)
            else:
                matrix = np.array(key_values).reshape(3, 3)
            
            det = int(np.linalg.det(matrix)) % 26
            if det == 0:
                return False
            
            det_inv = self._mod_inverse(det, 26)
            if det_inv is None:
                return False
            
            return True
            
        except (ValueError, IndexError):
            return False
