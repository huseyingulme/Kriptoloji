"""
Route Cipher - Rota Tabanlı Şifreleme

Metin bir matrise yerleştirilir ve belirli bir rota (spiral, satır, sütun, diagonal) 
izlenerek okunur.
"""

from algorithms.BaseCipher import BaseCipher
import math


class RouteCipher(BaseCipher):
    """
    Route Cipher - Rota tabanlı şifreleme.
    
    Metin bir matrise yerleştirilir ve belirli bir rota izlenerek okunur.
    """
    
    def __init__(self):
        super().__init__()
        self.name = "Route Cipher"
        self.description = "Rota tabanlı şifreleme - Matris içinde belirli rota izlenerek okuma"
        self.key_type = "string"
        self.min_key_length = 3
        self.max_key_length = 20
        self.key_description = "Format: 'rows:cols:route_type' (örn: '3:3:spiral', '4:4:row', '3:3:column', '3:3:diagonal'). Route types: spiral, row, column, diagonal"
        self.supports_binary = False
    
    def _parse_key(self, key: str) -> tuple:
        """Anahtarı parse eder: rows:cols:route_type"""
        try:
            parts = key.split(':')
            if len(parts) != 3:
                raise ValueError("Anahtar formatı: 'rows:cols:route_type'")
            
            rows = int(parts[0])
            cols = int(parts[1])
            route_type = parts[2].lower()
            
            if rows < 2 or cols < 2:
                raise ValueError("Satır ve sütun sayısı en az 2 olmalı")
            
            if route_type not in ['spiral', 'row', 'column', 'diagonal']:
                raise ValueError("Rota tipi: spiral, row, column, diagonal olmalı")
            
            return rows, cols, route_type
        
        except Exception as e:
            raise ValueError(f"Anahtar parse hatası: {str(e)}")
    
    def _spiral_read(self, matrix: list, rows: int, cols: int) -> str:
        """Spiral rota ile okur (saat yönünde dıştan içe)."""
        result = []
        top, bottom = 0, rows - 1
        left, right = 0, cols - 1
        
        while top <= bottom and left <= right:
            # Sağa
            for i in range(left, right + 1):
                if matrix[top][i] != ' ':
                    result.append(matrix[top][i])
            top += 1
            
            # Aşağı
            for i in range(top, bottom + 1):
                if matrix[i][right] != ' ':
                    result.append(matrix[i][right])
            right -= 1
            
            # Sola
            if top <= bottom:
                for i in range(right, left - 1, -1):
                    if matrix[bottom][i] != ' ':
                        result.append(matrix[bottom][i])
                bottom -= 1
            
            # Yukarı
            if left <= right:
                for i in range(bottom, top - 1, -1):
                    if matrix[i][left] != ' ':
                        result.append(matrix[i][left])
                left += 1
        
        return ''.join(result)
    
    def _spiral_write(self, text: str, rows: int, cols: int) -> list:
        """Spiral rota ile yazar (saat yönünde dıştan içe)."""
        matrix = [[' ' for _ in range(cols)] for _ in range(rows)]
        text_idx = 0
        top, bottom = 0, rows - 1
        left, right = 0, cols - 1
        
        while top <= bottom and left <= right and text_idx < len(text):
            # Sağa
            for i in range(left, right + 1):
                if text_idx < len(text):
                    matrix[top][i] = text[text_idx]
                    text_idx += 1
            top += 1
            
            # Aşağı
            for i in range(top, bottom + 1):
                if text_idx < len(text):
                    matrix[i][right] = text[text_idx]
                    text_idx += 1
            right -= 1
            
            # Sola
            if top <= bottom:
                for i in range(right, left - 1, -1):
                    if text_idx < len(text):
                        matrix[bottom][i] = text[text_idx]
                        text_idx += 1
                bottom -= 1
            
            # Yukarı
            if left <= right:
                for i in range(bottom, top - 1, -1):
                    if text_idx < len(text):
                        matrix[i][left] = text[text_idx]
                        text_idx += 1
                left += 1
        
        return matrix
    
    def _row_read(self, matrix: list, rows: int, cols: int) -> str:
        """Satır satır okur."""
        result = []
        for i in range(rows):
            for j in range(cols):
                if matrix[i][j] != ' ':
                    result.append(matrix[i][j])
        return ''.join(result)
    
    def _row_write(self, text: str, rows: int, cols: int) -> list:
        """Satır satır yazar."""
        matrix = [[' ' for _ in range(cols)] for _ in range(rows)]
        text_idx = 0
        for i in range(rows):
            for j in range(cols):
                if text_idx < len(text):
                    matrix[i][j] = text[text_idx]
                    text_idx += 1
        return matrix
    
    def _column_read(self, matrix: list, rows: int, cols: int) -> str:
        """Sütun sütun okur."""
        result = []
        for j in range(cols):
            for i in range(rows):
                if matrix[i][j] != ' ':
                    result.append(matrix[i][j])
        return ''.join(result)
    
    def _column_write(self, text: str, rows: int, cols: int) -> list:
        """Sütun sütun yazar."""
        matrix = [[' ' for _ in range(cols)] for _ in range(rows)]
        text_idx = 0
        for j in range(cols):
            for i in range(rows):
                if text_idx < len(text):
                    matrix[i][j] = text[text_idx]
                    text_idx += 1
        return matrix
    
    def _diagonal_read(self, matrix: list, rows: int, cols: int) -> str:
        """Diagonal (çapraz) okur."""
        result = []
        # Sol üstten sağ alta
        for d in range(rows + cols - 1):
            for i in range(rows):
                j = d - i
                if 0 <= j < cols:
                    if matrix[i][j] != ' ':
                        result.append(matrix[i][j])
        return ''.join(result)
    
    def _diagonal_write(self, text: str, rows: int, cols: int) -> list:
        """Diagonal (çapraz) yazar."""
        matrix = [[' ' for _ in range(cols)] for _ in range(rows)]
        text_idx = 0
        # Sol üstten sağ alta
        for d in range(rows + cols - 1):
            for i in range(rows):
                j = d - i
                if 0 <= j < cols and text_idx < len(text):
                    matrix[i][j] = text[text_idx]
                    text_idx += 1
        return matrix
    
    def encrypt(self, data: bytes, key: str) -> bytes:
        """
        Veriyi Route Cipher ile şifreler.
        
        Args:
            data: Şifrelenecek veri (bytes)
            key: Format: 'rows:cols:route_type'
            
        Returns:
            bytes: Şifrelenmiş veri
        """
        try:
            rows, cols, route_type = self._parse_key(key)
            
            # Veriyi string'e çevir ve temizle
            text = data.decode('utf-8', errors='ignore').upper().replace(' ', '')
            
            # Matrise yaz
            if route_type == 'spiral':
                matrix = self._spiral_write(text, rows, cols)
                # Spiral yazıldıktan sonra satır satır oku
                encrypted_text = self._row_read(matrix, rows, cols)
            elif route_type == 'row':
                matrix = self._row_write(text, rows, cols)
                # Satır satır yazıldıktan sonra sütun sütun oku
                encrypted_text = self._column_read(matrix, rows, cols)
            elif route_type == 'column':
                matrix = self._column_write(text, rows, cols)
                # Sütun sütun yazıldıktan sonra satır satır oku
                encrypted_text = self._row_read(matrix, rows, cols)
            elif route_type == 'diagonal':
                matrix = self._diagonal_write(text, rows, cols)
                # Diagonal yazıldıktan sonra satır satır oku
                encrypted_text = self._row_read(matrix, rows, cols)
            else:
                raise ValueError(f"Bilinmeyen rota tipi: {route_type}")
            
            return encrypted_text.encode('utf-8')
        
        except Exception as e:
            raise Exception(f"Route şifreleme hatası: {str(e)}")
    
    def decrypt(self, data: bytes, key: str) -> bytes:
        """
        Route Cipher ile şifrelenmiş veriyi çözer.
        
        Args:
            data: Çözülecek veri (bytes)
            key: Format: 'rows:cols:route_type'
            
        Returns:
            bytes: Çözülmüş veri
        """
        try:
            rows, cols, route_type = self._parse_key(key)
            
            # Veriyi string'e çevir
            text = data.decode('utf-8', errors='ignore').upper().replace(' ', '')
            
            # Matrise yaz (şifrelemenin tersi)
            if route_type == 'spiral':
                # Satır satır yaz
                matrix = self._row_write(text, rows, cols)
                # Spiral oku
                decrypted_text = self._spiral_read(matrix, rows, cols)
            elif route_type == 'row':
                # Sütun sütun yaz
                matrix = self._column_write(text, rows, cols)
                # Satır satır oku
                decrypted_text = self._row_read(matrix, rows, cols)
            elif route_type == 'column':
                # Satır satır yaz
                matrix = self._row_write(text, rows, cols)
                # Sütun sütun oku
                decrypted_text = self._column_read(matrix, rows, cols)
            elif route_type == 'diagonal':
                # Satır satır yaz
                matrix = self._row_write(text, rows, cols)
                # Diagonal oku
                decrypted_text = self._diagonal_read(matrix, rows, cols)
            else:
                raise ValueError(f"Bilinmeyen rota tipi: {route_type}")
            
            return decrypted_text.encode('utf-8')
        
        except Exception as e:
            raise Exception(f"Route çözme hatası: {str(e)}")

