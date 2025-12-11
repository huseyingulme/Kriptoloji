"""
Pigpen Cipher - Sembol Tabanlı Şifreleme

Her harf, özel bir sembol ile temsil edilir. Masonik şifreleme olarak da bilinir.
"""

from algorithms.BaseCipher import BaseCipher


class PigpenCipher(BaseCipher):
    """
    Pigpen Cipher - Sembol tabanlı şifreleme.
    
    Her harf, özel bir sembol ile temsil edilir.
    """
    
    def __init__(self):
        super().__init__()
        self.name = "Pigpen Cipher"
        self.description = "Sembol tabanlı şifreleme - Her harf özel sembol ile temsil edilir (Masonik şifreleme)"
        self.key_type = "none"
        self.min_key_length = 0
        self.max_key_length = 0
        self.key_description = "Anahtar gerekmez (otomatik sembol tablosu kullanılır)"
        self.supports_binary = False
        
        # Pigpen sembol tablosu
        # Her harf için özel sembol
        self.symbol_map = {
            'A': '┌─', 'B': '┐─', 'C': '└─', 'D': '┘─',
            'E': '├─', 'F': '┤─', 'G': '┬─', 'H': '┴─',
            'I': '┼─', 'J': '┼─',  # I ve J aynı sembol
            'K': '╔═', 'L': '╗═', 'M': '╚═', 'N': '╝═',
            'O': '╠═', 'P': '╣═', 'Q': '╦═', 'R': '╩═',
            'S': '╬═', 'T': '╬═',
            'U': '◊', 'V': '◊', 'W': '◊', 'X': '◊',
            'Y': '◊', 'Z': '◊'
        }
        
        # Ters mapping (sembol -> harf)
        self.reverse_map = {}
        for char, symbol in self.symbol_map.items():
            if symbol not in self.reverse_map:
                self.reverse_map[symbol] = char
            # I ve J aynı sembolü paylaşır
            if char == 'J':
                self.reverse_map[symbol] = 'I'  # Varsayılan olarak I
    
    def validate_key(self, key: str) -> bool:
        """Pigpen cipher anahtar gerektirmez."""
        return True
    
    def encrypt(self, data: bytes, key: str) -> bytes:
        """
        Veriyi Pigpen Cipher ile şifreler.
        
        Args:
            data: Şifrelenecek veri (bytes)
            key: Anahtar gerekmez (boş string olabilir)
            
        Returns:
            bytes: Şifrelenmiş veri (semboller)
        """
        try:
            # Veriyi string'e çevir ve büyük harfe çevir
            text = data.decode('utf-8', errors='ignore').upper()
            
            encrypted_chars = []
            for char in text:
                if char.isalpha():
                    # Harfi sembole çevir
                    symbol = self.symbol_map.get(char, char)
                    encrypted_chars.append(symbol)
                elif char == ' ':
                    encrypted_chars.append(' ')
                else:
                    # Diğer karakterler olduğu gibi kalır
                    encrypted_chars.append(char)
            
            encrypted_text = ''.join(encrypted_chars)
            return encrypted_text.encode('utf-8')
        
        except Exception as e:
            raise Exception(f"Pigpen şifreleme hatası: {str(e)}")
    
    def decrypt(self, data: bytes, key: str) -> bytes:
        """
        Pigpen Cipher ile şifrelenmiş veriyi çözer.
        
        Args:
            data: Çözülecek veri (bytes) - semboller
            key: Anahtar gerekmez (boş string olabilir)
            
        Returns:
            bytes: Çözülmüş veri
        """
        try:
            # Veriyi string'e çevir
            text = data.decode('utf-8', errors='ignore')
            
            decrypted_chars = []
            i = 0
            while i < len(text):
                char = text[i]
                
                # Boşluk karakteri
                if char == ' ':
                    decrypted_chars.append(' ')
                    i += 1
                    continue
                
                # Sembol kontrolü (2-3 karakterlik semboller olabilir)
                found = False
                for symbol_length in [3, 2, 1]:  # Önce uzun sembolleri kontrol et
                    if i + symbol_length <= len(text):
                        symbol = text[i:i+symbol_length]
                        if symbol in self.reverse_map:
                            decrypted_chars.append(self.reverse_map[symbol])
                            i += symbol_length
                            found = True
                            break
                
                if not found:
                    # Sembol bulunamadı, karakter olduğu gibi kalır
                    decrypted_chars.append(char)
                    i += 1
            
            decrypted_text = ''.join(decrypted_chars)
            return decrypted_text.encode('utf-8')
        
        except Exception as e:
            raise Exception(f"Pigpen çözme hatası: {str(e)}")

