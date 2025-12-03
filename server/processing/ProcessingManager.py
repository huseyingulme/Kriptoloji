"""
ProcessingManager sınıfı - İşlem taleplerini yönetir ve algoritmaları çağırır
"""
from typing import Dict, Any, Optional
from shared.utils import Logger


class ProcessingManager:
    
    def __init__(self):
        self.algorithms = {}
        self._register_algorithms()
    
    def _register_algorithms(self):
        try:
            from server.algorithms.CaesarCipher import CaesarCipher
            self.algorithms['caesar'] = CaesarCipher()
            
            from server.algorithms.VigenereCipher import VigenereCipher
            self.algorithms['vigenere'] = VigenereCipher()
            
            from server.algorithms.HillCipher import HillCipher
            self.algorithms['hill'] = HillCipher()
            
            from server.algorithms.PlayfairCipher import PlayfairCipher
            self.algorithms['playfair'] = PlayfairCipher()
            
            from server.algorithms.RailFenceCipher import RailFenceCipher
            self.algorithms['railfence'] = RailFenceCipher()
            
            from server.algorithms.ColumnarTranspositionCipher import ColumnarTranspositionCipher
            self.algorithms['columnar'] = ColumnarTranspositionCipher()
            
            from server.algorithms.PolybiusCipher import PolybiusCipher
            self.algorithms['polybius'] = PolybiusCipher()
            
            from server.algorithms.AESCipher import AESCipher
            self.algorithms['aes'] = AESCipher()
            
            Logger.info(f"{len(self.algorithms)} algoritma kaydedildi", "ProcessingManager")
            
        except Exception as e:
            Logger.error(f"Algoritma kaydetme hatası: {str(e)}", "ProcessingManager")
    
    def process_request(self, data: bytes, operation: str, algorithm: str, 
                      key: str, metadata: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        İşlem talebini işler
        
        Args:
            data: İşlenecek veri
            operation: İşlem tipi (ENCRYPT/DECRYPT)
            algorithm: Kullanılacak algoritma
            key: Şifreleme anahtarı
            metadata: Ek bilgiler
        
        Returns:
            İşlem sonucu
        """
        try:
            if algorithm not in self.algorithms:
                return {
                    'success': False,
                    'error': f"Desteklenmeyen algoritma: {algorithm}",
                    'data': None
                }
            
            if not key:
                return {
                    'success': False,
                    'error': "Anahtar boş olamaz",
                    'data': None
                }
            
            if not data:
                return {
                    'success': False,
                    'error': "Veri boş olamaz",
                    'data': None
                }
            
            cipher = self.algorithms[algorithm]
            
            if operation == 'ENCRYPT':
                result_data = cipher.encrypt(data, key)
                Logger.info(f"Şifreleme tamamlandı: {algorithm}", "ProcessingManager")
            elif operation == 'DECRYPT':
                result_data = cipher.decrypt(data, key)
                Logger.info(f"Çözme tamamlandı: {algorithm}", "ProcessingManager")
            else:
                return {
                    'success': False,
                    'error': f"Geçersiz işlem: {operation}",
                    'data': None
                }
            
            return {
                'success': True,
                'data': result_data,
                'algorithm': algorithm,
                'operation': operation
            }
            
        except Exception as e:
            Logger.error(f"İşlem hatası: {str(e)}", "ProcessingManager")
            return {
                'success': False,
                'error': f"İşlem hatası: {str(e)}",
                'data': None
            }
    
    def get_available_algorithms(self) -> list:
        return list(self.algorithms.keys())
    
    def get_algorithm_info(self, algorithm: str) -> Optional[Dict[str, Any]]:
        if algorithm not in self.algorithms:
            return None
        
        cipher = self.algorithms[algorithm]
        return {
            'name': algorithm,
            'description': getattr(cipher, 'description', 'Açıklama yok'),
            'key_type': getattr(cipher, 'key_type', 'string'),
            'supports_binary': getattr(cipher, 'supports_binary', True)
        }
    
    def validate_key(self, algorithm: str, key: str) -> bool:
        if algorithm not in self.algorithms:
            return False
        
        cipher = self.algorithms[algorithm]
        if hasattr(cipher, 'validate_key'):
            return cipher.validate_key(key)
        
        return bool(key)  # Varsayılan kontrol
    
    def get_key_requirements(self, algorithm: str) -> Dict[str, Any]:
        if algorithm not in self.algorithms:
            return {}
        
        cipher = self.algorithms[algorithm]
        return {
            'min_length': getattr(cipher, 'min_key_length', 1),
            'max_length': getattr(cipher, 'max_key_length', 256),
            'type': getattr(cipher, 'key_type', 'string'),
            'description': getattr(cipher, 'key_description', 'Anahtar açıklaması yok')
        }

