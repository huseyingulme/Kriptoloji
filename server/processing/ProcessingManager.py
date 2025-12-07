"""
ProcessingManager - Şifreleme İşlemlerini Yöneten Ana Sınıf

Bu sınıf, server tarafında tüm şifreleme ve deşifreleme işlemlerini yönetir.
Client'tan gelen istekleri alır, uygun algoritmayı seçer ve işlemi gerçekleştirir.

ÖNEMLİ: Tüm şifreleme işlemleri SERVER tarafında yapılır, client tarafında değil!
Bu, gerçek hayattaki güvenli sistemlerin çalışma mantığıyla aynıdır.
"""

import time
from typing import Dict, Any, Optional
from shared.utils import Logger
from shared.advanced_logger import advanced_logger


class ProcessingManager:
    """
    Şifreleme işlemlerini yöneten ana sınıf.
    
    Görevleri:
    1. Tüm şifreleme algoritmalarını kaydetmek
    2. Client'tan gelen istekleri işlemek
    3. Uygun algoritmayı seçip şifreleme/deşifreleme yapmak
    4. Sonuçları client'a geri göndermek
    """

    def __init__(self):
        """ProcessingManager'ı başlatır ve algoritmaları kaydeder."""
        self.algorithms = {}  # Tüm algoritmalar burada saklanır
        self._register_algorithms()

    def _register_algorithms(self):
        """
        Tüm şifreleme algoritmalarını kaydeder.
        
        Her algoritma bir sözlüğe eklenir ve daha sonra kullanılabilir.
        Yeni algoritma eklemek için buraya import ve kayıt eklenmelidir.
        """
        try:
            # Caesar Cipher - Klasik kaydırma algoritması
            from server.algorithms.CaesarCipher import CaesarCipher
            self.algorithms['caesar'] = CaesarCipher()

            # Vigenere Cipher - Çoklu anahtar kullanan algoritma
            from server.algorithms.VigenereCipher import VigenereCipher
            self.algorithms['vigenere'] = VigenereCipher()

            # Hill Cipher - Matris tabanlı şifreleme
            from server.algorithms.HillCipher import HillCipher
            self.algorithms['hill'] = HillCipher()

            # Playfair Cipher - İki harfli bloklar kullanan algoritma
            from server.algorithms.PlayfairCipher import PlayfairCipher
            self.algorithms['playfair'] = PlayfairCipher()

            # Rail Fence Cipher - Zigzag desenli şifreleme
            from server.algorithms.RailFenceCipher import RailFenceCipher
            self.algorithms['railfence'] = RailFenceCipher()

            # Columnar Transposition - Sütun bazlı yer değiştirme
            from server.algorithms.ColumnarTranspositionCipher import ColumnarTranspositionCipher
            self.algorithms['columnar'] = ColumnarTranspositionCipher()

            # Polybius Cipher - Kare tabanlı şifreleme
            from server.algorithms.PolybiusCipher import PolybiusCipher
            self.algorithms['polybius'] = PolybiusCipher()

            # AES - Gelişmiş şifreleme standardı
            from server.algorithms.AESCipher import AESCipher
            self.algorithms['aes'] = AESCipher()

            # DES - Veri şifreleme standardı
            from server.algorithms.DESCipher import DESCipher
            self.algorithms['des'] = DESCipher()

            Logger.info(f"{len(self.algorithms)} algoritma başarıyla kaydedildi", "ProcessingManager")

        except Exception as e:
            Logger.error(f"Algoritma kaydetme hatası: {str(e)}", "ProcessingManager")

    def process_request(self, data: bytes, operation: str, algorithm: str,
                      key: str, metadata: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Client'tan gelen şifreleme/deşifreleme isteğini işler.
        
        İşlem Adımları:
        1. Algoritmanın kayıtlı olup olmadığını kontrol eder
        2. Anahtar ve veri kontrolü yapar
        3. Uygun algoritmayı seçer
        4. Şifreleme veya deşifreleme işlemini gerçekleştirir
        5. Sonucu döndürür
        
        Args:
            data: Şifrelenecek/deşifrelenecek veri (bytes)
            operation: İşlem tipi ('ENCRYPT' veya 'DECRYPT')
            algorithm: Kullanılacak algoritma adı
            key: Şifreleme anahtarı
            metadata: Ek bilgiler (opsiyonel)
            
        Returns:
            Dict: İşlem sonucu (success, data, error vb.)
        """
        try:
            # 1. Algoritma kontrolü
            if algorithm not in self.algorithms:
                return {
                    'success': False,
                    'error': f"Desteklenmeyen algoritma: {algorithm}",
                    'data': None
                }

            # 2. Anahtar kontrolü (Polybius gibi bazı algoritmalar anahtar gerektirmez)
            if not key and algorithm not in ['polybius']:
                return {
                    'success': False,
                    'error': "Anahtar boş olamaz",
                    'data': None
                }

            # 3. Veri kontrolü
            if not data:
                return {
                    'success': False,
                    'error': "Veri boş olamaz",
                    'data': None
                }

            # 4. Algoritmayı seç
            cipher = self.algorithms[algorithm]

            # 5. İşlemi gerçekleştir ve süreyi ölç
            start_time = time.time()
            
            if operation == 'ENCRYPT':
                # ŞİFRELEME İŞLEMİ
                result_data = cipher.encrypt(data, key)
                duration = time.time() - start_time
                Logger.info(f"Şifreleme tamamlandı: {algorithm} ({duration:.3f}s)", "ProcessingManager")
                
                # Performans loglama
                advanced_logger.log_performance(f"encrypt_{algorithm}", duration, {"data_size": len(data)})
                advanced_logger.log_operation("encrypt", algorithm, True, {
                    "data_size": len(data), 
                    "duration": duration
                })
                
            elif operation == 'DECRYPT':
                # DEŞİFRELEME İŞLEMİ
                result_data = cipher.decrypt(data, key)
                duration = time.time() - start_time
                Logger.info(f"Çözme tamamlandı: {algorithm} ({duration:.3f}s)", "ProcessingManager")
                
                # Performans loglama
                advanced_logger.log_performance(f"decrypt_{algorithm}", duration, {"data_size": len(data)})
                advanced_logger.log_operation("decrypt", algorithm, True, {
                    "data_size": len(data), 
                    "duration": duration
                })
            else:
                return {
                    'success': False,
                    'error': f"Geçersiz işlem: {operation}",
                    'data': None
                }

            # 6. Başarılı sonucu döndür
            return {
                'success': True,
                'data': result_data,
                'algorithm': algorithm,
                'operation': operation
            }

        except ValueError as e:
            # Geçersiz parametre hatası
            Logger.error(f"Geçersiz parametre hatası: {str(e)}", "ProcessingManager")
            advanced_logger.log_operation(operation.lower(), algorithm, False, {
                "error": str(e), 
                "type": "ValueError"
            })
            return {
                'success': False,
                'error': f"Geçersiz parametre: {str(e)}",
                'data': None
            }
        except KeyError as e:
            # Eksik parametre hatası
            Logger.error(f"Eksik parametre hatası: {str(e)}", "ProcessingManager")
            advanced_logger.log_operation(operation.lower(), algorithm, False, {
                "error": str(e), 
                "type": "KeyError"
            })
            return {
                'success': False,
                'error': f"Eksik parametre: {str(e)}",
                'data': None
            }
        except Exception as e:
            # Genel hata
            Logger.error(f"İşlem hatası: {str(e)}", "ProcessingManager")
            import traceback
            error_trace = traceback.format_exc()
            Logger.debug(f"Detaylı hata: {error_trace}", "ProcessingManager")
            advanced_logger.log_operation(operation.lower(), algorithm, False, {
                "error": str(e), 
                "traceback": error_trace
            })
            return {
                'success': False,
                'error': f"İşlem hatası: {str(e)}",
                'data': None
            }

    def get_available_algorithms(self) -> list:
        """Kayıtlı tüm algoritmaların listesini döndürür."""
        return list(self.algorithms.keys())

    def get_algorithm_info(self, algorithm: str) -> Optional[Dict[str, Any]]:
        """
        Belirtilen algoritma hakkında bilgi döndürür.
        
        Returns:
            Dict: Algoritma bilgileri (name, description, key_type vb.)
        """
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
        """Anahtarın geçerli olup olmadığını kontrol eder."""
        if algorithm not in self.algorithms:
            return False

        cipher = self.algorithms[algorithm]
        if hasattr(cipher, 'validate_key'):
            return cipher.validate_key(key)

        return bool(key)

    def get_key_requirements(self, algorithm: str) -> Dict[str, Any]:
        """Algoritma için anahtar gereksinimlerini döndürür."""
        if algorithm not in self.algorithms:
            return {}

        cipher = self.algorithms[algorithm]
        return {
            'min_length': getattr(cipher, 'min_key_length', 1),
            'max_length': getattr(cipher, 'max_key_length', 256),
            'type': getattr(cipher, 'key_type', 'string'),
            'description': getattr(cipher, 'key_description', 'Anahtar açıklaması yok')
        }
