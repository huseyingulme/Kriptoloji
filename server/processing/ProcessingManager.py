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
            from algorithms.CaesarCipher import CaesarCipher
            self.algorithms['caesar'] = CaesarCipher()

            # Vigenere Cipher - Çoklu anahtar kullanan algoritma
            from algorithms.VigenereCipher import VigenereCipher
            self.algorithms['vigenere'] = VigenereCipher()

            # Affine Cipher - Doğrusal şifreleme algoritması
            from algorithms.AffineCipher import AffineCipher
            self.algorithms['affine'] = AffineCipher()

            # Hill Cipher - Matris tabanlı şifreleme
            from algorithms.HillCipher import HillCipher
            self.algorithms['hill'] = HillCipher()

            # Playfair Cipher - İki harfli bloklar kullanan algoritma
            from algorithms.PlayfairCipher import PlayfairCipher
            self.algorithms['playfair'] = PlayfairCipher()

            # Rail Fence Cipher - Zigzag desenli şifreleme
            from algorithms.RailFenceCipher import RailFenceCipher
            self.algorithms['railfence'] = RailFenceCipher()

            # Columnar Transposition - Sütun bazlı yer değiştirme
            from algorithms.ColumnarTranspositionCipher import ColumnarTranspositionCipher
            self.algorithms['columnar'] = ColumnarTranspositionCipher()

            # Polybius Cipher - Kare tabanlı şifreleme
            from algorithms.PolybiusCipher import PolybiusCipher
            self.algorithms['polybius'] = PolybiusCipher()

            # Substitution Cipher - Alfabe karıştırma şifreleme
            from algorithms.SubstitutionCipher import SubstitutionCipher
            self.algorithms['substitution'] = SubstitutionCipher()

            # Route Cipher - Rota tabanlı şifreleme
            from algorithms.RouteCipher import RouteCipher
            self.algorithms['route'] = RouteCipher()

            # Pigpen Cipher - Sembol tabanlı şifreleme
            from algorithms.PigpenCipher import PigpenCipher
            self.algorithms['pigpen'] = PigpenCipher()

            # AES - Gelişmiş şifreleme standardı (Kütüphaneli)
            from algorithms.AESCipher import AESCipher
            self.algorithms['aes'] = AESCipher()
            self.algorithms['aes_lib'] = AESCipher()  # Kütüphaneli versiyon

            # AES Manual - Kütüphanesiz manuel implementasyon
            from algorithms.AESManual import AESManual
            self.algorithms['aes_manual'] = AESManual()

            # DES - Veri şifreleme standardı (Kütüphaneli)
            from algorithms.DESCipher import DESCipher
            self.algorithms['des'] = DESCipher()
            self.algorithms['des_lib'] = DESCipher()  # Yeniden eklendi

            # DES Manual - Kütüphanesiz manuel implementasyon
            from algorithms.DESManual import DESManual
            self.algorithms['des_manual'] = DESManual()

            # RSA - Asimetrik şifreleme (Anahtar dağıtımı için) - Kütüphaneli
            from algorithms.RSACipher import RSACipher
            self.algorithms['rsa'] = RSACipher()
            self.algorithms['rsa_lib'] = RSACipher()  # Yeniden eklendi
            
            # RSA Manual - Kütüphanesiz manuel implementasyon
            from algorithms.RSAManual import RSAManual
            self.algorithms['rsa_manual'] = RSAManual()

            Logger.info(f"{len(self.algorithms)} algoritma başarıyla kaydedildi", "ProcessingManager")

        except Exception as e:
            Logger.error(f"Algoritma kaydetme hatası: {str(e)}", "ProcessingManager")
            import traceback
            Logger.debug(f"Detaylı hata: {traceback.format_exc()}", "ProcessingManager")

    def process_request(self, data: bytes, operation: str, algorithm: str,
                      key: str, metadata: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Client'tan gelen şifreleme/deşifreleme isteğini işler.
        
        İşlem Adımları:
        1. Algoritmanın kayıtlı olup olmadığını kontrol eder
        2. Anahtar ve veri kontrolü yapar
        3. Uygun algoritmayı seçer (kütüphaneli/kütüphanesiz mod)
        4. Şifreleme veya deşifreleme işlemini gerçekleştirir
           - ENCRYPT: cipher.encrypt(data, key) çağrılır
           - DECRYPT: cipher.decrypt(data, key) çağrılır
        5. Performans ölçümü yapılır ve loglanır
        6. Sonucu döndürür
        
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
            if not key and algorithm not in ['polybius', 'pigpen']:
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

            # 4. Algoritmayı seç (kütüphaneli/kütüphanesiz mod kontrolü)
            use_library = metadata.get('use_library', True) if metadata else True
            
            # Algoritma adını düzelt (mod seçimine göre)
            actual_algorithm = algorithm
            if algorithm in ['aes', 'aes_manual']:
                actual_algorithm = 'aes_lib' if use_library else 'aes_manual'
            elif algorithm in ['des', 'des_manual']:
                actual_algorithm = 'des_lib' if use_library else 'des_manual'
            elif algorithm in ['rsa', 'rsa_manual']:
                actual_algorithm = 'rsa_lib' if use_library else 'rsa_manual'
            
            if actual_algorithm not in self.algorithms:
                return {
                    'success': False,
                    'error': f"Desteklenmeyen algoritma: {actual_algorithm}",
                    'data': None
                }
            
            cipher = self.algorithms[actual_algorithm]

            # 5. İşlemi gerçekleştir ve süreyi ölç
            start_time = time.time()
            
            # İŞLEM BİLGİLERİNİ DETAYLI GÖSTER (Client-Server Mantığını Göstermek İçin)
            Logger.info("╔════════════════════════════════════════════════════════════╗", "ProcessingManager")
            Logger.info(f"║ İŞLEM TÜRÜ    : {operation:<35} ║", "ProcessingManager")
            Logger.info(f"║ ALGORİTMA     : {algorithm:<35} ║", "ProcessingManager")
            
            # Anahtarı güvenli göster (çok uzunsa kısalt)
            safe_key = str(key)
            if len(safe_key) > 40:
                safe_key = safe_key[:37] + "..."
            Logger.info(f"║ ANAHTAR       : {safe_key:<35} ║", "ProcessingManager")
            
            # Veri önizleme
            data_preview = str(data[:40])
            if len(data) > 40:
                data_preview = data_preview[:37] + "..."
            Logger.info(f"║ GİRDİ VERİSİ  : {data_preview:<35} ║", "ProcessingManager")
            Logger.info("╚════════════════════════════════════════════════════════════╝", "ProcessingManager")

            if operation == 'ENCRYPT':
                # ŞİFRELEME İŞLEMİ
                Logger.info(f"🔄 {algorithm} ile şifreleme işlemi başlatılıyor...", "ProcessingManager")
                result_data = cipher.encrypt(data, key)
                duration = time.time() - start_time
                
                # Çıktı önizleme
                result_preview = str(result_data[:40])
                if len(result_data) > 40:
                    result_preview = result_preview[:37] + "..."
                Logger.info(f"✅ Şifreleme tamamlandı ({duration:.3f}s)", "ProcessingManager")
                Logger.info(f"📦 ŞİFRELİ ÇIKTI : {result_preview}", "ProcessingManager")
                
                # RSA için "generate" kullanıldıysa private key'i de ekle
                # ÖNEMLİ: Eğer bu bir dosya işlemiyse (metadata'da filename varsa), 
                # etiketleri ekleme ki dosya bozulmasın!
                is_file = metadata and ('filename' in metadata or 'extension' in metadata)
                
                if not is_file and algorithm in ['rsa', 'rsa_manual', 'rsa_lib'] and (isinstance(key, str) and (key.lower() == 'generate' or not key or key.strip() == '')):
                    if hasattr(cipher, '_last_generated_private_key') and cipher._last_generated_private_key:
                        import base64
                        private_key_b64 = base64.b64encode(cipher._last_generated_private_key).decode('utf-8')
                        # Private key'i result_data'ya ekle (sadece metin modu için)
                        result_str = result_data.decode('utf-8', errors='ignore') if isinstance(result_data, bytes) else str(result_data)
                        result_data = f"RSA_PRIVATE_KEY:\n{private_key_b64}\n\nŞİFRELENMİŞ VERİ:\n{result_str}".encode('utf-8')
                
                # Performans loglama
                advanced_logger.log_performance(f"encrypt_{algorithm}", duration, {"data_size": len(data)})
                advanced_logger.log_operation("encrypt", algorithm, True, {
                    "data_size": len(data), 
                    "duration": duration
                })
                
            elif operation == 'DECRYPT':
                # DEŞİFRELEME İŞLEMİ (Akıllı Tespit ve Etiket Temizleme)
                Logger.info(f"🔄 {algorithm} ile şifre çözme işlemi başlatılıyor...", "ProcessingManager")
                
                # ÖNEMLİ: Eğer bu bir dosya işlemiyse, veriye hiç dokunma (binary bütünlüğü için)
                is_file = metadata and ('filename' in metadata or 'extension' in metadata)
                temp_data = data
                
                if not is_file:
                    try:
                        # Metin işlemleri için etiket temizleme ve otomatik tespit yap
                        data_str = data.decode('utf-8', errors='ignore').strip()
                        
                        # 0. ETİKETLERİ TEMİZLE
                        lines = data_str.split('\n')
                        clean_lines = []
                        for line in lines:
                            line_strip = line.strip()
                            if not line_strip: continue
                            if any(tag in line_strip for tag in [
                                "ŞİFRELENMİŞ VERİ:", "Şifrelenmiş Metin:", "Şifrelenmiş Veri (Hex):", 
                                "Hex Formatı:", "Base64 Formatı:", "Şifrelenmiş Veri (Base64):",
                                "RSA_PRIVATE_KEY:", "⚠️ ÖNEMLİ:", "Boyut:", "Not:"
                            ]):
                                continue
                            clean_lines.append(line_strip)
                        
                        if clean_lines:
                            # Hex/Base64 tespiti için birleştir
                            test_str = "".join(clean_lines).replace(" ", "")
                            if all(c in '0123456789abcdefABCDEF' for c in test_str) or \
                               all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" for c in test_str):
                                data_str = test_str
                            else:
                                data_str = "\n".join(clean_lines)

                        # Algoritma binary desteklemiyorsa (Klasik şifreleme), auto-decode yapma
                        supports_binary = getattr(cipher, 'supports_binary', True)
                        
                        if supports_binary:
                            # 1. HEX KONTROLÜ
                            hex_candidate = data_str.replace(" ", "").replace("\n", "").replace("\r", "")
                            if all(c in '0123456789abcdefABCDEF' for c in hex_candidate) and len(hex_candidate) % 2 == 0 and len(hex_candidate) > 0:
                                import binascii
                                try:
                                    temp_data = binascii.unhexlify(hex_candidate)
                                    Logger.info("💡 Giriş verisi HEX olarak algılandı.", "ProcessingManager")
                                except:
                                    temp_data = data_str.encode('utf-8')
                            
                            # 2. BASE64 KONTROLÜ
                            else:
                                base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
                                b64_candidate = hex_candidate
                                is_likely_b64 = (len(b64_candidate) > 8 and (b64_candidate.endswith('=') or (len(b64_candidate) % 4 == 0)))
                                
                                if is_likely_b64 and all(c in base64_chars for c in b64_candidate) and len(b64_candidate) > 0:
                                    import base64
                                    try:
                                        missing_padding = len(b64_candidate) % 4
                                        if missing_padding: b64_candidate += '=' * (4 - missing_padding)
                                        temp_data = base64.b64decode(b64_candidate)
                                        Logger.info("💡 Giriş verisi BASE64 olarak algılandı.", "ProcessingManager")
                                    except:
                                        temp_data = data_str.encode('utf-8')
                                else:
                                    temp_data = data_str.encode('utf-8')
                        else:
                            temp_data = data_str.encode('utf-8')
                            Logger.debug(f"💡 {algorithm} klasik şifreleme; direkt metin kullanılıyor.", "ProcessingManager")
                    except Exception as e:
                        Logger.debug(f"Otomatik veri tespit hatası: {str(e)}", "ProcessingManager")
                else:
                    Logger.info("💡 Dosya işlemi: Veri otomatik tespit yapılmadan ham bytes olarak işleniyor.", "ProcessingManager")

                try:
                    result_data = cipher.decrypt(temp_data, key)
                except Exception as e:
                    # Eğer hata 'Invalid padding bytes' ise ve yukarıda hex decode etmediysek, 
                    # bir de veriyi direkt bytes olarak görüp (hex değil) zorlamayı dene. 
                    # Ama genelde yukarıdaki hex tespiti yeterlidir.
                    raise e

                duration = time.time() - start_time
                
                # Çıktı önizleme
                result_preview = str(result_data[:40])
                if len(result_data) > 40:
                    result_preview = result_preview[:37] + "..."
                Logger.info(f"✅ Şifre çözme tamamlandı ({duration:.3f}s)", "ProcessingManager")
                Logger.info(f"📦 ÇÖZÜLMÜŞ ÇIKTI: {result_preview}", "ProcessingManager")
                
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
