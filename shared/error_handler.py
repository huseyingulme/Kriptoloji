"""
Bu dosya, uygulamada oluşabilecek hataların merkezi ve kontrollü şekilde
yönetilmesini sağlar. Tekrar deneme (retry), zaman aşımı (timeout),
kullanıcı dostu hata mesajları üretme ve otomatik yeniden bağlanma
mekanizmalarını içerir.

Amaç; sistemin kararlılığını artırmak, geçici hatalarda uygulamanın
çökmesini önlemek ve tüm hataları detaylı şekilde loglamaktır.
"""
import time
import functools
from typing import Callable, Any, Optional, Dict
from shared.advanced_logger import advanced_logger

class ErrorHandler:
    @staticmethod
    def retry(max_attempts: int = 3, delay: float = 1.0, backoff: float = 2.0, 
              exceptions: tuple = (Exception,)):
        def decorator(func: Callable) -> Callable:
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                attempt = 0
                current_delay = delay
                
                while attempt < max_attempts:
                    try:
                        return func(*args, **kwargs)
                    except exceptions as e:
                        attempt += 1
                        if attempt >= max_attempts:
                            advanced_logger.error(
                                f"Fonksiyon {func.__name__} {max_attempts} denemeden sonra başarısız: {str(e)}",
                                "ErrorHandler"
                            )
                            raise
                        
                        advanced_logger.warning(
                            f"Fonksiyon {func.__name__} deneme {attempt}/{max_attempts} başarısız, {current_delay}s sonra tekrar deneniyor: {str(e)}",
                            "ErrorHandler"
                        )
                        time.sleep(current_delay)
                        current_delay *= backoff
                
                return None
            return wrapper
        return decorator
    
    @staticmethod
    def timeout(seconds: float):
        def decorator(func: Callable) -> Callable:
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                import signal
                
                def timeout_handler(signum, frame):
                    raise TimeoutError(f"Fonksiyon {func.__name__} {seconds} saniye içinde tamamlanamadı")
                
                old_handler = signal.signal(signal.SIGALRM, timeout_handler)
                signal.alarm(int(seconds))
                
                try:
                    result = func(*args, **kwargs)
                finally:
                    signal.alarm(0)
                    signal.signal(signal.SIGALRM, old_handler)
                
                return result
            return wrapper
        return decorator
    
    @staticmethod
    def get_user_friendly_message(error: Exception) -> str:
        error_messages = {
            "ConnectionError": "Bağlantı hatası oluştu. Lütfen internet bağlantınızı kontrol edin.",
            "TimeoutError": "İşlem zaman aşımına uğradı. Lütfen tekrar deneyin.",
            "FileNotFoundError": "Dosya bulunamadı. Lütfen dosya yolunu kontrol edin.",
            "PermissionError": "Dosyaya erişim izniniz yok. Lütfen izinleri kontrol edin.",
            "ValueError": "Geçersiz değer girildi. Lütfen girdiğiniz değerleri kontrol edin.",
            "KeyError": "Gerekli parametre eksik. Lütfen tüm gerekli alanları doldurun.",
            "MemoryError": "Yetersiz bellek. Lütfen daha küçük bir dosya deneyin.",
            "OSError": "Sistem hatası oluştu. Lütfen tekrar deneyin."
        }
        
        error_type = type(error).__name__
        
        if error_type in error_messages:
            return error_messages[error_type]
        
        if "connection" in str(error).lower() or "bağlantı" in str(error).lower():
            return "Bağlantı hatası oluştu. Server'a bağlanılamıyor."
        
        if "timeout" in str(error).lower() or "zaman" in str(error).lower():
            return "İşlem zaman aşımına uğradı. Lütfen tekrar deneyin."
        
        return f"Bir hata oluştu: {str(error)}"
    
    @staticmethod
    def handle_error(error: Exception, context: str = "SYSTEM", 
                    log_details: Dict[str, Any] = None) -> Dict[str, Any]:
        user_message = ErrorHandler.get_user_friendly_message(error)
        
        error_details = {
            "error_type": type(error).__name__,
            "error_message": str(error),
            "user_message": user_message,
            "context": context,
            "details": log_details or {}
        }
        
        advanced_logger.error(
            f"Hata: {error_details['error_type']} - {error_details['error_message']}",
            context,
            exc_info=True
        )
        
        if log_details:
            advanced_logger.audit("SYSTEM", "error_occurred", error_details)
        
        return error_details

class AutoReconnect:
    def __init__(self, max_attempts: int = 5, delay: float = 2.0, backoff: float = 1.5):
        self.max_attempts = max_attempts
        self.delay = delay
        self.backoff = backoff
        self.attempt = 0
        self.current_delay = delay
    
    def reset(self):
        self.attempt = 0
        self.current_delay = self.delay
    
    def should_reconnect(self) -> bool:
        return self.attempt < self.max_attempts
    
    def get_delay(self) -> float:
        delay = self.current_delay
        self.attempt += 1
        self.current_delay *= self.backoff
        return delay
    
    def __call__(self, func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            reconnect = AutoReconnect(self.max_attempts, self.delay, self.backoff)
            
            while reconnect.should_reconnect():
                try:
                    result = func(*args, **kwargs)
                    reconnect.reset()
                    return result
                except (ConnectionError, OSError, TimeoutError) as e:
                    if not reconnect.should_reconnect():
                        raise
                    
                    delay = reconnect.get_delay()
                    advanced_logger.warning(
                        f"Bağlantı hatası, {delay:.1f}s sonra yeniden bağlanılıyor (Deneme {reconnect.attempt}/{self.max_attempts})",
                        "AutoReconnect"
                    )
                    time.sleep(delay)
            
            raise ConnectionError("Maksimum yeniden bağlanma denemesi aşıldı")
        
        return wrapper

