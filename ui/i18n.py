from typing import Dict, Any
from config import config_manager

class I18n:
    _translations = {
        "tr": {
            "app_title": "Kriptoloji Projesi",
            "server": "Server",
            "client": "Client",
            "connect": "Bağlan",
            "disconnect": "Bağlantıyı Kes",
            "encrypt": "Şifrele",
            "decrypt": "Çöz",
            "algorithm": "Algoritma",
            "key": "Anahtar",
            "file": "Dosya",
            "text": "Metin",
            "success": "Başarılı",
            "error": "Hata",
            "warning": "Uyarı",
            "info": "Bilgi",
            "save": "Kaydet",
            "load": "Yükle",
            "delete": "Sil",
            "clear": "Temizle",
            "settings": "Ayarlar",
            "about": "Hakkında",
            "exit": "Çıkış"
        },
        "en": {
            "app_title": "Cryptography Project",
            "server": "Server",
            "client": "Client",
            "connect": "Connect",
            "disconnect": "Disconnect",
            "encrypt": "Encrypt",
            "decrypt": "Decrypt",
            "algorithm": "Algorithm",
            "key": "Key",
            "file": "File",
            "text": "Text",
            "success": "Success",
            "error": "Error",
            "warning": "Warning",
            "info": "Info",
            "save": "Save",
            "load": "Load",
            "delete": "Delete",
            "clear": "Clear",
            "settings": "Settings",
            "about": "About",
            "exit": "Exit"
        }
    }
    
    @classmethod
    def get_language(cls) -> str:
        return config_manager.get("ui.language", "tr")
    
    @classmethod
    def set_language(cls, lang: str):
        if lang in cls._translations:
            config_manager.update_ui_preference("language", lang)
            return True
        return False
    
    @classmethod
    def t(cls, key: str, default: str = None) -> str:
        lang = cls.get_language()
        translations = cls._translations.get(lang, cls._translations["tr"])
        return translations.get(key, default or key)
    
    @classmethod
    def get_available_languages(cls) -> list:
        return list(cls._translations.keys())

i18n = I18n()

