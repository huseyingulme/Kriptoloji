import os
import json
from typing import Dict, Any, Optional
from pathlib import Path

class ConfigManager:
    _instance = None
    _config = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ConfigManager, cls).__new__(cls)
        return cls._instance
    
    def __init__(self):
        if self._config is None:
            self.config_dir = Path.home() / ".kriptoloji"
            self.config_file = self.config_dir / "config.json"
            self.user_prefs_file = self.config_dir / "user_preferences.json"
            self._config = {}
            self._user_prefs = {}
            self._load_default_config()
            self._load_config()
            self._load_user_preferences()
    
    def _load_default_config(self):
        self._config = {
            "server": {
                "host": os.getenv("KRIPTO_SERVER_HOST", "localhost"),
                "port": int(os.getenv("KRIPTO_SERVER_PORT", "12345")),
                "max_clients": int(os.getenv("KRIPTO_MAX_CLIENTS", "10")),
                "timeout": int(os.getenv("KRIPTO_TIMEOUT", "30")),
                "enable_ssl": os.getenv("KRIPTO_ENABLE_SSL", "false").lower() == "true"
            },
            "client": {
                "default_host": os.getenv("KRIPTO_CLIENT_HOST", "localhost"),
                "default_port": int(os.getenv("KRIPTO_CLIENT_PORT", "12345")),
                "connection_timeout": int(os.getenv("KRIPTO_CONN_TIMEOUT", "10")),
                "retry_attempts": int(os.getenv("KRIPTO_RETRY_ATTEMPTS", "3")),
                "retry_delay": float(os.getenv("KRIPTO_RETRY_DELAY", "1.0")),
                "auto_reconnect": os.getenv("KRIPTO_AUTO_RECONNECT", "true").lower() == "true"
            },
            "logging": {
                "level": os.getenv("KRIPTO_LOG_LEVEL", "INFO"),
                "file_enabled": os.getenv("KRIPTO_LOG_FILE", "true").lower() == "true",
                "log_dir": os.getenv("KRIPTO_LOG_DIR", str(self.config_dir / "logs")),
                "max_file_size_mb": int(os.getenv("KRIPTO_LOG_MAX_SIZE", "10")),
                "backup_count": int(os.getenv("KRIPTO_LOG_BACKUPS", "5")),
                "audit_enabled": os.getenv("KRIPTO_AUDIT_ENABLED", "true").lower() == "true"
            },
            "performance": {
                "chunk_size": int(os.getenv("KRIPTO_CHUNK_SIZE", "4096")),
                "max_file_size_mb": int(os.getenv("KRIPTO_MAX_FILE_SIZE", "100")),
                "enable_cache": os.getenv("KRIPTO_ENABLE_CACHE", "true").lower() == "true",
                "cache_size_mb": int(os.getenv("KRIPTO_CACHE_SIZE", "50")),
                "parallel_workers": int(os.getenv("KRIPTO_PARALLEL_WORKERS", "4"))
            },
            "security": {
                "key_encryption": os.getenv("KRIPTO_KEY_ENCRYPTION", "true").lower() == "true",
                "session_timeout": int(os.getenv("KRIPTO_SESSION_TIMEOUT", "3600")),
                "rate_limit": int(os.getenv("KRIPTO_RATE_LIMIT", "100"))
            },
            "ui": {
                "theme": "light",
                "language": "tr",
                "window_width": 900,
                "window_height": 700,
                "font_size": 11,
                "font_family": "Arial"
            },
            "features": {
                "enable_nested_encryption": True,
                "enable_digital_signature": True,
                "enable_key_sharing": True,
                "enable_benchmark": True,
                "enable_history": True,
                "wireshark_mode": os.getenv("KRIPTO_WIRESHARK_MODE", "false").lower() == "true"
            }
        }
    
    def _load_config(self):
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    file_config = json.load(f)
                    self._merge_config(self._config, file_config)
            except Exception as e:
                print(f"Config yükleme hatası: {e}")
    
    def _load_user_preferences(self):
        if self.user_prefs_file.exists():
            try:
                with open(self.user_prefs_file, 'r', encoding='utf-8') as f:
                    self._user_prefs = json.load(f)
                    if "ui" in self._user_prefs:
                        self._config["ui"].update(self._user_prefs["ui"])
            except Exception as e:
                print(f"Kullanıcı tercihleri yükleme hatası: {e}")
    
    def _merge_config(self, base: Dict, override: Dict):
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._merge_config(base[key], value)
            else:
                base[key] = value
    
    def save_config(self):
        self.config_dir.mkdir(parents=True, exist_ok=True)
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(self._config, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"Config kaydetme hatası: {e}")
    
    def save_user_preferences(self):
        self.config_dir.mkdir(parents=True, exist_ok=True)
        try:
            prefs = {
                "ui": self._config.get("ui", {})
            }
            with open(self.user_prefs_file, 'w', encoding='utf-8') as f:
                json.dump(prefs, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"Kullanıcı tercihleri kaydetme hatası: {e}")
    
    def get(self, key_path: str, default: Any = None) -> Any:
        keys = key_path.split('.')
        value = self._config
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        return value
    
    def set(self, key_path: str, value: Any):
        keys = key_path.split('.')
        config = self._config
        for key in keys[:-1]:
            if key not in config:
                config[key] = {}
            config = config[key]
        config[keys[-1]] = value
    
    def get_all(self) -> Dict[str, Any]:
        return self._config.copy()
    
    def update_ui_preference(self, key: str, value: Any):
        if "ui" not in self._config:
            self._config["ui"] = {}
        self._config["ui"][key] = value
        self.save_user_preferences()

config_manager = ConfigManager()

