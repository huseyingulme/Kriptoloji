from typing import Dict, Any
from config import config_manager

class ThemeManager:
    _themes = {
        "light": {
            "bg": "#ffffff",
            "fg": "#000000",
            "bg_secondary": "#f5f5f5",
            "fg_secondary": "#333333",
            "accent": "#2196F3",
            "accent_hover": "#1976D2",
            "success": "#4CAF50",
            "error": "#f44336",
            "warning": "#FF9800",
            "border": "#cccccc",
            "text_input_bg": "#ffffff",
            "button_bg": "#2196F3",
            "button_fg": "#ffffff"
        },
        "dark": {
            "bg": "#1e1e1e",
            "fg": "#ffffff",
            "bg_secondary": "#2d2d2d",
            "fg_secondary": "#e0e0e0",
            "accent": "#64B5F6",
            "accent_hover": "#42A5F5",
            "success": "#81C784",
            "error": "#e57373",
            "warning": "#FFB74D",
            "border": "#404040",
            "text_input_bg": "#2d2d2d",
            "button_bg": "#64B5F6",
            "button_fg": "#000000"
        }
    }
    
    @classmethod
    def get_theme(cls, theme_name: str = None) -> Dict[str, str]:
        if theme_name is None:
            theme_name = config_manager.get("ui.theme", "light")
        
        return cls._themes.get(theme_name, cls._themes["light"])
    
    @classmethod
    def get_current_theme(cls) -> str:
        return config_manager.get("ui.theme", "light")
    
    @classmethod
    def set_theme(cls, theme_name: str):
        if theme_name in cls._themes:
            config_manager.update_ui_preference("theme", theme_name)
            return True
        return False
    
    @classmethod
    def get_available_themes(cls) -> list:
        return list(cls._themes.keys())

theme_manager = ThemeManager()

