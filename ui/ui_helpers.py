import tkinter as tk
from tkinter import ttk
from typing import Callable, Optional
from ui.theme_manager import theme_manager
from ui.i18n import i18n

class ProgressManager:
    def __init__(self, parent):
        self.parent = parent
        self.progress_vars = {}
        self.progress_bars = {}
    
    def create_progress(self, container, key: str) -> ttk.Progressbar:
        var = tk.DoubleVar()
        progress = ttk.Progressbar(
            container,
            variable=var,
            maximum=100,
            mode='determinate'
        )
        self.progress_vars[key] = var
        self.progress_bars[key] = progress
        return progress
    
    def update_progress(self, key: str, value: float):
        if key in self.progress_vars:
            self.progress_vars[key].set(value)
    
    def reset_progress(self, key: str):
        if key in self.progress_vars:
            self.progress_vars[key].set(0)

class KeyboardShortcuts:
    _shortcuts = {}
    
    @classmethod
    def register(cls, widget, key: str, callback: Callable, modifiers: list = None):
        if modifiers is None:
            modifiers = []
        
        key_combo = f"{'+'.join(modifiers)}+{key}" if modifiers else key
        widget.bind(f"<{key_combo}>", lambda e: callback())
        cls._shortcuts[key_combo] = callback
    
    @classmethod
    def get_shortcuts(cls) -> dict:
        return cls._shortcuts.copy()

class DragDropHandler:
    @staticmethod
    def enable_drag_drop(widget, callback: Callable):
        def on_drop(event):
            try:
                files = widget.tk.splitlist(event.data)
                if files:
                    callback(files[0])
            except Exception as e:
                print(f"Drag-drop hatası: {str(e)}")
        
        widget.drop_target_register('DND_Files')
        widget.dnd_bind('<<Drop>>', on_drop)

class NotificationManager:
    def __init__(self, parent):
        self.parent = parent
        self.notifications = []
    
    def show_notification(self, message: str, type: str = "info", duration: int = 3000):
        theme = theme_manager.get_theme()
        
        colors = {
            "success": theme["success"],
            "error": theme["error"],
            "warning": theme["warning"],
            "info": theme["accent"]
        }
        
        color = colors.get(type, theme["accent"])
        
        notification = tk.Toplevel(self.parent)
        notification.overrideredirect(True)
        notification.configure(bg=color)
        
        label = tk.Label(
            notification,
            text=message,
            bg=color,
            fg=theme["fg"],
            font=("Arial", 10),
            padx=20,
            pady=10
        )
        label.pack()
        
        x = self.parent.winfo_x() + self.parent.winfo_width() - 300
        y = self.parent.winfo_y() + 50
        notification.geometry(f"+{x}+{y}")
        
        def close_notification():
            notification.destroy()
            if notification in self.notifications:
                self.notifications.remove(notification)
        
        self.notifications.append(notification)
        notification.after(duration, close_notification)

def apply_theme(widget, theme_name: str = None):
    theme = theme_manager.get_theme(theme_name)
    
    if isinstance(widget, tk.Tk) or isinstance(widget, tk.Toplevel):
        widget.configure(bg=theme["bg"])
    
    for child in widget.winfo_children():
        try:
            if isinstance(child, (tk.Label, tk.Button, tk.Frame)):
                if isinstance(child, tk.Label):
                    child.configure(bg=theme["bg"], fg=theme["fg"])
                elif isinstance(child, tk.Button):
                    child.configure(bg=theme["button_bg"], fg=theme["button_fg"])
                elif isinstance(child, tk.Frame):
                    child.configure(bg=theme["bg_secondary"])
            
            apply_theme(child, theme_name)
        except:
            pass

