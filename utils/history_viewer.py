import tkinter as tk
from tkinter import ttk, scrolledtext
from typing import List, Dict, Any
from shared.advanced_logger import advanced_logger
from ui.i18n import i18n
from ui.theme_manager import theme_manager
import json

class HistoryViewer:
    def __init__(self, parent):
        self.parent = parent
        self.window = None
    
    def show(self):
        if self.window:
            self.window.lift()
            return
        
        self.window = tk.Toplevel(self.parent)
        self.window.title(i18n.t("history", "İşlem Geçmişi"))
        self.window.geometry("1000x600")
        
        theme = theme_manager.get_theme()
        self.window.configure(bg=theme["bg"])
        
        notebook = ttk.Notebook(self.window)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self._create_operation_tab(notebook)
        self._create_performance_tab(notebook)
        self._create_audit_tab(notebook)
        
        self.window.protocol("WM_DELETE_WINDOW", self._on_close)
    
    def _create_operation_tab(self, notebook):
        frame = ttk.Frame(notebook)
        notebook.add(frame, text=i18n.t("operations", "İşlemler"))
        
        toolbar = ttk.Frame(frame)
        toolbar.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(toolbar, text=i18n.t("refresh", "Yenile"), 
                  command=self._refresh_operations).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text=i18n.t("clear", "Temizle"), 
                  command=self._clear_operations).pack(side=tk.LEFT, padx=5)
        
        tree = ttk.Treeview(frame, columns=("timestamp", "type", "algorithm", "success"), 
                           show="tree headings")
        tree.heading("#0", text="ID")
        tree.heading("timestamp", text="Zaman")
        tree.heading("type", text="Tip")
        tree.heading("algorithm", text="Algoritma")
        tree.heading("success", text="Durum")
        
        tree.column("#0", width=50)
        tree.column("timestamp", width=200)
        tree.column("type", width=100)
        tree.column("algorithm", width=150)
        tree.column("success", width=100)
        
        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.operation_tree = tree
        self._refresh_operations()
    
    def _create_performance_tab(self, notebook):
        frame = ttk.Frame(notebook)
        notebook.add(frame, text=i18n.t("performance", "Performans"))
        
        text = scrolledtext.ScrolledText(frame, wrap=tk.WORD, height=25)
        text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.performance_text = text
        self._refresh_performance()
    
    def _create_audit_tab(self, notebook):
        frame = ttk.Frame(notebook)
        notebook.add(frame, text=i18n.t("audit", "Denetim"))
        
        text = scrolledtext.ScrolledText(frame, wrap=tk.WORD, height=25)
        text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.audit_text = text
        self._refresh_audit()
    
    def _refresh_operations(self):
        for item in self.operation_tree.get_children():
            self.operation_tree.delete(item)
        
        history = advanced_logger.get_operation_history(limit=100)
        for i, op in enumerate(history):
            status = i18n.t("success", "Başarılı") if op.get("success") else i18n.t("error", "Hata")
            self.operation_tree.insert("", tk.END, text=str(i+1),
                                     values=(
                                         op.get("timestamp", ""),
                                         op.get("type", ""),
                                         op.get("algorithm", ""),
                                         status
                                     ))
    
    def _refresh_performance(self):
        self.performance_text.delete("1.0", tk.END)
        metrics = advanced_logger.get_performance_metrics(limit=50)
        
        if not metrics:
            self.performance_text.insert("1.0", i18n.t("no_data", "Veri yok"))
            return
        
        for metric in metrics:
            line = f"{metric.get('timestamp', '')} | {metric.get('operation', '')} | "
            line += f"{metric.get('duration_ms', 0):.2f}ms\n"
            self.performance_text.insert(tk.END, line)
    
    def _refresh_audit(self):
        self.audit_text.delete("1.0", tk.END)
        audit_log = advanced_logger.get_audit_log(limit=100)
        
        if not audit_log:
            self.audit_text.insert("1.0", i18n.t("no_data", "Veri yok"))
            return
        
        for entry in audit_log:
            line = f"{entry.get('timestamp', '')} | {entry.get('user', '')} | "
            line += f"{entry.get('action', '')} | {json.dumps(entry.get('details', {}))}\n"
            self.audit_text.insert(tk.END, line)
    
    def _clear_operations(self):
        advanced_logger.clear_history()
        self._refresh_operations()
    
    def _on_close(self):
        self.window.destroy()
        self.window = None

