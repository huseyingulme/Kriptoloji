import os
import logging
import logging.handlers
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any
from threading import Lock
import json
import time

class AdvancedLogger:
    _instance = None
    _lock = Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super(AdvancedLogger, cls).__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self.log_dir = Path.home() / ".kriptoloji" / "logs"
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        self.audit_log_file = self.log_dir / "audit.log"
        self.performance_log_file = self.log_dir / "performance.log"
        self.history_file = self.log_dir / "history.json"
        
        self.loggers = {}
        self.handlers = {}
        self.performance_metrics = []
        self.operation_history = []
        self._max_history = 1000
        
        self._setup_loggers()
        self._initialized = True
    
    def _setup_loggers(self):
        try:
            from config import config_manager
            
            log_level = getattr(logging, config_manager.get("logging.level", "INFO"), logging.INFO)
            file_enabled = config_manager.get("logging.file_enabled", True)
            max_size = config_manager.get("logging.max_file_size_mb", 10) * 1024 * 1024
            backup_count = config_manager.get("logging.backup_count", 5)
        except:
            log_level = logging.INFO
            file_enabled = True
            max_size = 10 * 1024 * 1024
            backup_count = 5
        
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        console_handler = logging.StreamHandler()
        console_handler.setLevel(log_level)
        console_handler.setFormatter(formatter)
        
        self.main_logger = logging.getLogger('Kriptoloji')
        self.main_logger.setLevel(log_level)
        self.main_logger.addHandler(console_handler)
        
        if file_enabled:
            log_file = self.log_dir / "application.log"
            file_handler = logging.handlers.RotatingFileHandler(
                log_file,
                maxBytes=max_size,
                backupCount=backup_count,
                encoding='utf-8'
            )
            file_handler.setLevel(log_level)
            file_handler.setFormatter(formatter)
            self.main_logger.addHandler(file_handler)
            self.handlers['file'] = file_handler
        
        self.audit_logger = logging.getLogger('Kriptoloji.Audit')
        self.audit_logger.setLevel(logging.INFO)
        
        if file_enabled:
            audit_handler = logging.handlers.RotatingFileHandler(
                self.audit_log_file,
                maxBytes=max_size,
                backupCount=backup_count,
                encoding='utf-8'
            )
            audit_handler.setFormatter(formatter)
            self.audit_logger.addHandler(audit_handler)
            self.audit_logger.addHandler(console_handler)
        
        self.performance_logger = logging.getLogger('Kriptoloji.Performance')
        self.performance_logger.setLevel(logging.INFO)
        
        if file_enabled:
            perf_handler = logging.handlers.RotatingFileHandler(
                self.performance_log_file,
                maxBytes=max_size,
                backupCount=backup_count,
                encoding='utf-8'
            )
            perf_handler.setFormatter(formatter)
            self.performance_logger.addHandler(perf_handler)
    
    def info(self, message: str, component: str = "SYSTEM"):
        self.main_logger.info(f"[{component}] {message}")
    
    def error(self, message: str, component: str = "SYSTEM", exc_info=False):
        self.main_logger.error(f"[{component}] {message}", exc_info=exc_info)
    
    def warning(self, message: str, component: str = "SYSTEM"):
        self.main_logger.warning(f"[{component}] {message}")
    
    def debug(self, message: str, component: str = "SYSTEM"):
        self.main_logger.debug(f"[{component}] {message}")
    
    def audit(self, user: str, action: str, details: Dict[str, Any] = None):
        try:
            from config import config_manager
            audit_enabled = config_manager.get("logging.audit_enabled", True)
        except:
            audit_enabled = True
        
        if not audit_enabled:
            return
        
        timestamp = datetime.now().isoformat()
        audit_entry = {
            "timestamp": timestamp,
            "user": user,
            "action": action,
            "details": details or {}
        }
        
        self.audit_logger.info(
            f"USER: {user} | ACTION: {action} | DETAILS: {json.dumps(details or {})}"
        )
        
        self._save_to_history("audit", audit_entry)
    
    def log_performance(self, operation: str, duration: float, details: Dict[str, Any] = None):
        timestamp = datetime.now().isoformat()
        metric = {
            "timestamp": timestamp,
            "operation": operation,
            "duration_ms": duration * 1000,
            "details": details or {}
        }
        
        self.performance_metrics.append(metric)
        if len(self.performance_metrics) > 100:
            self.performance_metrics.pop(0)
        
        self.performance_logger.info(
            f"OPERATION: {operation} | DURATION: {duration*1000:.2f}ms | DETAILS: {json.dumps(details or {})}"
        )
    
    def log_operation(self, operation_type: str, algorithm: str, success: bool, 
                     details: Dict[str, Any] = None):
        timestamp = datetime.now().isoformat()
        operation = {
            "timestamp": timestamp,
            "type": operation_type,
            "algorithm": algorithm,
            "success": success,
            "details": details or {}
        }
        
        self.operation_history.append(operation)
        if len(self.operation_history) > self._max_history:
            self.operation_history.pop(0)
        
        self._save_to_history("operation", operation)
    
    def _save_to_history(self, history_type: str, entry: Dict[str, Any]):
        try:
            if not self.history_file.exists():
                history = {"audit": [], "operation": []}
            else:
                with open(self.history_file, 'r', encoding='utf-8') as f:
                    history = json.load(f)
            
            if history_type not in history:
                history[history_type] = []
            
            history[history_type].append(entry)
            
            if len(history[history_type]) > self._max_history:
                history[history_type] = history[history_type][-self._max_history:]
            
            with open(self.history_file, 'w', encoding='utf-8') as f:
                json.dump(history, f, indent=2, ensure_ascii=False)
        except Exception as e:
            self.main_logger.error(f"Geçmiş kaydetme hatası: {e}")
    
    def get_performance_metrics(self, limit: int = 50) -> list:
        return self.performance_metrics[-limit:]
    
    def get_operation_history(self, limit: int = 100) -> list:
        return self.operation_history[-limit:]
    
    def get_audit_log(self, limit: int = 100) -> list:
        try:
            if not self.history_file.exists():
                return []
            
            with open(self.history_file, 'r', encoding='utf-8') as f:
                history = json.load(f)
            
            audit_log = history.get("audit", [])
            return audit_log[-limit:]
        except:
            return []
    
    def clear_history(self):
        self.operation_history.clear()
        self.performance_metrics.clear()
        if self.history_file.exists():
            try:
                self.history_file.unlink()
            except:
                pass

advanced_logger = AdvancedLogger()

