"""
Logging utilities for Zodiac Security Analyzer
Provides centralized logging configuration
"""

import logging
import sys
from pathlib import Path
from datetime import datetime
from typing import Optional
from rich.logging import RichHandler
from rich.console import Console


def setup_logger(
    name: str,
    level: int = logging.INFO,
    log_file: Optional[Path] = None,
    use_rich: bool = True
) -> logging.Logger:
    """
    Setup a logger with optional file output and rich formatting
    
    Args:
        name: Logger name
        level: Logging level
        log_file: Optional file to write logs
        use_rich: Use rich formatting for console output
        
    Returns:
        Configured logger instance
    """
    
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Remove existing handlers
    logger.handlers = []
    
    # Console handler with rich formatting
    if use_rich:
        console_handler = RichHandler(
            console=Console(stderr=True),
            show_time=True,
            show_path=False,
            markup=True
        )
        console_handler.setLevel(level)
        console_formatter = logging.Formatter("%(message)s")
        console_handler.setFormatter(console_formatter)
    else:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level)
        console_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        console_handler.setFormatter(console_formatter)
    
    logger.addHandler(console_handler)
    
    # File handler if specified
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(level)
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
    
    return logger


class SecurityLogger:
    """
    Specialized logger for security events
    Tracks security-relevant events separately
    """
    
    def __init__(self, log_dir: Path = None):
        if log_dir is None:
            log_dir = Path.cwd() / "security_logs"
        
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Create separate log file for security events
        timestamp = datetime.now().strftime("%Y%m%d")
        security_log_file = self.log_dir / f"security_{timestamp}.log"
        
        self.logger = setup_logger(
            "security",
            level=logging.DEBUG,
            log_file=security_log_file,
            use_rich=False
        )
    
    def log_finding(self, finding: dict):
        """Log a security finding"""
        self.logger.info(
            f"FINDING: {finding.get('severity', 'UNKNOWN')} - "
            f"{finding.get('rule_id', 'unknown')} - "
            f"{finding.get('file', 'N/A')}:{finding.get('line', 0)}"
        )
    
    def log_validation(self, finding_id: str, status: str, confidence: float):
        """Log finding validation result"""
        self.logger.info(
            f"VALIDATION: {finding_id} -> {status} (confidence: {confidence:.2%})"
        )
    
    def log_critical(self, message: str):
        """Log critical security event"""
        self.logger.critical(f"CRITICAL: {message}")
    
    def log_suspicious(self, message: str):
        """Log suspicious activity"""
        self.logger.warning(f"SUSPICIOUS: {message}")


class PerformanceLogger:
    """
    Logger for performance metrics
    Tracks execution times and resource usage
    """
    
    def __init__(self):
        self.logger = setup_logger("performance", level=logging.DEBUG)
        self.timings = {}
        self.start_times = {}
    
    def start_timer(self, operation: str):
        """Start timing an operation"""
        self.start_times[operation] = datetime.now()
        self.logger.debug(f"Started: {operation}")
    
    def end_timer(self, operation: str) -> float:
        """End timing and return duration"""
        if operation not in self.start_times:
            self.logger.warning(f"No start time for operation: {operation}")
            return 0.0
        
        duration = (datetime.now() - self.start_times[operation]).total_seconds()
        self.timings[operation] = duration
        
        del self.start_times[operation]
        
        self.logger.info(f"Completed: {operation} in {duration:.2f}s")
        return duration
    
    def get_report(self) -> dict:
        """Get performance report"""
        return {
            "timings": self.timings,
            "total_time": sum(self.timings.values()),
            "operations": len(self.timings)
        }


# Global logger instances
_default_logger = None
_security_logger = None
_performance_logger = None


def get_logger(name: str = "zodiac") -> logging.Logger:
    """Get or create the default logger"""
    global _default_logger
    if _default_logger is None:
        _default_logger = setup_logger(name)
    return _default_logger


def get_security_logger() -> SecurityLogger:
    """Get or create the security logger"""
    global _security_logger
    if _security_logger is None:
        _security_logger = SecurityLogger()
    return _security_logger


def get_performance_logger() -> PerformanceLogger:
    """Get or create the performance logger"""
    global _performance_logger
    if _performance_logger is None:
        _performance_logger = PerformanceLogger()
    return _performance_logger