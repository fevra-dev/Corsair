"""
Winston-style logging configuration for Corsair.

Provides structured logging with multiple levels and formatters.
All modules should use get_logger(__name__) for consistent logging.

Usage:
    from corsair.utils.logger import get_logger
    logger = get_logger(__name__)
    
    logger.info("Starting scan...")
    logger.debug(f"Headers received: {headers}")
    logger.warning("Deprecated header detected")
    logger.error(f"Scan failed: {error}")
"""

import logging
import sys
from typing import Optional
from datetime import datetime
from pathlib import Path


class CorsairLogger:
    """
    Centralized logging configuration for Corsair.
    
    Logging Levels:
        - ERROR: Critical failures, exceptions, scan failures
        - WARNING: Potential issues, deprecated features, security concerns
        - INFO: Workflow steps, scan progress, major operations
        - DEBUG: Detailed analysis, header values, internal state
    
    Example:
        CorsairLogger.setup(level="DEBUG", verbose=True)
    """
    
    # Standard format: [timestamp] [level] [module] message
    LOG_FORMAT = (
        "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s"
    )
    
    # Verbose format: includes line numbers and function names
    LOG_FORMAT_VERBOSE = (
        "[%(asctime)s] [%(levelname)s] [%(name)s:%(lineno)d] "
        "[%(funcName)s] %(message)s"
    )
    
    # JSON format for structured logging (future enhancement)
    LOG_FORMAT_JSON = (
        '{"timestamp": "%(asctime)s", "level": "%(levelname)s", '
        '"module": "%(name)s", "line": %(lineno)d, "message": "%(message)s"}'
    )

    @classmethod
    def setup(
        cls,
        level: str = "INFO",
        log_file: Optional[Path] = None,
        verbose: bool = False,
        json_format: bool = False
    ) -> logging.Logger:
        """
        Configure logging for the entire application.
        
        Args:
            level: Log level (DEBUG, INFO, WARNING, ERROR)
            log_file: Optional file path for log output
            verbose: Use verbose format with line numbers and function names
            json_format: Use JSON format for structured logging
            
        Returns:
            Root logger for corsair namespace
            
        Example:
            # Development mode with full debugging
            CorsairLogger.setup(level="DEBUG", verbose=True)
            
            # Production mode with file logging
            CorsairLogger.setup(
                level="INFO",
                log_file=Path("/var/log/corsair.log")
            )
        """
        # Get or create the root logger for our namespace
        logger = logging.getLogger("corsair")
        logger.setLevel(getattr(logging, level.upper(), logging.INFO))
        
        # Clear existing handlers to prevent duplicate logs
        logger.handlers.clear()
        
        # Prevent propagation to root logger
        logger.propagate = False
        
        # Choose format based on options
        if json_format:
            fmt = cls.LOG_FORMAT_JSON
        elif verbose:
            fmt = cls.LOG_FORMAT_VERBOSE
        else:
            fmt = cls.LOG_FORMAT
        
        formatter = logging.Formatter(fmt, datefmt="%Y-%m-%d %H:%M:%S")
        
        # Console handler - always add
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setFormatter(formatter)
        console_handler.setLevel(getattr(logging, level.upper(), logging.INFO))
        logger.addHandler(console_handler)
        
        # File handler - optional
        if log_file:
            try:
                file_handler = logging.FileHandler(log_file, encoding='utf-8')
                file_handler.setFormatter(formatter)
                file_handler.setLevel(logging.DEBUG)  # Log everything to file
                logger.addHandler(file_handler)
                logger.debug(f"File logging enabled: {log_file}")
            except Exception as e:
                logger.warning(f"Could not create log file {log_file}: {e}")
        
        logger.info(
            f"Corsair logger initialized | "
            f"level={level} | verbose={verbose} | file={log_file or 'None'}"
        )
        
        return logger

    @classmethod
    def get_child(cls, name: str) -> logging.Logger:
        """
        Get a child logger for a specific module.
        
        Args:
            name: Module name (typically __name__)
            
        Returns:
            Logger instance for the module
        """
        return logging.getLogger(f"corsair.{name}")


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger for a specific module.
    
    This is the primary function modules should use to get a logger.
    The logger will be a child of the corsair root logger,
    inheriting its configuration.
    
    Args:
        name: Module name (typically pass __name__)
        
    Returns:
        Configured logger instance
        
    Usage:
        from corsair.utils.logger import get_logger
        
        logger = get_logger(__name__)
        
        # Different log levels for different scenarios
        logger.debug(f"Parsing CSP directives: {csp_value}")
        logger.info(f"Scan started for {url}")
        logger.warning(f"Deprecated header detected: {header}")
        logger.error(f"Connection failed: {error}")
        
        # Structured logging with context
        logger.info(
            f"[CSP] Analysis complete | "
            f"directives={len(directives)} | "
            f"issues={len(findings)}"
        )
    """
    # Handle both full module paths and short names
    if name.startswith("corsair."):
        return logging.getLogger(name)
    elif name.startswith("corsair."):
        # Support package naming
        short_name = name.replace("corsair.", "")
        return logging.getLogger(f"corsair.{short_name}")
    else:
        return logging.getLogger(f"corsair.{name}")


def log_scan_start(logger: logging.Logger, url: str, options: dict = None) -> None:
    """
    Helper to log scan start with consistent formatting.
    
    Args:
        logger: Logger instance
        url: Target URL
        options: Optional scan options dict
    """
    opts_str = ", ".join(f"{k}={v}" for k, v in (options or {}).items())
    logger.info(f"[SCAN] Starting | url={url} | {opts_str}")


def log_scan_complete(
    logger: logging.Logger,
    url: str,
    score: int,
    grade: str,
    duration_ms: int,
    findings_count: int
) -> None:
    """
    Helper to log scan completion with consistent formatting.
    
    Args:
        logger: Logger instance
        url: Target URL
        score: Security score (0-100)
        grade: Letter grade (A-F)
        duration_ms: Scan duration in milliseconds
        findings_count: Number of issues found
    """
    logger.info(
        f"[SCAN] Complete | url={url} | "
        f"score={score}/100 ({grade}) | "
        f"issues={findings_count} | "
        f"duration={duration_ms}ms"
    )


def log_finding(
    logger: logging.Logger,
    header: str,
    severity: str,
    title: str,
    analyzer: str = None
) -> None:
    """
    Helper to log security findings with consistent formatting.
    
    Args:
        logger: Logger instance
        header: Header name
        severity: Finding severity
        title: Finding title
        analyzer: Analyzer name (optional)
    """
    prefix = f"[{analyzer}]" if analyzer else "[FINDING]"
    logger.info(f"{prefix} {severity} | {header} | {title}")
