"""
Centralized logging configuration for oauth-https-proxy-client.

This module provides a consistent logging setup across all components
with support for TRACE level logging.
"""

import logging
import os
import sys
from typing import Optional

# Define TRACE level (below DEBUG)
TRACE_LEVEL = 5

def add_trace_level():
    """Add TRACE level to logging module."""
    logging.addLevelName(TRACE_LEVEL, "TRACE")
    
    def trace(self, message, *args, **kwargs):
        if self.isEnabledFor(TRACE_LEVEL):
            self._log(TRACE_LEVEL, message, args, **kwargs)
    
    logging.Logger.trace = trace

# Add TRACE level on module import
add_trace_level()

def setup_logging(level: Optional[str] = None, debug: bool = False) -> None:
    """
    Configure logging for the application.
    
    Args:
        level: Log level string (TRACE, DEBUG, INFO, WARNING, ERROR, CRITICAL)
        debug: If True, sets level to TRACE regardless of other settings
    """
    # Determine log level
    if debug:
        log_level = TRACE_LEVEL
    elif level:
        if level.upper() == "TRACE":
            log_level = TRACE_LEVEL
        else:
            log_level = getattr(logging, level.upper(), logging.INFO)
    else:
        # Default to TRACE for all debug output
        env_level = os.getenv("LOG_LEVEL", "TRACE").upper()
        if env_level == "TRACE":
            log_level = TRACE_LEVEL
        else:
            log_level = getattr(logging, env_level, TRACE_LEVEL)
    
    # Configure root logger
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        handlers=[
            logging.StreamHandler(sys.stderr)
        ]
    )
    
    # Set level for all oauth_proxy_client loggers
    logging.getLogger("oauth_proxy_client").setLevel(log_level)
    
    # Also set urllib3 to WARNING to reduce noise
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)

def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance for the given module name.
    
    Args:
        name: Name of the module/component
        
    Returns:
        Configured logger instance
    """
    return logging.getLogger(f"oauth_proxy_client.{name}")

# Initialize logging on module import with TRACE level by default
setup_logging(level="TRACE")