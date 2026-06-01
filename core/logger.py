"""Centralized logging system for all fsociety-reborn tools."""

import logging
import os
from datetime import datetime


def setup_logger(tool_name, log_dir="logs", level=logging.DEBUG):
    """
    Setup a logger for a specific tool with both file and console handlers.
    
    Args:
        tool_name (str): Name of the tool (used in log filename)
        log_dir (str): Directory to store log files
        level (int): Logging level (default: DEBUG)
    
    Returns:
        logging.Logger: Configured logger instance
    """
    # Create logs directory if it doesn't exist
    os.makedirs(log_dir, exist_ok=True)
    
    # Create logger
    logger = logging.getLogger(tool_name)
    logger.setLevel(level)
    
    # Prevent duplicate handlers
    if logger.hasHandlers():
        logger.handlers.clear()
    
    # Generate timestamped log file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(log_dir, f"{tool_name}_{timestamp}.log")
    
    # File handler — captures EVERYTHING at DEBUG level
    fh = logging.FileHandler(log_file)
    fh.setLevel(logging.DEBUG)
    
    # Console handler — shows INFO and above only
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    
    # Formatter
    formatter = logging.Formatter(
        '[%(asctime)s] [%(name)s] [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    fh.setFormatter(formatter)
    ch.setFormatter(formatter)
    
    # Add handlers to logger
    logger.addHandler(fh)
    logger.addHandler(ch)
    
    logger.debug(f"Logger initialized for tool: {tool_name}")
    logger.debug(f"Log file: {log_file}")
    
    return logger
