import logging
import sys
import os
from pathlib import Path
import structlog
from logging.handlers import RotatingFileHandler

def setup_logging(component_name: str, log_level: str = "INFO"):
    """
    Configures centralized structured logging for Sentinel Core.
    Outputs:
    - Console: Human-readable, colorized.
    - data/logs/{component}.log: JSON format for ingestion/analysis.
    - data/logs/errors.log: Aggregated JSON errors.
    """
    
    log_dir = Path("data/logs")
    log_dir.mkdir(parents=True, exist_ok=True)
    
    # Standard library logging configuration
    logging_level = getattr(logging, log_level.upper(), logging.INFO)
    
    # Processors for structlog
    shared_processors = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    # 1. File Handler (JSON)
    file_formatter = structlog.stdlib.ProcessorFormatter(
        processor=structlog.processors.JSONRenderer(),
        foreign_pre_chain=shared_processors,
    )
    
    file_handler = RotatingFileHandler(
        log_dir / f"{component_name}.log", 
        maxBytes=10*1024*1024, 
        backupCount=3
    )
    file_handler.setFormatter(file_formatter)
    
    # 2. Global Error Handler (JSON)
    error_handler = RotatingFileHandler(
        log_dir / "errors.log", 
        maxBytes=10*1024*1024, 
        backupCount=5
    )
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(file_formatter)

    # 3. Console Handler (Pretty)
    console_formatter = structlog.stdlib.ProcessorFormatter(
        processor=structlog.dev.ConsoleRenderer(colors=True),
        foreign_pre_chain=shared_processors,
    )
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(console_formatter)

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.handlers = [console_handler, file_handler, error_handler]
    root_logger.setLevel(logging_level)

    # Configure structlog
    structlog.configure(
        processors=shared_processors + [
            structlog.stdlib.filter_by_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.UnicodeDecoder(),
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

def get_logger(name: str):
    """Returns a bound logger with the specified component name."""
    return structlog.get_logger(name)
