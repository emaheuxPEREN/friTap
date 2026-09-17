#!/usr/bin/env python3

"""Legacy compatibility module for friTap.

Contains extracted inline output logic from ssl_logger.py that is
preserved for backward compatibility when output handlers are not active.
"""

from .session_manager import SessionManager as SessionManager
from .ssl_logger_core import SSL_Logger as SSL_Logger
from .ssl_logger_core import get_addr_string as get_addr_string
