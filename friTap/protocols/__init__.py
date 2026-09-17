#!/usr/bin/env python3

"""Protocol handler abstraction for friTap."""

from .base import BackendSupport, ProtocolHandler
from .registry import ProtocolRegistry

#from .ipsec_handler import IPSecHandler
from .ssh_handler import SSHHandler
from .tls_handler import TLSHandler

__all__ = [
    "BackendSupport",
    "ProtocolHandler",
    "ProtocolRegistry",
    "TLSHandler",
#    "IPSecHandler",
    "SSHHandler",
]
