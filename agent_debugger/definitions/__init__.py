"""Extraction definitions for debugger-based key extraction."""

from .base import (
    BreakpointSpec,
    ExtractionDefinition,
    StructExtraction,
    StructField,
    resolve_offset,
)
from .ipsec_strongswan import IPSEC_STRONGSWAN
from .ssh_openssh import SSH_OPENSSH

__all__ = [
    "StructField",
    "StructExtraction",
    "BreakpointSpec",
    "ExtractionDefinition",
    "resolve_offset",
    "SSH_OPENSSH",
    "IPSEC_STRONGSWAN",
]
