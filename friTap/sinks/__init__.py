"""Sink implementations for friTap pipeline output."""

from .base import Sink
from .live_pcapng import LivePcapngSink
from .live_wireshark import LiveWiresharkSink
from .pcap import PcapSink
from .pcapng import PcapngSink

__all__ = [
    "Sink",
    "PcapSink",
    "PcapngSink",
    "LivePcapngSink",
    "LiveWiresharkSink",
]
