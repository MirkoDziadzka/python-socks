"""
Python SOCKS4 proxy client library.

This package provides functionality to connect through SOCKS4 proxies.
"""

from .socks_proxy import create_connection_via_socks, make_connect_message, SocksException

__version__ = "1.0.0"
__all__ = ["create_connection_via_socks", "make_connect_message", "SocksException"] 