#!/usr/bin/env python3

import socket
import struct


class SocksException(Exception):
    """Exception raised for SOCKS proxy related errors."""
    pass


def make_connect_message(ip, port):
    """Create a SOCKS 4 connect message.
    
    Args:
        ip (str): Target IP address
        port (int): Target port number
        
    Returns:
        bytes: SOCKS4 connect message
    """
    message = b""
    message += b"\x04"  # version
    message += b"\x01"  # want to connect
    message += struct.pack("!H", port)
    message += socket.inet_aton(ip)  # add ip
    message += b"\x00"  # empty string
    return message


def create_connection_via_socks(socks_addr, ip, port):
    """Create a connection via SOCKS proxy.
    
    Works like socket.create_connection but with a socks proxy in between.
    
    Args:
        socks_addr (tuple): SOCKS proxy address (host, port)
        ip (str): Target IP address
        port (int): Target port number
        
    Returns:
        socket: Connected socket through SOCKS proxy
        
    Raises:
        SocksException: If SOCKS connection fails
    """
    s = socket.create_connection(socks_addr)
    # now we have a socket connection to the socks proxy. Now ask
    # the socks server to connect to our target.
    connect_request = make_connect_message(ip, port)
    s.send(connect_request)
    connect_response = s.recv(8)
    n, status = struct.unpack("BBxxxxxx", connect_response)
    assert n == 0x00, "not a socks proxy?"
    if status != 0x5A:
        raise SocksException("socks connection failed with code 0x%02x" % status)
    # Ok ... from now on the connection should be transparent
    return s 