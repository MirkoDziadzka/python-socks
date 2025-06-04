#!/usr/bin/env python3

"""
Demo script showing how to use the SOCKS proxy functionality.

This script demonstrates connecting to a web server through a SOCKS4 proxy
and fetching a simple HTTP response.
"""

import socket
import sys
import os

# Try to import from installed package first, then fall back to src
try:
    from socks_proxy import create_connection_via_socks, SocksException
except ImportError:
    # Add src directory to path for development
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))
    from socks_proxy import create_connection_via_socks, SocksException


def demo_socks_connection():
    """Demonstrate SOCKS proxy connection."""
    # Configuration
    socks_proxy_addr = ("::1", 1080)  # IPv6 localhost, port 1080
    hostname = "bithalde.de"
    target_port = 80
    
    try:
        # Resolve hostname to IP
        target_ip = socket.gethostbyname(hostname)
        print(f"Resolved {hostname} to {target_ip}")
        
        # Create connection through SOCKS proxy
        print(f"Connecting to {hostname}:{target_port} via SOCKS proxy at {socks_proxy_addr}")
        s = create_connection_via_socks(socks_proxy_addr, target_ip, target_port)
        print("Connected successfully!")
        
        # Send HTTP request
        http_request = f"GET / HTTP/1.0\r\nHost: {hostname}\r\n\r\n"
        s.send(http_request.encode())
        print("HTTP request sent")
        
        # Receive and print response
        print("\n--- HTTP Response ---")
        response_data = b""
        while True:
            chunk = s.recv(1024)
            if not chunk:
                break
            response_data += chunk
            print(chunk.decode('utf-8', errors='ignore'), end='')
        
        s.close()
        print("\n--- End of Response ---")
        
    except socket.gaierror as e:
        print(f"DNS resolution failed: {e}")
    except ConnectionRefusedError as e:
        print(f"Could not connect to SOCKS proxy: {e}")
        print("Make sure you have a SOCKS proxy running on the specified address")
    except SocksException as e:
        print(f"SOCKS proxy error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")


def demo_with_different_targets():
    """Demonstrate connecting to different targets."""
    targets = [
        ("httpbin.org", 80),
        ("example.com", 80),
        ("google.com", 80)
    ]
    
    socks_proxy_addr = ("127.0.0.1", 1080)  # IPv4 localhost
    
    for hostname, port in targets:
        print(f"\n--- Testing connection to {hostname}:{port} ---")
        try:
            target_ip = socket.gethostbyname(hostname)
            s = create_connection_via_socks(socks_proxy_addr, target_ip, port)
            
            # Send a simple HTTP HEAD request
            request = f"HEAD / HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n"
            s.send(request.encode())
            
            # Read just the status line
            response = s.recv(1024).decode('utf-8', errors='ignore')
            status_line = response.split('\r\n')[0]
            print(f"Response: {status_line}")
            
            s.close()
            
        except Exception as e:
            print(f"Failed to connect to {hostname}: {e}")


if __name__ == "__main__":
    print("SOCKS Proxy Demo")
    print("================")
    print("\nNote: This demo requires a SOCKS4 proxy running on localhost:1080")
    print("You can set up a SOCKS proxy using SSH: ssh -D 1080 user@server")
    print("Or use other SOCKS proxy software like Dante, etc.\n")
    
    # Run the main demo
    demo_socks_connection()
    
    # Uncomment the line below to test multiple targets
    # demo_with_different_targets() 