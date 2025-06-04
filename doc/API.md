# API Documentation

## Classes

### SocksException

Exception raised for SOCKS proxy related errors.

**Inheritance:** `Exception`

**Usage:**
```python
try:
    # ... SOCKS operation ...
except SocksException as e:
    print(f"SOCKS error: {e}")
```

## Functions

### make_connect_message(ip, port)

Create a SOCKS4 connect message.

**Args:**
- `ip` (str): Target IP address
- `port` (int): Target port number

**Returns:**
- `bytes`: SOCKS4 connect message

**Raises:**
- `socket.error`: If the IP address is invalid

**Example:**
```python
message = make_connect_message("192.168.1.1", 80)
# Returns: b'\x04\x01\x00P\xc0\xa8\x01\x01\x00'
```

### create_connection_via_socks(socks_addr, ip, port)

Create a connection via SOCKS proxy.

Works like `socket.create_connection` but with a SOCKS proxy in between.

**Args:**
- `socks_addr` (tuple): SOCKS proxy address (host, port)
- `ip` (str): Target IP address  
- `port` (int): Target port number

**Returns:**
- `socket.socket`: Connected socket through SOCKS proxy

**Raises:**
- `SocksException`: If SOCKS connection fails
- `ConnectionError`: If unable to connect to SOCKS proxy
- `AssertionError`: If server response is not from a SOCKS proxy

**Example:**
```python
import socket
from socks_proxy import create_connection_via_socks

# Connect through SOCKS proxy
socks_addr = ("127.0.0.1", 1080)
target_ip = socket.gethostbyname("example.com")
s = create_connection_via_socks(socks_addr, target_ip, 80)

# Use the socket normally
s.send(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
response = s.recv(1024)
s.close()
```

## SOCKS4 Protocol Details

### Request Format

| Field | Size | Description |
|-------|------|-------------|
| Version | 1 byte | Must be 0x04 for SOCKS4 |
| Command | 1 byte | 0x01 for TCP connection |
| Port | 2 bytes | Target port (network byte order) |
| IP | 4 bytes | Target IP address |
| User ID | Variable | Null-terminated string (often empty) |

### Response Format

| Field | Size | Description |
|-------|------|-------------|
| Null | 1 byte | Always 0x00 |
| Status | 1 byte | 0x5A = success, others = error |
| Port | 2 bytes | Ignored |
| IP | 4 bytes | Ignored |

### Status Codes

- `0x5A`: Request granted
- `0x5B`: Request rejected or failed  
- `0x5C`: Request failed (client not running identd)
- `0x5D`: Request failed (identd authentication failed) 