import socket
import struct


"""
From https://en.wikipedia.org/wiki/SOCKS:

A typical SOCKS4 connection request looks like this:

SOCKS client to SOCKS server:

field 1: SOCKS version number, 1 byte, must be 0x04 for this version
field 2: command code, 1 byte:
0x01 = establish a TCP/IP stream connection
0x02 = establish a TCP/IP port binding
field 3: port number, 2 bytes (in network byte order)
field 4: IP address, 4 bytes (in network byte order)
field 5: the user ID string, variable length, terminated with a null (0x00)
SOCKS server to SOCKS client:

field 1: null byte
field 2: status, 1 byte:
0x5A = request granted
0x5B = request rejected or failed
0x5C = request failed because client is not running identd (or not reachable from the server)
0x5D = request failed because client's identd could not confirm the user ID string in the request
field 3: 2 arbitrary bytes, which should be ignored
field 4: 4 arbitrary bytes, which should be ignored

"""

def make_connect_message(ip, port):
    """ create a SOCKS 4 connect message
    """
    message = b''
    message += b"\x04"  # version
    message += b"\x01"  # want to connect
    message += struct.pack("!H", port)
    message += socket.inet_aton(ip)  # add ip
    message += b"\x00"  # empty string
    return message

def create_connection_via_socks(socks_addr, ip, port):
    """ works like socket.crreate_connection but with a socks proxy in between
    """
    s = socket.create_connection(socks_addr)
    # now we have a socket connection to the socks proxy. Now ask
    # the socks server to connect to our target.
    connect_request = make_connect_message(ip, port)
    s.send(connect_request)
    connect_response = s.recv(8)
    n, status = struct.unpack("BBxxxxxx", connect_response)
    assert n == 0x00, "no a socks proxy?"
    if status != 0x5a:
        raise Exception("socks connection failed with code 0x%02x" % status)
    # Ok ... from now on the connection should be transparent
    return s

if __name__ == '__main__':
    s = create_connection_via_socks(("::1", 1080), "78.47.48.145" , 80)
    s.send("GET / HTTP/1.0\r\nHost: bithalde.de\r\n\r\n")
    print(s.recv(42))
