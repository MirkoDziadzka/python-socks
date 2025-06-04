#!/usr/bin/env python3

import pytest
import socket
import struct
from unittest.mock import Mock, patch, MagicMock

from socks_proxy import make_connect_message, create_connection_via_socks, SocksException


class TestMakeConnectMessage:
    """Test cases for make_connect_message function."""
    
    def test_make_connect_message_basic(self):
        """Test basic SOCKS4 connect message creation."""
        ip = "192.168.1.1"
        port = 80
        
        message = make_connect_message(ip, port)
        
        # Check message structure
        assert len(message) == 9  # 1 + 1 + 2 + 4 + 1
        assert message[0:1] == b"\x04"  # SOCKS version 4
        assert message[1:2] == b"\x01"  # Connect command
        
        # Check port (network byte order)
        port_bytes = struct.unpack("!H", message[2:4])[0]
        assert port_bytes == port
        
        # Check IP address
        ip_bytes = message[4:8]
        assert ip_bytes == socket.inet_aton(ip)
        
        # Check null terminator
        assert message[8:9] == b"\x00"
    
    def test_make_connect_message_different_ports(self):
        """Test message creation with different port numbers."""
        test_cases = [
            ("127.0.0.1", 22),
            ("10.0.0.1", 443),
            ("172.16.0.1", 8080),
            ("192.168.0.1", 65535)
        ]
        
        for ip, port in test_cases:
            message = make_connect_message(ip, port)
            port_bytes = struct.unpack("!H", message[2:4])[0]
            assert port_bytes == port
    
    def test_make_connect_message_invalid_ip(self):
        """Test message creation with invalid IP address."""
        with pytest.raises(socket.error):
            make_connect_message("invalid.ip.address", 80)


class TestCreateConnectionViaSocks:
    """Test cases for create_connection_via_socks function."""
    
    @patch('socket.create_connection')
    def test_successful_connection(self, mock_create_connection):
        """Test successful SOCKS connection."""
        # Mock socket
        mock_socket = Mock()
        mock_create_connection.return_value = mock_socket
        
        # Mock successful SOCKS response (0x00, 0x5A, followed by 6 arbitrary bytes)
        mock_socket.recv.return_value = b"\x00\x5A\x00\x00\x00\x00\x00\x00"
        
        # Test the connection
        socks_addr = ("127.0.0.1", 1080)
        target_ip = "192.168.1.1"
        target_port = 80
        
        result = create_connection_via_socks(socks_addr, target_ip, target_port)
        
        # Verify the socket creation and message sending
        mock_create_connection.assert_called_once_with(socks_addr)
        mock_socket.send.assert_called_once()
        mock_socket.recv.assert_called_once_with(8)
        
        # Verify the correct connect message was sent
        sent_message = mock_socket.send.call_args[0][0]
        expected_message = make_connect_message(target_ip, target_port)
        assert sent_message == expected_message
        
        assert result == mock_socket
    
    @patch('socket.create_connection')
    def test_connection_rejected(self, mock_create_connection):
        """Test SOCKS connection rejection."""
        mock_socket = Mock()
        mock_create_connection.return_value = mock_socket
        
        # Mock rejected SOCKS response (0x00, 0x5B - request rejected)
        mock_socket.recv.return_value = b"\x00\x5B\x00\x00\x00\x00\x00\x00"
        
        socks_addr = ("127.0.0.1", 1080)
        target_ip = "192.168.1.1"
        target_port = 80
        
        with pytest.raises(SocksException) as exc_info:
            create_connection_via_socks(socks_addr, target_ip, target_port)
        
        assert "socks connection failed with code 0x5b" in str(exc_info.value)
    
    @patch('socket.create_connection')
    def test_invalid_socks_response(self, mock_create_connection):
        """Test invalid SOCKS server response."""
        mock_socket = Mock()
        mock_create_connection.return_value = mock_socket
        
        # Mock invalid SOCKS response (first byte should be 0x00)
        mock_socket.recv.return_value = b"\x01\x5A\x00\x00\x00\x00\x00\x00"
        
        socks_addr = ("127.0.0.1", 1080)
        target_ip = "192.168.1.1"
        target_port = 80
        
        with pytest.raises(AssertionError) as exc_info:
            create_connection_via_socks(socks_addr, target_ip, target_port)
        
        assert "not a socks proxy?" in str(exc_info.value)
    
    @patch('socket.create_connection')
    def test_various_socks_error_codes(self, mock_create_connection):
        """Test various SOCKS error codes."""
        mock_socket = Mock()
        mock_create_connection.return_value = mock_socket
        
        error_codes = [0x5B, 0x5C, 0x5D]  # Different SOCKS4 error codes
        
        for error_code in error_codes:
            mock_socket.recv.return_value = b"\x00" + bytes([error_code]) + b"\x00\x00\x00\x00\x00\x00"
            
            with pytest.raises(SocksException) as exc_info:
                create_connection_via_socks(("127.0.0.1", 1080), "192.168.1.1", 80)
            
            assert f"socks connection failed with code 0x{error_code:02x}" in str(exc_info.value)


class TestSocksException:
    """Test cases for SocksException."""
    
    def test_socks_exception_creation(self):
        """Test SocksException can be created and raised."""
        message = "Test error message"
        
        with pytest.raises(SocksException) as exc_info:
            raise SocksException(message)
        
        assert str(exc_info.value) == message
    
    def test_socks_exception_inheritance(self):
        """Test SocksException inherits from Exception."""
        assert issubclass(SocksException, Exception)


class TestIntegration:
    """Integration tests - these require an actual SOCKS proxy for full testing."""
    
    @pytest.mark.integration
    @pytest.mark.skip(reason="Requires running SOCKS proxy server")
    def test_real_socks_connection(self):
        """Test with a real SOCKS proxy (skipped by default)."""
        # This test would require a running SOCKS proxy
        # You can enable it for manual testing with a real proxy
        socks_addr = ("127.0.0.1", 1080)
        target_ip = socket.gethostbyname("httpbin.org")
        target_port = 80
        
        try:
            s = create_connection_via_socks(socks_addr, target_ip, target_port)
            # Send a simple HTTP request
            request = b"GET /ip HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n"
            s.send(request)
            
            # Read response
            response = b""
            while True:
                chunk = s.recv(1024)
                if not chunk:
                    break
                response += chunk
            
            s.close()
            
            # Basic validation that we got an HTTP response
            assert b"HTTP/" in response
            assert b"200" in response or b"301" in response or b"302" in response
            
        except Exception as e:
            pytest.skip(f"SOCKS proxy not available: {e}")


if __name__ == "__main__":
    # Run the tests
    pytest.main([__file__, "-v"]) 