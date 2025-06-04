# python-socks

A simple SOCKS4 proxy client implementation in Python.

This project demonstrates how SOCKS4 proxying works and provides a reusable Python module for connecting through SOCKS4 proxies.

## Project Structure

```
python-socks/
├── src/                    # Source code
│   ├── __init__.py        # Package initialization  
│   └── socks_proxy.py     # Main SOCKS4 implementation
├── test/                  # Test files
│   ├── __init__.py        # Test package initialization
│   └── test_socks_proxy.py # Comprehensive pytest test suite
├── doc/                   # Documentation
│   ├── API.md            # API documentation
│   └── DEVELOPMENT.md    # Development guide
├── demo.py               # Example usage and demonstration script
├── setup.py              # Package setup for installation
├── requirements.txt      # Development dependencies
├── pytest.ini           # Pytest configuration
└── README.md            # This file
```

## Installation

### From Source

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd python-socks
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Install the package in development mode:
   ```bash
   pip install -e .
   ```

### Using pip (when published)

```bash
pip install python-socks
```

## Usage

### As a Module

```python
import socket
from src.socks_proxy import create_connection_via_socks, SocksException

# Connect through SOCKS4 proxy
try:
    socks_addr = ("127.0.0.1", 1080)  # SOCKS proxy address
    target_ip = socket.gethostbyname("example.com")
    target_port = 80
    
    s = create_connection_via_socks(socks_addr, target_ip, target_port)
    # Use socket 's' for communication
    s.close()
except SocksException as e:
    print(f"SOCKS error: {e}")
```

### Demo Script

Run the demo script to see the SOCKS proxy in action:

```bash
python demo.py
```

**Note:** This requires a SOCKS4 proxy running on `localhost:1080`. You can set one up using SSH:

```bash
ssh -D 1080 user@remote-server
```

## Testing

The project uses pytest for testing with comprehensive coverage:

```bash
# Run all tests
pytest

# Run with coverage report
pytest --cov=src --cov-report=html

# Run only unit tests (skip integration tests)
pytest -m "not integration"

# Run with verbose output
pytest -v
```

### Test Structure

- **Unit tests**: Test individual functions in isolation using mocks
- **Integration tests**: Test real SOCKS proxy interactions (skipped by default)
- **Error handling tests**: Test various failure scenarios
- **Edge case tests**: Test boundary conditions and invalid inputs

## Documentation

- **[API Documentation](doc/API.md)** - Detailed API reference
- **[Development Guide](doc/DEVELOPMENT.md)** - Setup and contribution guidelines

## SOCKS4 Protocol

This implementation follows the SOCKS4 protocol specification:

### Request Format
- **Version**: 0x04 (1 byte)
- **Command**: 0x01 for TCP connection (1 byte)
- **Port**: Target port in network byte order (2 bytes)
- **IP**: Target IP address (4 bytes)
- **User ID**: Null-terminated string (variable length, often empty)

### Server Response
- **Null byte**: 0x00 (1 byte)
- **Status**: 0x5A for success, other values for various errors (1 byte)
- **Ignored fields**: 6 bytes (port and IP, usually ignored)

### Status Codes
- `0x5A`: Request granted
- `0x5B`: Request rejected or failed
- `0x5C`: Request failed (client not running identd)
- `0x5D`: Request failed (identd authentication failed)

## Development

To contribute to this project:

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Run the test suite: `pytest`
5. Submit a pull request

See [DEVELOPMENT.md](doc/DEVELOPMENT.md) for detailed development guidelines.

## License

See LICENSE file for details.
