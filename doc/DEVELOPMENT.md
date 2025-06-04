# Development Guide

## Project Structure

```
python-socks/
├── src/                    # Source code
│   ├── __init__.py        # Package initialization
│   └── socks_proxy.py     # Main SOCKS implementation
├── test/                  # Test files
│   ├── __init__.py        # Test package initialization
│   └── test_socks_proxy.py # Test suite
├── doc/                   # Documentation
│   ├── API.md            # API documentation
│   └── DEVELOPMENT.md    # This file
├── demo.py               # Demo script
├── setup.py              # Package setup
├── requirements.txt      # Development dependencies
├── pytest.ini           # Pytest configuration
└── README.md            # Project readme
```

## Setting Up Development Environment

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd python-socks
   ```

2. **Create a virtual environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install development dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Install the package in development mode:**
   ```bash
   pip install -e .
   ```

## Running Tests

### All Tests
```bash
pytest
```

### Unit Tests Only (skip integration tests)
```bash
pytest -m "not integration"
```

### With Coverage
```bash
pytest --cov=src --cov-report=html
```

### Specific Test File
```bash
pytest test/test_socks_proxy.py -v
```

## Code Style

- Follow PEP 8 style guidelines
- Use meaningful variable and function names
- Add docstrings to all public functions and classes
- Keep functions focused and small
- Add type hints where appropriate

## Testing Guidelines

### Unit Tests
- Test individual functions in isolation
- Use mocking for external dependencies
- Test both success and failure cases
- Test edge cases and invalid inputs

### Integration Tests
- Test real interactions between components
- Mark with `@pytest.mark.integration`
- Skip by default (require manual enabling)
- Document setup requirements

### Test Structure
```python
class TestFunctionName:
    """Test cases for function_name."""
    
    def test_basic_functionality(self):
        """Test basic use case."""
        # Arrange
        # Act  
        # Assert
        
    def test_error_conditions(self):
        """Test error handling."""
        with pytest.raises(ExpectedException):
            # Test code
```

## Contributing

1. **Fork the repository**
2. **Create a feature branch:**
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. **Make your changes**
4. **Add tests for your changes**
5. **Run the test suite:**
   ```bash
   pytest
   ```
6. **Update documentation if needed**
7. **Commit your changes:**
   ```bash
   git commit -m "Add your descriptive commit message"
   ```
8. **Push to your fork:**
   ```bash
   git push origin feature/your-feature-name
   ```
9. **Create a pull request**

## Release Process

1. **Update version number** in `setup.py` and `src/__init__.py`
2. **Update CHANGELOG.md** (if it exists)
3. **Run full test suite:**
   ```bash
   pytest
   ```
4. **Build the package:**
   ```bash
   python setup.py sdist bdist_wheel
   ```
5. **Tag the release:**
   ```bash
   git tag v1.0.0
   git push origin v1.0.0
   ```

## Debugging

### Setting up a test SOCKS proxy

For integration testing, you can set up a SOCKS proxy using SSH:

```bash
# Create SSH tunnel with SOCKS proxy
ssh -D 1080 -N user@remote-server

# Or use a local SOCKS proxy like Dante
# (Installation varies by OS)
```

### Running the demo

```bash
python demo.py
```

### Manual testing

```python
import socket
from src.socks_proxy import create_connection_via_socks

# Test with a real proxy
socks_addr = ("127.0.0.1", 1080)
target_ip = socket.gethostbyname("httpbin.org")
s = create_connection_via_socks(socks_addr, target_ip, 80)
```

## Common Issues

### Import Errors
- Make sure you're in the project root directory
- Ensure the virtual environment is activated
- Check that the package is installed in development mode

### Test Failures
- Check that you have the latest dependencies installed
- Ensure you're not running integration tests without a SOCKS proxy
- Verify network connectivity for hostname resolution tests

### SOCKS Proxy Issues
- Ensure the SOCKS proxy is running and accessible
- Check firewall settings
- Verify the proxy supports SOCKS4 protocol 