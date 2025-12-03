# Installation & Deployment Guide

## Quick Start

### macOS/Linux

```bash
# Clone the repository
git clone https://github.com/PowerProgrammer05/Purple-Hat.git
cd Purple-Hat

# Run setup script
chmod +x install.sh
./install.sh

# Start the application
python3 main.py          # Terminal mode
python3 -m ui.webapp_v3  # Web interface
```

### Windows

```bash
# Clone the repository
git clone https://github.com/PowerProgrammer05/Purple-Hat.git
cd Purple-Hat

# Create virtual environment
python -m venv venv
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install -e .

# Create directories
mkdir results logs sessions

# Run the application
python main.py          # Terminal mode
python -m ui.webapp_v3  # Web interface
```

## Docker Installation

### Prerequisites
- Docker and Docker Compose installed
- Minimum 2GB RAM
- Linux, macOS, or Windows with WSL2

### Setup

```bash
# Build Docker image
docker build -t purple-hat:latest .

# Run container
docker run -d \
  --name purple-hat \
  -p 5000:5000 \
  -v $(pwd)/results:/app/results \
  -v $(pwd)/sessions:/app/sessions \
  -v $(pwd)/config.json:/app/config.json:ro \
  purple-hat:latest

# Access web interface
open http://localhost:5000
```

### Using Docker Compose

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f purple-hat

# Stop services
docker-compose down

# Rebuild image
docker-compose build --no-cache
```

## Development Installation

### Prerequisites
- Python 3.8+
- pip and virtualenv
- Git

### Step-by-step Installation

```bash
# Clone repository
git clone https://github.com/PowerProgrammer05/Purple-Hat.git
cd Purple-Hat

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Upgrade pip
pip install --upgrade pip setuptools wheel

# Install dependencies
pip install -r requirements.txt

# Install in development mode
pip install -e .

# Create directories
mkdir -p results logs sessions

# Verify installation
python3 -c "from core import PurpleHatEngine; print('Installation successful!')"
```

## Platform-Specific Instructions

### macOS

```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python 3
brew install python3

# Install additional tools
brew install nmap dnsmasq

# Follow standard installation above
```

### Linux (Ubuntu/Debian)

```bash
# Update system
sudo apt-get update && sudo apt-get upgrade -y

# Install Python and dependencies
sudo apt-get install -y python3 python3-pip python3-venv python3-dev
sudo apt-get install -y nmap dnsutils net-tools

# Follow standard installation above
```

### Linux (CentOS/RHEL)

```bash
# Install Python and dependencies
sudo yum install -y python3 python3-pip python3-devel
sudo yum install -y nmap bind-utils net-tools

# Follow standard installation above
```

## Configuration

### config.json

The main configuration file controls framework behavior:

```json
{
  "framework": {
    "name": "PURPLE HAT",
    "version": "2.0.0",
    "description": "Comprehensive Security Testing Framework"
  },
  "settings": {
    "timeout": 5,
    "retries": 3,
    "verify_ssl": true,
    "proxy_enabled": false,
    "proxy_url": "http://127.0.0.1:8080"
  },
  "webui": {
    "host": "127.0.0.1",
    "port": 5000,
    "debug": false,
    "admin_username": "admin",
    "admin_password": "ADMIN1234"
  }
}
```

### Environment Variables

```bash
# Web interface configuration
export FLASK_ENV=production
export FLASK_APP=ui.webapp_v3
export SECRET_KEY=your-secret-key

# Proxy configuration
export PURPLEHAT_PROXY_ENABLED=true
export PURPLEHAT_PROXY_URL=http://proxy.example.com:8080

# SQLMap integration
export PURPLEHAT_SQLMAP_PATH=/path/to/sqlmap.py

# Logging
export PURPLEHAT_LOG_LEVEL=INFO
```

## Running the Application

### Terminal Interface

```bash
# Interactive mode
python3 main.py

# With specific mode
python3 main.py --mode ready-to-go      # Quick scanning
python3 main.py --mode professional     # Advanced scanning

# With verbosity
python3 main.py --verbose
```

### Web Interface

```bash
# Start web server
python3 -m ui.webapp_v3

# With custom settings
FLASK_ENV=production FLASK_DEBUG=false python3 -m ui.webapp_v3

# Access in browser
open http://127.0.0.1:5000
```

### Command Line (Future)

```bash
# Direct scanning
purplehat scan --target http://example.com --module sql_injection

# With custom configuration
purplehat scan --target example.com --mode professional --threads 20

# Generate report
purplehat report --scan-id abc123 --format html --output report.html
```

## Troubleshooting

### Installation Issues

**Problem**: `pip: command not found`
```bash
# Solution: Install pip
python3 -m ensurepip --upgrade
```

**Problem**: `ModuleNotFoundError` after installation
```bash
# Solution: Reinstall in development mode
pip install -e . --force-reinstall
```

**Problem**: Permission denied when running scripts
```bash
# Solution: Make scripts executable
chmod +x install.sh
chmod +x run.sh
```

### Runtime Issues

**Problem**: Port 5000 already in use
```bash
# Solution: Use different port
FLASK_PORT=5001 python3 -m ui.webapp_v3

# Or kill existing process
lsof -ti:5000 | xargs kill -9
```

**Problem**: SSL certificate verification errors
```json
{
  "settings": {
    "verify_ssl": false  // Only for testing/development!
  }
}
```

**Problem**: Proxy not working
```bash
# Verify proxy configuration
export PURPLEHAT_PROXY_URL=http://proxy.example.com:8080
python3 main.py --verbose
```

### Docker Issues

**Problem**: Container exits immediately
```bash
# Check logs
docker logs purple-hat

# Run interactively
docker run -it purple-hat:latest /bin/bash
```

**Problem**: Port conflicts
```bash
# Use different port
docker run -p 8000:5000 purple-hat:latest
```

## Security Checklist

Before deployment to production:

- [ ] Change default credentials in `config.json`
- [ ] Set `FLASK_DEBUG=false` and `FLASK_ENV=production`
- [ ] Change `SECRET_KEY` environment variable
- [ ] Enable HTTPS/SSL if exposing over network
- [ ] Restrict access with firewall rules
- [ ] Enable authentication/authorization
- [ ] Audit log files regularly
- [ ] Keep dependencies updated
- [ ] Use strong, unique API keys
- [ ] Implement rate limiting

## Performance Tuning

### Threading

```json
{
  "settings": {
    "sql_injection_threads": 20,  // Increase for faster scanning
    "port_scan_threads": 100
  }
}
```

### Timeout Settings

```json
{
  "settings": {
    "timeout": 10,   // Increase for slow networks
    "retries": 5     // Increase for unstable connections
  }
}
```

### Memory Management

- Reduce payload size for memory-constrained systems
- Use limited port ranges in production
- Enable result caching

## Integration

### GitHub Actions

```yaml
name: PURPLE HAT Scan
on: [push]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Setup Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.9'
      - name: Install PURPLE HAT
        run: pip install -r requirements.txt
      - name: Run Security Scan
        run: python3 main.py --mode ready-to-go
```

### CI/CD Pipeline

```bash
#!/bin/bash
# Deploy and run security scan

docker build -t purple-hat:$VERSION .
docker run --rm \
  -v /app/config.json:/app/config.json \
  purple-hat:$VERSION \
  python3 main.py --mode professional
```

## Support & Resources

- **Documentation**: https://github.com/PowerProgrammer05/Purple-Hat
- **Issues**: https://github.com/PowerProgrammer05/Purple-Hat/issues
- **Discussions**: https://github.com/PowerProgrammer05/Purple-Hat/discussions

## License

PURPLE HAT is licensed under the MIT License. See LICENSE file for details.

---

**For questions or issues, please refer to the official documentation or community forums.**
