#!/bin/bash
# PURPLE HAT Setup Script
# Quick installation and setup for PURPLE HAT framework

set -e

echo "╔════════════════════════════════════════╗"
echo "║   PURPLE HAT - Setup & Installation   ║"
echo "╚════════════════════════════════════════╝"
echo ""

# Check Python version
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
REQUIRED_VERSION="3.8"

if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
    echo "❌ Python 3.8+ is required. Found: $PYTHON_VERSION"
    exit 1
fi

echo "✅ Python $PYTHON_VERSION detected"
echo ""

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
    echo "✅ Virtual environment created"
else
    echo "✅ Virtual environment already exists"
fi

# Activate virtual environment
echo "🔄 Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "📦 Upgrading pip..."
pip install --upgrade pip setuptools wheel > /dev/null 2>&1

# Install requirements
echo "📦 Installing dependencies..."
pip install -r requirements.txt > /dev/null 2>&1
echo "✅ Dependencies installed"

# Optional: Install in development mode
echo ""
read -p "Install in development mode? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    pip install -e . > /dev/null 2>&1
    echo "✅ Development mode installed"
fi

# Create necessary directories
echo ""
echo "📁 Creating directories..."
mkdir -p results logs sessions
echo "✅ Directories created"

# Configuration
echo ""
echo "⚙️  Configuration"
echo "   - Update config.json with your settings"
echo "   - Change default credentials before deployment"
echo "   - Configure proxy settings if needed"

# Final message
echo ""
echo "╔════════════════════════════════════════╗"
echo "║        Setup Complete! 🎉              ║"
echo "╚════════════════════════════════════════╝"
echo ""
echo "📚 Usage:"
echo ""
echo "   Terminal Mode:"
echo "   $ python3 main.py"
echo ""
echo "   Web Interface:"
echo "   $ python3 -m ui.webapp_v3"
echo "   → Open http://127.0.0.1:5000 in browser"
echo ""
echo "📖 Documentation:"
echo "   - README.md: Full documentation"
echo "   - config.json: Configuration options"
echo "   - Help system: Inside application"
echo ""
echo "For more information, visit: https://github.com/PowerProgrammer05/Purple-Hat"
echo ""
