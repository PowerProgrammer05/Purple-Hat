#!/bin/bash

echo "🎯 PURPLE HAT Setup"
echo ""

if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed."
    echo ""
    echo "Installation instructions:"
    echo "macOS: brew install python3"
    echo "Ubuntu/Debian: sudo apt-get install python3"
    echo "CentOS/RHEL: sudo yum install python3"
    exit 1
fi

PYTHON_VERSION=$(python3 --version | grep -oP '\d+\.\d+')
REQUIRED_VERSION="3.7"

if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" = "$REQUIRED_VERSION" ]; then
    echo "✓ Python version: $PYTHON_VERSION"
else
    echo "❌ Python 3.7+ is required (found $PYTHON_VERSION)"
    exit 1
fi

echo ""
echo "✓ Setup complete!"
echo ""
echo "Quick start:"
echo "  ./run.sh"
echo ""
echo "Or run directly:"
echo "  python3 main.py"
