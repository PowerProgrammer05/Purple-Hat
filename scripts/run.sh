#!/bin/bash

echo "🎯 PURPLE HAT - Security Testing Framework"
echo ""

if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed."
    echo "Install Python 3 and try again."
    exit 1
fi

cd "$(dirname "$0")"

python3 main.py
