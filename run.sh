#!/bin/bash
# Roleplay Circles v2 - Local Development

cd "$(dirname "$0")"

# Create venv if needed
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
fi

# Activate and install
source venv/bin/activate
pip install -q -r requirements.txt

# Create data directory
mkdir -p data

echo ""
echo "🎯 Roleplay Circles v2"
echo "   http://localhost:5050"
echo ""

python app.py
