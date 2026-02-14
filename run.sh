#!/bin/bash
# Roleplay Circles MVP - Startup Script

cd "$(dirname "$0")"

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate and install dependencies
source venv/bin/activate
pip install -q -r requirements.txt

# Run the app
echo ""
echo "🎯 Starting Roleplay Circles..."
echo "   Open http://localhost:5050"
echo "   Press Ctrl+C to stop"
echo ""
python app.py
