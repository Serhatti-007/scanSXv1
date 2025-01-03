#!/bin/bash

# Setup script for scanSXv1 project
echo "Starting setup for scanSXv1..."

# Install Python 3 and pip if not installed
echo "Checking for Python 3 and pip..."
if ! command -v python3 &> /dev/null
then
    echo "Python 3 not found. Installing Python 3..."
    sudo apt install python3 -y
fi

if ! command -v pip3 &> /dev/null
then
    echo "pip not found. Installing pip..."
    sudo apt install python3-pip -y
fi

# Install required Python libraries
echo "Installing Python dependencies..."
pip3 install -r requirements.txt --break-system-packages

# Setup complete
echo "Setup complete! You can now run the project using 'python3 scanSXv1.py'."
