#!/bin/bash

# AzurEye Installation Script

echo "🔧 Installing AzurEye..."

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed. Please install Python 3.7 or higher."
    exit 1
fi

# Check if pip is installed
if ! command -v pip3 &> /dev/null; then
    echo "❌ pip3 is not installed. Please install pip3."
    exit 1
fi

# Check if Azure CLI is installed
if ! command -v az &> /dev/null; then
    echo "❌ Azure CLI is not installed. Please install Azure CLI 2.0 or higher."
    echo "   Visit: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli"
    exit 1
fi

# Install Python dependencies
echo "📦 Installing Python dependencies..."
pip3 install -r requirements.txt

# Check Azure CLI extensions
echo "🔍 Checking Azure CLI extensions..."

# Install logic extension if not present
if ! az extension list --query "[?name=='logic']" | grep -q "logic"; then
    echo "📦 Installing Azure CLI logic extension..."
    az extension add --name logic
fi

# Install automation extension if not present
if ! az extension list --query "[?name=='automation']" | grep -q "automation"; then
    echo "📦 Installing Azure CLI automation extension..."
    az extension add --name automation
fi

# Check if user is logged in to Azure
echo "🔐 Checking Azure authentication..."
if ! az account show &> /dev/null; then
    echo "⚠️  You are not logged in to Azure. Please run 'az login' to authenticate."
    echo "   After logging in, you can start the application with: python3 app.py"
else
    echo "✅ Azure authentication verified."
    echo ""
    echo "🚀 Installation complete! You can now start the application with:"
    echo "   python3 app.py"
    echo ""
    echo "📖 Then open your browser and go to: http://localhost:5000"
fi

echo ""
echo "📚 For more information, see the README.md file."
