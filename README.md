# AzurEye

A comprehensive security scanning tool for Azure resources that identifies potential vulnerabilities and security misconfigurations across multiple Azure services.

## 🔍 Overview

AzurEye is a Flask-based web application that performs automated security assessments of your Azure environment. It scans various Azure services to identify hardcoded secrets, insecure configurations, and other security vulnerabilities.

## 🚀 Features

### Supported Azure Services
- **Storage Accounts** - Scans for public access, container permissions, and sensitive data
- **Key Vaults** - Analyzes access policies, secrets, certificates, and keys
- **Logic Apps (Standard & Consumption)** - Checks for hardcoded secrets in connections, workflows, and app settings
- **Function Apps** - Scans app settings and code for sensitive information
- **Automation Accounts** - Analyzes runbooks for hardcoded credentials and sensitive data
- **Service Principal Roles** - Reviews role assignments and permissions

### Key Capabilities
- **Real-time Scanning** - Live progress updates with Server-Sent Events (SSE)
- **Comprehensive Reporting** - Detailed HTML reports with vulnerability categorization
- **Visual Data Dashboard** - Interactive charts and graphs showing security posture
- **Database Storage** - SQLite database for scan history and results
- **Export Functionality** - Export scan results as HTML reports
- **Multi-subscription Support** - Scan across multiple Azure subscriptions

## 📋 Prerequisites

### System Requirements
- Python 3.7 or higher
- Azure CLI 2.0 or higher
- Internet connection for Azure API calls

### Azure Authentication
```bash
# Login to Azure
az login

# Verify login
az account show
```

## 🛠️ Installation

### Option 1: Automated Installation (Recommended)
```bash
# Clone the repository
git clone https://github.com/simplyrishabh/AzurEye.git
cd AzurEye

# Run the automated installation script
./install.sh
```

### Option 2: Manual Installation
```bash
# 1. Clone the repository
git clone https://github.com/simplyrishabh/AzurEye.git
cd AzurEye

# 2. Install Python dependencies
pip install flask

# 3. Install Azure CLI extensions
az extension add --name logic
az extension add --name automation

# 4. Verify Azure CLI setup
az --version
az account show
```

## 🚀 Usage

### Start the Application
```bash
python3 app.py
```

The application will start on `http://localhost:5000`

### Web Interface
1. Open your browser and navigate to `http://localhost:5000`
2. Select the Azure service you want to scan
3. Choose your subscription(s)
4. Click "Start Scan" to begin the security assessment
5. Monitor real-time progress and results
6. Export detailed HTML reports

### Command Line Usage
The application is primarily designed for web interface usage, but you can also run individual scan modules programmatically.

## 📁 Project Structure

```
AzurEye/
├── app.py                          # Main Flask application
├── modules/                        # Scan modules for different Azure services
│   ├── automation.py              # Automation Account scanner
│   ├── functionapp.py             # Function App scanner
│   ├── keyvaults.py               # Key Vault scanner
│   ├── logicapp_consumption.py    # Logic App Consumption scanner
│   ├── logicapp_standard.py       # Logic App Standard scanner
│   ├── service_principal_roles.py # Service Principal scanner
│   └── storage.py                 # Storage Account scanner
├── templates/                      # HTML templates
│   ├── base.html                  # Base template
│   ├── dashboard.html             # Dashboard view
│   ├── index.html                 # Home page
│   └── [service].html             # Service-specific templates
├── static/                        # Static assets
│   ├── css/style.css              # Stylesheets
│   └── js/scripts.js              # JavaScript
├── utils/                         # Utility modules
│   ├── az_cli_utils.py           # Azure CLI utilities
│   ├── display_utils.py          # Display utilities
│   ├── output_utils.py           # Output formatting
│   ├── report_utils.py           # Report generation
│   └── sensitive_data_utils.py   # Sensitive data detection
├── results/                       # Scan results (auto-generated)
├── reports/                       # HTML reports (auto-generated)
├── azurEye.db                     # Main database
├── azurEye_visualization.db       # Visualization database
└── visualization_db.py            # Visualization database utilities
```

## 🔧 Configuration

### Database
The application uses SQLite databases:
- `azurEye.db` - Main database for scan results and vulnerability findings
- `azurEye_visualization.db` - Database for visual data dashboard

### Scan Settings
- **Max Run History**: Configurable limit for Logic App run history analysis
- **Sensitive Data Patterns**: Customizable regex patterns for detecting sensitive information
- **Timeout Settings**: Configurable timeouts for Azure CLI commands

## 📊 Reports

### HTML Reports
- **Individual Service Reports** - Detailed reports for each scanned service
- **Comprehensive Dashboard Report** - Overview of all scan results
- **Vulnerability Details** - Categorized findings with recommendations

### Report Features
- Executive summary with vulnerability counts
- Detailed vulnerability descriptions
- Code snippets showing issues
- Security recommendations
- Resource breakdown by subscription
- Timestamp and user information

## 🔒 Security Considerations

### Data Handling
- Scan results are stored locally in SQLite databases
- No data is transmitted to external services
- Sensitive information is detected but not stored in plain text

### Permissions
The application requires the following Azure permissions:
- **Reader** role on subscriptions to enumerate resources
- **Key Vault Secrets User** role to read Key Vault secrets
- **Storage Blob Data Reader** role to read Storage Account contents

### Best Practices
- Run scans in a secure environment
- Regularly review and clean up scan results
- Use least-privilege access for Azure authentication
- Keep Azure CLI and extensions updated

## 🐛 Troubleshooting

### Common Issues

#### Azure CLI Not Found
```bash
# Install Azure CLI
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
```

#### Not Logged In
```bash
# Login to Azure
az login
```

#### Permission Denied
```bash
# Check current user and permissions
az account show
az role assignment list --assignee $(az account show --query user.name -o tsv)
```

#### Flask Import Error
```bash
# Install Flask
pip install flask
```

### Debug Mode
Enable debug mode by setting `debug=True` in `app.py`:
```python
app.run(debug=True, port='5000')
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup
```bash
# Install development dependencies
pip install flask

# Run in development mode
python3 app.py
```

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is designed for security assessment purposes only. Users are responsible for:
- Ensuring they have proper authorization to scan Azure resources
- Complying with their organization's security policies
- Using the tool in accordance with Azure's terms of service
- Properly handling and securing scan results

## 🆘 Support

For support, please:
1. Check the [Issues](https://github.com/simplyrishabh/AzurEye/issues) page
2. Create a new issue with detailed information about your problem
3. Include Azure CLI version, Python version, and error messages

## 🔄 Version History

- **v1.0.0** - Initial release with support for Storage Accounts, Key Vaults, Logic Apps, Function Apps, and Automation Accounts

---

**Made with ❤️ for Azure Security**
