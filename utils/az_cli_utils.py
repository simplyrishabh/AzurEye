import subprocess
import sys
import pkg_resources
import json

def check_az_cli():
    try:
        result = subprocess.run("az --version", shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            print("AZ CLI not installed. Installing...")
            subprocess.run("pip install azure-cli", shell=True, check=True)
        return True
    except Exception:
        print("AZ CLI installation check failed. Please install manually.")
        return False

def ensure_az_login():
    result = subprocess.run("az account show", shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        print("Please run 'az login' to authenticate.")
        sys.exit(1)

def install_az_extension(extension_name):
    try:
        result = subprocess.run(f"az extension list --query '[].name' -o tsv", shell=True, capture_output=True, text=True)
        if result.returncode == 0 and extension_name not in result.stdout:
            print(f"Installing AZ CLI extension: {extension_name}")
            subprocess.run(f"az extension add --name {extension_name}", shell=True, check=True)
    except Exception:
        print(f"Failed to install AZ CLI extension: {extension_name}. Please install manually.")

def install_python_deps():
    required = {"colorama", "tabulate"}
    installed = {pkg.key for pkg in pkg_resources.working_set}
    missing = required - installed
    if missing:
        print(f"Installing missing Python dependencies: {missing}")
        subprocess.run([sys.executable, "-m", "pip", "install", *missing], check=True)

def setup_environment(selected_modules):
    if not check_az_cli():
        sys.exit(1)
    ensure_az_login()
    install_python_deps()
    
    extension_map = {
        "logicapp_standard": "logic",
        "logicapp_consumption": "logic",
        "automation": "automation"
    }
    
    for module in selected_modules:
        if module in extension_map:
            install_az_extension(extension_map[module])

def run_az_command(command, timeout=30):
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=timeout)
        if result.returncode == 0 and result.stdout:
            return result.stdout.strip()
        return None
    except subprocess.TimeoutExpired:
        return None
    except Exception:
        return None

def get_current_user_principal_id():
    output = run_az_command("az ad signed-in-user show --query id -o tsv")
    return output if output else None

def get_subscriptions():
    output = run_az_command("az account list --query '[].id' -o json")
    return json.loads(output) if output else []

def get_role_assignments(principal_id):
    output = run_az_command(f"az role assignment list --assignee {principal_id} --all --query '[].{{roleDefinitionName:roleDefinitionName, scope:scope}}' -o json")
    return json.loads(output) if output else []

def get_access_token(resource="https://management.azure.com"):
    output = run_az_command(f"az account get-access-token --resource {resource} --query accessToken -o tsv")
    return output if output else None
