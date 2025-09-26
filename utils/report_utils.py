import json
import os
from datetime import datetime
from flask import render_template
from utils.az_cli_utils import get_current_user_principal_id

def generate_html_report(scan_type, scan_results, scan_duration=None):
    """
    Generate a beautiful HTML security report from scan results
    
    Args:
        scan_type (str): Type of scan (e.g., "Logic App Consumption", "Key Vaults")
        scan_results (dict): Results from the scan
        scan_duration (str): Duration of the scan
    
    Returns:
        str: HTML content of the report
    """
    
    try:
        from app import get_user_details
        user_details = get_user_details()
        user_name = user_details.get('displayName', 'Unknown User')
        user_email = user_details.get('userPrincipalName', 'unknown@example.com')
    except:
        user_name = 'Unknown User'
        user_email = 'unknown@example.com'
    
    vulnerabilities = []
    resource_breakdown = {}
    total_resources = 0
    total_vulnerabilities = 0
    
    if scan_type == "Logic App Consumption":
        vulnerabilities, resource_breakdown, total_resources, total_vulnerabilities = _process_logicapp_consumption_results(scan_results)
    elif scan_type == "Logic App Standard":
        vulnerabilities, resource_breakdown, total_resources, total_vulnerabilities = _process_logicapp_standard_results(scan_results)
    elif scan_type == "Key Vaults":
        vulnerabilities, resource_breakdown, total_resources, total_vulnerabilities = _process_keyvault_results(scan_results)
    elif scan_type == "Storage Accounts":
        vulnerabilities, resource_breakdown, total_resources, total_vulnerabilities = _process_storage_results(scan_results)
    elif scan_type == "Function Apps":
        vulnerabilities, resource_breakdown, total_resources, total_vulnerabilities = _process_functionapp_results(scan_results)
    elif scan_type == "Automation Accounts":
        vulnerabilities, resource_breakdown, total_resources, total_vulnerabilities = _process_automation_results(scan_results)
    
    secure_count = total_resources - total_vulnerabilities
    
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Render the HTML report
    html_content = render_template('report_template.html',
        report_title=f"{scan_type} Security Assessment",
        timestamp=timestamp,
        user_name=user_name,
        user_email=user_email,
        scan_type=scan_type,
        scan_duration=scan_duration or "N/A",
        total_subscriptions=len(scan_results.get('subscriptions', {})),
        total_resources=total_resources,
        total_vulnerabilities=total_vulnerabilities,
        secure_count=secure_count,
        vulnerabilities=vulnerabilities,
        resource_breakdown=resource_breakdown
    )
    
    return html_content

def _process_logicapp_consumption_results(scan_results):
    """Process Logic App Consumption scan results"""
    vulnerabilities = []
    resource_breakdown = {}
    total_resources = 0
    total_vulnerabilities = 0
    
    for subscription_id, apps in scan_results.get('subscriptions', {}).items():
        if subscription_id not in resource_breakdown:
            resource_breakdown[subscription_id] = []
        
        for app_name, app_data in apps.items():
            total_resources += 1
            vulnerability_count = 0
            
            # Process code findings (Main Code tab)
            for finding in app_data.get('code_findings', []):
                vulnerabilities.append({
                    'title': 'Hardcoded Secret in Main Code',
                    'category': 'Main Code',
                    'resource_name': app_name,
                    'resource_group': app_data.get('resource_group', 'N/A'),
                    'subscription_id': subscription_id,
                    'description': f'Hardcoded secret or sensitive information found in Logic App main code: {finding}',
                    'code_snippet': _extract_code_snippet(finding),
                    'recommendation': '''Remove all hardcoded secrets (e.g., clientId, clientSecret, tenantId) from the workflow definition.
Use Azure Key Vault to store and retrieve secrets securely at runtime.
Reference secrets using Key Vault actions, managed connectors, or expressions.'''
                })
                vulnerability_count += 1
            
            # Process parameter findings (Main Code tab)
            for finding in app_data.get('param_findings', []):
                vulnerabilities.append({
                    'title': 'Insecure Parameter Configuration',
                    'category': 'Main Code',
                    'resource_name': app_name,
                    'resource_group': app_data.get('resource_group', 'N/A'),
                    'subscription_id': subscription_id,
                    'description': f'Insecure parameter configuration detected: {finding}',
                    'code_snippet': None,
                    'recommendation': '''Remove all hardcoded secrets (e.g., clientId, clientSecret, tenantId) from the workflow definition.
Use Azure Key Vault to store and retrieve secrets securely at runtime.
Reference secrets using Key Vault actions, managed connectors, or expressions.'''
                })
                vulnerability_count += 1
            
            # Process version findings (Version History tab)
            for finding in app_data.get('version_findings', []):
                vulnerabilities.append({
                    'title': 'Version History Security Issue',
                    'category': 'Version History',
                    'resource_name': app_name,
                    'resource_group': app_data.get('resource_group', 'N/A'),
                    'subscription_id': subscription_id,
                    'description': f'Version history issue detected: {finding}',
                    'code_snippet': None,
                    'recommendation': '''Be aware that Azure Logic Apps (Consumption) retains the last 10 versions of the workflow automatically.
You cannot delete individual versions.
If any version contains sensitive data (e.g., secrets), the only secure option is to:
• Delete the Logic App completely
• Recreate it using the sanitized, secure version
• Rotate any exposed credentials that were previously hardcoded.'''
                })
                vulnerability_count += 1
            
            # Process run findings (Run History tab)
            for finding in app_data.get('run_findings', []):
                vulnerabilities.append({
                    'title': 'Run History Security Issue',
                    'category': 'Run History',
                    'resource_name': app_name,
                    'resource_group': app_data.get('resource_group', 'N/A'),
                    'subscription_id': subscription_id,
                    'description': f'Run history security issue detected: {finding}',
                    'code_snippet': None,
                    'recommendation': '''Logic App run history stores inputs and outputs for each action. By default, this includes sensitive data, unless explicitly disabled.
Navigate to the Logic App Designer > Settings > Security and enable:
• Secure Inputs: ON
• Secure Outputs: ON
This ensures that sensitive data will not be visible in:
• Logic App run history
• Diagnostic logs
• Azure Monitor or Log Analytics'''
                })
                vulnerability_count += 1
            
            if vulnerability_count > 0:
                total_vulnerabilities += 1
            
            resource_breakdown[subscription_id].append({
                'name': app_name,
                'resource_group': app_data.get('resource_group', 'N/A'),
                'type': 'Logic App (Consumption)',
                'vulnerability_count': vulnerability_count
            })
    
    return vulnerabilities, resource_breakdown, total_resources, total_vulnerabilities

def _process_logicapp_standard_results(scan_results):
    """Process Logic App Standard scan results"""
    vulnerabilities = []
    resource_breakdown = {}
    total_resources = 0
    total_vulnerabilities = 0
    
    for subscription_id, apps in scan_results.get('subscriptions', {}).items():
        if subscription_id not in resource_breakdown:
            resource_breakdown[subscription_id] = []
        
        for app_name, app_data in apps.items():
            total_resources += 1
            vulnerability_count = 0
            
            # Process the new nested findings structure
            findings = app_data.get('findings', {}).get('regular', {})
            
            # Process connections findings
            for finding in findings.get('connections', []):
                vulnerabilities.append({
                    'title': 'Hardcoded Secret in Connections',
                    'category': 'Connections',
                    'resource_name': app_name,
                    'resource_group': app_data.get('resource_group', 'N/A'),
                    'subscription_id': subscription_id,
                    'description': f'Hardcoded secret or sensitive information found in Logic App connections: {finding}',
                    'code_snippet': _extract_code_snippet(finding),
                    'recommendation': '''Remove all hardcoded secrets (e.g., clientId, clientSecret, tenantId) from the workflow definition.
Use Azure Key Vault to store and retrieve secrets securely at runtime.
Reference secrets using Key Vault actions, managed connectors, or expressions.'''
                })
                vulnerability_count += 1
            
            # Process app-level parameters findings
            for finding in findings.get('app_level_parameters', []):
                vulnerabilities.append({
                    'title': 'Insecure Parameter Configuration',
                    'category': 'App Parameters',
                    'resource_name': app_name,
                    'resource_group': app_data.get('resource_group', 'N/A'),
                    'subscription_id': subscription_id,
                    'description': f'Insecure parameter configuration detected: {finding}',
                    'code_snippet': _extract_code_snippet(finding),
                    'recommendation': '''Remove all hardcoded secrets (e.g., clientId, clientSecret, tenantId) from the workflow definition.
Use Azure Key Vault to store and retrieve secrets securely at runtime.
Reference secrets using Key Vault actions, managed connectors, or expressions.'''
                })
                vulnerability_count += 1
            
            # Process app settings findings
            for finding in findings.get('app_settings', []):
                vulnerabilities.append({
                    'title': 'Sensitive Data in App Settings',
                    'category': 'App Settings',
                    'resource_name': app_name,
                    'resource_group': app_data.get('resource_group', 'N/A'),
                    'subscription_id': subscription_id,
                    'description': f'Sensitive configuration found in Logic App settings: {finding}',
                    'code_snippet': _extract_code_snippet(finding),
                    'recommendation': '''Remove all hardcoded secrets (e.g., clientId, clientSecret, tenantId) from the workflow definition.
Use Azure Key Vault to store and retrieve secrets securely at runtime.
Reference secrets using Key Vault actions, managed connectors, or expressions.'''
                })
                vulnerability_count += 1
            
            # Process workflows findings
            for finding in findings.get('workflows', []):
                vulnerabilities.append({
                    'title': 'Hardcoded Secret in Workflow',
                    'category': 'Workflows',
                    'resource_name': app_name,
                    'resource_group': app_data.get('resource_group', 'N/A'),
                    'subscription_id': subscription_id,
                    'description': f'Hardcoded secret or sensitive information found in Logic App workflow: {finding}',
                    'code_snippet': _extract_code_snippet(finding),
                    'recommendation': '''Remove all hardcoded secrets (e.g., clientId, clientSecret, tenantId) from the workflow definition.
Use Azure Key Vault to store and retrieve secrets securely at runtime.
Reference secrets using Key Vault actions, managed connectors, or expressions.'''
                })
                vulnerability_count += 1
            
            # Process run history findings
            for finding in findings.get('run_history', []):
                vulnerabilities.append({
                    'title': 'Run History Security Issue',
                    'category': 'Run History',
                    'resource_name': app_name,
                    'resource_group': app_data.get('resource_group', 'N/A'),
                    'subscription_id': subscription_id,
                    'description': f'Run history security issue detected: {finding}',
                    'code_snippet': _extract_code_snippet(finding),
                    'recommendation': '''Logic App run history stores inputs and outputs for each action. By default, this includes sensitive data, unless explicitly disabled.
Navigate to the Logic App Designer > Settings > Security and enable:
• Secure Inputs: ON
• Secure Outputs: ON
This ensures that sensitive data will not be visible in:
• Logic App run history
• Diagnostic logs
• Azure Monitor or Log Analytics'''
                })
                vulnerability_count += 1
            
            if vulnerability_count > 0:
                total_vulnerabilities += 1
            
            resource_breakdown[subscription_id].append({
                'name': app_name,
                'resource_group': app_data.get('resource_group', 'N/A'),
                'type': 'Logic App (Standard)',
                'vulnerability_count': vulnerability_count
            })
    
    return vulnerabilities, resource_breakdown, total_resources, total_vulnerabilities

def _process_keyvault_results(scan_results):
    """Process Key Vault scan results"""
    vulnerabilities = []
    resource_breakdown = {}
    total_resources = 0
    total_vulnerabilities = 0
    
    for subscription_id, vaults in scan_results.get('subscriptions', {}).items():
        if subscription_id not in resource_breakdown:
            resource_breakdown[subscription_id] = []
        
        for vault_name, vault_data in vaults.items():
            total_resources += 1
            vulnerability_count = 0
            
            # Process privilege-based findings
            privileges = vault_data.get('privileges', {})
            can_read_secrets = privileges.get('can_read_secrets', False)
            can_read_certs = privileges.get('can_read_certs', False)
            can_read_keys = privileges.get('can_read_keys', False)
            
            # Check assets to see if there's actual content
            assets = vault_data.get('assets', {})
            has_secrets = bool(assets.get('secrets', {}))
            has_certificates = bool(assets.get('certificates', {}))
            has_keys = bool(assets.get('keys', {}))
            
            # Check for excessive privileges - count each access type as separate vulnerability
            if can_read_secrets and can_read_certs and can_read_keys:
                # Create separate findings for each access type to count properly
                if can_read_secrets:
                    content_info = f"Found {len(assets.get('secrets', {}))} secrets" if has_secrets else "No secrets currently stored"
                    vulnerabilities.append({
                        'title': 'Key Vault Secrets Access',
                        'category': 'RBAC',
                        'resource_name': vault_name,
                        'resource_group': vault_data.get('resource_group', 'N/A'),
                        'subscription_id': subscription_id,
                        'description': f'User has access to read secrets from Key Vault. {content_info}',
                        'code_snippet': None,
                        'recommendation': '''Only assign users or service principals just enough access to perform their required tasks.
Avoid giving broad access to all secret types (secrets, keys, certificates) unless justified.
Where possible, avoid giving individual user accounts access to secrets and keys.
Use Managed Identity, service principals, or workload identities to allow apps to access secrets programmatically and securely.
Use Azure RBAC roles like:
• Key Vault Secrets User – only for reading secrets.
• Key Vault Certificates Officer – only for managing certificates.
• Key Vault Crypto User – only for using (not exporting) keys.
Avoid assigning the Key Vault Contributor or Owner role unless absolutely necessary.
Audit every access to secrets, keys, and certificates, and set alerts on unexpected access patterns.'''
                    })
                    vulnerability_count += 1
                
                if can_read_certs:
                    content_info = f"Found {len(assets.get('certificates', {}))} certificates" if has_certificates else "No certificates currently stored"
                    vulnerabilities.append({
                        'title': 'Key Vault Certificates Access',
                        'category': 'RBAC',
                        'resource_name': vault_name,
                        'resource_group': vault_data.get('resource_group', 'N/A'),
                        'subscription_id': subscription_id,
                        'description': f'User has access to read certificates from Key Vault. {content_info}',
                        'code_snippet': None,
                        'recommendation': '''Only assign users or service principals just enough access to perform their required tasks.
Avoid giving broad access to all secret types (secrets, keys, certificates) unless justified.
Where possible, avoid giving individual user accounts access to secrets and keys.
Use Managed Identity, service principals, or workload identities to allow apps to access secrets programmatically and securely.
Use Azure RBAC roles like:
• Key Vault Secrets User – only for reading secrets.
• Key Vault Certificates Officer – only for managing certificates.
• Key Vault Crypto User – only for using (not exporting) keys.
Avoid assigning the Key Vault Contributor or Owner role unless absolutely necessary.
Audit every access to secrets, keys, and certificates, and set alerts on unexpected access patterns.'''
                    })
                    vulnerability_count += 1
                
                if can_read_keys:
                    content_info = f"Found {len(assets.get('keys', {}))} keys" if has_keys else "No keys currently stored"
                    vulnerabilities.append({
                        'title': 'Key Vault Keys Access',
                        'category': 'RBAC',
                        'resource_name': vault_name,
                        'resource_group': vault_data.get('resource_group', 'N/A'),
                        'subscription_id': subscription_id,
                        'description': f'User has access to read keys from Key Vault. {content_info}',
                        'code_snippet': None,
                        'recommendation': '''Only assign users or service principals just enough access to perform their required tasks.
Avoid giving broad access to all secret types (secrets, keys, certificates) unless justified.
Where possible, avoid giving individual user accounts access to secrets and keys.
Use Managed Identity, service principals, or workload identities to allow apps to access secrets programmatically and securely.
Use Azure RBAC roles like:
• Key Vault Secrets User – only for reading secrets.
• Key Vault Certificates Officer – only for managing certificates.
• Key Vault Crypto User – only for using (not exporting) keys.
Avoid assigning the Key Vault Contributor or Owner role unless absolutely necessary.
Audit every access to secrets, keys, and certificates, and set alerts on unexpected access patterns.'''
                    })
                    vulnerability_count += 1
            elif can_read_secrets or can_read_certs or can_read_keys:
                # Individual privilege findings
                if can_read_secrets:
                    content_info = f"Found {len(assets.get('secrets', {}))} secrets" if has_secrets else "No secrets currently stored"
                    vulnerabilities.append({
                        'title': 'Key Vault Secrets Access',
                        'category': 'RBAC',
                        'resource_name': vault_name,
                        'resource_group': vault_data.get('resource_group', 'N/A'),
                        'subscription_id': subscription_id,
                        'description': f'User has access to read secrets from Key Vault. {content_info}',
                        'code_snippet': None,
                        'recommendation': '''Only assign users or service principals just enough access to perform their required tasks.
Avoid giving broad access to all secret types (secrets, keys, certificates) unless justified.
Where possible, avoid giving individual user accounts access to secrets and keys.
Use Managed Identity, service principals, or workload identities to allow apps to access secrets programmatically and securely.
Use Azure RBAC roles like:
• Key Vault Secrets User – only for reading secrets.
• Key Vault Certificates Officer – only for managing certificates.
• Key Vault Crypto User – only for using (not exporting) keys.
Avoid assigning the Key Vault Contributor or Owner role unless absolutely necessary.
Audit every access to secrets, keys, and certificates, and set alerts on unexpected access patterns.'''
                    })
                    vulnerability_count += 1
                
                if can_read_certs:
                    content_info = f"Found {len(assets.get('certificates', {}))} certificates" if has_certificates else "No certificates currently stored"
                    vulnerabilities.append({
                        'title': 'Key Vault Certificates Access',
                        'category': 'RBAC',
                        'resource_name': vault_name,
                        'resource_group': vault_data.get('resource_group', 'N/A'),
                        'subscription_id': subscription_id,
                        'description': f'User has access to read certificates from Key Vault. {content_info}',
                        'code_snippet': None,
                        'recommendation': '''Only assign users or service principals just enough access to perform their required tasks.
Avoid giving broad access to all secret types (secrets, keys, certificates) unless justified.
Where possible, avoid giving individual user accounts access to secrets and keys.
Use Managed Identity, service principals, or workload identities to allow apps to access secrets programmatically and securely.
Use Azure RBAC roles like:
• Key Vault Secrets User – only for reading secrets.
• Key Vault Certificates Officer – only for managing certificates.
• Key Vault Crypto User – only for using (not exporting) keys.
Avoid assigning the Key Vault Contributor or Owner role unless absolutely necessary.
Audit every access to secrets, keys, and certificates, and set alerts on unexpected access patterns.'''
                    })
                    vulnerability_count += 1
                
                if can_read_keys:
                    content_info = f"Found {len(assets.get('keys', {}))} keys" if has_keys else "No keys currently stored"
                    vulnerabilities.append({
                        'title': 'Key Vault Keys Access',
                        'category': 'RBAC',
                        'resource_name': vault_name,
                        'resource_group': vault_data.get('resource_group', 'N/A'),
                        'subscription_id': subscription_id,
                        'description': f'User has access to read keys from Key Vault. {content_info}',
                        'code_snippet': None,
                        'recommendation': '''Only assign users or service principals just enough access to perform their required tasks.
Avoid giving broad access to all secret types (secrets, keys, certificates) unless justified.
Where possible, avoid giving individual user accounts access to secrets and keys.
Use Managed Identity, service principals, or workload identities to allow apps to access secrets programmatically and securely.
Use Azure RBAC roles like:
• Key Vault Secrets User – only for reading secrets.
• Key Vault Certificates Officer – only for managing certificates.
• Key Vault Crypto User – only for using (not exporting) keys.
Avoid assigning the Key Vault Contributor or Owner role unless absolutely necessary.
Audit every access to secrets, keys, and certificates, and set alerts on unexpected access patterns.'''
                    })
                    vulnerability_count += 1
            
            # Process accessible assets findings - show actual values
            assets = vault_data.get('assets', {})
            if assets:
                for asset_type, items in assets.items():
                    if items:  # Only if there are actual items
                        # Create detailed description with actual values
                        if asset_type == 'secrets':
                            secret_details = []
                            for secret_name, secret_value in items.items():
                                secret_details.append(f"{secret_name}: {secret_value}")
                            description = f'Found {len(items)} accessible secrets in Key Vault:\n' + '\n'.join(secret_details)
                        elif asset_type == 'certificates':
                            cert_details = []
                            for cert_name, cert_thumbprint in items.items():
                                cert_details.append(f"{cert_name}: {cert_thumbprint}")
                            description = f'Found {len(items)} accessible certificates in Key Vault:\n' + '\n'.join(cert_details)
                        elif asset_type == 'keys':
                            key_details = []
                            for key_name, key_id in items.items():
                                key_details.append(f"{key_name}: {key_id}")
                            description = f'Found {len(items)} accessible keys in Key Vault:\n' + '\n'.join(key_details)
                        else:
                            description = f'Found {len(items)} accessible {asset_type} in Key Vault: {", ".join(items.keys())}'
                        
                        vulnerabilities.append({
                            'title': f'Accessible {asset_type.capitalize()} Found',
                            'category': 'Accessible Assets',
                            'resource_name': vault_name,
                            'resource_group': vault_data.get('resource_group', 'N/A'),
                            'subscription_id': subscription_id,
                            'description': description,
                            'code_snippet': None,
                            'recommendation': '''Only assign users or service principals just enough access to perform their required tasks.
Avoid giving broad access to all secret types (secrets, keys, certificates) unless justified.
Where possible, avoid giving individual user accounts access to secrets and keys.
Use Managed Identity, service principals, or workload identities to allow apps to access secrets programmatically and securely.
Use Azure RBAC roles like:
• Key Vault Secrets User – only for reading secrets.
• Key Vault Certificates Officer – only for managing certificates.
• Key Vault Crypto User – only for using (not exporting) keys.
Avoid assigning the Key Vault Contributor or Owner role unless absolutely necessary.
Audit every access to secrets, keys, and certificates, and set alerts on unexpected access patterns.'''
                        })
                        vulnerability_count += 1
            
            # Process RBAC warning
            rbac_warning = vault_data.get('rbac_warning')
            if rbac_warning:
                vulnerabilities.append({
                    'title': 'Key Vault Access Policy Warning',
                    'category': 'Access Policies',
                    'resource_name': vault_name,
                    'resource_group': vault_data.get('resource_group', 'N/A'),
                    'subscription_id': subscription_id,
                    'description': rbac_warning,
                    'code_snippet': None,
                    'recommendation': '''Only assign users or service principals just enough access to perform their required tasks.
Avoid giving broad access to all secret types (secrets, keys, certificates) unless justified.
Where possible, avoid giving individual user accounts access to secrets and keys.
Use Managed Identity, service principals, or workload identities to allow apps to access secrets programmatically and securely.
Use Azure RBAC roles like:
• Key Vault Secrets User – only for reading secrets.
• Key Vault Certificates Officer – only for managing certificates.
• Key Vault Crypto User – only for using (not exporting) keys.
Avoid assigning the Key Vault Contributor or Owner role unless absolutely necessary.
Audit every access to secrets, keys, and certificates, and set alerts on unexpected access patterns.'''
                })
                vulnerability_count += 1
            
            if vulnerability_count > 0:
                total_vulnerabilities += 1
            
            resource_breakdown[subscription_id].append({
                'name': vault_name,
                'resource_group': vault_data.get('resource_group', 'N/A'),
                'type': 'Key Vault',
                'vulnerability_count': vulnerability_count
            })
    
    return vulnerabilities, resource_breakdown, total_resources, total_vulnerabilities

def _process_storage_results(scan_results):
    """Process Storage Account scan results"""
    vulnerabilities = []
    resource_breakdown = {}
    total_resources = 0
    total_vulnerabilities = 0
    
    for subscription_id, accounts in scan_results.get('subscriptions', {}).items():
        if subscription_id not in resource_breakdown:
            resource_breakdown[subscription_id] = []
        
        for account_name, account_data in accounts.items():
            total_resources += 1
            vulnerability_count = 0
            
            # Process access findings for different storage types
            categories_to_check = ["containers", "queues", "tables", "file_shares"]
            for category in categories_to_check:
                if category in account_data and account_data[category]:
                    for item_name, item_data in account_data[category].items():
                        if isinstance(item_data, dict) and item_data.get("access") == "Access Granted":
                            vulnerabilities.append({
                                'title': f'Storage {category.capitalize()} Access Granted',
                                'category': 'Access Configuration',
                                'resource_name': account_name,
                                'resource_group': account_data.get('resource_group', 'N/A'),
                                'subscription_id': subscription_id,
                                'description': f'Access granted to {category[:-1]} "{item_name}" in Storage Account',
                                'code_snippet': None,
                                'recommendation': '''Apply least privilege — limit users to only the specific roles they need.
Avoid granting Owner or Contributor unless strictly necessary.
Use Scoped RBAC roles (e.g., limit to a single container instead of whole account).'''
                            })
                            vulnerability_count += 1
            
            # Process encryption findings
            for finding in account_data.get('encryption_findings', []):
                vulnerabilities.append({
                    'title': 'Storage Account Encryption Issue',
                    'category': 'Encryption',
                    'resource_name': account_name,
                    'resource_group': account_data.get('resource_group', 'N/A'),
                    'subscription_id': subscription_id,
                    'description': f'Encryption configuration issue: {finding}',
                    'code_snippet': None,
                    'recommendation': '''Apply least privilege — limit users to only the specific roles they need.
Avoid granting Owner or Contributor unless strictly necessary.
Use Scoped RBAC roles (e.g., limit to a single container instead of whole account).'''
                })
                vulnerability_count += 1
            
            if vulnerability_count > 0:
                total_vulnerabilities += 1
            
            resource_breakdown[subscription_id].append({
                'name': account_name,
                'resource_group': account_data.get('resource_group', 'N/A'),
                'type': 'Storage Account',
                'vulnerability_count': vulnerability_count
            })
    
    return vulnerabilities, resource_breakdown, total_resources, total_vulnerabilities

def _process_functionapp_results(scan_results):
    """Process Function App scan results"""
    vulnerabilities = []
    resource_breakdown = {}
    total_resources = 0
    total_vulnerabilities = 0
    
    for subscription_id, apps in scan_results.get('subscriptions', {}).items():
        if subscription_id not in resource_breakdown:
            resource_breakdown[subscription_id] = []
        
        for app_name, app_data in apps.items():
            total_resources += 1
            vulnerability_count = 0
            
            # Process app settings findings
            for finding in app_data.get('appsettings_findings', []):
                vulnerabilities.append({
                    'title': 'Sensitive Data in App Settings',
                    'category': 'App Settings',
                    'resource_name': app_name,
                    'resource_group': app_data.get('resource_group', 'N/A'),
                    'subscription_id': subscription_id,
                    'description': f'Sensitive configuration found in Function App settings: {finding}',
                    'code_snippet': None,
                    'recommendation': '''All sensitive configuration values, such as secrets, connection strings, and API keys, should be stored in Azure Key Vault rather than directly in app settings.
Use Key Vault references in app settings to securely retrieve secrets at runtime, ensuring that no actual secret values are stored in the Function App configuration.
Enable Managed Identity on the Function App to allow it to authenticate to Azure Key Vault securely without the need for hardcoded credentials.
Assign the Function App's identity the least-privilege role, such as Key Vault Secrets User, to ensure it can only access the secrets it needs.'''
                })
                vulnerability_count += 1
            
            # Process app files findings
            for finding in app_data.get('file_findings', []):
                vulnerabilities.append({
                    'title': 'Security Issue in App Files',
                    'category': 'App Files',
                    'resource_name': app_name,
                    'resource_group': app_data.get('resource_group', 'N/A'),
                    'subscription_id': subscription_id,
                    'description': f'Security issue found in Function App files: {finding}',
                    'code_snippet': None,
                    'recommendation': '''Access to Function App files, including deployment interfaces such as Kudu/SCM and FTP, should be strictly limited to authorized users and should be disabled if not required.
Integrate automated secret scanning tools into your CI/CD pipeline to detect and block credentials or secrets before they are deployed.
Apply network-level restrictions, such as IP filtering or private endpoints, to limit external access to your deployment and management interfaces.'''
                })
                vulnerability_count += 1
            
            # Process app keys findings
            for finding in app_data.get('appkeys_findings', []):
                vulnerabilities.append({
                    'title': 'Function App Key Security Issue',
                    'category': 'App Keys',
                    'resource_name': app_name,
                    'resource_group': app_data.get('resource_group', 'N/A'),
                    'subscription_id': subscription_id,
                    'description': f'Function App key security issue: {finding}',
                    'code_snippet': None,
                    'recommendation': '''Limit access to function keys by ensuring only specific roles (e.g., Function App Contributor) have the ability to view or regenerate keys.
Implement a key rotation policy to regularly regenerate function keys, especially after personnel changes or potential exposure.'''
                })
                vulnerability_count += 1
            
            if vulnerability_count > 0:
                total_vulnerabilities += 1
            
            resource_breakdown[subscription_id].append({
                'name': app_name,
                'resource_group': app_data.get('resource_group', 'N/A'),
                'type': 'Function App',
                'vulnerability_count': vulnerability_count
            })
    
    return vulnerabilities, resource_breakdown, total_resources, total_vulnerabilities

def _process_automation_results(scan_results):
    """Process Automation Account scan results"""
    vulnerabilities = []
    resource_breakdown = {}
    total_resources = 0
    total_vulnerabilities = 0
    
    for subscription_id, accounts in scan_results.get('subscriptions', {}).items():
        if subscription_id not in resource_breakdown:
            resource_breakdown[subscription_id] = []
        
        for account_name, account_data in accounts.items():
            total_resources += 1
            vulnerability_count = 0
            
            # Process runbook-specific findings - group by runbook to avoid duplicate vulnerabilities
            runbooks = account_data.get('runbooks', {})
            runbooks_with_issues = []
            
            for runbook_name, runbook_data in runbooks.items():
                if isinstance(runbook_data, dict):
                    runbook_issues = []
                    
                    # Check for runbook-specific sensitive data
                    runbook_sensitive_data = runbook_data.get('sensitive_data', [])
                    if runbook_sensitive_data:
                        runbook_issues.extend(runbook_sensitive_data)
                    
                    # Check for runbook errors
                    if 'error' in runbook_data:
                        runbook_issues.append(f"Error: {runbook_data['error']}")
                    
                    # If this runbook has issues, add it to the list
                    if runbook_issues:
                        runbooks_with_issues.append({
                            'name': runbook_name,
                            'issues': runbook_issues,
                            'state': runbook_data.get('state', 'Unknown'),
                            'type': runbook_data.get('type', 'Unknown')
                        })
            
            # Create one vulnerability per runbook with issues
            for runbook_info in runbooks_with_issues:
                runbook_name = runbook_info['name']
                issues = runbook_info['issues']
                state = runbook_info['state']
                runbook_type = runbook_info['type']
                
                # Create a consolidated description
                if len(issues) == 1:
                    description = f'Runbook "{runbook_name}" (State: {state}, Type: {runbook_type}) contains sensitive data: {issues[0]}'
                else:
                    description = f'Runbook "{runbook_name}" (State: {state}, Type: {runbook_type}) contains {len(issues)} instances of sensitive data'
                
                # Create a consolidated code snippet with all findings
                code_snippet = f"Runbook: {runbook_name}\nState: {state}\nType: {runbook_type}\n\nSensitive Data Found:\n"
                for i, issue in enumerate(issues, 1):
                    code_snippet += f"{i}. {issue}\n"
                
                vulnerabilities.append({
                    'title': 'Automation Account Runbook Security Issue',
                    'category': 'Runbook Security',
                    'resource_name': account_name,
                    'resource_group': account_data.get('resource_group', 'N/A'),
                    'subscription_id': subscription_id,
                    'description': description,
                    'code_snippet': code_snippet,
                    'recommendation': '''Avoid hardcoding any credentials (usernames, passwords, API keys, client secrets) directly in runbooks.
Store all secrets in Azure Key Vault and retrieve them securely at runtime.
Audit existing runbooks for embedded secrets using scanning tools or manual code review.
Define a policy stating that no secrets should exist in cleartext within scripts or configurations.'''
                })
                vulnerability_count += 1
            
            if vulnerability_count > 0:
                total_vulnerabilities += 1
            
            resource_breakdown[subscription_id].append({
                'name': account_name,
                'resource_group': account_data.get('resource_group', 'N/A'),
                'type': 'Automation Account',
                'vulnerability_count': vulnerability_count
            })
    
    return vulnerabilities, resource_breakdown, total_resources, total_vulnerabilities

def _extract_code_snippet(finding):
    """Extract code snippet from finding for display in report"""
    # This is a simplified version - in reality, you'd want to extract actual code snippets
    if 'password' in finding.lower() or 'secret' in finding.lower() or 'key' in finding.lower():
        return f"// Vulnerable code detected:\n// {finding}\n// TODO: Remove hardcoded values and use secure configuration"
    return None

def save_html_report(html_content, scan_type):
    """Save HTML report to file"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"azurEye_{scan_type.replace(' ', '_')}_report_{timestamp}.html"
    
    # Create reports directory if it doesn't exist
    reports_dir = "reports"
    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir)
    
    filepath = os.path.join(reports_dir, filename)
    
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    return filepath, filename

class Vulnerability:
    """Simple class to represent vulnerability data for template rendering"""
    def __init__(self, title, category, resource_name, resource_group, subscription_id, description, code_snippet, recommendation):
        self.title = title
        self.category = category
        self.resource_name = resource_name
        self.resource_group = resource_group
        self.subscription_id = subscription_id
        self.description = description
        self.code_snippet = code_snippet
        self.recommendation = recommendation

def generate_dashboard_report(scan_stats, service_details, user_details, subscriptions, scan_summary, resource_distribution, all_scan_results):
    """Generate comprehensive dashboard report with all scan results and vulnerabilities"""
    from datetime import datetime
    from flask import render_template
    
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # For now, create a simple test with actual vulnerability data from database
    all_vulnerabilities = []
    total_resources = 0
    total_vulnerabilities = 0
    
    # Get vulnerability data directly from database
    try:
        import sqlite3
        conn = sqlite3.connect('azurEye.db')
        cursor = conn.cursor()
        cursor.execute("""
            SELECT subscription_id, service_type, service_name, resource_group, 
                   vulnerability_title, category, description, code_snippet, 
                   recommendation, scan_timestamp
            FROM vulnerability_findings 
            ORDER BY service_type, subscription_id, service_name, vulnerability_title
        """)
        
        vulnerability_results = cursor.fetchall()
        conn.close()
        
        # Create Vulnerability objects from database data
        for row in vulnerability_results:
            subscription_id, service_type, service_name, resource_group, vulnerability_title, category, description, code_snippet, recommendation, scan_timestamp = row
            
            vulnerability_obj = Vulnerability(
                title=vulnerability_title,
                category=category,
                resource_name=service_name,
                resource_group=resource_group,
                subscription_id=subscription_id,
                description=description,
                code_snippet=code_snippet,
                recommendation=recommendation
            )
            all_vulnerabilities.append(vulnerability_obj)
            total_vulnerabilities += 1
        
        # Count total resources from scan_results
        conn = sqlite3.connect('azurEye.db')
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM scan_results")
        total_resources = cursor.fetchone()[0]
        conn.close()
        
    except Exception as e:
        print(f"Error getting vulnerability data: {e}")
        # Fallback to basic data
        total_resources = 0
        total_vulnerabilities = 0
    
    # Create comprehensive report data
    report_data = {
        'report_title': 'AzurEye Comprehensive Security Report',
        'timestamp': timestamp,
        'user_name': user_details.get('displayName', 'Unknown User'),
        'user_email': user_details.get('userPrincipalName', 'Unknown Email'),
        'user_details': user_details,
        'subscriptions': subscriptions,
        'scan_stats': scan_stats,
        'service_details': service_details,
        'scan_summary': scan_summary,
        'resource_distribution': resource_distribution,
        'all_scan_results': all_scan_results,
        'vulnerabilities': all_vulnerabilities,
        'total_resources': total_resources,
        'total_vulnerabilities': total_vulnerabilities,
        'resources_with_issues': total_vulnerabilities,
        'secure_resources': total_resources - total_vulnerabilities,
        'secure_count': total_resources - total_vulnerabilities,
        'total_subscriptions': len(subscriptions),
        'scan_type': 'Comprehensive Security Assessment',
        'scan_duration': 'N/A'
    }
    
    # For now, use the fallback HTML to ensure we get vulnerability data
    # TODO: Fix the main template rendering issue
    return generate_basic_dashboard_html(report_data)

def generate_basic_dashboard_html(report_data):
    """Generate basic HTML dashboard report as fallback"""
    html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{report_data['title']}</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        body {{ font-family: 'Inter', sans-serif; background-color: #f9fafb; color: #1f2937; line-height: 1.6; margin: 0; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 2rem; }}
        .header {{ background: linear-gradient(135deg, #1e3a8a 0%, #3b82f6 100%); color: white; padding: 2rem; text-align: center; border-radius: 0 0 0.5rem 0.5rem; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); }}
        .section {{ background: white; padding: 1.5rem; margin-bottom: 1.5rem; border-radius: 0.5rem; box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05); }}
        .section h2 {{ font-size: 1.5rem; font-weight: 600; color: #1e3a8a; margin-bottom: 1rem; border-bottom: 2px solid #e5e7eb; padding-bottom: 0.5rem; }}
        .vulnerability-card {{ background: linear-gradient(135deg, #fef2f2 0%, #fee2e2 100%); border: 2px solid #fca5a5; border-radius: 0.75rem; padding: 1.5rem; margin: 1rem 0; }}
        .table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; }}
        .table th, .table td {{ padding: 0.75rem; text-align: left; border-bottom: 1px solid #e5e7eb; }}
        .table th {{ background-color: #f3f4f6; font-weight: 600; color: #1f2937; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1 class="text-3xl font-bold">{report_data['title']}</h1>
            <p class="text-sm mt-2">Generated on {report_data['timestamp']}</p>
        </div>

        <div class="section">
            <h2>Executive Summary</h2>
            <p><strong>Total Resources Scanned:</strong> {report_data['total_resources']}</p>
            <p><strong>Resources with Issues:</strong> {report_data['resources_with_issues']}</p>
            <p><strong>Secure Resources:</strong> {report_data['secure_resources']}</p>
            <p><strong>Total Subscriptions:</strong> {len(report_data['subscriptions'])}</p>
        </div>

        <div class="section">
            <h2>User Details</h2>
            <p><strong>Name:</strong> {report_data['user_details'].get('displayName', 'N/A')}</p>
            <p><strong>Email:</strong> {report_data['user_details'].get('userPrincipalName', 'N/A')}</p>
        </div>

        <div class="section">
            <h2>Scan Results by Service Type</h2>
            <table class="table">
                <thead>
                    <tr>
                        <th>Service Type</th>
                        <th>Total Scanned</th>
                        <th>With Issues</th>
                        <th>Secure</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(f'''
                    <tr>
                        <td>{service_type}</td>
                        <td>{service_data['total_scanned']}</td>
                        <td>{service_data['total_with_findings']}</td>
                        <td>{service_data['total_scanned'] - service_data['total_with_findings']}</td>
                    </tr>
                    ''' for service_type, service_data in report_data['all_scan_results'].items())}
                </tbody>
            </table>
        </div>

        <div class="section">
            <h2>Security Findings</h2>
            {''.join(f'''
            <div class="vulnerability-card">
                <h3 class="text-lg font-semibold text-gray-800">{vuln.title}</h3>
                <p class="text-gray-600"><strong>Resource:</strong> {vuln.resource_name}</p>
                <p class="text-gray-600"><strong>Category:</strong> {vuln.category}</p>
                <p class="text-gray-600"><strong>Resource Group:</strong> {vuln.resource_group}</p>
                <p class="text-gray-600"><strong>Subscription:</strong> {vuln.subscription_id}</p>
                <p class="text-gray-700 mt-2">{vuln.description}</p>
                {f'<div class="mt-3 p-3 bg-gray-50 border border-gray-200 rounded"><h4 class="font-semibold text-gray-800">Code Snippet:</h4><pre class="text-gray-700 text-sm">{vuln.code_snippet}</pre></div>' if vuln.code_snippet else ''}
                <div class="mt-3 p-3 bg-green-50 border border-green-200 rounded">
                    <h4 class="font-semibold text-green-800">Recommendation:</h4>
                    <p class="text-green-700">{vuln.recommendation}</p>
                </div>
            </div>
            ''' for vuln in report_data['vulnerabilities']) if report_data['vulnerabilities'] else '<p class="text-green-600">No security issues found!</p>'}
        </div>
    </div>
</body>
</html>
    """
    return html_content

def generate_logicapp_standard_report(data):
    """Generate Logic App Standard audit report"""
    import time
    
    report_lines = []
    report_lines.append("=" * 80)
    report_lines.append("AZURE LOGIC APP STANDARD SECURITY AUDIT REPORT")
    report_lines.append("=" * 80)
    report_lines.append(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    report_lines.append("")
    
    if 'subscriptions' in data:
        for subscription_id, logic_apps in data['subscriptions'].items():
            report_lines.append(f"SUBSCRIPTION: {subscription_id}")
            report_lines.append("-" * 60)
            
            for app_name, app_data in logic_apps.items():
                report_lines.append(f"\nLogic App: {app_name}")
                report_lines.append(f"Resource Group: {app_data.get('resource_group', 'Unknown')}")
                
                findings = app_data.get('findings', {}).get('regular', {})
                has_findings = app_data.get('has_findings', False)
                
                if has_findings:
                    report_lines.append("STATUS: ⚠️  SECURITY ISSUES FOUND")
                    
                    # Connections
                    if findings.get('connections'):
                        report_lines.append("\n  CONNECTIONS:")
                        for finding in findings['connections']:
                            report_lines.append(f"    - {finding}")
                    
                    # App-level Parameters
                    if findings.get('app_level_parameters'):
                        report_lines.append("\n  APP-LEVEL PARAMETERS:")
                        for finding in findings['app_level_parameters']:
                            report_lines.append(f"    - {finding}")
                    
                    # App Settings
                    if findings.get('app_settings'):
                        report_lines.append("\n  APP SETTINGS:")
                        for finding in findings['app_settings']:
                            report_lines.append(f"    - {finding}")
                    
                    # Workflows
                    if findings.get('workflows'):
                        report_lines.append("\n  WORKFLOWS:")
                        for finding in findings['workflows']:
                            report_lines.append(f"    - {finding}")
                    
                    # Run History
                    if findings.get('run_history'):
                        report_lines.append("\n  RUN HISTORY:")
                        for finding in findings['run_history']:
                            report_lines.append(f"    - {finding}")
                else:
                    report_lines.append("STATUS: ✅ No security issues found")
                
                report_lines.append("")
    
    # Summary
    total_apps = sum(len(apps) for apps in data.get('subscriptions', {}).values())
    apps_with_findings = sum(
        sum(1 for app_data in apps.values() if app_data.get('has_findings', False))
        for apps in data.get('subscriptions', {}).values()
    )
    
    report_lines.append("=" * 80)
    report_lines.append("SUMMARY")
    report_lines.append("=" * 80)
    report_lines.append(f"Total Logic Apps Scanned: {total_apps}")
    report_lines.append(f"Apps with Security Issues: {apps_with_findings}")
    report_lines.append(f"Apps without Issues: {total_apps - apps_with_findings}")
    report_lines.append("")
    report_lines.append("RECOMMENDATIONS:")
    report_lines.append("- Review and secure any hardcoded credentials found")
    report_lines.append("- Use Azure Key Vault for sensitive configuration values")
    report_lines.append("- Implement proper access controls and monitoring")
    report_lines.append("- Regularly audit Logic App configurations")
    report_lines.append("")
    report_lines.append("=" * 80)
    
    return "\n".join(report_lines)
