import json
import os
import time
import subprocess
from flask import Response, render_template, request, jsonify
from utils.az_cli_utils import run_az_command, get_current_user_principal_id, get_role_assignments
from utils.output_utils import write_findings

def register_routes(app):
    # Key Vault Functions
    def get_keyvault_privileges(role_assignments):
        privileges = {}
        can_read_secrets = False
        can_read_certs = False
        can_read_keys = False

        role_capabilities = {
            "Key Vault Secrets User": ["List and read secret values"],
            "Key Vault Secrets Officer": ["List, read, and manage secret values"],
            "Key Vault Crypto User": ["List and read/use keys"],
            "Key Vault Crypto Officer": ["List, read, and manage keys"],
            "Key Vault Certificate User": ["List and read certificate values"],
            "Key Vault Certificates Officer": ["List, read, and manage certificates"],
            "Key Vault Administrator": ["Full access to secrets, keys, and certificates"],
            "Key Vault Data Access Administrator": ["Full access to secrets, keys, and certificates (read, write, delete)"],
            "Key Vault Contributor": ["Full access to secrets, keys, and certificates"],
            "Owner": ["Full access to all resources, including secrets, keys, and certificates"],
            "Contributor": ["Full access to secrets, keys, and certificates"],
            "Key Vault Reader": ["Read metadata of vaults, secrets, keys, and certificates"]
        }

        for assignment in role_assignments:
            role_name = assignment["roleDefinitionName"]
            scope = assignment["scope"]
            if role_name in role_capabilities:
                privileges[role_name] = {"scope": scope, "capabilities": role_capabilities[role_name]}
                if role_name in ["Key Vault Secrets User", "Key Vault Secrets Officer", "Key Vault Administrator", "Key Vault Data Access Administrator", "Key Vault Contributor", "Owner", "Contributor"]:
                    can_read_secrets = True
                if role_name in ["Key Vault Certificate User", "Key Vault Certificates Officer", "Key Vault Administrator", "Key Vault Data Access Administrator", "Key Vault Contributor", "Owner", "Contributor"]:
                    can_read_certs = True
                if role_name in ["Key Vault Crypto User", "Key Vault Crypto Officer", "Key Vault Administrator", "Key Vault Data Access Administrator", "Key Vault Contributor", "Owner", "Contributor"]:
                    can_read_keys = True

        return privileges, can_read_secrets, can_read_certs, can_read_keys

    def get_keyvaults(subscription):
        output = run_az_command(f"az keyvault list --subscription {subscription} --query '[].{{name:name, resourceGroup:resourceGroup}}' -o json")
        return json.loads(output) if output else []

    def check_rbac_enabled(vault_name, subscription):
        output = run_az_command(f"az keyvault show --name {vault_name} --subscription {subscription} --query properties.enableRbacAuthorization -o tsv")
        return output == "true" if output else False

    def access_keyvault(vault_name, resource_group, subscription, can_read_secrets, can_read_certs, can_read_keys):
        results = {}
        base_cmd = f"az keyvault {{type}} {{action}} --vault-name {vault_name} --subscription {subscription}"

        rbac_enabled = check_rbac_enabled(vault_name, subscription)
        rbac_warning = f"Warning: {vault_name} uses access policies, not RBAC" if not rbac_enabled else None

        if can_read_secrets and rbac_enabled:
            secrets = run_az_command(base_cmd.format(type="secret", action="list") + " --query '[].name' -o tsv")
            if secrets:
                results["secrets"] = {}
                for secret in secrets.splitlines():
                    value = run_az_command(base_cmd.format(type="secret", action="show") + f" --name {secret} --query value -o tsv")
                    if value:
                        results["secrets"][secret] = value

        if can_read_certs and rbac_enabled:
            certs = run_az_command(base_cmd.format(type="certificate", action="list") + " --query '[].name' -o tsv")
            if certs:
                results["certificates"] = {}
                for cert in certs.splitlines():
                    thumbprint = run_az_command(base_cmd.format(type="certificate", action="show") + f" --name {cert} --query x509Thumbprint -o tsv")
                    if thumbprint:
                        results["certificates"][cert] = thumbprint

        if can_read_keys and rbac_enabled:
            keys = run_az_command(base_cmd.format(type="key", action="list") + " --query '[].name' -o tsv")
            if keys:
                results["keys"] = {}
                for key in keys.splitlines():
                    kid = run_az_command(base_cmd.format(type="key", action="show") + f" --name {key} --query key.kid -o tsv")
                    if kid:
                        results["keys"][key] = kid

        return results, rbac_warning

    def analyze_keyvaults_stream(subscriptions):
        from app import save_scan_result, save_detailed_scan_results  # Lazy import inside the function
        from visualization_db import save_vulnerability_findings, save_detailed_scan_results as save_visual_detailed_scan_results  # Lazy import inside the function
        
        output_dir = "results/keyvault"
        os.makedirs(output_dir, exist_ok=True)

        principal_id = get_current_user_principal_id()
        if not principal_id:
            yield json.dumps({"error": "Unable to get Principal ID. Run 'az login'."}) + "\n"
            return

        role_assignments = get_role_assignments(principal_id)
        if not role_assignments:
            yield json.dumps({"error": "No role assignments found."}) + "\n"
            return

        privileges, can_read_secrets, can_read_certs, can_read_keys = get_keyvault_privileges(role_assignments)
        total_vaults = sum(len(get_keyvaults(sub)) for sub in subscriptions)
        
        # Check if there are any key vaults to scan
        if total_vaults == 0:
            yield json.dumps({"error": "No key vaults found in any subscription."}) + "\n"
            return
        
        total_findings = 0
        vaults_processed = 0
        start_time = time.time()

        for subscription in subscriptions:
            vaults = get_keyvaults(subscription)
            sub_results = {}

            for vault in vaults:
                vaults_processed += 1
                vault_name = vault["name"]
                resource_group = vault["resourceGroup"]
                findings = f"Findings for Key Vault: {vault_name}\n"
                vault_data = {
                    "resource_group": resource_group,
                    "privileges": {
                        "can_read_secrets": can_read_secrets,
                        "can_read_certs": can_read_certs,
                        "can_read_keys": can_read_keys
                    },
                    "assets": {},
                    "rbac_warning": None
                }

                findings += "   Access Privileges:\n"
                findings += f"      - Can read secrets: {'Yes' if can_read_secrets else 'No'}\n"
                findings += f"      - Can read certificates: {'Yes' if can_read_certs else 'No'}\n"
                findings += f"      - Can read keys: {'Yes' if can_read_keys else 'No'}\n"

                assets, rbac_warning = access_keyvault(vault_name, resource_group, subscription, can_read_secrets, can_read_certs, can_read_keys)
                vault_data["assets"] = assets
                vault_data["rbac_warning"] = rbac_warning

                # Collect all findings for database storage
                all_findings = []
                all_findings.append(f"Can read secrets: {'Yes' if can_read_secrets else 'No'}")
                all_findings.append(f"Can read certificates: {'Yes' if can_read_certs else 'No'}")
                all_findings.append(f"Can read keys: {'Yes' if can_read_keys else 'No'}")

                if assets:
                    for asset_type, items in assets.items():
                        findings += f"   {asset_type.capitalize()}:\n"
                        for name, value in items.items():
                            findings += f"      - {name}: {value}\n"
                            all_findings.append(f"Accessible {asset_type}: {name} = {value}")
                else:
                    findings += "   Accessible Assets: None found\n"
                    all_findings.append("Accessible Assets: None found")

                if rbac_warning:
                    findings += f"   Warning: {rbac_warning}\n"
                    all_findings.append(f"Warning: {rbac_warning}")

                # Save detailed Key Vault results to database
                save_detailed_scan_results(
                    subscription_id=subscription,
                    service_type="Key Vault",
                    service_name=vault_name,
                    resource_group=resource_group,
                    resource_name=vault_name,
                    resource_state="Active",
                    resource_type="Key Vault",
                    findings_json=json.dumps(all_findings)
                )

                # Save to visualization database only if there are actual vulnerabilities
                if assets or (can_read_secrets or can_read_certs or can_read_keys):
                    save_visual_detailed_scan_results(
                        subscription_id=subscription,
                        service_type="Key Vault",
                        service_name=vault_name,
                        resource_group=resource_group,
                        resource_name=vault_name,
                        resource_state="Active",
                        resource_type="Key Vault",
                        findings_json=json.dumps(all_findings)
                    )

                # Save individual vulnerabilities to visualization database
                if can_read_secrets:
                    save_vulnerability_findings(
                        subscription_id=subscription,
                        service_type="Key Vault",
                        service_name=vault_name,
                        resource_group=resource_group,
                        vulnerability_title="Excessive Access Privileges: Secrets Read Access",
                        category="Access Privileges",
                        description=f"User has read access to secrets in Key Vault '{vault_name}' in resource group '{resource_group}'",
                        code_snippet="Can read secret values",
                        recommendation="Review and limit secret access permissions. Use principle of least privilege and consider using Azure Key Vault access policies or RBAC for fine-grained control."
                    )

                if can_read_certs:
                    save_vulnerability_findings(
                        subscription_id=subscription,
                        service_type="Key Vault",
                        service_name=vault_name,
                        resource_group=resource_group,
                        vulnerability_title="Excessive Access Privileges: Certificates Read Access",
                        category="Access Privileges",
                        description=f"User has read access to certificates in Key Vault '{vault_name}' in resource group '{resource_group}'",
                        code_snippet="Can read certificate values",
                        recommendation="Review and limit certificate access permissions. Use principle of least privilege and consider using Azure Key Vault access policies or RBAC for fine-grained control."
                    )

                if can_read_keys:
                    save_vulnerability_findings(
                        subscription_id=subscription,
                        service_type="Key Vault",
                        service_name=vault_name,
                        resource_group=resource_group,
                        vulnerability_title="Excessive Access Privileges: Keys Read Access",
                        category="Access Privileges",
                        description=f"User has read access to keys in Key Vault '{vault_name}' in resource group '{resource_group}'",
                        code_snippet="Can read key values",
                        recommendation="Review and limit key access permissions. Use principle of least privilege and consider using Azure Key Vault access policies or RBAC for fine-grained control."
                    )

                if assets:
                    for asset_type, asset_list in assets.items():
                        if asset_list and isinstance(asset_list, list):
                            # Convert to list of strings for safe joining
                            asset_strings = [str(asset) for asset in asset_list]
                            save_vulnerability_findings(
                                subscription_id=subscription,
                                service_type="Key Vault",
                                service_name=vault_name,
                                resource_group=resource_group,
                                vulnerability_title=f"Accessible Assets: {asset_type.title()}",
                                category="Accessible Assets",
                                description=f"Found {len(asset_list)} accessible {asset_type} in Key Vault '{vault_name}' in resource group '{resource_group}'",
                                code_snippet=f"Accessible {asset_type}: {', '.join(asset_strings[:5])}{'...' if len(asset_strings) > 5 else ''}",
                                recommendation="Review accessible assets and ensure they are necessary. Consider removing unused or unnecessary assets to reduce attack surface."
                            )

                sub_results[vault_name] = vault_data
                if assets or rbac_warning or (can_read_secrets or can_read_certs or can_read_keys):
                    write_findings("keyvault", subscription, vault_name + ".txt", findings)
                    total_findings += 1

                yield json.dumps({
                    "type": "vault",
                    "subscription": subscription,
                    "vault": {vault_name: vault_data},
                    "progress": {
                        "vaults_processed": vaults_processed,
                        "total_vaults": total_vaults,
                        "percentage": round((vaults_processed / total_vaults) * 100, 2)
                    }
                }) + "\n"

            if sub_results:
                yield json.dumps({"type": "subscription_complete", "subscription": subscription, "vaults": sub_results}) + "\n"

        elapsed_time = time.time() - start_time
        yield json.dumps({
            "type": "summary",
            "total_subs": len(subscriptions),
            "total_vaults": total_vaults,
            "total_findings": total_findings,
            "elapsed_time": round(elapsed_time, 2)
        }) + "\n"

    def get_subscriptions():
        return json.loads(run_az_command("az account list --query '[].{id:id, name:name}' -o json") or "[]")

    def get_total_keyvaults():
        subscriptions = get_subscriptions()
        return sum(len(get_keyvaults(sub["id"])) for sub in subscriptions)

    # Routes
    @app.route('/key_vaults')
    def key_vaults():
        # Render immediately with placeholder count, fetch real count asynchronously
        return render_template('key_vaults.html', total_vaults=0)

    @app.route('/get_total_keyvaults')
    def get_total_keyvaults_endpoint():
        try:
            total_vaults = get_total_keyvaults()
            return jsonify({'total_vaults': total_vaults})
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/scan_keyvaults_stream')
    def scan_keyvaults_stream():
        subscriptions = [sub["id"] for sub in get_subscriptions()]
        def generate():
            for update in analyze_keyvaults_stream(subscriptions):
                yield f"data: {update}\n\n"
        return Response(generate(), mimetype='text/event-stream')

    @app.route('/export_keyvaults', methods=['POST'])
    def export_keyvaults():
        try:
            results = request.get_json()
            
            # Generate beautiful HTML report
            from utils.report_utils import generate_html_report, save_html_report
            
            html_content = generate_html_report("Key Vaults", results)
            filepath, filename = save_html_report(html_content, "Key Vaults")
            
            return jsonify({
                "status": "success", 
                "message": f"HTML report generated successfully: {filename}",
                "filename": filename,
                "filepath": filepath
            })
        except Exception as e:
            print(f"Error generating HTML report: {e}")
            # Fallback to text export
            try:
                with open("keyvault_audit_summary.txt", "w") as f:
                    for sub_id, vaults in results["subscriptions"].items():
                        f.write(f"\nSubscription: {sub_id}\n")
                        for vault_name, vault_data in vaults.items():
                            f.write(f"  Key Vault: {vault_name}\n")
                            f.write("    Access Privileges:\n")
                            f.write(f"      - Can read secrets: {'Yes' if vault_data['privileges']['can_read_secrets'] else 'No'}\n")
                            f.write(f"      - Can read certificates: {'Yes' if vault_data['privileges']['can_read_certs'] else 'No'}\n")
                            f.write(f"      - Can read keys: {'Yes' if vault_data['privileges']['can_read_keys'] else 'No'}\n")
                            if vault_data["assets"]:
                                for asset_type, items in vault_data["assets"].items():
                                    f.write(f"    {asset_type.capitalize()}:\n")
                                    for name, value in items.items():
                                        f.write(f"      - {name}: {value}\n")
                            else:
                                f.write("    Accessible Assets: None found\n")
                            if vault_data["rbac_warning"]:
                                f.write(f"    Warning: {vault_data['rbac_warning']}\n")
                    f.write("\nSummary:\n")
                    f.write(f"  Subscriptions Analyzed: {results['total_subs']}\n")
                    f.write(f"  Key Vaults Processed: {results['total_vaults']}\n")
                    f.write(f"  Key Vaults with Findings: {results['total_findings']}\n")
                    f.write(f"  Time Taken: {results['elapsed_time']} seconds\n")
                return jsonify({"status": "success", "message": "Text report exported successfully (HTML generation failed)"})
            except Exception as e2:
                return jsonify({"status": "error", "message": f"Both HTML and text export failed: {str(e2)}"}), 500

    return {
        "get_total_keyvaults": get_total_keyvaults
    }
