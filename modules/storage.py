import subprocess
import json
import os
import time
from flask import Flask, Response, render_template, request, jsonify
from utils.output_utils import write_findings

def register_routes(app):
    def get_subscriptions():
        output = subprocess.run("az account list --query '[].id' -o json", shell=True, capture_output=True, text=True, timeout=30)
        return json.loads(output.stdout) if output.returncode == 0 and output.stdout else []

    def get_storage_accounts(subscription):
        output = subprocess.run(
            f"az storage account list --subscription {subscription} --query '[].{{name:name, resourceGroup:resourceGroup}}' -o json",
            shell=True, capture_output=True, text=True, timeout=60
        )
        return json.loads(output.stdout) if output.returncode == 0 and output.stdout else []

    def get_access_token(resource="https://management.azure.com"):
        output = subprocess.run(
            f"az account get-access-token --resource {resource} --query accessToken -o tsv",
            shell=True, capture_output=True, text=True, timeout=10
        )
        return output.stdout.strip() if output.returncode == 0 and output.stdout else None

    def list_containers(subscription, account, resource_group, token):
        url = f"https://management.azure.com/subscriptions/{subscription}/resourceGroups/{resource_group}/providers/Microsoft.Storage/storageAccounts/{account}/blobServices/default/containers?api-version=2023-01-01"
        command = f"curl -s -X GET '{url}' -H 'Authorization: Bearer {token}' -H 'Content-Type: application/json'"
        #print(command)
        output = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
        if output.returncode == 0 and output.stdout:
            data = json.loads(output.stdout)
            return data.get("value", []) if "error" not in data else []
        return []

    def check_blob_access(account, container, token):
        url = f"https://{account}.blob.core.windows.net/{container}?restype=container&comp=list"
        command = f"curl -s -X GET '{url}' -H 'Authorization: Bearer {token}' -H 'x-ms-version: 2022-11-02'"
        output = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
        if output.returncode == 0:
            stdout = output.stdout.strip()
            if "EnumerationResults" in stdout:
                return "Access Granted" if "<Blob>" in stdout else "No Blobs Found"
            return "Access Denied"
        return "Error"

    def list_queues(subscription, account, resource_group, token):
        url = f"https://management.azure.com/subscriptions/{subscription}/resourceGroups/{resource_group}/providers/Microsoft.Storage/storageAccounts/{account}/queueServices/default/queues?api-version=2023-05-01"
        command = f"curl -s -X GET '{url}' -H 'Authorization: Bearer {token}' -H 'Content-Type: application/json'"
        output = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
        if output.returncode == 0 and output.stdout:
            data = json.loads(output.stdout)
            return data.get("value", []) if "error" not in data else []
        return []

    def check_queue_access(account, queue, token):
        url = f"https://{account}.queue.core.windows.net/{queue}/messages?peekonly=true"
        command = f"curl -s -X GET '{url}' -H 'Authorization: Bearer {token}' -H 'x-ms-version: 2022-11-02'"
        print(command)
        output = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
        if output.returncode == 0:
            stdout = output.stdout.strip()
            if "DequeueCount" in stdout:
                return "Access Granted" if "<QueueMessage>" in stdout else "No Messages Found"
            return "Access Denied"
        return "Error"

    def list_tables(subscription, account, resource_group, token):
        url = f"https://management.azure.com/subscriptions/{subscription}/resourceGroups/{resource_group}/providers/Microsoft.Storage/storageAccounts/{account}/tableServices/default/tables?api-version=2023-05-01"
        command = f"curl -s -X GET '{url}' -H 'Authorization: Bearer {token}' -H 'Content-Type: application/json'"
        output = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
        if output.returncode == 0 and output.stdout:
            data = json.loads(output.stdout)
            return data.get("value", []) if "error" not in data else []
        return []

    def check_table_access(account, table, token):
        url = f"https://{account}.table.core.windows.net/{table}()"
        command = f"curl -s -X GET '{url}' -H 'Authorization: Bearer {token}' -H 'x-ms-version: 2022-11-02'"
        output = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
        if output.returncode == 0:
            stdout = output.stdout.strip()
            if f"<title type=\"text\">{table}</title>" in stdout:
                return "Access Granted" if "PartitionKey" in stdout or "RowKey" in stdout else "No Entities Found"
            return "Access Denied"
        return "Error"

    def list_file_shares(subscription, account, resource_group, token):
        url = f"https://management.azure.com/subscriptions/{subscription}/resourceGroups/{resource_group}/providers/Microsoft.Storage/storageAccounts/{account}/fileServices/default/shares?api-version=2023-01-01"
        command = f"curl -s -X GET '{url}' -H 'Authorization: Bearer {token}' -H 'Content-Type: application/json'"
        output = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
        if output.returncode == 0 and output.stdout:
            data = json.loads(output.stdout)
            return data.get("value", []) if "error" not in data else []
        return []

    def check_file_access(account, share, token):
        url = f"https://{account}.file.core.windows.net/{share}?restype=directory&comp=list"
        command = f"curl -s -X GET '{url}' -H 'Authorization: Bearer {token}' -H 'x-ms-version: 2022-11-02' -H 'x-ms-file-request-intent: backup'"
        output = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
        if output.returncode == 0:
            stdout = output.stdout.strip()
            if "EnumerationResults" in stdout and f"ShareName=\"{share}\"" in stdout:
                return "Access Granted" if "Content-Length" in stdout else "No Files Found"
            return "Access Denied"
        return "Error"

    def audit_storage_accounts_stream(subscription, output_dir, management_token, storage_token):
        from app import save_detailed_scan_results  # Lazy import inside the function
        from visualization_db import save_vulnerability_findings, save_detailed_scan_results as save_visual_detailed_scan_results  # Lazy import inside the function
        
        accounts = get_storage_accounts(subscription)
        total_accounts = len(accounts)
        for acct_idx, account in enumerate(accounts, 1):
            name = account["name"]
            resource_group = account["resourceGroup"]
            file_content = f"Storage Account: {name}\n"
            has_access_granted = False

            account_data = {
                "name": name,
                "resource_group": resource_group,
                "containers": {},
                "queues": {},
                "tables": {},
                "file_shares": {}
            }

            containers = list_containers(subscription, name, resource_group, management_token)
            if containers:
                findings = []
                for container in containers[:5]:
                    result = check_blob_access(name, container["name"], storage_token)
                    account_data["containers"][container["name"]] = {"access": result}
                    if result == "Access Granted":
                        findings.append(f"      Container: {container['name']} - {result}")
                        has_access_granted = True
                if findings:
                    file_content += "   Containers:\n" + "\n".join(findings) + "\n"
            else:
                file_content += "   Containers: No containers found\n"

            queues = list_queues(subscription, name, resource_group, management_token)
            if queues:
                findings = []
                for queue in queues[:5]:
                    result = check_queue_access(name, queue["name"], storage_token)
                    account_data["queues"][queue["name"]] = {"access": result}
                    if result == "Access Granted":
                        findings.append(f"      Queue: {queue['name']} - {result}")
                        has_access_granted = True
                if findings:
                    file_content += "   Queues:\n" + "\n".join(findings) + "\n"
            else:
                file_content += "   Queues: No queues found\n"

            tables = list_tables(subscription, name, resource_group, management_token)
            if tables:
                findings = []
                for table in tables[:5]:
                    result = check_table_access(name, table["name"], storage_token)
                    account_data["tables"][table["name"]] = {"access": result}
                    if result == "Access Granted":
                        findings.append(f"      Table: {table['name']} - {result}")
                        has_access_granted = True
                if findings:
                    file_content += "   Tables:\n" + "\n".join(findings) + "\n"
            else:
                file_content += "   Tables: No tables found\n"

            shares = list_file_shares(subscription, name, resource_group, management_token)
            if shares:
                findings = []
                for share in shares[:5]:
                    result = check_file_access(name, share["name"], storage_token)
                    account_data["file_shares"][share["name"]] = {"access": result}
                    if result == "Access Granted":
                        findings.append(f"      File Share: {share['name']} - {result}")
                        has_access_granted = True
                if findings:
                    file_content += "   File Shares:\n" + "\n".join(findings) + "\n"
            else:
                file_content += "   File Shares: No file shares found\n"

            all_findings = []
            if account_data["containers"]:
                for container_name, container_data in account_data["containers"].items():
                    if container_data["access"] == "Access Granted":
                        all_findings.append(f"Container Access: {container_name} - {container_data['access']}")
            if account_data["queues"]:
                for queue_name, queue_data in account_data["queues"].items():
                    if queue_data["access"] == "Access Granted":
                        all_findings.append(f"Queue Access: {queue_name} - {queue_data['access']}")
            if account_data["tables"]:
                for table_name, table_data in account_data["tables"].items():
                    if table_data["access"] == "Access Granted":
                        all_findings.append(f"Table Access: {table_name} - {table_data['access']}")
            if account_data["file_shares"]:
                for share_name, share_data in account_data["file_shares"].items():
                    if share_data["access"] == "Access Granted":
                        all_findings.append(f"File Share Access: {share_name} - {share_data['access']}")
            
            # If no access granted, add a note
            if not all_findings:
                all_findings.append("No access granted to storage resources")

            # Save detailed Storage Account results to database
            save_detailed_scan_results(
                subscription_id=subscription,
                service_type="Storage Account",
                service_name=name,
                resource_group=resource_group,
                resource_name=name,
                resource_state="Active",
                resource_type="Storage Account",
                findings_json=json.dumps(all_findings)
            )

            # Save to visualization database only if there are actual vulnerabilities
            if has_access_granted:
                save_visual_detailed_scan_results(
                    subscription_id=subscription,
                    service_type="Storage Account",
                    service_name=name,
                    resource_group=resource_group,
                    resource_name=name,
                    resource_state="Active",
                    resource_type="Storage Account",
                    findings_json=json.dumps(all_findings)
                )

            # Save individual vulnerabilities to visualization database
            if has_access_granted:
                # Container access vulnerabilities
                for container_name, container_data in account_data.get("containers", {}).items():
                    if container_data.get("access") == "Access Granted":
                        save_vulnerability_findings(
                            subscription_id=subscription,
                            service_type="Storage Account",
                            service_name=name,
                            resource_group=resource_group,
                            vulnerability_title=f"Container Access Granted: {container_name}",
                            category="Access Granted",
                            description=f"Container '{container_name}' in Storage Account '{name}' has {container_data.get('access', 'Unknown')} access",
                            code_snippet=f"Container: {container_name}, Access: {container_data.get('access', 'Unknown')}",
                            recommendation="Review container access permissions. Ensure containers with sensitive data are set to private access. Use Azure Storage access policies for fine-grained control."
                        )

                # File share access vulnerabilities
                for share_name, share_data in account_data.get("file_shares", {}).items():
                    if share_data.get("access") == "Access Granted":
                        save_vulnerability_findings(
                            subscription_id=subscription,
                            service_type="Storage Account",
                            service_name=name,
                            resource_group=resource_group,
                            vulnerability_title=f"File Share Access Granted: {share_name}",
                            category="Access Granted",
                            description=f"File Share '{share_name}' in Storage Account '{name}' has {share_data.get('access', 'Unknown')} access",
                            code_snippet=f"File Share: {share_name}, Access: {share_data.get('access', 'Unknown')}",
                            recommendation="Review file share access permissions. Ensure file shares with sensitive data are set to private access. Use Azure Storage access policies for fine-grained control."
                        )

            if has_access_granted:
                write_findings("storage", subscription, f"{name}.txt", file_content)

            yield json.dumps({
                "type": "account",
                "subscription": subscription,
                "account": {name: account_data},
                "progress": {
                    "accounts_processed": acct_idx,
                    "total_accounts": total_accounts,
                    "percentage": round((acct_idx / total_accounts) * 100, 2) if total_accounts > 0 else 100
                }
            }) + "\n"

    def analyze_storage_stream(subscriptions):
        from app import save_scan_result, save_detailed_scan_results  # Lazy import inside the function
        from visualization_db import save_vulnerability_findings, save_detailed_scan_results as save_visual_detailed_scan_results  # Lazy import inside the function
        
        output_dir = "results/storage"
        os.makedirs(output_dir, exist_ok=True)

        total_storage_accounts = sum(len(get_storage_accounts(sub)) for sub in subscriptions)
        
        # Check if there are any storage accounts to scan
        if total_storage_accounts == 0:
            yield json.dumps({"error": "No storage accounts found in any subscription."}) + "\n"
            return
        
        total_access_granted = 0
        accounts_processed = 0
        start_time = time.time()

        management_token = get_access_token("https://management.azure.com")
        storage_token = get_access_token("https://storage.azure.com")
        if not management_token or not storage_token:
            yield json.dumps({"error": "Unable to get access tokens. Run 'az login'."}) + "\n"
            return

        for subscription in subscriptions:
            for update in audit_storage_accounts_stream(subscription, output_dir, management_token, storage_token):
                data = json.loads(update.strip())
                accounts_processed = data["progress"]["accounts_processed"]
                # Only check the nested dictionaries (containers, queues, tables, file_shares) for "access"
                account_data = list(data["account"].values())[0]  # Get the inner account data
                categories_to_check = ["containers", "queues", "tables", "file_shares"]
                has_access = False
                for category in categories_to_check:
                    if category in account_data:
                        for item in account_data[category].values():
                            if isinstance(item, dict) and item.get("access") == "Access Granted":
                                has_access = True
                                break
                    if has_access:
                        break
                if has_access:
                    total_access_granted += 1
                yield update

        elapsed_time = time.time() - start_time
        yield json.dumps({
            "type": "summary",
            "total_subs": len(subscriptions),
            "total_storage_accounts": total_storage_accounts,
            "total_access_granted": total_access_granted,
            "elapsed_time": round(elapsed_time, 2)
        }) + "\n"

    def get_total_storage_accounts():
        return sum(len(get_storage_accounts(sub)) for sub in get_subscriptions())

    # Routes
    @app.route('/storage_accounts')
    def storage_accounts():
        # Render immediately with placeholder count, fetch real count asynchronously
        return render_template('storage_accounts.html', total_storage_accounts=0)

    @app.route('/get_total_storage_accounts')
    def get_total_storage_accounts_endpoint():
        try:
            total_storage_accounts = get_total_storage_accounts()
            return jsonify({'total_storage_accounts': total_storage_accounts})
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/scan_storage_stream')
    def scan_storage_stream():
        subscriptions = get_subscriptions()
        def generate():
            for update in analyze_storage_stream(subscriptions):
                yield f"data: {update}\n\n"
        return Response(generate(), mimetype='text/event-stream')

    @app.route('/export_storage', methods=['POST'])
    def export_storage():
        try:
            results = request.get_json()
            
            # Generate beautiful HTML report
            from utils.report_utils import generate_html_report, save_html_report
            
            html_content = generate_html_report("Storage Accounts", results)
            filepath, filename = save_html_report(html_content, "Storage Accounts")
            
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
                with open("storage_audit_summary.txt", "w") as f:
                    for sub_id, accounts in results["subscriptions"].items():
                        f.write(f"\nSubscription: {sub_id}\n")
                        for acct_name, acct_data in accounts.items():
                            f.write(f"  Storage Account: {acct_name}\n")
                            f.write(f"    Resource Group: {acct_data['resource_group']}\n")
                            for category, items in acct_data.items():
                                if category in ["containers", "queues", "tables", "file_shares"]:
                                    if items:
                                        f.write(f"    {category.capitalize()}:\n")
                                        for name, info in items.items():
                                            f.write(f"      - {name}: {info['access']}\n")
                                    else:
                                        f.write(f"    {category.capitalize()}: None found\n")
                    f.write("\nSummary:\n")
                    f.write(f"  Subscriptions Analyzed: {results['total_subs']}\n")
                    f.write(f"  Storage Accounts Processed: {results['total_storage_accounts']}\n")
                    f.write(f"  Storage Accounts with Access Granted: {results['total_access_granted']}\n")
                    f.write(f"  Time Taken: {results['elapsed_time']} seconds\n")
                return jsonify({"status": "success", "message": "Text report exported successfully (HTML generation failed)"})
            except Exception as e2:
                return jsonify({"status": "error", "message": f"Both HTML and text export failed: {str(e2)}"}), 500
