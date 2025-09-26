import json
import os
import base64
import re
import time
from utils.az_cli_utils import run_az_command, get_access_token
from utils.output_utils import write_findings

def get_automation_accounts(subscription):
    """
    Fetch all automation accounts in the given subscription.
    """
    try:
        output = run_az_command(
            f"az automation account list --subscription {subscription} --query '[].{{name:name, resourceGroup:resourceGroup}}' -o json",
            timeout=60
        )
        return json.loads(output) if output else []
    except Exception as e:
        print(f"Error fetching automation accounts for subscription {subscription}: {e}")
        return []

def list_runbooks(subscription, account, resource_group, token):
    """
    List all runbooks for a given automation account.
    """
    url = f"https://management.azure.com/subscriptions/{subscription}/resourceGroups/{resource_group}/providers/Microsoft.Automation/automationAccounts/{account}/runbooks?api-version=2022-06-30-preview"
    try:
        result = run_az_command(
            f"curl -s -X GET '{url}' -H 'Authorization: Bearer {token}' -H 'Content-Type: application/json'",
            timeout=30
        )
        if result:
            data = json.loads(result)
            return data.get("value", []) if "error" not in data else f"{data['error']['code']} - {data['error']['message']}"
        return "Unknown Error"
    except Exception as e:
        print(f"Error listing runbooks for account {account}: {e}")
        return "Unknown Error"

def get_runbook_content(subscription, account, resource_group, runbook, state, runbook_type, token):
    """
    Fetch the content of a runbook (published or draft).
    """
    content_results = {}
    base_url = f"https://management.azure.com/subscriptions/{subscription}/resourceGroups/{resource_group}/providers/Microsoft.Automation/automationAccounts/{account}/runbooks/{runbook}"
    
    try:
        if state in ["Published", "Edit"]:
            published_url = f"{base_url}/content?api-version=2015-10-31"
            result = run_az_command(
                f"curl -s -X GET '{published_url}' -H 'Authorization: Bearer {token}' -H 'Content-Type: application/json'",
                timeout=30
            )
            if result:
                if runbook_type == "GraphPowerShell":
                    try:
                        data = json.loads(result)
                        content_results["published"] = base64.b64decode(data.get("RunbookDefinition", "")).decode('utf-8', errors='ignore') if "RunbookDefinition" in data else "Error: No RunbookDefinition in JSON"
                    except json.JSONDecodeError:
                        content_results["published"] = "Error: Expected JSON but got invalid format"
                else:
                    content_results["published"] = result

        if state in ["New", "Edit"]:
            draft_url = f"{base_url}/draft/content?api-version=2015-10-31"
            result = run_az_command(
                f"curl -s -X GET '{draft_url}' -H 'Authorization: Bearer {token}' -H 'Content-Type: application/json'",
                timeout=30
            )
            if result:
                if runbook_type == "GraphPowerShell":
                    try:
                        data = json.loads(result)
                        content_results["draft"] = base64.b64decode(data.get("RunbookDefinition", "")).decode('utf-8', errors='ignore') if "RunbookDefinition" in data else "Error: No RunbookDefinition in JSON"
                    except json.JSONDecodeError:
                        content_results["draft"] = "Error: Expected JSON but got invalid format"
                else:
                    content_results["draft"] = result

        return content_results if content_results else {"error": f"Unsupported state: {state}"}
    except Exception as e:
        print(f"Error fetching runbook content for {runbook}: {e}")
        return {"error": str(e)}

def search_sensitive_data(content):
    """
    Search for sensitive data in runbook content.
    """
    findings = []
    keywords = ["pass", "password", "client_id", "client_secret"]
    for keyword in keywords:
        if keyword in content.lower():
            for i, line in enumerate(content.splitlines()):
                if keyword in line.lower():
                    findings.append(f"Potential sensitive data '{keyword}' in line {i+1}: {line.strip()}")
    guid_pattern = r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
    for guid in re.findall(guid_pattern, content):
        findings.append(f"Subscription GUID found: {guid}")
    return findings

def analyze_automation_stream(subscriptions):
    """
    Analyze automation accounts across all subscriptions using a streaming approach.
    """
    from app import save_scan_result, save_detailed_scan_results  # Lazy import inside the function
    from visualization_db import save_vulnerability_findings, save_detailed_scan_results as save_visual_detailed_scan_results  # Lazy import inside the function

    output_dir = "results/automation"
    os.makedirs(output_dir, exist_ok=True)

    token = get_access_token()
    if not token:
        yield json.dumps({"error": "Unable to get access token."}) + "\n"
        return

    total_accounts = sum(len(get_automation_accounts(sub)) for sub in subscriptions)
    
    # Check if there are any automation accounts to scan
    if total_accounts == 0:
        yield json.dumps({"error": "No automation accounts found in any subscription."}) + "\n"
        return
    
    total_findings = 0
    accounts_processed = 0
    start_time = time.time()

    for subscription in subscriptions:
        accounts = get_automation_accounts(subscription)
        sub_results = {}

        for account in accounts:
            accounts_processed += 1
            name = account["name"]
            resource_group = account["resourceGroup"]
            findings = f"Findings for Automation Account: {name}\n"
            account_data = {
                "resource_group": resource_group,
                "runbooks": {},
                "sensitive_data": []
            }

            # Runbooks
            runbooks = list_runbooks(subscription, name, resource_group, token)
            if not isinstance(runbooks, list):
                account_data["runbooks"]["error"] = runbooks
                findings += f"   Runbooks: {runbooks}\n"
            elif not runbooks:
                account_data["runbooks"]["none"] = "No Runbooks found"
                findings += "   Runbooks: No Runbooks found\n"
            else:
                for runbook in runbooks:
                    runbook_name = runbook["name"]
                    state = runbook.get("properties", {}).get("state", "Unknown")
                    runbook_type = runbook.get("properties", {}).get("runbookType", "Unknown")
                    runbook_data = {"state": state, "type": runbook_type, "sensitive_data": []}

                    content_results = get_runbook_content(subscription, name, resource_group, runbook_name, state, runbook_type, token)
                    if "error" in content_results:
                        runbook_data["error"] = content_results["error"]
                        findings += f"   Runbook: {runbook_name} - {content_results['error']}\n"
                        
                        # Save error to database
                        save_detailed_scan_results(
                            subscription_id=subscription,
                            service_type="Automation Account",
                            service_name=name,
                            resource_group=resource_group,
                            resource_name=runbook_name,
                            resource_state=state,
                            resource_type=runbook_type,
                            findings_json=json.dumps([f"Error: {content_results['error']}"])
                        )
                    else:
                        all_runbook_findings = []
                        for content_type, content in content_results.items():
                            if content.startswith("Error"):
                                runbook_data[content_type] = content
                                findings += f"   Runbook: {runbook_name} ({content_type}) - {content}\n"
                                all_runbook_findings.append(f"Error: {content}")
                            else:
                                sensitive_data = search_sensitive_data(content)
                                if sensitive_data:
                                    runbook_data["sensitive_data"].extend(sensitive_data)
                                    account_data["sensitive_data"].extend(sensitive_data)
                                    all_runbook_findings.extend(sensitive_data)
                                findings += f"   Runbook: {runbook_name} (State: {state}, Type: {runbook_type})\n"
                                if sensitive_data:
                                    for idx, finding in enumerate(sensitive_data, 1):
                                        findings += f"      - {finding}\n"
                                else:
                                    findings += "      - No Sensitive Data Found\n"
                                    all_runbook_findings.append("No Sensitive Data Found")
                        
                        # Save detailed runbook results to database
                        save_detailed_scan_results(
                            subscription_id=subscription,
                            service_type="Automation Account",
                            service_name=name,
                            resource_group=resource_group,
                            resource_name=runbook_name,
                            resource_state=state,
                            resource_type=runbook_type,
                            findings_json=json.dumps(all_runbook_findings)
                        )

                        # Save to visualization database only if there are actual vulnerabilities
                        if sensitive_data:
                            save_visual_detailed_scan_results(
                                subscription_id=subscription,
                                service_type="Automation Account",
                                service_name=name,
                                resource_group=resource_group,
                                resource_name=runbook_name,
                                resource_state=state,
                                resource_type=runbook_type,
                                findings_json=json.dumps(all_runbook_findings)
                            )

                        # Save individual vulnerabilities to visualization database
                        if sensitive_data:
                            for idx, finding in enumerate(sensitive_data, 1):
                                save_vulnerability_findings(
                                    subscription_id=subscription,
                                    service_type="Automation Account",
                                    service_name=name,
                                    resource_group=resource_group,
                                    vulnerability_title=f"Sensitive Data in Runbook: {runbook_name} (#{idx})",
                                    category="Sensitive Data",
                                    description=f"Sensitive information found in runbook '{runbook_name}' ({content_type}) in automation account '{name}': {finding}",
                                    code_snippet=finding,
                                    recommendation="Review and secure all sensitive data in runbooks. Remove hardcoded secrets, passwords, and other sensitive information. Use Azure Key Vault or secure parameter management."
                                )
                    account_data["runbooks"][runbook_name] = runbook_data

            sub_results[name] = account_data
            if account_data["sensitive_data"]:
                write_findings("automation", subscription, f"{name}.txt", findings)
                total_findings += 1

            yield json.dumps({
                "type": "account",
                "subscription": subscription,
                "account": {name: account_data},
                "progress": {
                    "accounts_processed": accounts_processed,
                    "total_accounts": total_accounts,
                    "percentage": round((accounts_processed / total_accounts) * 100, 2) if total_accounts > 0 else 0
                }
            }) + "\n"

        if sub_results:
            yield json.dumps({"type": "subscription_complete", "subscription": subscription, "accounts": sub_results}) + "\n"

    elapsed_time = time.time() - start_time
    yield json.dumps({
        "type": "summary",
        "total_subs": len(subscriptions),
        "total_accounts": total_accounts,
        "total_findings": total_findings,
        "elapsed_time": round(elapsed_time, 2)
    }) + "\n"

def get_total_automation_accounts():
    """
    Get the total number of automation accounts across all subscriptions.
    """
    from app import get_subscriptions  # Lazy import
    subscriptions = get_subscriptions()
    return sum(len(get_automation_accounts(sub["id"])) for sub in subscriptions)

def register_routes(app):
    """
    Register routes for automation account scanning.
    """
    from flask import render_template, request, jsonify, Response  # Import here to avoid circular imports
    from app import get_subscriptions, save_scan_result  # Lazy import inside the function

    @app.route('/automation', methods=['GET'], endpoint='automation_page')
    def automation():
        # Render immediately with placeholder count, fetch real count asynchronously
        return render_template('automation.html', total_accounts=0)

    @app.route('/get_total_automation_accounts')
    def get_total_automation_accounts_endpoint():
        try:
            total_accounts = get_total_automation_accounts()
            return jsonify({'total_accounts': total_accounts})
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/scan_automation_stream', methods=['GET'], endpoint='scan_automation_stream')
    def scan_automation_stream():
        subscriptions = get_subscriptions()
        subscriptions = [sub["id"] for sub in subscriptions]
        def generate():
            for update in analyze_automation_stream(subscriptions):
                yield f"data: {update}\n\n"
        return Response(generate(), mimetype='text/event-stream')

    @app.route('/export_automation', methods=['POST'], endpoint='export_automation_endpoint')
    def export_automation():
        try:
            results = request.get_json()
            
            # Generate beautiful HTML report
            from utils.report_utils import generate_html_report, save_html_report
            
            html_content = generate_html_report("Automation Accounts", results)
            filepath, filename = save_html_report(html_content, "Automation Accounts")
            
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
                with open("automation_audit_summary.txt", "w") as f:
                    for sub_id, accounts in results["subscriptions"].items():
                        f.write(f"\nSubscription: {sub_id}\n")
                        for account_name, account_data in accounts.items():
                            f.write(f"  Automation Account: {account_name}\n")
                            f.write(f"    Resource Group: {account_data['resource_group']}\n")
                            if "runbooks" in account_data:
                                f.write("    Runbooks:\n")
                                for runbook_name, runbook_data in account_data["runbooks"].items():
                                    if "error" in runbook_data:
                                        f.write(f"      - {runbook_name}: {runbook_data['error']}\n")
                                    elif "none" in runbook_data:
                                        f.write(f"      - {runbook_data['none']}\n")
                                    else:
                                        f.write(f"      - {runbook_name} (State: {runbook_data['state']}, Type: {runbook_data['type']})\n")
                                        if runbook_data.get("sensitive_data"):
                                            for finding in runbook_data["sensitive_data"]:
                                                f.write(f"        - {finding}\n")
                                        else:
                                            f.write("        - No Sensitive Data Found\n")
                    f.write("\nSummary:\n")
                    f.write(f"  Subscriptions Analyzed: {results['total_subs']}\n")
                    f.write(f"  Automation Accounts Processed: {results['total_accounts']}\n")
                    f.write(f"  Automation Accounts with Findings: {results['total_findings']}\n")
                    f.write(f"  Time Taken: {results['elapsed_time']} seconds\n")
                return jsonify({"status": "success", "message": "Text report exported successfully (HTML generation failed)"})
            except Exception as e2:
                return jsonify({"status": "error", "message": f"Both HTML and text export failed: {str(e2)}"}), 500

    return {
        "get_total_automation_accounts": get_total_automation_accounts
    }
