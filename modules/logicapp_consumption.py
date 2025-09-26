import subprocess
import json
import os
import re
import random
from flask import Flask, Response, render_template, request, jsonify
from utils.output_utils import write_findings

def register_routes(app):
    def check_az_login():
        try:
            result = subprocess.run("az account show -o json", shell=True, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                return True
            else:
                print(f"check_az_login failed: {result.stderr}")
                return False
        except subprocess.TimeoutExpired:
            print("check_az_login timed out")
            return False
        except Exception as e:
            print(f"Error in check_az_login: {str(e)}")
            return False

    def get_subscriptions():
        try:
            command = "az account list --query '[].id' -o json"
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
            if result.returncode == 0 and result.stdout:
                return json.loads(result.stdout)
            else:
                print(f"get_subscriptions failed: {result.stderr}")
                return []
        except subprocess.TimeoutExpired:
            print("get_subscriptions timed out")
            return []
        except Exception as e:
            print(f"Error in get_subscriptions: {str(e)}")
            return []

    def get_consumption_logic_apps(subscription):
        try:
            command = f"az rest --method GET --uri '/subscriptions/{subscription}/providers/Microsoft.Logic/workflows?api-version=2016-06-01' -o json"
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=60)
            if result.returncode == 0 and result.stdout:
                data = json.loads(result.stdout)
                apps = [{"name": w["name"], "resourceGroup": w["id"].split('/')[4], "plan": "Consumption"} for w in data.get("value", [])]
                return apps
            else:
                print(f"get_consumption_logic_apps failed for subscription {subscription}: {result.stderr}")
                return []
        except subprocess.TimeoutExpired:
            print(f"get_consumption_logic_apps timed out for subscription {subscription}")
            return []
        except Exception as e:
            print(f"Error in get_consumption_logic_apps for subscription {subscription}: {str(e)}")
            return []

    def get_logic_app_definition(subscription, resource_group, logic_app):
        try:
            command = f"az logic workflow show --subscription {subscription} --resource-group {resource_group} --name {logic_app} -o json"
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
            if result.returncode == 0 and result.stdout:
                return json.loads(result.stdout)
            else:
                print(f"get_logic_app_definition failed for {logic_app}: {result.stderr}")
                return None
        except subprocess.TimeoutExpired:
            print(f"get_logic_app_definition timed out for {logic_app}")
            return None
        except Exception as e:
            print(f"Error in get_logic_app_definition for {logic_app}: {str(e)}")
            return None

    def get_logic_app_revisions(subscription, resource_group, logic_app):
        try:
            command = f"az rest --method GET --uri '/subscriptions/{subscription}/resourceGroups/{resource_group}/providers/Microsoft.Logic/workflows/{logic_app}/versions?api-version=2016-06-01' -o json"
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
            if result.returncode == 0 and result.stdout:
                revisions = json.loads(result.stdout).get("value", [])
                return [rev["name"] for rev in revisions]
            else:
                print(f"get_logic_app_revisions failed for {logic_app}: {result.stderr}")
                return []
        except subprocess.TimeoutExpired:
            print(f"get_logic_app_revisions timed out for {logic_app}")
            return []
        except Exception as e:
            print(f"Error in get_logic_app_revisions for {logic_app}: {str(e)}")
            return []

    def get_revision_code(subscription, resource_group, logic_app, revision):
        try:
            command = f"az rest --method GET --uri '/subscriptions/{subscription}/resourceGroups/{resource_group}/providers/Microsoft.Logic/workflows/{logic_app}/versions/{revision}?api-version=2016-06-01' -o json"
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
            if result.returncode == 0 and result.stdout:
                return json.loads(result.stdout)
            else:
                print(f"get_revision_code failed for revision {revision} in {logic_app}: {result.stderr}")
                return None
        except subprocess.TimeoutExpired:
            print(f"get_revision_code timed out for revision {revision} in {logic_app}")
            return None
        except Exception as e:
            print(f"Error in get_revision_code for revision {revision} in {logic_app}: {str(e)}")
            return None

    def get_run_history(subscription, resource_group, logic_app):
        try:
            command = f"az rest --method GET --uri '/subscriptions/{subscription}/resourceGroups/{resource_group}/providers/Microsoft.Logic/workflows/{logic_app}/runs?api-version=2016-06-01' -o json"
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
            if result.returncode == 0 and result.stdout:
                return json.loads(result.stdout).get("value", [])
            else:
                print(f"get_run_history failed for {logic_app}: {result.stderr}")
                return []
        except subprocess.TimeoutExpired:
            print(f"get_run_history timed out for {logic_app}")
            return []
        except Exception as e:
            print(f"Error in get_run_history for {logic_app}: {str(e)}")
            return []

    def get_run_actions(subscription, resource_group, logic_app, run_name):
        try:
            command = f"az rest --method GET --uri 'https://management.azure.com/subscriptions/{subscription}/resourceGroups/{resource_group}/providers/Microsoft.Logic/workflows/{logic_app}/runs/{run_name}/actions?api-version=2016-06-01' -o json"
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
            if result.returncode == 0 and result.stdout:
                return json.loads(result.stdout).get("value", [])
            else:
                print(f"get_run_actions failed for run {run_name} in {logic_app}: {result.stderr}")
                return []
        except subprocess.TimeoutExpired:
            print(f"get_run_actions timed out for run {run_name} in {logic_app}")
            return []
        except Exception as e:
            print(f"Error in get_run_actions for run {run_name} in {logic_app}: {str(e)}")
            return []

    def curl_action_uri(uri):
        try:
            curl_command = f"curl -s \"{uri}\""
            result = subprocess.run(curl_command, shell=True, capture_output=True, text=True, timeout=30)
            if result.returncode == 0 and result.stdout:
                try:
                    return json.loads(result.stdout)
                except json.JSONDecodeError:
                    return result.stdout
            else:
                print(f"curl_action_uri failed for URI {uri}: {result.stderr}")
                return None
        except subprocess.TimeoutExpired:
            print(f"curl_action_uri timed out for URI {uri}")
            return None
        except Exception as e:
            print(f"Error in curl_action_uri for URI {uri}: {str(e)}")
            return None

    def find_auth_blocks(data, source="code", findings=None):
        if findings is None:
            findings = []

        if isinstance(data, dict):
            auth_block = data.get("authentication")
            if (auth_block and 
                isinstance(auth_block, dict) and 
                auth_block.get("type") == "ActiveDirectoryOAuth" and 
                "tenant" in auth_block and 
                "clientId" in auth_block and 
                "secret" in auth_block):
                secret = auth_block["secret"]
                if (isinstance(secret, str) and 
                    ((secret.startswith('@appsetting(') and secret.endswith(')')) or 
                     (secret.startswith('@body(') and secret.endswith(')')) or 
                     (secret.startswith('@parameters(') and secret.endswith(')')) or 
                     (secret.startswith('@{body(') and ")?['value']}" in secret))):
                    return findings
                tenant = auth_block["tenant"]
                client_id = auth_block["clientId"]
                finding = (
                    f"Authentication block found in {source}: "
                    f"tenant={tenant}, clientId={client_id}, secret={secret}"
                )
                findings.append(finding)
            elif (data.get("Type") == "ActiveDirectoryOAuth" and 
                  "Tenant" in data and 
                  "ClientId" in data and 
                  "Secret" in data):
                secret = data["Secret"]
                if (isinstance(secret, str) and 
                    ((secret.startswith('@appsetting(') and secret.endswith(')')) or 
                     (secret.startswith('@body(') and secret.endswith(')')) or 
                     (secret.startswith('@parameters(') and secret.endswith(')')) or 
                     (secret.startswith('@{body(') and ")?['value']}" in secret))):
                    return findings
                tenant = data["Tenant"]
                client_id = data["ClientId"]
                finding = (
                    f"Flat ActiveDirectoryOAuth credentials found in {source}: "
                    f"tenant={tenant}, clientId={client_id}, secret={secret}"
                )
                findings.append(finding)
            
            for value in data.values():
                find_auth_blocks(value, source, findings)
        elif isinstance(data, list):
            for item in data:
                find_auth_blocks(item, source, findings)

        return findings

    def find_sensitive_info(data, source="code"):
        findings = []
        if not data:
            return findings

        if isinstance(data, dict):
            data_str = json.dumps(data)
            findings.extend(find_auth_blocks(data, source))
        else:
            data_str = str(data)
            try:
                data_dict = json.loads(data_str)
                findings.extend(find_auth_blocks(data_dict, source))
            except json.JSONDecodeError:
                pass

        patterns = {
            "Client ID": r'"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"',
            "Secret": r'"secret[s]?":\s*"([^"]+)"',
            "Username": r'"username":\s*"([^"]+)"',
            "Password": r'"password":\s*"([^"]+)"',
            "Storage Key": r'"[A-Za-z0-9+/]{88}=="',
            "Generic Key": r'"key[s]?":\s*"([^"]{10,})"',
            "Connection String": r'"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^"]+"'
        }

        exclude_keywords = {"Append", "Variable", "ActiveDirectory", "runtime", "Configuration", "triggers", "actions", "parameters", "outputs"}
        subscription_pattern = r'/subscriptions/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})/'
        header_pattern = r'["\']?(x-ms-request-id|x-ms-correlation-request-id|x-ms-workflow-subscription-id|session-id|x-ms-client-request-id|X-ARR-LOG-ID|X-CorrelationContext|originAlertId)["\']?:\s*["\']?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})["\']?'

        found_matches = set()
        subscription_ids = set(re.findall(subscription_pattern, data_str))
        header_guids = set(match[1] for match in re.findall(header_pattern, data_str))

        for info_type, pattern in patterns.items():
            matches = re.finditer(pattern, data_str)
            for match in matches:
                full_match = match.group(0)
                value = match.group(1) if match.groups() else full_match.strip('"')
                clean_value = value.strip('"')

                if (clean_value.startswith('@appsetting(') and clean_value.endswith(')')) or \
                   (clean_value.startswith('@body(') and clean_value.endswith(')')) or \
                   (clean_value.startswith('@parameters(') and clean_value.endswith(')')) or \
                   (clean_value.startswith('@{body(') and ")?['value']}" in clean_value):
                    continue

                match_clean = clean_value
                if (match_clean and 
                    (info_type != "Client ID" or (match_clean not in subscription_ids and match_clean not in header_guids))):
                    finding = f"{info_type} found in {source}: {full_match}"
                    found_matches.add(finding)
                    findings.append(finding)

        standalone_secret_pattern = r'"[-_~A-Za-z0-9]{20,}"'
        standalone_matches = re.finditer(standalone_secret_pattern, data_str)
        for match in standalone_matches:
            full_match = match.group(0)
            value = full_match.strip('"')
            if (value.startswith('@appsetting(') and value.endswith(')')) or \
               (value.startswith('@body(') and value.endswith(')')) or \
               (value.startswith('@parameters(') and value.endswith(')')) or \
               (value.startswith('@{body(') and ")?['value']}" in value):
                continue
            match_clean = value
            if (re.search(r'[0-9]', match_clean) and 
                re.search(r'[a-zA-Z]', match_clean) and 
                not any(keyword in match_clean for keyword in exclude_keywords) and 
                match_clean and 
                match_clean not in subscription_ids and 
                match_clean not in header_guids):
                finding = f"Potential Secret found in {source}: {full_match}"
                if finding not in found_matches:
                    found_matches.add(finding)
                    findings.append(finding)

        return findings

    def analyze_run_history(runs, subscription, resource_group, logic_app, max_runs):
        findings = []
        if not runs:
            return findings

        num_runs_to_analyze = min(len(runs), max_runs)
        if len(runs) > num_runs_to_analyze:
            runs = random.sample(runs, num_runs_to_analyze)

        for run in runs:
            run_id = run.get("name", "unknown")
            actions = get_run_actions(subscription, resource_group, logic_app, run_id)
            action_findings = []
            for action in actions:
                action_name = action.get("name", "unknown")
                for link_type in ["inputsLink", "outputsLink"]:
                    link = action.get("properties", {}).get(link_type, {})
                    uri = link.get("uri")
                    if uri:
                        action_data = curl_action_uri(uri)
                        if action_data:
                            action_findings.extend(find_sensitive_info(action_data, f"run {run_id} action {action_name} {link_type}"))
            findings.extend(action_findings)

        return findings

    def audit_consumption_logic_apps_stream(subscription, output_dir, max_runs=10):
        try:
            apps = get_consumption_logic_apps(subscription)
            for app in apps:
                name = app["name"]
                resource_group = app["resourceGroup"]
                app_data = {
                    "name": name,
                    "resource_group": resource_group,
                    "code_findings": [],
                    "param_findings": [],
                    "version_findings": [],
                    "run_findings": [],
                    "has_findings": False
                }

                # Main Code
                app_details = get_logic_app_definition(subscription, resource_group, name)
                if app_details:
                    code_findings = find_sensitive_info(app_details.get("definition", {}), "current code")
                    param_findings = find_sensitive_info(app_details.get("parameters", {}), "current parameters")
                    app_data["code_findings"] = code_findings
                    app_data["param_findings"] = param_findings

                # Versions
                revisions = get_logic_app_revisions(subscription, resource_group, name)
                version_findings = []
                if revisions:
                    for revision in revisions:
                        revision_code = get_revision_code(subscription, resource_group, name, revision)
                        if revision_code:
                            rev_code_findings = find_sensitive_info(revision_code.get("properties", {}).get("definition", {}), f"revision {revision} code")
                            rev_param_findings = find_sensitive_info(revision_code.get("properties", {}).get("parameters", {}), f"revision {revision} parameters")
                            version_findings.extend(rev_code_findings)
                            version_findings.extend(rev_param_findings)
                app_data["version_findings"] = version_findings

                # Run History
                run_history = get_run_history(subscription, resource_group, name)
                run_findings = analyze_run_history(run_history, subscription, resource_group, name, max_runs)
                app_data["run_findings"] = run_findings

                # Compute has_findings
                app_data["has_findings"] = (
                    len(app_data["code_findings"]) > 0 or
                    len(app_data["param_findings"]) > 0 or
                    len(app_data["version_findings"]) > 0 or
                    len(app_data["run_findings"]) > 0
                )

                # Collect all findings for database storage
                all_findings = []
                if app_data["code_findings"]:
                    all_findings.extend([f"Main Code: {f}" for f in app_data["code_findings"]])
                if app_data["param_findings"]:
                    all_findings.extend([f"Parameters: {f}" for f in app_data["param_findings"]])
                if app_data["version_findings"]:
                    all_findings.extend([f"Version History: {f}" for f in app_data["version_findings"]])
                if app_data["run_findings"]:
                    all_findings.extend([f"Run History: {f}" for f in app_data["run_findings"]])
                
                # If no findings, add a note
                if not all_findings:
                    all_findings.append("No sensitive data found")

                # Save detailed Logic App Consumption results to database
                from app import save_detailed_scan_results
                from visualization_db import save_vulnerability_findings, save_detailed_scan_results as save_visual_detailed_scan_results
                
                save_detailed_scan_results(
                    subscription_id=subscription,
                    service_type="Logic App Consumption",
                    service_name=name,
                    resource_group=resource_group,
                    resource_name=name,
                    resource_state="Active",
                    resource_type="Logic App Consumption",
                    findings_json=json.dumps(all_findings)
                )

                # Save to visualization database only if there are actual vulnerabilities
                if app_data["has_findings"]:
                    save_visual_detailed_scan_results(
                        subscription_id=subscription,
                        service_type="Logic App Consumption",
                        service_name=name,
                        resource_group=resource_group,
                        resource_name=name,
                        resource_state="Active",
                        resource_type="Logic App Consumption",
                        findings_json=json.dumps(all_findings)
                    )

                # Save individual vulnerabilities to visualization database
                if app_data["code_findings"]:
                    for idx, finding in enumerate(app_data["code_findings"], 1):
                        save_vulnerability_findings(
                            subscription_id=subscription,
                            service_type="Logic App Consumption",
                            service_name=name,
                            resource_group=resource_group,
                            vulnerability_title=f"Main Code Issue #{idx}",
                            category="Main Code",
                            description=f"Sensitive information found in Logic App Consumption '{name}' main code: {finding}",
                            code_snippet=finding,
                            recommendation="Review and secure all sensitive data in Logic App code. Remove hardcoded secrets, passwords, and other sensitive information. Use Azure Key Vault or secure parameter management."
                        )

                if app_data["param_findings"]:
                    for idx, finding in enumerate(app_data["param_findings"], 1):
                        save_vulnerability_findings(
                            subscription_id=subscription,
                            service_type="Logic App Consumption",
                            service_name=name,
                            resource_group=resource_group,
                            vulnerability_title=f"Parameters Issue #{idx}",
                            category="Parameters",
                            description=f"Sensitive information found in Logic App Consumption '{name}' parameters: {finding}",
                            code_snippet=finding,
                            recommendation="Review and secure all sensitive data in Logic App parameters. Remove hardcoded secrets, passwords, and other sensitive information. Use Azure Key Vault or secure parameter management."
                        )

                if app_data["version_findings"]:
                    for idx, finding in enumerate(app_data["version_findings"], 1):
                        save_vulnerability_findings(
                            subscription_id=subscription,
                            service_type="Logic App Consumption",
                            service_name=name,
                            resource_group=resource_group,
                            vulnerability_title=f"Version History Issue #{idx}",
                            category="Version History",
                            description=f"Sensitive information found in Logic App Consumption '{name}' version history: {finding}",
                            code_snippet=finding,
                            recommendation="Review version history for sensitive data exposure. Consider cleaning up old versions that contain sensitive information."
                        )

                if app_data["run_findings"]:
                    for idx, finding in enumerate(app_data["run_findings"], 1):
                        save_vulnerability_findings(
                            subscription_id=subscription,
                            service_type="Logic App Consumption",
                            service_name=name,
                            resource_group=resource_group,
                            vulnerability_title=f"Run History Issue #{idx}",
                            category="Run History",
                            description=f"Sensitive information found in Logic App Consumption '{name}' run history: {finding}",
                            code_snippet=finding,
                            recommendation="Review run history for sensitive data exposure. Consider implementing data sanitization in run outputs."
                        )

                # Write findings to file if any
                if app_data["has_findings"]:
                    file_content = f"Logic App: {name} (Consumption)\n"
                    if app_data["code_findings"] or app_data["param_findings"]:
                        file_content += "   Main Code:\n" + "\n".join([f"      - {f}" for f in app_data["code_findings"] + app_data["param_findings"]]) + "\n"
                    if app_data["version_findings"]:
                        file_content += "   Versions:\n" + "\n".join([f"      - {f}" for f in app_data["version_findings"]]) + "\n"
                    if app_data["run_findings"]:
                        file_content += "   Run History:\n" + "\n".join([f"      - {f}" for f in app_data["run_findings"]]) + "\n"
                    write_findings("logicapp_consumption", subscription, f"{name}.txt", file_content)

                # Yield app data without progress (progress is handled globally)
                yield json.dumps({
                    "type": "logicapp",
                    "subscription": subscription,
                    "logic_app": {name: app_data}
                }) + "\n"
        except Exception as e:
            print(f"Error in audit_consumption_logic_apps_stream: {str(e)}")
            yield json.dumps({"error": f"Error scanning Logic Apps (Consumption): {str(e)}"}) + "\n"

    def analyze_logicapp_consumption_stream(subscriptions, max_runs=10):
        try:
            from app import save_scan_result, save_detailed_scan_results  # Lazy import inside the function
            
            output_dir = "results/logicapp_consumption"
            os.makedirs(output_dir, exist_ok=True)

            # Calculate total apps across all subscriptions upfront
            total_logic_apps = sum(len(get_consumption_logic_apps(sub)) for sub in subscriptions)
            
            # Check if there are any logic apps to scan
            if total_logic_apps == 0:
                yield json.dumps({"error": "No Logic Apps (Consumption) found in any subscription."}) + "\n"
                return
            
            total_access_granted = 0
            global_apps_processed = 0

            if not check_az_login():
                yield json.dumps({"error": "Unable to proceed without az login. Run 'az login'."}) + "\n"
                return

            total_subs = len(subscriptions)
            for subscription in subscriptions:
                for update in audit_consumption_logic_apps_stream(subscription, output_dir, max_runs):
                    data = json.loads(update.strip())
                    if data.get("error"):
                        yield update
                        return
                    
                    # Update global progress tracking
                    global_apps_processed += 1
                    app_name = list(data["logic_app"].keys())[0]
                    app_data = data["logic_app"][app_name]
                    if app_data["has_findings"]:
                        total_access_granted += 1
                    
                    # Create updated progress data with global tracking
                    updated_data = {
                        "type": "logicapp",
                        "subscription": data["subscription"],
                        "logic_app": data["logic_app"],
                        "progress": {
                            "apps_processed": global_apps_processed,
                            "total_apps": total_logic_apps,
                            "percentage": round((global_apps_processed / total_logic_apps) * 100, 2) if total_logic_apps > 0 else 100
                        }
                    }
                    yield json.dumps(updated_data) + "\n"

            yield json.dumps({
                "type": "summary",
                "total_subs": total_subs,
                "total_logic_apps": total_logic_apps,
                "total_findings": total_access_granted,
                "elapsed_time": 0  # You can add timing logic if needed
            }) + "\n"
        except Exception as e:
            print(f"Error in analyze_logicapp_consumption_stream: {str(e)}")
            yield json.dumps({"error": f"Error in Logic App (Consumption) scan: {str(e)}"}) + "\n"

    def get_total_consumption_logic_apps():
        try:
            return sum(len(get_consumption_logic_apps(sub)) for sub in get_subscriptions())
        except Exception as e:
            print(f"Error in get_total_consumption_logic_apps: {str(e)}")
            return 0

    # Routes
    @app.route('/logic_app_consumption')
    def logic_app_consumption():
        try:
            # Load page immediately without calculating total count
            return render_template('logic_app_consumption.html', total_logic_apps=0)
        except Exception as e:
            print(f"Error rendering logic_app_consumption: {str(e)}")
            return jsonify({"error": f"Error loading Logic App (Consumption) page: {str(e)}"}), 500

    @app.route('/get_total_consumption_logic_apps')
    def get_total_consumption_logic_apps_route():
        try:
            total_logic_apps = get_total_consumption_logic_apps()
            return jsonify({"total_logic_apps": total_logic_apps})
        except Exception as e:
            print(f"Error getting total consumption logic apps: {str(e)}")
            return jsonify({"error": f"Error getting total Logic Apps count: {str(e)}"}), 500

    @app.route('/scan_logicapp_consumption_stream')
    def scan_logicapp_consumption_stream():
        try:
            max_runs = int(request.args.get('max_runs', 10))
            if max_runs < 1:
                max_runs = 10
            subscriptions = get_subscriptions()
            def generate():
                for update in analyze_logicapp_consumption_stream(subscriptions, max_runs):
                    yield f"data: {update}\n\n"
            return Response(generate(), mimetype='text/event-stream')
        except Exception as e:
            print(f"Error in scan_logicapp_consumption_stream: {str(e)}")
            return jsonify({"error": f"Error in scan_logicapp_consumption_stream: {str(e)}"}), 500

    @app.route('/export_logicapp_consumption', methods=['POST'])
    def export_logicapp_consumption():
        try:
            results = request.get_json()
            
            # Generate beautiful HTML report
            from utils.report_utils import generate_html_report, save_html_report
            
            html_content = generate_html_report("Logic App Consumption", results)
            filepath, filename = save_html_report(html_content, "Logic App Consumption")
            
            return jsonify({
                "status": "success", 
                "message": f"Beautiful HTML report generated successfully: {filename}",
                "filename": filename,
                "filepath": filepath
            })
        except Exception as e:
            print(f"Error generating HTML report: {e}")
            # Fallback to text export
            try:
                with open("logicapp_consumption_audit_summary.txt", "w") as f:
                    for sub_id, apps in results["subscriptions"].items():
                        f.write(f"\nSubscription: {sub_id}\n")
                        for app_name, app_data in apps.items():
                            f.write(f"  Logic App: {app_name} (Consumption)\n")
                            f.write(f"    Resource Group: {app_data['resource_group']}\n")
                            if app_data["code_findings"] or app_data["param_findings"]:
                                f.write(f"    Main Code:\n")
                                for finding in app_data["code_findings"] + app_data["param_findings"]:
                                    f.write(f"      - {finding}\n")
                            if app_data["version_findings"]:
                                f.write(f"    Versions:\n")
                                for finding in app_data["version_findings"]:
                                    f.write(f"      - {finding}\n")
                            if app_data["run_findings"]:
                                f.write(f"    Run History:\n")
                                for finding in app_data["run_findings"]:
                                    f.write(f"      - {finding}\n")
                    f.write("\nSummary:\n")
                    f.write(f"  Subscriptions Analyzed: {results['total_subs']}\n")
                    f.write(f"  Logic Apps Processed: {results['total_logic_apps']}\n")
                    f.write(f"  Logic Apps with Findings: {results['total_findings']}\n")
                    f.write(f"  Time Taken: {results['elapsed_time']} seconds\n")
                return jsonify({"status": "success", "message": "Text report exported successfully (HTML generation failed)"})
            except Exception as e2:
                return jsonify({"status": "error", "message": f"Both HTML and text export failed: {str(e2)}"}), 500
