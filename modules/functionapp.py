import subprocess
import json
import os
import re
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

    def get_function_apps(subscription):
        try:
            command = f"az functionapp list --subscription {subscription} -o json"
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=60)
            if result.returncode == 0 and result.stdout:
                apps = json.loads(result.stdout)
                function_apps = [{"name": app["name"], "resourceGroup": app["resourceGroup"]} for app in apps]
                return function_apps
            else:
                print(f"get_function_apps failed for subscription {subscription}: {result.stderr}")
                return []
        except subprocess.TimeoutExpired:
            print(f"get_function_apps timed out for subscription {subscription}")
            return []
        except Exception as e:
            print(f"Error in get_function_apps for subscription {subscription}: {str(e)}")
            return []

    def get_function_app_settings(subscription, resource_group, function_app):
        try:
            command = (
                f"az functionapp config appsettings list "
                f"--name {function_app} --resource-group {resource_group} --subscription {subscription} "
                f"-o json"
            )
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
            if result.returncode == 0 and result.stdout:
                appsettings = json.loads(result.stdout)
                return {item["name"]: item["value"] for item in appsettings}
            else:
                print(f"get_function_app_settings failed for {function_app}: {result.stderr}")
                return None
        except subprocess.TimeoutExpired:
            print(f"get_function_app_settings timed out for {function_app}")
            return None
        except Exception as e:
            print(f"Error in get_function_app_settings for {function_app}: {str(e)}")
            return None

    def get_function_app_keys(subscription, resource_group, function_app):
        try:
            command = (
                f"az functionapp keys list "
                f"--name {function_app} --resource-group {resource_group} --subscription {subscription} "
                f"-o json"
            )
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
            if result.returncode == 0 and result.stdout:
                return json.loads(result.stdout)
            else:
                print(f"get_function_app_keys failed for {function_app}: {result.stderr}")
                return None
        except subprocess.TimeoutExpired:
            print(f"get_function_app_keys timed out for {function_app}")
            return None
        except Exception as e:
            print(f"Error in get_function_app_keys for {function_app}: {str(e)}")
            return None

    def get_function_app_runtime(subscription, resource_group, function_app):
        try:
            command = (
                f"az functionapp config show "
                f"--name {function_app} --resource-group {resource_group} --subscription {subscription} "
                f"-o json"
            )
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
            if result.returncode == 0 and result.stdout:
                config = json.loads(result.stdout)
                settings = get_function_app_settings(subscription, resource_group, function_app)
                runtime = settings.get("FUNCTIONS_WORKER_RUNTIME", config.get("functionAppRuntime", "unknown")).lower() if settings else "unknown"
                return runtime
            else:
                print(f"get_function_app_runtime failed for {function_app}: {result.stderr}")
                return "unknown"
        except subprocess.TimeoutExpired:
            print(f"get_function_app_runtime timed out for {function_app}")
            return "unknown"
        except Exception as e:
            print(f"Error in get_function_app_runtime for {function_app}: {str(e)}")
            return "unknown"

    def list_function_app_files(subscription, resource_group, function_app):
        try:
            command = (
                f"az rest --method GET "
                f"--uri '/subscriptions/{subscription}/resourceGroups/{resource_group}/providers/Microsoft.Web/sites/{function_app}/hostruntime/admin/vfs/?relativePath=1&api-version=2021-01-15' "
                f"-o json"
            )
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
            if result.returncode == 0 and result.stdout:
                return json.loads(result.stdout)
            else:
                # Check if it's an authorization error
                if "Unauthorized" in result.stderr or "Forbidden" in result.stderr:
                    print(f"list_function_app_files: Insufficient permissions for {function_app} - Kudu API access denied")
                else:
                    print(f"list_function_app_files failed for {function_app}: {result.stderr}")
                return None
        except subprocess.TimeoutExpired:
            print(f"list_function_app_files timed out for {function_app}")
            return None
        except Exception as e:
            print(f"Error in list_function_app_files for {function_app}: {str(e)}")
            return None

    def get_file_content(subscription, resource_group, function_app, file_name):
        try:
            command = (
                f"az rest --method GET "
                f"--uri '/subscriptions/{subscription}/resourceGroups/{resource_group}/providers/Microsoft.Web/sites/{function_app}/hostruntime/admin/vfs/{file_name}?relativePath=1&api-version=2021-01-15' "
                f"-o tsv"
            )
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
            if result.returncode == 0 and result.stdout:
                return result.stdout.strip()
            else:
                # Check if it's an authorization error
                if "Unauthorized" in result.stderr or "Forbidden" in result.stderr:
                    print(f"get_file_content: Insufficient permissions for {file_name} in {function_app} - Kudu API access denied")
                else:
                    print(f"get_file_content failed for {file_name} in {function_app}: {result.stderr}")
                return None
        except subprocess.TimeoutExpired:
            print(f"get_file_content timed out for {file_name} in {function_app}")
            return None
        except Exception as e:
            print(f"Error in get_file_content for {file_name} in {function_app}: {str(e)}")
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
                tenant = auth_block["tenant"]
                client_id = auth_block["clientId"]
                secret = auth_block["secret"]
                finding = (
                    f"Authentication block found in {source}: "
                    f"tenant={tenant}, clientId={client_id}, secret={secret}"
                )
                findings.append(finding)
            elif (data.get("Type") == "ActiveDirectoryOAuth" and 
                  "Tenant" in data and 
                  "ClientId" in data and 
                  "Secret" in data):
                tenant = data["Tenant"]
                client_id = data["ClientId"]
                secret = data["Secret"]
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
            "Secret": r'"secret[s]?":\s*"[-_~A-Za-z0-9]{20,}"',
            "Username": r'"username":\s*"[^"]+"',
            "Password": r'"password":\s*"[^"]+"',
            "Storage Key": r'"[A-Za-z0-9+/]{88}=="',
            "Function App Master Key": r'"masterKey":\s*"[A-Za-z0-9+/=_-]{20,}"',
            "Function App Function Key": r'"functionKeys":\s*{[^}]*"[^"]*":\s*"[A-Za-z0-9+/=_-]{20,}"',
            "Function App Individual Key": r'"[^"]*":\s*"[A-Za-z0-9+/=_-]{20,}"',
            "Function App System Key": r'"systemKeys":\s*{[^}]*"[^"]*":\s*"[A-Za-z0-9+/=_-]{20,}"',
            "Generic Key": r'"key[s]?":\s*"[^"]{10,}"',
            "Connection String": r'"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^"]+"'

        }

        exclude_keywords = {"Append", "Variable", "ActiveDirectory", "runtime", "Configuration", "triggers", "actions", "parameters", "outputs"}
        subscription_pattern = r'/subscriptions/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})/'
        header_pattern = r'["\']?(x-ms-request-id|x-ms-correlation-request-id|x-ms-workflow-subscription-id|session-id|x-ms-client-request-id|X-ARR-LOG-ID|X-CorrelationContext|originAlertId)["\']?:\s*["\']?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})["\']?'

        found_matches = set()
        subscription_ids = set(re.findall(subscription_pattern, data_str))
        header_guids = set(match[1] for match in re.findall(header_pattern, data_str))

        for info_type, pattern in patterns.items():
            matches = re.findall(pattern, data_str)
            for match in matches:
                match_clean = match.strip('"')
                if match.strip() and (info_type != "Client ID" or (match_clean not in subscription_ids and match_clean not in header_guids)):
                    finding = f"{info_type} found in {source}: {match}"
                    found_matches.add(finding)
                    findings.append(finding)

        standalone_secret_pattern = r'"[-_~A-Za-z0-9]{20,}"'
        standalone_matches = re.findall(standalone_secret_pattern, data_str)
        for match in standalone_matches:
            match_clean = match.strip('"')
            if (re.search(r'[0-9]', match) and re.search(r'[a-zA-Z]', match) and 
                not any(keyword in match for keyword in exclude_keywords) and 
                match.strip() and match_clean not in subscription_ids and match_clean not in header_guids):
                finding = f"Potential Secret found in {source}: {match}"
                if finding not in found_matches:
                    found_matches.add(finding)
                    findings.append(finding)

        return findings

    def audit_function_apps_stream(subscription, output_dir, apps_processed, total_apps):
        try:
            apps = get_function_apps(subscription)
            for app in apps:
                apps_processed += 1
                name = app["name"]
                resource_group = app["resourceGroup"]
                app_data = {
                    "name": name,
                    "resource_group": resource_group,
                    "appsettings": {},
                    "appkeys": {},
                    "files": {},
                    "appsettings_findings": [],
                    "appkeys_findings": [],
                    "file_findings": [],
                    "has_findings": False  # Use Python's False (uppercase)
                }

                # App Settings
                appsettings = get_function_app_settings(subscription, resource_group, name)
                if appsettings:
                    appsettings_findings = find_sensitive_info(appsettings, "app settings")
                    app_data["appsettings"] = appsettings
                    app_data["appsettings_findings"] = appsettings_findings

                # App Keys
                appkeys = get_function_app_keys(subscription, resource_group, name)
                if appkeys:
                    appkeys_findings = find_sensitive_info(appkeys, "app keys")
                    app_data["appkeys"] = appkeys
                    app_data["appkeys_findings"] = appkeys_findings

                # App Files
                files = list_function_app_files(subscription, resource_group, name)
                if files:
                    runtime = get_function_app_runtime(subscription, resource_group, name)
                    app_data["runtime"] = runtime
                    file_findings = []
                    for file in files:
                        if file["mime"] != "inode/directory":
                            file_name = file["name"]
                            file_content_raw = get_file_content(subscription, resource_group, name, file_name)
                            if file_content_raw:
                                file_specific_findings = find_sensitive_info(file_content_raw, f"file {file_name}")
                                app_data["files"][file_name] = file_content_raw
                                file_findings.extend(file_specific_findings)
                    app_data["file_findings"] = file_findings
                else:
                    # Add note when file access is denied
                    app_data["file_access_note"] = "File access denied - insufficient permissions for Kudu API"

                # Compute has_findings
                app_data["has_findings"] = (
                    len(app_data["appsettings_findings"]) > 0 or
                    len(app_data["appkeys_findings"]) > 0 or
                    len(app_data["file_findings"]) > 0
                )

                # Collect all findings for database storage
                all_findings = []
                if app_data["appsettings_findings"]:
                    all_findings.extend([f"App Settings: {f}" for f in app_data["appsettings_findings"]])
                if app_data["appkeys_findings"]:
                    all_findings.extend([f"App Keys: {f}" for f in app_data["appkeys_findings"]])
                if app_data["file_findings"]:
                    all_findings.extend([f"App Files: {f}" for f in app_data["file_findings"]])
                if app_data.get("file_access_note"):
                    all_findings.append(f"Note: {app_data['file_access_note']}")
                
                # If no findings, add a note
                if not all_findings:
                    all_findings.append("No sensitive data found")

                # Save detailed Function App results to database
                from app import save_detailed_scan_results
                from visualization_db import save_vulnerability_findings, save_detailed_scan_results as save_visual_detailed_scan_results
                
                save_detailed_scan_results(
                    subscription_id=subscription,
                    service_type="Function App",
                    service_name=name,
                    resource_group=resource_group,
                    resource_name=name,
                    resource_state="Active",
                    resource_type="Function App",
                    findings_json=json.dumps(all_findings)
                )

                # Save to visualization database only if there are actual vulnerabilities
                if app_data["has_findings"]:
                    save_visual_detailed_scan_results(
                        subscription_id=subscription,
                        service_type="Function App",
                        service_name=name,
                        resource_group=resource_group,
                        resource_name=name,
                        resource_state="Active",
                        resource_type="Function App",
                        findings_json=json.dumps(all_findings)
                    )

                # Save individual vulnerabilities to visualization database
                if app_data["appsettings_findings"]:
                    for idx, finding in enumerate(app_data["appsettings_findings"], 1):
                        save_vulnerability_findings(
                            subscription_id=subscription,
                            service_type="Function App",
                            service_name=name,
                            resource_group=resource_group,
                            vulnerability_title=f"App Settings Issue #{idx}",
                            category="App Settings",
                            description=f"Sensitive information found in Function App '{name}' app settings: {finding}",
                            code_snippet=finding,
                            recommendation="Review and secure all sensitive data in Function App settings. Remove hardcoded secrets, passwords, and other sensitive information. Use Azure Key Vault or secure parameter management."
                        )

                if app_data["appkeys_findings"]:
                    for idx, finding in enumerate(app_data["appkeys_findings"], 1):
                        save_vulnerability_findings(
                            subscription_id=subscription,
                            service_type="Function App",
                            service_name=name,
                            resource_group=resource_group,
                            vulnerability_title=f"App Keys Issue #{idx}",
                            category="App Keys",
                            description=f"Sensitive information found in Function App '{name}' app keys: {finding}",
                            code_snippet=finding,
                            recommendation="Review and secure all sensitive data in Function App keys. Remove hardcoded secrets, passwords, and other sensitive information. Use Azure Key Vault or secure parameter management."
                        )

                if app_data["file_findings"]:
                    for idx, finding in enumerate(app_data["file_findings"], 1):
                        save_vulnerability_findings(
                            subscription_id=subscription,
                            service_type="Function App",
                            service_name=name,
                            resource_group=resource_group,
                            vulnerability_title=f"App Files Issue #{idx}",
                            category="App Files",
                            description=f"Sensitive information found in Function App '{name}' app files: {finding}",
                            code_snippet=finding,
                            recommendation="Review and secure all sensitive data in Function App files. Remove hardcoded secrets, passwords, and other sensitive information. Use Azure Key Vault or secure parameter management."
                        )

                # Write findings to file if any
                if app_data["has_findings"]:
                    file_content = f"Function App: {name}\n"
                    if app_data["appsettings"]:
                        file_content += "   App Settings:\n" + "\n".join([f"      - {f}" for f in app_data["appsettings_findings"]]) + "\n"
                    if app_data["appkeys"]:
                        file_content += "   App Keys:\n" + "\n".join([f"      - {f}" for f in app_data["appkeys_findings"]]) + "\n"
                    if app_data["file_findings"]:
                        file_content += "   App Files:\n" + "\n".join([f"      - {f}" for f in app_data["file_findings"]]) + "\n"
                    write_findings("functionapp", subscription, f"{name}.txt", file_content)

                # Yield app data with progress
                yield json.dumps({
                    "type": "functionapp",
                    "subscription": subscription,
                    "function_app": {name: app_data},
                    "progress": {
                        "apps_processed": apps_processed,
                        "total_apps": total_apps,
                        "percentage": round((apps_processed / total_apps) * 100, 2) if total_apps > 0 else 0
                    }
                }) + "\n"
        except Exception as e:
            print(f"Error in audit_function_apps_stream: {str(e)}")
            yield json.dumps({"error": f"Error scanning Function Apps: {str(e)}"}) + "\n"

    def analyze_functionapp_stream(subscriptions):
        try:
            from app import save_scan_result, save_detailed_scan_results  # Lazy import inside the function
            
            output_dir = "results/functionapp"
            os.makedirs(output_dir, exist_ok=True)

            # Calculate total apps across all subscriptions upfront
            total_function_apps = sum(len(get_function_apps(sub)) for sub in subscriptions)
            
            # Check if there are any function apps to scan
            if total_function_apps == 0:
                yield json.dumps({"error": "No function apps found in any subscription."}) + "\n"
                return
            
            total_access_granted = 0
            global_apps_processed = 0

            if not check_az_login():
                yield json.dumps({"error": "Unable to proceed without az login. Run 'az login'."}) + "\n"
                return

            total_subs = len(subscriptions)
            for subscription in subscriptions:
                for update in audit_function_apps_stream(subscription, output_dir, global_apps_processed, total_function_apps):
                    data = json.loads(update.strip())
                    if data.get("error"):
                        yield update
                        return
                    
                    # Update global progress tracking
                    global_apps_processed += 1
                    app_name = list(data["function_app"].keys())[0]
                    app_data = data["function_app"][app_name]
                    if app_data["has_findings"]:
                        total_access_granted += 1
                    
                    # Create updated progress data with global tracking
                    updated_data = {
                        "type": "functionapp",
                        "subscription": data["subscription"],
                        "function_app": data["function_app"],
                        "progress": {
                            "apps_processed": global_apps_processed,
                            "total_apps": total_function_apps,
                            "percentage": round((global_apps_processed / total_function_apps) * 100, 2) if total_function_apps > 0 else 100
                        }
                    }
                    yield json.dumps(updated_data) + "\n"

            yield json.dumps({
                "type": "summary",
                "total_subs": total_subs,
                "total_function_apps": total_function_apps,
                "total_findings": total_access_granted,
                "elapsed_time": 0  # You can add timing logic if needed
            }) + "\n"
        except Exception as e:
            print(f"Error in analyze_functionapp_stream: {str(e)}")
            yield json.dumps({"error": f"Error in Function App scan: {str(e)}"}) + "\n"

    def get_total_function_apps():
        try:
            return sum(len(get_function_apps(sub)) for sub in get_subscriptions())
        except Exception as e:
            print(f"Error in get_total_function_apps: {str(e)}")
            return 0

    # Routes
    @app.route('/function_app')
    def function_app():
        try:
            # Load page immediately without calculating total count
            return render_template('function_app.html', total_function_apps=0)
        except Exception as e:
            print(f"Error rendering function_app: {str(e)}")
            return jsonify({"error": f"Error loading Function App page: {str(e)}"}), 500

    @app.route('/get_total_function_apps')
    def get_total_function_apps_route():
        try:
            total_function_apps = get_total_function_apps()
            return jsonify({"total_function_apps": total_function_apps})
        except Exception as e:
            print(f"Error getting total function apps: {str(e)}")
            return jsonify({"error": f"Error getting total Function Apps count: {str(e)}"}), 500

    @app.route('/scan_functionapp_stream')
    def scan_functionapp_stream():
        try:
            subscriptions = get_subscriptions()
            def generate():
                for update in analyze_functionapp_stream(subscriptions):
                    yield f"data: {update}\n\n"
            return Response(generate(), mimetype='text/event-stream')
        except Exception as e:
            print(f"Error in scan_functionapp_stream: {str(e)}")
            return jsonify({"error": f"Error in scan_functionapp_stream: {str(e)}"}), 500

    @app.route('/export_functionapp', methods=['POST'])
    def export_functionapp():
        try:
            results = request.get_json()
            
            # Generate beautiful HTML report
            from utils.report_utils import generate_html_report, save_html_report
            
            html_content = generate_html_report("Function Apps", results)
            filepath, filename = save_html_report(html_content, "Function Apps")
            
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
                with open("functionapp_audit_summary.txt", "w") as f:
                    for sub_id, apps in results["subscriptions"].items():
                        f.write(f"\nSubscription: {sub_id}\n")
                        for app_name, app_data in apps.items():
                            f.write(f"  Function App: {app_name}\n")
                            f.write(f"    Resource Group: {app_data['resource_group']}\n")
                            if app_data["appsettings_findings"]:
                                f.write(f"    App Settings:\n")
                                for finding in app_data["appsettings_findings"]:
                                    f.write(f"      - {finding}\n")
                            if app_data["appkeys_findings"]:
                                f.write(f"    App Keys:\n")
                                for finding in app_data["appkeys_findings"]:
                                    f.write(f"      - {finding}\n")
                            if app_data["file_findings"]:
                                f.write(f"    App Files:\n")
                                for finding in app_data["file_findings"]:
                                    f.write(f"      - {finding}\n")
                    f.write("\nSummary:\n")
                    f.write(f"  Subscriptions Analyzed: {results['total_subs']}\n")
                    f.write(f"  Function Apps Processed: {results['total_function_apps']}\n")
                    f.write(f"  Function Apps with Findings: {results['total_findings']}\n")
                    f.write(f"  Time Taken: {results['elapsed_time']} seconds\n")
                return jsonify({"status": "success", "message": "Text report exported successfully (HTML generation failed)"})
            except Exception as e2:
                return jsonify({"status": "error", "message": f"Both HTML and text export failed: {str(e2)}"}), 500
