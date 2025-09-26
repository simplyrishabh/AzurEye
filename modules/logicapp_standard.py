import subprocess
import json
import os
import re
import random
import time
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

    def get_standard_logic_apps(subscription):
        try:
            command = f"az logicapp list --subscription {subscription} -o json"
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=60)
            if result.returncode == 0 and result.stdout:
                apps = json.loads(result.stdout)
                standard_apps = [
                    {"name": app["name"], "resourceGroup": app["resourceGroup"], "plan": "Standard"}
                    for app in apps
                ]
                print(f"Found {len(standard_apps)} Standard Logic Apps in subscription {subscription}")
                return standard_apps
            else:
                print(f"get_standard_logic_apps failed for subscription {subscription}: {result.stderr}")
                return []
        except subprocess.TimeoutExpired:
            print(f"get_standard_logic_apps timed out for subscription {subscription}")
            return []
        except Exception as e:
            print(f"Error in get_standard_logic_apps for subscription {subscription}: {str(e)}")
            return []

    def get_standard_connections(subscription, resource_group, logic_app):
        try:
            command = (
                f"az rest --method GET "
                f"--uri '/subscriptions/{subscription}/resourceGroups/{resource_group}/providers/Microsoft.Web/sites/{logic_app}/workflowsconfiguration/connections?api-version=2018-11-01' "
                f"-o json"
            )
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
            if result.returncode == 0 and result.stdout:
                return json.loads(result.stdout)
            else:
                error_msg = result.stderr.strip()
                if "AuthorizationFailed" in error_msg or "Unauthorized" in error_msg:
                    print(f"Unauthorized to fetch connections for {logic_app}: Insufficient permissions—requires elevated role (e.g., Contributor).")
                else:
                    print(f"Error fetching connections for {logic_app}: {error_msg[:50]}...")
                return None
        except subprocess.TimeoutExpired:
            print(f"Connections fetch timed out for {logic_app}")
            return None
        except Exception as e:
            print(f"Error fetching connections for {logic_app}: {str(e)}")
            return None

    def get_standard_logic_app_definition(subscription, resource_group, logic_app):
        try:
            command = (
                f"az rest --method GET "
                f"--uri '/subscriptions/{subscription}/resourceGroups/{resource_group}/providers/Microsoft.Web/sites/{logic_app}?api-version=2022-03-01' "
                f"-o json"
            )
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
            if result.returncode == 0 and result.stdout:
                return json.loads(result.stdout)
            else:
                error_msg = result.stderr.strip()
                if "AuthorizationFailed" in error_msg or "Unauthorized" in error_msg:
                    print(f"Unauthorized to fetch definition for {logic_app}: Insufficient permissions—requires elevated role (e.g., Contributor).")
                else:
                    print(f"Error fetching definition for {logic_app}: {error_msg[:50]}...")
                return None
        except subprocess.TimeoutExpired:
            print(f"Definition fetch timed out for {logic_app}")
            return None
        except Exception as e:
            print(f"Error fetching definition for {logic_app}: {str(e)}")
            return None

    def get_standard_appsettings(subscription, resource_group, logic_app):
        try:
            command = (
                f"az logicapp config appsettings list "
                f"--name {logic_app} --resource-group {resource_group} --subscription {subscription} "
                f"-o json"
            )
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
            if result.returncode == 0 and result.stdout:
                appsettings = json.loads(result.stdout)
                return {item["name"]: item["value"] for item in appsettings}
            else:
                error_msg = result.stderr.strip()
                if "AuthorizationFailed" in error_msg or "Unauthorized" in error_msg:
                    print(f"Unauthorized to fetch app settings for {logic_app}: Insufficient permissions—requires elevated role (e.g., Contributor).")
                else:
                    print(f"Error fetching app settings for {logic_app}: {error_msg[:50]}...")
                return None
        except subprocess.TimeoutExpired:
            print(f"App settings fetch timed out for {logic_app}")
            return None
        except Exception as e:
            print(f"Error fetching app settings for {logic_app}: {str(e)}")
            return None

    def get_standard_workflows(subscription, resource_group, logic_app):
        try:
            command = (
                f"az rest --method GET "
                f"--uri '/subscriptions/{subscription}/resourceGroups/{resource_group}/providers/Microsoft.Web/sites/{logic_app}/hostruntime/runtime/webhooks/workflow/api/management/workflows?api-version=2022-03-01' "
                f"-o json"
            )
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
            if result.returncode == 0 and result.stdout:
                workflows = json.loads(result.stdout)
                return workflows
            else:
                error_msg = result.stderr.strip()
                if "AuthorizationFailed" in error_msg or "Unauthorized" in error_msg:
                    print(f"Unauthorized to fetch workflows for {logic_app}: Insufficient permissions—requires elevated role (e.g., Contributor).")
                else:
                    print(f"Error fetching workflows for {logic_app}: {error_msg[:50]}...")
                return []
        except subprocess.TimeoutExpired:
            print(f"Workflows fetch timed out for {logic_app}")
            return []
        except Exception as e:
            print(f"Error fetching workflows for {logic_app}: {str(e)}")
            return []

    def get_standard_workflow_definition(subscription, resource_group, logic_app, workflow_name):
        try:
            command = (
                f"az rest --method GET "
                f"--uri '/subscriptions/{subscription}/resourceGroups/{resource_group}/providers/Microsoft.Web/sites/{logic_app}/workflows/{workflow_name}?api-version=2018-11-01&$expand=parameters.json' "
                f"-o json"
            )
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
            if result.returncode == 0 and result.stdout:
                return json.loads(result.stdout)
            else:
                error_msg = result.stderr.strip()
                if "AuthorizationFailed" in error_msg or "Unauthorized" in error_msg:
                    print(f"Unauthorized to fetch workflow definition for {workflow_name} in {logic_app}: Insufficient permissions—requires elevated role (e.g., Contributor).")
                else:
                    print(f"Error fetching workflow definition for {workflow_name} in {logic_app}: {error_msg[:50]}...")
                return None
        except subprocess.TimeoutExpired:
            print(f"Workflow definition fetch timed out for {workflow_name} in {logic_app}")
            return None
        except Exception as e:
            print(f"Error fetching workflow definition for {workflow_name} in {logic_app}: {str(e)}")
            return None

    def get_standard_run_history(subscription, resource_group, logic_app, workflow_name):
        try:
            command = (
                f"az rest --method GET "
                f"--uri '/subscriptions/{subscription}/resourceGroups/{resource_group}/providers/Microsoft.Web/sites/{logic_app}/hostruntime/runtime/webhooks/workflow/api/management/workflows/{workflow_name}/runs?api-version=2022-03-01' "
                f"-o json"
            )
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
            if result.returncode == 0 and result.stdout:
                return json.loads(result.stdout).get("value", [])
            else:
                error_msg = result.stderr.strip()
                if "BadRequest" in error_msg:
                    print(f"No run history available for {workflow_name} in {logic_app}")
                    return []
                elif "AuthorizationFailed" in error_msg or "Unauthorized" in error_msg:
                    print(f"Unauthorized to fetch run history for {workflow_name} in {logic_app}: Insufficient permissions—requires elevated role (e.g., Contributor).")
                else:
                    print(f"Error fetching run history for {workflow_name} in {logic_app}: {error_msg[:50]}...")
                return []
        except subprocess.TimeoutExpired:
            print(f"Run history fetch timed out for {workflow_name} in {logic_app}")
            return []
        except Exception as e:
            print(f"Error fetching run history for {workflow_name} in {logic_app}: {str(e)}")
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
                    f"Flat ActiveDirectoryOAuth credentials found in {source}: "
                    f"tenant={tenant}, clientId={client_id}, secret={secret}\n"
                    f"    Note: This might be used for service principal login with: "
                    f"az login --service-principal --username {client_id} --password {secret} --tenant {tenant}. "
                    f"Verify privileges as it could grant additional access."
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
                    f"tenant={tenant}, clientId={client_id}, secret={secret}\n"
                    f"    Note: This might be used for service principal login with: "
                    f"az login --service-principal --username {client_id} --password {secret} --tenant {tenant}. "
                    f"Verify privileges as it could grant additional access."
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

    def analyze_run_history(runs, subscription, resource_group, logic_app, workflow_name, max_runs=10):
        findings = []
        if not runs:
            return findings

        num_runs_to_analyze = min(len(runs), max_runs)
        if len(runs) > num_runs_to_analyze:
            runs = random.sample(runs, num_runs_to_analyze)

        for run in runs:
            run_id = run.get("name", "unknown")
            action_findings = []
            trigger = run.get("properties", {}).get("trigger", {})
            for link_type in ["inputsLink", "outputsLink"]:
                uri = trigger.get(link_type, {}).get("uri")
                if uri:
                    action_data = curl_action_uri(uri)
                    if action_data:
                        action_findings.extend(find_sensitive_info(action_data, f"run {run_id} trigger {link_type}"))
                    else:
                        print(f"Warning: Could not load trigger {link_type} for run {run_id} in {logic_app} due to access restrictions.")

            if action_findings:
                findings.extend(action_findings)

        return findings

    def audit_standard_logic_apps_stream(subscription, output_dir, max_runs=10):
        try:
            apps = get_standard_logic_apps(subscription)
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

                connections = get_standard_connections(subscription, resource_group, name)
                if connections:
                    conn_findings = find_sensitive_info(connections, "connections")
                    app_data["code_findings"].extend(conn_findings)

                app_details = get_standard_logic_app_definition(subscription, resource_group, name)
                if app_details:
                    param_findings = find_sensitive_info(app_details.get("properties", {}).get("parameters", {}), "app-level parameters")
                    app_data["param_findings"] = param_findings

                appsettings = get_standard_appsettings(subscription, resource_group, name)
                if appsettings:
                    appsettings_findings = find_sensitive_info(appsettings, "app settings")
                    app_data["code_findings"].extend(appsettings_findings)

                workflows = get_standard_workflows(subscription, resource_group, name)
                if workflows:
                    for workflow in workflows:
                        workflow_name = workflow.get("name", "unknown")
                        workflow_def = get_standard_workflow_definition(subscription, resource_group, name, workflow_name)
                        if workflow_def:
                            wf_code_findings = find_sensitive_info(workflow_def.get("properties", {}).get("definition", {}), f"workflow {workflow_name} code")
                            wf_param_findings = find_sensitive_info(workflow_def.get("properties", {}).get("parameters", {}), f"workflow {workflow_name} parameters")
                            app_data["code_findings"].extend(wf_code_findings)
                            app_data["param_findings"].extend(wf_param_findings)

                        run_history = get_standard_run_history(subscription, resource_group, name, workflow_name)
                        if run_history or run_history == []:
                            run_findings = analyze_run_history(run_history, subscription, resource_group, name, workflow_name, max_runs)
                            app_data["run_findings"].extend(run_findings)

                app_data["has_findings"] = (
                    len(app_data["code_findings"]) > 0 or
                    len(app_data["param_findings"]) > 0 or
                    len(app_data["version_findings"]) > 0 or
                    len(app_data["run_findings"]) > 0
                )

                all_findings = []
                if app_data["code_findings"]:
                    all_findings.extend([f"Main Code: {f}" for f in app_data["code_findings"]])
                if app_data["param_findings"]:
                    all_findings.extend([f"Parameters: {f}" for f in app_data["param_findings"]])
                if app_data["version_findings"]:
                    all_findings.extend([f"Version History: {f}" for f in app_data["version_findings"]])
                if app_data["run_findings"]:
                    all_findings.extend([f"Run History: {f}" for f in app_data["run_findings"]])
                
                if not all_findings:
                    all_findings.append("No sensitive data found")

                from app import save_detailed_scan_results
                from visualization_db import save_vulnerability_findings, save_detailed_scan_results as save_visual_detailed_scan_results
                
                save_detailed_scan_results(
                    subscription_id=subscription,
                    service_type="Logic App Standard",
                    service_name=name,
                    resource_group=resource_group,
                    resource_name=name,
                    resource_state="Active",
                    resource_type="Logic App Standard",
                    findings_json=json.dumps(all_findings)
                )

                if app_data["has_findings"]:
                    save_visual_detailed_scan_results(
                        subscription_id=subscription,
                        service_type="Logic App Standard",
                        service_name=name,
                        resource_group=resource_group,
                        resource_name=name,
                        resource_state="Active",
                        resource_type="Logic App Standard",
                        findings_json=json.dumps(all_findings)
                    )

                connections_findings = []
                app_settings_findings = []
                workflows_findings = []
                
                for finding in app_data["code_findings"]:
                    if "connections" in finding.lower():
                        connections_findings.append(finding)
                    elif "app settings" in finding.lower():
                        app_settings_findings.append(finding)
                    elif "workflow" in finding.lower():
                        workflows_findings.append(finding)
                    else:
                        connections_findings.append(finding)
                
                for idx, finding in enumerate(connections_findings, 1):
                    save_vulnerability_findings(
                        subscription_id=subscription,
                        service_type="Logic App Standard",
                        service_name=name,
                        resource_group=resource_group,
                        vulnerability_title=f"Connections Issue #{idx}",
                        category="Connections",
                        description=f"Sensitive information found in Logic App Standard '{name}' connections: {finding}",
                        code_snippet=finding,
                        recommendation="Review and secure all sensitive data in Logic App connections. Remove hardcoded secrets, passwords, and other sensitive information. Use Azure Key Vault or secure parameter management."
                    )
                
                for idx, finding in enumerate(app_settings_findings, 1):
                    save_vulnerability_findings(
                        subscription_id=subscription,
                        service_type="Logic App Standard",
                        service_name=name,
                        resource_group=resource_group,
                        vulnerability_title=f"App Settings Issue #{idx}",
                        category="App Settings",
                        description=f"Sensitive information found in Logic App Standard '{name}' app settings: {finding}",
                        code_snippet=finding,
                        recommendation="Review and secure all sensitive data in Logic App app settings. Remove hardcoded secrets, passwords, and other sensitive information. Use Azure Key Vault or secure parameter management."
                    )
                
                for idx, finding in enumerate(workflows_findings, 1):
                    save_vulnerability_findings(
                        subscription_id=subscription,
                        service_type="Logic App Standard",
                        service_name=name,
                        resource_group=resource_group,
                        vulnerability_title=f"Workflows Issue #{idx}",
                        category="Workflows",
                        description=f"Sensitive information found in Logic App Standard '{name}' workflows: {finding}",
                        code_snippet=finding,
                        recommendation="Review and secure all sensitive data in Logic App workflows. Remove hardcoded secrets, passwords, and other sensitive information. Use Azure Key Vault or secure parameter management."
                    )

                if app_data["param_findings"]:
                    for idx, finding in enumerate(app_data["param_findings"], 1):
                        save_vulnerability_findings(
                            subscription_id=subscription,
                            service_type="Logic App Standard",
                            service_name=name,
                            resource_group=resource_group,
                            vulnerability_title=f"Parameters Issue #{idx}",
                            category="Parameters",
                            description=f"Sensitive information found in Logic App Standard '{name}' parameters: {finding}",
                            code_snippet=finding,
                            recommendation="Review and secure all sensitive data in Logic App parameters. Remove hardcoded secrets, passwords, and other sensitive information. Use Azure Key Vault or secure parameter management."
                        )

                if app_data["version_findings"]:
                    for idx, finding in enumerate(app_data["version_findings"], 1):
                        save_vulnerability_findings(
                            subscription_id=subscription,
                            service_type="Logic App Standard",
                            service_name=name,
                            resource_group=resource_group,
                            vulnerability_title=f"Version History Issue #{idx}",
                            category="Version History",
                            description=f"Sensitive information found in Logic App Standard '{name}' version history: {finding}",
                            code_snippet=finding,
                            recommendation="Review version history for sensitive data exposure. Consider cleaning up old versions that contain sensitive information."
                        )

                if app_data["run_findings"]:
                    for idx, finding in enumerate(app_data["run_findings"], 1):
                        save_vulnerability_findings(
                            subscription_id=subscription,
                            service_type="Logic App Standard",
                            service_name=name,
                            resource_group=resource_group,
                            vulnerability_title=f"Run History Issue #{idx}",
                            category="Run History",
                            description=f"Sensitive information found in Logic App Standard '{name}' run history: {finding}",
                            code_snippet=finding,
                            recommendation="Review run history for sensitive data exposure. Consider implementing data sanitization in run outputs."
                        )

                # Write findings to file if any
                if app_data["has_findings"]:
                    file_content = f"Logic App: {name} (Standard)\n"
                    if app_data["code_findings"] or app_data["param_findings"]:
                        file_content += "   Main Code:\n" + "\n".join([f"      - {f}" for f in app_data["code_findings"] + app_data["param_findings"]]) + "\n"
                    if app_data["version_findings"]:
                        file_content += "   Versions:\n" + "\n".join([f"      - {f}" for f in app_data["version_findings"]]) + "\n"
                    if app_data["run_findings"]:
                        file_content += "   Run History:\n" + "\n".join([f"      - {f}" for f in app_data["run_findings"]]) + "\n"
                    write_findings("logicapp_standard", subscription, f"{name}.txt", file_content)

                # Transform data structure to match frontend expectations
                # Separate findings by type for better organization
                connections_findings = []
                app_settings_findings = []
                workflows_findings = []
                
                for finding in app_data["code_findings"]:
                    if "connections" in finding.lower():
                        connections_findings.append(finding)
                    elif "app settings" in finding.lower():
                        app_settings_findings.append(finding)
                    elif "workflow" in finding.lower():
                        workflows_findings.append(finding)
                    else:
                        connections_findings.append(finding)
                
                transformed_app_data = {
                    "name": name,
                    "resource_group": resource_group,
                    "findings": {
                        "regular": {
                            "connections": connections_findings,
                            "app_level_parameters": app_data["param_findings"],
                            "app_settings": app_settings_findings,
                            "workflows": workflows_findings,
                            "run_history": app_data["run_findings"]
                        },
                        "critical": []
                    },
                    "has_findings": app_data["has_findings"]
                }

                # Yield app data without progress (progress is handled globally)
                yield json.dumps({
                    "type": "logicapp_standard",
                    "subscription": subscription,
                    "logic_app": {name: transformed_app_data}
                }) + "\n"
        except Exception as e:
            print(f"Error in audit_standard_logic_apps_stream: {str(e)}")
            # Only yield error for critical failures, not for individual resource access issues
            if "NotFound" not in str(e) and "Unauthorized" not in str(e):
                yield json.dumps({"error": f"Error scanning Logic Apps (Standard): {str(e)}"}) + "\n"

    def analyze_logicapp_standard_stream(subscriptions, max_runs=10):
        try:
            from app import save_scan_result, save_detailed_scan_results  # Lazy import inside the function
            
            start_time = time.time()
            output_dir = "results/logicapp_standard"
            os.makedirs(output_dir, exist_ok=True)

            # Calculate total apps across all subscriptions upfront
            total_logic_apps = sum(len(get_standard_logic_apps(sub)) for sub in subscriptions)
            
            # Check if there are any logic apps to scan
            if total_logic_apps == 0:
                yield json.dumps({"error": "No Logic Apps (Standard) found in any subscription."}) + "\n"
                return
            
            total_access_granted = 0
            global_apps_processed = 0

            if not check_az_login():
                yield json.dumps({"error": "Unable to proceed without az login. Run 'az login'."}) + "\n"
                return

            total_subs = len(subscriptions)
            for subscription in subscriptions:
                for update in audit_standard_logic_apps_stream(subscription, output_dir, max_runs):
                    data = json.loads(update.strip())
                    if data.get("error"):
                        print(f"Error in scan: {data.get('error')}")
                        # Don't return early for individual errors, continue with other subscriptions
                        continue
                    
                    # Update global progress tracking
                    global_apps_processed += 1
                    app_name = list(data["logic_app"].keys())[0]
                    app_data = data["logic_app"][app_name]
                    if app_data["has_findings"]:
                        total_access_granted += 1
                    
                    # Create updated progress data with global tracking
                    updated_data = {
                        "type": "logicapp_standard",
                        "subscription": data["subscription"],
                        "logic_app": data["logic_app"],
                        "progress": {
                            "apps_processed": global_apps_processed,
                            "total_apps": total_logic_apps,
                            "percentage": round((global_apps_processed / total_logic_apps) * 100, 2) if total_logic_apps > 0 else 100
                        }
                    }
                    yield json.dumps(updated_data) + "\n"

            elapsed_time = int(time.time() - start_time)
            print(f"Sending summary: total_subs={total_subs}, total_logic_apps={total_logic_apps}, total_findings={total_access_granted}")
            yield json.dumps({
                "type": "summary",
                "total_subs": total_subs,
                "total_logic_apps": total_logic_apps,
                "total_findings": total_access_granted,
                "elapsed_time": elapsed_time
            }) + "\n"
        except Exception as e:
            print(f"Error in analyze_logicapp_standard_stream: {str(e)}")
            yield json.dumps({"error": f"Error in Logic App (Standard) scan: {str(e)}"}) + "\n"

    def get_total_standard_logic_apps():
        try:
            return sum(len(get_standard_logic_apps(sub)) for sub in get_subscriptions())
        except Exception as e:
            print(f"Error in get_total_standard_logic_apps: {str(e)}")
            return 0

    # Routes
    @app.route('/logic_app_standard')
    def logic_app_standard():
        try:
            # Load page immediately without calculating total count
            return render_template('logic_app_standard.html', total_logicapps=0)
        except Exception as e:
            print(f"Error rendering logic_app_standard: {str(e)}")
            return jsonify({"error": f"Error loading Logic App (Standard) page: {str(e)}"}), 500

    @app.route('/get_total_standard_logic_apps')
    def get_total_standard_logic_apps_route():
        try:
            total_logicapps = get_total_standard_logic_apps()
            return jsonify({"total_logicapps": total_logicapps})
        except Exception as e:
            print(f"Error getting total standard logic apps: {str(e)}")
            return jsonify({"error": f"Error getting total Logic Apps count: {str(e)}"}), 500

    @app.route('/scan_logicapp_standard_stream')
    def scan_logicapp_standard_stream():
        try:
            max_runs = int(request.args.get('max_runs', 10))
            if max_runs < 1:
                max_runs = 10
            subscriptions = get_subscriptions()
            def generate():
                for update in analyze_logicapp_standard_stream(subscriptions, max_runs):
                    yield f"data: {update}\n\n"
            return Response(generate(), mimetype='text/event-stream')
        except Exception as e:
            print(f"Error in scan_logicapp_standard_stream: {str(e)}")
            return jsonify({"error": f"Error in scan_logicapp_standard_stream: {str(e)}"}), 500

