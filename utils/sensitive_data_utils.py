import json
import re

def curl_action_uri(uri):
    output = run_az_command(f"curl -s \"{uri}\"", timeout=30)
    if output:
        try:
            return json.loads(output)
        except json.JSONDecodeError:
            return output
    return None

def find_auth_blocks(data, source="code", findings=None):
    if findings is None:
        findings = []

    if isinstance(data, dict):
        auth_block = data.get("authentication")
        if (auth_block and auth_block.get("type") == "ActiveDirectoryOAuth" and
            "tenant" in auth_block and "clientId" in auth_block and "secret" in auth_block):
            secret = auth_block["secret"]
            if (isinstance(secret, str) and
                (secret.startswith('@appsetting(') or secret.startswith('@body(') or
                 secret.startswith('@parameters(') or '@{body(' in secret)):
                return findings
            tenant = auth_block["tenant"]
            client_id = auth_block["clientId"]
            findings.append(f"Authentication block in {source}: tenant={tenant}, clientId={client_id}, secret={secret}")
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

    subscription_ids = set(re.findall(subscription_pattern, data_str))
    header_guids = set(match[1] for match in re.findall(header_pattern, data_str))

    for info_type, pattern in patterns.items():
        matches = re.finditer(pattern, data_str)
        for match in matches:
            full_match = match.group(0)
            value = match.group(1) if match.groups() else full_match.strip('"')
            clean_value = value.strip('"')
            if (clean_value.startswith('@appsetting(') or clean_value.startswith('@body(') or
                clean_value.startswith('@parameters(') or '@{body(' in clean_value):
                continue
            if (clean_value and
                (info_type != "Client ID" or (clean_value not in subscription_ids and clean_value not in header_guids))):
                findings.append(f"{info_type} found in {source}: {full_match}")

    standalone_secret_pattern = r'"[-_~A-Za-z0-9]{20,}"'
    for match in re.finditer(standalone_secret_pattern, data_str):
        value = match.group(0).strip('"')
        if (value.startswith('@appsetting(') or value.startswith('@body(') or
            value.startswith('@parameters(') or '@{body(' in value):
            continue
        if (re.search(r'[0-9]', value) and re.search(r'[a-zA-Z]', value) and
            not any(keyword in value for keyword in exclude_keywords) and
            value not in subscription_ids and value not in header_guids):
            findings.append(f"Potential Secret found in {source}: {match.group(0)}")

    return findings
