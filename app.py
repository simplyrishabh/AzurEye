import json
import os
import sqlite3
import subprocess
import time
from datetime import datetime
from flask import Flask, render_template, Response, request, jsonify, send_file
from io import BytesIO
from collections import defaultdict
from modules.keyvaults import register_routes as register_keyvaults_routes
from modules.storage import register_routes as register_storage_routes
from modules.logicapp_standard import register_routes as register_logicapp_standard_routes
from modules.functionapp import register_routes as register_functionapp_routes
from modules.logicapp_consumption import register_routes as register_logicapp_consumption_routes
from modules.service_principal_roles import register_routes as register_service_principal_roles_routes
from modules.automation import register_routes as register_automation_routes
from utils.az_cli_utils import run_az_command, get_current_user_principal_id, get_role_assignments

app = Flask(__name__)

def init_db():
    conn = sqlite3.connect('azurEye.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS scan_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        subscription_id TEXT,
        service_type TEXT,
        service_name TEXT,
        has_findings INTEGER,
        timestamp TEXT,
        UNIQUE(subscription_id, service_type, service_name)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS stats_cache (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        stats_json TEXT,
        timestamp TEXT
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS vulnerability_findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        subscription_id TEXT,
        service_type TEXT,
        service_name TEXT,
        resource_group TEXT,
        vulnerability_title TEXT,
        category TEXT,
        description TEXT,
        code_snippet TEXT,
        recommendation TEXT,
        scan_timestamp TEXT,
        UNIQUE(subscription_id, service_type, service_name, vulnerability_title)
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS detailed_scan_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        subscription_id TEXT,
        service_type TEXT,
        service_name TEXT,
        resource_group TEXT,
        resource_name TEXT,
        resource_state TEXT,
        resource_type TEXT,
        findings_json TEXT,
        scan_timestamp TEXT,
        UNIQUE(subscription_id, service_type, service_name, resource_name)
    )''')
    
    conn.commit()
    conn.close()

init_db()

@app.route('/')
def index():
    try:
        conn = sqlite3.connect('azurEye.db')
        c = conn.cursor()
        c.execute('''
            SELECT subscription_id, service_type, service_name, has_findings, timestamp 
            FROM scan_results 
            ORDER BY timestamp DESC 
            LIMIT 5
        ''')
        basic_scans = c.fetchall()
        
        # Get detailed scan results for additional context
        c.execute('''
            SELECT subscription_id, service_type, service_name, resource_group, resource_name, 
                   resource_state, resource_type, findings_json, scan_timestamp
            FROM detailed_scan_results 
            ORDER BY scan_timestamp DESC 
            LIMIT 5
        ''')
        detailed_scans = c.fetchall()
        
        recent_scans = []
        for row in basic_scans:
            subscription_id, service_type, service_name, has_findings, timestamp = row
            
            # Find corresponding detailed scan data
            detailed_data = None
            for detail_row in detailed_scans:
                if (detail_row[0] == subscription_id and 
                    detail_row[1] == service_type and 
                    detail_row[2] == service_name):
                    detailed_data = {
                        'resource_group': detail_row[3],
                        'resource_name': detail_row[4],
                        'resource_state': detail_row[5],
                        'resource_type': detail_row[6],
                        'findings_json': detail_row[7],
                        'scan_timestamp': detail_row[8]
                    }
                    break
            
            # Count findings if available
            findings_count = 0
            if detailed_data and detailed_data['findings_json']:
                try:
                    findings = json.loads(detailed_data['findings_json'])
                    findings_count = len([f for f in findings if 'No Sensitive Data Found' not in f and 'No access granted' not in f])
                except:
                    findings_count = 0
            
            scan_data = {
                "subscription_id": subscription_id,
                "service_type": service_type,
                "service_name": service_name,
                "has_findings": bool(has_findings),
                "timestamp": timestamp,
                "findings_count": findings_count,
                "detailed_data": detailed_data
            }
            recent_scans.append(scan_data)
        
        # Calculate quick statistics for recent activity
        total_recent_scans = len(recent_scans)
        recent_with_findings = len([s for s in recent_scans if s['has_findings']])
        total_recent_findings = sum(s['findings_count'] for s in recent_scans)
        
        conn.close()
        
        return render_template('index.html', 
                             recent_scans=recent_scans,
                             recent_stats={
                                 'total_scans': total_recent_scans,
                                 'scans_with_findings': recent_with_findings,
                                 'total_findings': total_recent_findings
                             })
    except Exception as e:
        print(f"Error rendering index.html: {e}")
        return "Error: Could not load the home page.", 500

@app.route('/fetch_stats', methods=['GET'])
def fetch_stats():
    try:
        az_check = run_az_command("az --version")
        if not az_check:
            return jsonify({
                "status": "error", 
                "message": "Azure CLI not installed or not available",
                "stats": {
                    "subscriptions": 0,
                    "keyvaults": 0,
                    "storage": 0,
                    "logicapps": 0,
                    "logicapps_consumption": 0,
                    "functionapps": 0,
                    "automationaccounts": 0
                },
                "error_type": "azure_cli_missing"
            })
        
        try:
            account_info = run_az_command("az account show")
            if not account_info:
                return jsonify({
                    "status": "error",
                    "message": "Not logged in to Azure. Please run 'az login' first.",
                    "stats": {
                        "subscriptions": 0,
                        "keyvaults": 0,
                        "storage": 0,
                        "logicapps": 0,
                        "logicapps_consumption": 0,
                        "functionapps": 0,
                        "automationaccounts": 0
                    },
                    "error_type": "azure_not_logged_in"
                })
        except:
            return jsonify({
                "status": "error",
                "message": "Azure authentication failed. Please run 'az login' first.",
                "stats": {
                    "subscriptions": 0,
                    "keyvaults": 0,
                    "storage": 0,
                    "logicapps": 0,
                    "logicapps_consumption": 0,
                    "functionapps": 0,
                    "automationaccounts": 0
                },
                "error_type": "azure_auth_failed"
            })

        # Check if stats are already in the database (but only if Azure CLI is working)
        cached_stats = get_stats_from_db()
        if cached_stats and any(v > 0 for v in cached_stats.values()):
            return jsonify({"status": "success", "stats": cached_stats})

        # Calculate stats if not cached or if cached stats are all zeros
        print("Calculating fresh stats from Azure...")
        subscriptions = get_subscriptions()
        if not subscriptions:
            return jsonify({
                "status": "error",
                "message": "No subscriptions found or access denied",
                "stats": {
                    "subscriptions": 0,
                    "keyvaults": 0,
                    "storage": 0,
                    "logicapps": 0,
                    "logicapps_consumption": 0,
                    "functionapps": 0,
                    "automationaccounts": 0
                },
                "error_type": "no_subscriptions"
            })
        
        stats = {
            "subscriptions": len(subscriptions),
            "keyvaults": sum(len(get_keyvaults(sub["id"])) for sub in subscriptions),
            "storage": sum(len(get_storage_accounts(sub["id"])) for sub in subscriptions),
            "logicapps": sum(len(get_standard_logic_apps(sub["id"])) for sub in subscriptions),
            "logicapps_consumption": sum(len(get_consumption_logic_apps(sub["id"])) for sub in subscriptions),
            "functionapps": sum(len(get_function_apps(sub["id"])) for sub in subscriptions),
            "automationaccounts": sum(len(get_automation_accounts(sub["id"])) for sub in subscriptions)
        }
        
        print(f"Calculated stats: {stats}")
        
        # Save stats to database
        save_stats_to_db(stats)
        return jsonify({"status": "success", "stats": stats})
    except Exception as e:
        print(f"Error fetching stats: {e}")
        return jsonify({
            "status": "error", 
            "message": str(e),
            "stats": {
                "subscriptions": 0,
                "keyvaults": 0,
                "storage": 0,
                "logicapps": 0,
                "logicapps_consumption": 0,
                "functionapps": 0,
                "automationaccounts": 0
            },
            "error_type": "general_error"
        }), 500

@app.route('/dashboard')
def dashboard():
    try:
        # Calculate stats for the dashboard from the database
        scan_stats = get_scan_stats()
        
        # Try to get subscriptions, but handle the case where it fails
        try:
            subscriptions = get_subscriptions()
            subscription_count = len(subscriptions)
        except Exception as e:
            print(f"Warning: Could not fetch subscriptions: {e}")
            subscription_count = 0
        
        # Check if any scans have been performed
        total_scanned = sum(scan_stats["scanned"].values())
        has_scans = total_scanned > 0
        
        stats = {
            "subscriptions": subscription_count,
            "keyvaults": scan_stats["scanned"]["Key Vault"],
            "storage": scan_stats["scanned"]["Storage Account"],
            "logicapps": scan_stats["scanned"]["Logic App Standard"],
            "logicapps_consumption": scan_stats["scanned"]["Logic App Consumption"],
            "functionapps": scan_stats["scanned"]["Function App"],
            "automationaccounts": scan_stats["scanned"]["Automation Account"],
            "keyvaults_findings": scan_stats["findings"]["Key Vault"],
            "storage_findings": scan_stats["findings"]["Storage Account"],
            "logicapps_findings": scan_stats["findings"]["Logic App Standard"],
            "logicapps_consumption_findings": scan_stats["findings"]["Logic App Consumption"],
            "functionapps_findings": scan_stats["findings"]["Function App"],
            "automationaccounts_findings": scan_stats["findings"]["Automation Account"],
            "has_scans": has_scans,
            "total_scanned": total_scanned
        }
        # Get resource distribution data
        resource_distribution = get_resource_distribution()
        
        return render_template('dashboard.html', stats=stats, scan_stats=scan_stats, resource_distribution=resource_distribution)
    except Exception as e:
        print(f"Error rendering dashboard.html: {e}")
        import traceback
        traceback.print_exc()
        return "Error: Could not load the dashboard.", 500

# General Data Functions
def get_subscriptions():
    try:
        return json.loads(run_az_command("az account list --query '[].{id:id, name:name}' -o json") or "[]")
    except Exception as e:
        print(f"Error fetching subscriptions: {e}")
        return []

def get_user_details():
    try:
        return json.loads(run_az_command("az ad signed-in-user show -o json") or "{}")
    except Exception as e:
        print(f"Error fetching user details: {e}")
        return {}

# Placeholder functions for stats (to be replaced by actual module functions)
def get_keyvaults(subscription):
    try:
        output = run_az_command(f"az keyvault list --subscription {subscription} --query '[].{{name:name, resourceGroup:resourceGroup}}' -o json")
        return json.loads(output) if output else []
    except Exception as e:
        print(f"Error fetching key vaults for subscription {subscription}: {e}")
        return []

def get_storage_accounts(subscription):
    try:
        output = run_az_command(f"az storage account list --subscription {subscription} --query '[].{{name:name, resourceGroup:resourceGroup}}' -o json")
        return json.loads(output) if output else []
    except Exception as e:
        print(f"Error fetching storage accounts for subscription {subscription}: {e}")
        return []

def get_standard_logic_apps(subscription):
    try:
        output = run_az_command(f"az logicapp list --subscription {subscription} -o json")
        apps = json.loads(output) if output else []
        # Filter for standard apps (might need refinement based on actual output)
        standard_apps = [app for app in apps if 'Kind' not in app or app.get('kind') != 'consumption'] # Simple check, adjust if needed
        return [{"name": app["name"], "resourceGroup": app["resourceGroup"], "plan": "Standard"} for app in standard_apps]
    except Exception as e:
        print(f"Error fetching standard logic apps for subscription {subscription}: {e}")
        return []

def get_function_apps(subscription):
    try:
        output = run_az_command(f"az functionapp list --subscription {subscription} -o json")
        apps = json.loads(output) if output else []
        return [{"name": app["name"], "resourceGroup": app["resourceGroup"]} for app in apps]
    except Exception as e:
        print(f"Error fetching function apps for subscription {subscription}: {e}")
        return []

def get_consumption_logic_apps(subscription):
    try:
        # Consumption Logic Apps are often retrieved differently, e.g., via REST or checking 'kind'
        # Assuming `az logic workflow list` might be better or use the existing REST call
        command = f"az rest --method GET --uri '/subscriptions/{subscription}/providers/Microsoft.Logic/workflows?api-version=2016-06-01' -o json"
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=60)
        if result.returncode == 0 and result.stdout:
            data = json.loads(result.stdout)
            # Filter for Consumption plan based on the 'sku' or lack of 'plan' property maybe
            apps = [{"name": w["name"], "resourceGroup": w["id"].split('/')[4], "plan": "Consumption"}
                    for w in data.get("value", []) if w.get("kind") == "Stateful" or w.get("kind") == "Stateless"] # Adjust kind filter as needed
                    # Alternative: Filter based on sku if available: if w.get("sku", {}).get("name") == "Consumption"
            return apps
        else:
            print(f"Error fetching consumption logic apps for subscription {subscription}: {result.stderr}")
            return []
    except subprocess.TimeoutExpired:
        print(f"Consumption logic apps fetch timed out for subscription {subscription}")
        return []
    except Exception as e:
        print(f"Error fetching consumption logic apps for subscription {subscription}: {str(e)}")
        return []

# *** ADDED FUNCTION ***
def get_automation_accounts(subscription):
    """Fetches automation accounts for a given subscription."""
    try:
        output = run_az_command(f"az automation account list --subscription {subscription} --query '[].{{name:name, resourceGroup:resourceGroup}}' -o json")
        return json.loads(output) if output else []
    except Exception as e:
        print(f"Error fetching automation accounts for subscription {subscription}: {e}")
        return []

# Database Functions
def save_scan_result(subscription_id, service_type, service_name, has_findings):
    conn = None # Initialize conn to None
    try:
        conn = sqlite3.connect('azurEye.db')
        c = conn.cursor()
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        c.execute('''INSERT OR REPLACE INTO scan_results (subscription_id, service_type, service_name, has_findings, timestamp)
                       VALUES (?, ?, ?, ?, ?)''',
                  (subscription_id, service_type, service_name, has_findings, timestamp))
        conn.commit()
        print(f"Saved scan result: subscription_id={subscription_id}, service_type={service_type}, service_name={service_name}, has_findings={has_findings}")
    except Exception as e:
        print(f"Error saving scan result to database: {e}")
    finally:
        if conn:
            conn.close()

def save_stats_to_db(stats):
    conn = None # Initialize conn to None
    try:
        conn = sqlite3.connect('azurEye.db')
        c = conn.cursor()
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        stats_json = json.dumps(stats)
         # Always use ID 1 for the single cache entry
        c.execute('''INSERT OR REPLACE INTO stats_cache (id, stats_json, timestamp)
                       VALUES (1, ?, ?)''', (stats_json, timestamp))
        conn.commit()
        print(f"Saved stats to database: {stats}")
    except Exception as e:
        print(f"Error saving stats to database: {e}")
    finally:
        if conn:
            conn.close()

def get_stats_from_db():
    conn = None # Initialize conn to None
    try:
        conn = sqlite3.connect('azurEye.db')
        c = conn.cursor()
        c.execute('SELECT stats_json FROM stats_cache WHERE id = 1') # Fetch the specific cache entry
        result = c.fetchone()
        if result and result[0]:
            # *** ADDED CHECK *** Ensure automationaccounts key exists before returning
            stats_data = json.loads(result[0])
            if 'automationaccounts' in stats_data:
                 print("Returning cached stats from DB.")
                 return stats_data
            else:
                 print("Cached stats missing 'automationaccounts' key. Will recalculate.")
                 return None # Force recalculation if the key is missing
        return None
    except Exception as e:
        print(f"Error retrieving stats from database: {e}")
        return None
    finally:
        if conn:
            conn.close()

def get_scan_stats():
    conn = None # Initialize conn to None
    try:
        conn = sqlite3.connect('azurEye.db')
        c = conn.cursor()
        # Count unique scanned services by type
        c.execute('SELECT service_type, COUNT(DISTINCT service_name) as scanned FROM scan_results GROUP BY service_type')
        scanned = dict(c.fetchall())
        # Count unique services with findings by type
        c.execute('SELECT service_type, COUNT(DISTINCT service_name) as findings FROM scan_results WHERE has_findings = 1 GROUP BY service_type')
        findings = dict(c.fetchall())
        # Debug: Print all scan results
        # c.execute('SELECT * FROM scan_results')
        # all_results = c.fetchall()
        # print(f"All scan results in database: {all_results}")

        return {
            "scanned": {
                "Key Vault": scanned.get("Key Vault", 0),
                "Storage Account": scanned.get("Storage Account", 0),
                "Logic App Standard": scanned.get("Logic App Standard", 0),
                "Logic App Consumption": scanned.get("Logic App Consumption", 0),
                "Function App": scanned.get("Function App", 0),
                "Automation Account": scanned.get("Automation Account", 0) # Ensure this key exists
            },
            "findings": {
                "Key Vault": findings.get("Key Vault", 0),
                "Storage Account": findings.get("Storage Account", 0),
                "Logic App Standard": findings.get("Logic App Standard", 0),
                "Logic App Consumption": findings.get("Logic App Consumption", 0),
                "Function App": findings.get("Function App", 0),
                "Automation Account": findings.get("Automation Account", 0) # Ensure this key exists
            }
        }
    except Exception as e:
        print(f"Error retrieving scan stats: {e}")
        # Return structure with all keys, even if zero
        return {
            "scanned": {"Key Vault": 0, "Storage Account": 0, "Logic App Standard": 0, "Logic App Consumption": 0, "Function App": 0, "Automation Account": 0},
            "findings": {"Key Vault": 0, "Storage Account": 0, "Logic App Standard": 0, "Logic App Consumption": 0, "Function App": 0, "Automation Account": 0}
        }
    finally:
         if conn:
             conn.close()

def get_service_details():
    conn = None
    try:
        conn = sqlite3.connect('azurEye.db')
        c = conn.cursor()
        c.execute('SELECT service_type, service_name, has_findings FROM scan_results')
        results = c.fetchall()

        # Organize by service type
        service_details = defaultdict(lambda: {"scanned": set(), "with_findings": set()})
        for service_type, service_name, has_findings in results:
            service_details[service_type]["scanned"].add(service_name)
            if has_findings:
                service_details[service_type]["with_findings"].add(service_name)

        # Convert sets back to lists for JSON serialization
        final_details = {
            stype: {"scanned": sorted(list(details["scanned"])), "with_findings": sorted(list(details["with_findings"]))}
            for stype, details in service_details.items()
        }
        return final_details
    except Exception as e:
        print(f"Error retrieving service details: {e}")
        return {}
    finally:
        if conn:
            conn.close()

def get_scan_summary():
    conn = None
    try:
        conn = sqlite3.connect('azurEye.db')
        c = conn.cursor()
        c.execute('SELECT COUNT(*) FROM scan_results')
        total_scans = c.fetchone()[0] or 0
        c.execute('SELECT COUNT(*) FROM scan_results WHERE has_findings = 1')
        total_findings = c.fetchone()[0] or 0
        return {"total_scans": total_scans, "total_findings": total_findings}
    except Exception as e:
        print(f"Error retrieving scan summary: {e}")
        return {"total_scans": 0, "total_findings": 0}
    finally:
        if conn:
            conn.close()

def get_resource_distribution():
    conn = None
    try:
        conn = sqlite3.connect('azurEye.db')
        c = conn.cursor()
        c.execute('SELECT subscription_id, COUNT(DISTINCT service_name) as resource_count FROM scan_results GROUP BY subscription_id')
        results = c.fetchall()

        # Fetch subscription names
        subscription_map = {sub['id']: sub['name'] for sub in get_subscriptions()}
        labels = []
        data = []
        backgroundColors = ['#00BCD4', '#10B981', '#F59E0B', '#8B5CF6', '#EF4444', '#6B7280'] # Add more if needed
        borderColors = ['#00ACC1', '#059669', '#D97706', '#7C3AED', '#B91C1C', '#4B5563'] # Add more if needed

        for i, (sub_id, count) in enumerate(results):
            sub_name = subscription_map.get(sub_id, f"Unknown Sub ({sub_id[:8]}...)") # Handle unknown subs
            labels.append(sub_name)
            data.append(count)

        # Ensure enough colors, repeat if necessary
        num_results = len(labels)
        final_bg_colors = (backgroundColors * (num_results // len(backgroundColors) + 1))[:num_results]
        final_border_colors = (borderColors * (num_results // len(borderColors) + 1))[:num_results]


        return {
            "labels": labels,
            "data": data,
            "backgroundColors": final_bg_colors,
            "borderColors": final_border_colors
        }
    except Exception as e:
        print(f"Error retrieving resource distribution: {e}")
        return {"labels": [], "data": [], "backgroundColors": [], "borderColors": []}
    finally:
        if conn:
            conn.close()


# Reset database
@app.route('/reset_database', methods=['POST'])
def reset_database():
    conn = None
    try:
        conn = sqlite3.connect('azurEye.db')
        c = conn.cursor()
        c.execute('DELETE FROM scan_results')
        c.execute('DELETE FROM stats_cache') # Clear cache as well
        conn.commit()
        print("Database reset successfully")
        return jsonify({"status": "success", "message": "Database reset successfully"})
    except Exception as e:
        print(f"Error resetting database: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500
    finally:
        if conn:
            conn.close()

# Export dashboard to HTML
@app.route('/visual_data')
def visual_data():
    """Interactive Visual Data Representation with drag-and-drop vulnerability visualization"""
    try:
        from visualization_db import get_all_vulnerability_data
        
        # Get all vulnerability data from visualization database
        vulnerability_data = get_all_vulnerability_data()
        
        # Organize data by service type and categories
        visual_data = {}
        category_colors = {
            'Main Code': '#FF6B6B',      # Red
            'Parameters': '#4ECDC4',     # Teal
            'Version History': '#45B7D1', # Blue
            'Run History': '#96CEB4',    # Green
            'App Settings': '#FFEAA7',   # Yellow
            'App Keys': '#DDA0DD',       # Plum
            'App Files': '#98D8C8',      # Mint
            'Secrets': '#F7DC6F',        # Light Yellow
            'Keys': '#BB8FCE',           # Light Purple
            'Certificates': '#85C1E9',   # Light Blue
            'Sensitive Data': '#F8C471', # Orange
            'Access Privileges': '#82E0AA' # Light Green
        }
        
        for row in vulnerability_data:
            service_type, sub_id, rg, service_name, vuln_title, category, description, code_snippet, recommendation, timestamp = row
            
            if service_type not in visual_data:
                visual_data[service_type] = {
                    'total_vulnerabilities': 0,
                    'categories': {},
                    'resources': {}
                }
            
            # Count by category
            if category not in visual_data[service_type]['categories']:
                visual_data[service_type]['categories'][category] = {
                    'count': 0,
                    'color': category_colors.get(category, '#95A5A6'),
                    'vulnerabilities': []
                }
            
            visual_data[service_type]['categories'][category]['count'] += 1
            visual_data[service_type]['categories'][category]['vulnerabilities'].append({
                'title': vuln_title,
                'description': description,
                'code_snippet': code_snippet,
                'recommendation': recommendation,
                'subscription_id': sub_id,
                'resource_group': rg,
                'service_name': service_name,
                'timestamp': timestamp
            })
            
            # Count by resource
            resource_key = f"{sub_id}/{rg}/{service_name}"
            if resource_key not in visual_data[service_type]['resources']:
                visual_data[service_type]['resources'][resource_key] = {
                    'subscription_id': sub_id,
                    'resource_group': rg,
                    'service_name': service_name,
                    'vulnerability_count': 0,
                    'categories': set()
                }
            
            visual_data[service_type]['resources'][resource_key]['vulnerability_count'] += 1
            visual_data[service_type]['resources'][resource_key]['categories'].add(category)
            visual_data[service_type]['total_vulnerabilities'] += 1
        
        # Convert sets to lists for JSON serialization
        for service_type in visual_data:
            for resource_key in visual_data[service_type]['resources']:
                visual_data[service_type]['resources'][resource_key]['categories'] = list(
                    visual_data[service_type]['resources'][resource_key]['categories']
                )
        
        return render_template('visual_data_tree.html', visual_data=visual_data, category_colors=category_colors)
    except Exception as e:
        print(f"Error loading visual data: {e}")
        import traceback
        traceback.print_exc()
        return "Error: Could not load the visual data.", 500

@app.route('/export_logicapp_standard', methods=['POST'])
def export_logicapp_standard():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        # Generate HTML report using the proper function
        from utils.report_utils import generate_html_report, save_html_report
        
        # Create HTML report content
        html_content = generate_html_report("Logic App Standard", data)
        
        # Save HTML report to reports folder
        filepath, filename = save_html_report(html_content, "Logic App Standard")
        
        return jsonify({
            "success": True,
            "message": f"HTML report exported to {filename}",
            "filename": filename
        })
        
    except Exception as e:
        print(f"Error exporting Logic App Standard report: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/export_dashboard_to_html', methods=['POST'])
def export_dashboard_to_html():
    try:
        # Generate comprehensive dashboard report with all scan results
        from utils.report_utils import generate_dashboard_report, save_html_report
        
        # Fetch all scan data from database
        scan_stats = get_scan_stats()
        service_details = get_service_details()
        user_details = get_user_details()
        subscriptions = get_subscriptions()
        scan_summary = get_scan_summary()
        resource_distribution = get_resource_distribution()

        # For now, create a simple test report with actual vulnerability data
        # TODO: Fix the complex data collection issue
        
        # Get vulnerability data from database (preferred) or fallback to files
        all_vulnerabilities = []
        try:
            conn = sqlite3.connect('azurEye.db')
            cursor = conn.cursor()
            
            # First, try to get detailed scan results from database
            cursor.execute("""
                SELECT subscription_id, service_type, service_name, resource_group, 
                       resource_name, resource_state, resource_type, findings_json, scan_timestamp
                FROM detailed_scan_results 
                ORDER BY scan_timestamp DESC
            """)
            
            detailed_results = cursor.fetchall()
            
            if detailed_results:
                # Use database results
                for row in detailed_results:
                    subscription_id, service_type, service_name, resource_group, resource_name, resource_state, resource_type, findings_json, scan_timestamp = row
                    
                    try:
                        findings = json.loads(findings_json) if findings_json else []
                        
                        # Filter out "No Sensitive Data Found" and "No access granted" - these are not vulnerabilities
                        actual_findings = [f for f in findings if 'No Sensitive Data Found' not in f and 'No access granted' not in f]
                        
                        if actual_findings:  # Only create vulnerability if there are actual findings
                            findings_text = f"Resource: {resource_name} ({resource_state}, {resource_type})\n"
                            findings_text += '\n'.join(actual_findings[:10])  # Show first 10 findings
                            if len(actual_findings) > 10:
                                findings_text += f'\n... and {len(actual_findings) - 10} more findings'
                            
                            all_vulnerabilities.append({
                                'title': f'{service_type} Security Issue',
                                'category': 'Security Finding',
                                'resource_name': f"{service_name} - {resource_name}",
                                'resource_group': resource_group or 'N/A',
                                'subscription_id': subscription_id,
                                'description': f'Security issues found in {service_type.lower()} resource "{resource_name}" in {service_name}. Resource state: {resource_state}.',
                                'code_snippet': findings_text,
                                'recommendation': f'Review {service_type} security configuration and follow best practices for {service_type.lower()} security.'
                            })
                    except Exception as e:
                        print(f"Error processing detailed result for {resource_name}: {e}")
            
            else:
                # Fallback to reading from files (for backward compatibility)
                cursor.execute("""
                    SELECT DISTINCT sr.subscription_id, sr.service_type, sr.service_name, sr.timestamp
                    FROM scan_results sr
                    WHERE sr.has_findings = 1
                    ORDER BY sr.timestamp DESC
                """)
                
                current_scan_results = cursor.fetchall()
                
                for row in current_scan_results:
                    subscription_id, service_type, service_name, scan_timestamp = row
                    
                    # Try to read the actual scan result file to get detailed findings
                    detailed_findings = []
                    resource_group = 'N/A'
                    
                    try:
                        # Map service type to directory name
                        service_dir_map = {
                            'Automation Account': 'automation',
                            'Function App': 'functionapp', 
                            'Key Vault': 'keyvault',
                            'Logic App Consumption': 'logicapp_consumption',
                            'Logic App Standard': 'logicapp_standard',
                            'Storage Account': 'storage'
                        }
                        
                        service_dir = service_dir_map.get(service_type, service_type.lower().replace(' ', '_'))
                        result_file_path = f"results/{service_dir}/{subscription_id}/{service_name}.txt.txt"
                        
                        if os.path.exists(result_file_path):
                            with open(result_file_path, 'r', encoding='utf-8') as f:
                                content = f.read()
                                
                            # Extract resource group from file path or content
                            if "/" in service_name:
                                parts = service_name.split("/")
                                if len(parts) > 1:
                                    resource_group = parts[0]
                                    service_name = parts[1]
                            
                            # Extract general findings
                            lines = content.split('\n')
                            for line in lines:
                                if any(keyword in line.lower() for keyword in ['sensitive', 'password', 'secret', 'key', 'guid', 'hardcoded', 'access', 'privilege']):
                                    # Filter out "No Sensitive Data Found" and "No access granted" - these are not vulnerabilities
                                    if 'No Sensitive Data Found' not in line and 'No access granted' not in line:
                                        detailed_findings.append(line.strip())
                                    
                    except Exception as e:
                        print(f"Error reading scan result file for {service_name}: {e}")
                    
                    # Create vulnerability entry
                    if detailed_findings:
                        findings_text = '\n'.join(detailed_findings[:10])  # Show first 10 findings
                        if len(detailed_findings) > 10:
                            findings_text += f'\n... and {len(detailed_findings) - 10} more findings'
                    else:
                        findings_text = f'Security issues detected in {service_type}: {service_name}'
                    
                    all_vulnerabilities.append({
                        'title': f'{service_type} Security Issue',
                        'category': 'Security Finding',
                        'resource_name': service_name,
                        'resource_group': resource_group,
                        'subscription_id': subscription_id,
                        'description': f'Security issues detected in {service_type}: {service_name}. Scanned on {scan_timestamp}.',
                        'code_snippet': findings_text,
                        'recommendation': f'Review {service_type} security configuration and follow best practices for {service_type.lower()} security.'
                    })
            
            conn.close()
                
        except Exception as e:
            print(f"Error getting current scan data: {e}")
        
        # Calculate actual totals from database
        try:
            conn = sqlite3.connect('azurEye.db')
            cursor = conn.cursor()
            
            # Get total resources scanned
            cursor.execute("SELECT COUNT(DISTINCT service_name) FROM scan_results")
            total_resources_scanned = cursor.fetchone()[0]
            
            # Get resources with findings
            cursor.execute("SELECT COUNT(DISTINCT service_name) FROM scan_results WHERE has_findings = 1")
            resources_with_findings = cursor.fetchone()[0]
            
            # Calculate secure resources (scanned but no findings)
            secure_resources = total_resources_scanned - resources_with_findings
            
            conn.close()
        except Exception as e:
            print(f"Error calculating totals from database: {e}")
            # Fallback to vulnerability count if database query fails
            total_resources_scanned = len(all_vulnerabilities)
            resources_with_findings = len(all_vulnerabilities)
            secure_resources = 0

        # Create simple report data
        report_data = {
            'report_title': 'AzurEye Comprehensive Security Report',
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'user_name': user_details.get('displayName', 'Unknown User'),
            'user_email': user_details.get('userPrincipalName', 'Unknown Email'),
            'total_resources': total_resources_scanned,
            'total_vulnerabilities': resources_with_findings,
            'secure_count': secure_resources,
            'total_subscriptions': len(subscriptions),
            'vulnerabilities': all_vulnerabilities
        }
        
        # Group vulnerabilities by service type for tabbed interface
        vulnerabilities_by_service = {}
        for vuln in all_vulnerabilities:
            service_type = vuln['title'].split(' Security Issue')[0]
            if service_type not in vulnerabilities_by_service:
                vulnerabilities_by_service[service_type] = []
            vulnerabilities_by_service[service_type].append(vuln)
        
        # Generate vulnerability cards HTML for each service type
        def generate_vulnerability_cards(vulns):
            if not vulns:
                return '<div class="no-issues"><i class="fas fa-check-circle text-4xl mb-4"></i><p>No security issues found in this service type!</p></div>'
            
            cards_html = ""
            for vuln in vulns:
                code_snippet_html = ""
                if vuln['code_snippet']:
                    code_snippet_html = f'<div class="code-snippet"><h4 class="text-white font-semibold mb-2"><i class="fas fa-code mr-2"></i>Detailed Findings:</h4><pre>{vuln["code_snippet"]}</pre></div>'
                
                cards_html += f'''
                <div class="vulnerability-card">
                    <div class="vulnerability-header">
                        <h3 class="text-xl font-bold text-gray-800">{vuln["title"]}</h3>
                        <span class="severity-badge">
                            <i class="fas fa-exclamation-triangle mr-1"></i>
                            Security Issue
                        </span>
                    </div>
                    
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                        <div>
                            <p class="text-gray-600"><strong>Resource Name:</strong> {vuln["resource_name"]}</p>
                            <p class="text-gray-600"><strong>Subscription:</strong> {vuln["subscription_id"]}</p>
                        </div>
                        <div>
                            <p class="text-gray-600"><strong>Category:</strong> {vuln["category"]}</p>
                            <p class="text-gray-600"><strong>Resource Group:</strong> {vuln["resource_group"]}</p>
                        </div>
                    </div>
                    
                    <p class="text-gray-700 mb-4">{vuln["description"]}</p>
                    
                    {code_snippet_html}
                    
                    <div class="recommendation">
                        <h4 class="font-bold text-green-800 mb-2">
                            <i class="fas fa-lightbulb mr-2"></i>Recommendation
                        </h4>
                        <p class="text-green-700">{vuln["recommendation"]}</p>
                    </div>
                </div>
                '''
            return cards_html

        # Generate tabbed HTML report
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{report_data['report_title']} - AzurEye Security Report</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        body {{ 
            font-family: 'Inter', sans-serif; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #1f2937; 
            line-height: 1.6; 
            margin: 0; 
            min-height: 100vh;
        }}
        .container {{ 
            max-width: 1400px; 
            margin: 0 auto; 
            padding: 2rem; 
        }}
        .header {{ 
            background: linear-gradient(135deg, #1e3a8a 0%, #3b82f6 100%); 
            color: white; 
            padding: 3rem 2rem; 
            text-align: center; 
            border-radius: 1rem 1rem 0 0; 
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
            margin-bottom: 2rem;
        }}
        .summary-cards {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }}
        .summary-card {{
            background: white;
            padding: 2rem;
            border-radius: 1rem;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.1);
            text-align: center;
            transition: transform 0.3s ease;
        }}
        .summary-card:hover {{
            transform: translateY(-5px);
        }}
        .summary-card h3 {{
            font-size: 2rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
        }}
        .summary-card.total {{ color: #3b82f6; }}
        .summary-card.issues {{ color: #ef4444; }}
        .summary-card.secure {{ color: #10b981; }}
        .summary-card.subscriptions {{ color: #8b5cf6; }}
        
        .tabs-container {{
            background: white;
            border-radius: 1rem;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
            overflow: hidden;
        }}
        .tabs-header {{
            display: flex;
            background: #f8fafc;
            border-bottom: 1px solid #e2e8f0;
            overflow-x: auto;
        }}
        .tab-button {{
            flex: 1;
            padding: 1rem 1.5rem;
            background: none;
            border: none;
            cursor: pointer;
            font-weight: 600;
            color: #64748b;
            transition: all 0.3s ease;
            white-space: nowrap;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0.5rem;
        }}
        .tab-button:hover {{
            background: #e2e8f0;
            color: #1e293b;
        }}
        .tab-button.active {{
            background: white;
            color: #1e3a8a;
            border-bottom: 3px solid #3b82f6;
        }}
        .tab-content {{
            display: none;
            padding: 2rem;
        }}
        .tab-content.active {{
            display: block;
        }}
        .service-summary {{
            background: linear-gradient(135deg, #f0f9ff 0%, #e0f2fe 100%);
            border: 1px solid #0ea5e9;
            border-radius: 0.75rem;
            padding: 1.5rem;
            margin-bottom: 2rem;
        }}
        .vulnerability-card {{ 
            background: linear-gradient(135deg, #fef2f2 0%, #fee2e2 100%); 
            border: 2px solid #fca5a5; 
            border-radius: 1rem; 
            padding: 2rem; 
            margin: 1.5rem 0; 
            transition: transform 0.3s ease;
        }}
        .vulnerability-card:hover {{
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(0, 0, 0, 0.1);
        }}
        .vulnerability-header {{
            display: flex;
            justify-content: between;
            align-items: center;
            margin-bottom: 1rem;
        }}
        .severity-badge {{
            background: linear-gradient(135deg, #fef3c7 0%, #fde68a 100%);
            color: #92400e;
            padding: 0.5rem 1rem;
            border-radius: 2rem;
            font-size: 0.875rem;
            font-weight: 600;
        }}
        .code-snippet {{
            background: #1f2937;
            color: #f9fafb;
            padding: 1.5rem;
            border-radius: 0.5rem;
            font-family: 'Monaco', 'Menlo', monospace;
            font-size: 0.875rem;
            line-height: 1.5;
            overflow-x: auto;
            margin: 1rem 0;
        }}
        .recommendation {{
            background: linear-gradient(135deg, #f0fdf4 0%, #dcfce7 100%);
            border: 1px solid #22c55e;
            border-radius: 0.75rem;
            padding: 1.5rem;
            margin-top: 1rem;
        }}
        .no-issues {{
            text-align: center;
            padding: 3rem;
            color: #10b981;
            font-size: 1.125rem;
        }}
        .service-icon {{
            width: 24px;
            height: 24px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1 class="text-4xl font-bold mb-4">
                <i class="fas fa-shield-alt mr-3"></i>
                {report_data['report_title']}
            </h1>
            <p class="text-lg opacity-90 mb-2">Comprehensive Azure Security Assessment</p>
            <p class="text-sm opacity-75">Generated on {report_data['timestamp']}</p>
            <div class="mt-4 flex justify-center gap-4 text-sm">
                <span><i class="fas fa-user mr-1"></i> {report_data['user_name']}</span>
                <span><i class="fas fa-envelope mr-1"></i> {report_data['user_email']}</span>
        </div>
        </div>

        <div class="summary-cards">
            <div class="summary-card total">
                <h3>{report_data['total_resources']}</h3>
                <p class="text-gray-600">Total Resources</p>
        </div>
            <div class="summary-card issues">
                <h3>{report_data['total_vulnerabilities']}</h3>
                <p class="text-gray-600">Resources with Issues</p>
            </div>
            <div class="summary-card secure">
                <h3>{report_data['secure_count']}</h3>
                <p class="text-gray-600">Secure Resources</p>
            </div>
            <div class="summary-card subscriptions">
                <h3>{report_data['total_subscriptions']}</h3>
                <p class="text-gray-600">Subscriptions</p>
            </div>
        </div>

        <div class="tabs-container">
            <div class="tabs-header">
                {''.join(f'''
                <button class="tab-button {'active' if i == 0 else ''}" onclick="showTab('{service_type.lower().replace(' ', '_')}')">
                    <i class="fas fa-{{
                        'cogs' if 'automation' in service_type.lower() else
                        'key' if 'key' in service_type.lower() else
                        'server' if 'function' in service_type.lower() else
                        'workflow' if 'logic' in service_type.lower() else
                        'database' if 'storage' in service_type.lower() else
                        'cloud'
                    }} service-icon"></i>
                    {service_type}
                    <span class="ml-2 bg-red-100 text-red-800 px-2 py-1 rounded-full text-xs">{len(vulns)}</span>
                </button>
                ''' for i, (service_type, vulns) in enumerate(vulnerabilities_by_service.items()))}
        </div>

            {''.join(f'''
            <div id="tab-{service_type.lower().replace(' ', '_')}" class="tab-content {'active' if i == 0 else ''}">
                <div class="service-summary">
                    <h2 class="text-2xl font-bold text-blue-900 mb-2">
                        <i class="fas fa-{{
                            'cogs' if 'automation' in service_type.lower() else
                            'key' if 'key' in service_type.lower() else
                            'server' if 'function' in service_type.lower() else
                            'workflow' if 'logic' in service_type.lower() else
                            'database' if 'storage' in service_type.lower() else
                            'cloud'
                        }} mr-2"></i>
                        {service_type} Security Assessment
                    </h2>
                    <p class="text-blue-700">
                        Found <strong>{len(vulns)} resources</strong> with security issues in {service_type.lower()}.
                        Review the findings below and follow the recommendations to improve security posture.
                    </p>
        </div>

                {generate_vulnerability_cards(vulns)}
                </div>
            ''' for i, (service_type, vulns) in enumerate(vulnerabilities_by_service.items()))}
        </div>
    </div>

    <script>
        function showTab(tabName) {{
            // Hide all tab contents
            const tabContents = document.querySelectorAll('.tab-content');
            tabContents.forEach(content => content.classList.remove('active'));
            
            // Remove active class from all tab buttons
            const tabButtons = document.querySelectorAll('.tab-button');
            tabButtons.forEach(button => button.classList.remove('active'));
            
            // Show selected tab content
            document.getElementById('tab-' + tabName).classList.add('active');
            
            // Add active class to clicked button
            event.target.classList.add('active');
        }}
        
        // Add smooth scrolling for better UX
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {{
            anchor.addEventListener('click', function (e) {{
                e.preventDefault();
                document.querySelector(this.getAttribute('href')).scrollIntoView({{
                    behavior: 'smooth'
                }});
            }});
        }});
    </script>
</body>
</html>
        """

        # Save the report
        filepath, filename = save_html_report(html_content, "AzurEye Dashboard Report")
        
        return jsonify({
            "status": "success", 
            "message": f"Comprehensive dashboard report generated successfully: {filename}",
            "filename": filename,
            "filepath": filepath
        })
    except Exception as e:
        print(f"Error generating dashboard report: {e}")
        return jsonify({"status": "error", "message": f"Failed to generate dashboard report: {str(e)}"}), 500

def save_vulnerability_findings(subscription_id, service_type, service_name, resource_group, vulnerability_title, category, description, code_snippet, recommendation):
    """Save detailed vulnerability findings to database"""
    try:
        conn = sqlite3.connect('azurEye.db')
        c = conn.cursor()
        c.execute('''
            INSERT OR REPLACE INTO vulnerability_findings 
            (subscription_id, service_type, service_name, resource_group, vulnerability_title, 
             category, description, code_snippet, recommendation, scan_timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (subscription_id, service_type, service_name, resource_group, vulnerability_title,
              category, description, code_snippet, recommendation, datetime.now().isoformat()))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error saving vulnerability findings: {e}")
        return False

def save_detailed_scan_results(subscription_id, service_type, service_name, resource_group, resource_name, resource_state, resource_type, findings_json):
    """Save detailed scan results (runbooks, specific findings) to database"""
    try:
        conn = sqlite3.connect('azurEye.db')
        c = conn.cursor()
        c.execute('''
            INSERT OR REPLACE INTO detailed_scan_results 
            (subscription_id, service_type, service_name, resource_group, resource_name, 
             resource_state, resource_type, findings_json, scan_timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (subscription_id, service_type, service_name, resource_group, resource_name,
              resource_state, resource_type, findings_json, datetime.now().isoformat()))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error saving detailed scan results: {e}")
        return False

def collect_all_scan_results():
    """Collect all scan results from database for comprehensive reporting"""
    try:
        conn = sqlite3.connect('azurEye.db')
        cursor = conn.cursor()
        
        # Get all scan results grouped by service type
        cursor.execute("""
            SELECT service_type, subscription_id, service_name, has_findings, scan_timestamp
            FROM scan_results 
            ORDER BY service_type, subscription_id, service_name
        """)
        
        results = cursor.fetchall()
        
        # Get all detailed vulnerability findings
        cursor.execute("""
            SELECT subscription_id, service_type, service_name, resource_group, 
                   vulnerability_title, category, description, code_snippet, 
                   recommendation, scan_timestamp
            FROM vulnerability_findings 
            ORDER BY service_type, subscription_id, service_name, vulnerability_title
        """)
        
        vulnerability_results = cursor.fetchall()
        conn.close()
        
        # Organize results by service type
        organized_results = {}
        for row in results:
            service_type, subscription_id, service_name, has_findings, scan_timestamp = row
            
            if service_type not in organized_results:
                organized_results[service_type] = {
                    'subscriptions': {},
                    'total_scanned': 0,
                    'total_with_findings': 0
                }
            
            if subscription_id not in organized_results[service_type]['subscriptions']:
                organized_results[service_type]['subscriptions'][subscription_id] = {
                    'services': {},
                    'scanned': 0,
                    'with_findings': 0
                }
            
            organized_results[service_type]['subscriptions'][subscription_id]['services'][service_name] = {
                'has_findings': bool(has_findings),
                'scan_timestamp': scan_timestamp,
                'vulnerabilities': []
            }
            
            organized_results[service_type]['subscriptions'][subscription_id]['scanned'] += 1
            organized_results[service_type]['total_scanned'] += 1
            
            if has_findings:
                organized_results[service_type]['subscriptions'][subscription_id]['with_findings'] += 1
                organized_results[service_type]['total_with_findings'] += 1
        
        # Add detailed vulnerability findings
        for row in vulnerability_results:
            subscription_id, service_type, service_name, resource_group, vulnerability_title, category, description, code_snippet, recommendation, scan_timestamp = row
            
            if service_type in organized_results and subscription_id in organized_results[service_type]['subscriptions']:
                if service_name in organized_results[service_type]['subscriptions'][subscription_id]['services']:
                    vulnerability = {
                        'title': vulnerability_title,
                        'category': category,
                        'resource_group': resource_group,
                        'description': description,
                        'code_snippet': code_snippet,
                        'recommendation': recommendation,
                        'scan_timestamp': scan_timestamp
                    }
                    organized_results[service_type]['subscriptions'][subscription_id]['services'][service_name]['vulnerabilities'].append(vulnerability)
        
        return organized_results
        
    except Exception as e:
        print(f"Error collecting scan results: {e}")
        return {}

@app.route('/reports/<filename>')
def serve_report(filename):
    """Serve generated HTML reports"""
    try:
        reports_dir = os.path.join(os.getcwd(), 'reports')
        filepath = os.path.join(reports_dir, filename)
        
        if os.path.exists(filepath):
            return send_file(filepath, as_attachment=True)
        else:
            return jsonify({"error": "Report not found"}), 404
    except Exception as e:
        print(f"Error serving report: {e}")
        return jsonify({"error": "Failed to serve report"}), 500

@app.route('/role_assignments')
def role_assignments():
    # Render immediately with empty data, fetch real data asynchronously
    return render_template('role_assignments.html', role_assignments=[], loading=True)

@app.route('/get_role_assignments')
def get_role_assignments_endpoint():
    try:
        role_assignments_data = get_role_assignments(get_current_user_principal_id()) if get_current_user_principal_id() else []

        # Add capabilities mapping
        capabilities_map = {
            # Privileged roles
            "Contributor": ["Grants full access to manage all resources, but does not allow you to assign roles in Azure RBAC, manage assignments in Azure Blueprints, or share image galleries"],
            "Owner": ["Grants full access to manage all resources, including the ability to assign roles in Azure RBAC"],
            "Role Based Access Control Administrator": ["Manage access to Azure resources by assigning roles using Azure RBAC. This role does not allow you to manage access using other ways, such as Azure Policy"],
            "User Access Administrator": ["Lets you manage user access to Azure resources"],
            
            # General roles
            "Reader": ["View all resources, but does not allow you to make any changes"],
            
            # Key Vault roles
            "Key Vault Secrets User": ["List and read secret values"],
            "Key Vault Secrets Officer": ["List, read, and manage secret values"],
            "Key Vault Certificates Officer": ["List, read, and manage certificates"],
            "Key Vault Crypto Officer": ["List, read, and manage keys"],
            "Key Vault Crypto User": ["List and read keys"],
            "Key Vault Administrator": ["Full access to manage vaults, secrets, keys, and certificates"],
            "Key Vault Reader": ["Read metadata of vaults, secrets, keys, and certificates (control plane)"],
            "Key Vault Contributor": ["Manage vaults, but not access secrets/keys/certs unless other roles assigned"],
            "Key Vault Data Access Administrator": ["Full access to secrets, keys, and certificates (data plane - read, write, delete)"],
            "Key Vault Certificate User": ["List and read certificate values"],
            
            # Storage roles
            "Storage Blob Data Contributor": ["Read, write, and delete Azure Storage containers and blobs"],
            "Storage Blob Data Reader": ["Read and list Azure Storage containers and blobs"],
            "Storage Account Contributor": ["Manage storage accounts, but not access to data"],
            "Storage Account Key Operator Service Role": ["List and regenerate keys for Storage Accounts"],
            "Storage File Data SMB Share Contributor": ["Allows for read, write, and delete access in Azure Storage file shares over SMB"],
            "Storage File Data SMB Share Elevated Contributor": ["Allows for read, write, delete and modify NTFS permissions access in Azure Storage file shares over SMB"],
            "Storage File Data SMB Share Reader": ["Allows for read access to Azure Storage file shares over SMB"],
            "Storage Queue Data Contributor": ["Read, write, and delete Azure Storage queues and queue messages"],
            "Storage Queue Data Message Processor": ["Peek and retrieve one or more messages from an Azure Storage queue"],
            "Storage Queue Data Message Sender": ["Add messages to an Azure Storage queue"],
            "Storage Queue Data Reader": ["Read and list Azure Storage queues and queue messages"],
            "Storage Table Data Contributor": ["Read, write, and delete Azure Storage tables and entities"],
            "Storage Table Data Reader": ["Read and query Azure Storage tables and entities"],
            
            # Compute roles
            "Virtual Machine Contributor": ["Lets you manage virtual machines, but not access to them, and not the virtual network or storage account they're connected to"],
            "Classic Virtual Machine Contributor": ["Lets you manage classic virtual machines, but not access to them, and not the virtual network or storage account they're connected to"],
            "Virtual Machine Administrator Login": ["View Virtual Machines in the portal and login as administrator"],
            "Virtual Machine User Login": ["View Virtual Machines in the portal and login as a regular user"],
            "Azure Batch Account Contributor": ["Grants full access to manage all Batch resources, including Batch accounts, pools and jobs"],
            "Azure Batch Account Reader": ["Lets you view all resources including pools and jobs in the Batch account"],
            
            # Networking roles
            "Network Contributor": ["Lets you manage networks, but not access to them"],
            "DNS Zone Contributor": ["Lets you manage DNS zones and record sets in Azure DNS, but does not let you control who has access to them"],
            "Private DNS Zone Contributor": ["Lets you manage private DNS zone resources, but not the virtual networks they are linked to"],
            "Traffic Manager Contributor": ["Lets you manage Traffic Manager profiles, but does not let you control who has access to them"],
            
            # Database roles
            "SQL DB Contributor": ["Lets you manage SQL databases, but not access to them. Also, you can't manage their security-related policies or their parent SQL servers"],
            "SQL Server Contributor": ["Lets you manage SQL servers and databases, but not access to them, and not their security-related policies"],
            "SQL Security Manager": ["Lets you manage the security-related policies of SQL servers and databases, but not access to them"],
            "Redis Cache Contributor": ["Lets you manage Redis caches, but not access to them"],
            
            # Web roles
            "App Service Contributor": ["Lets you manage the App Service, but not access to them"],
            "App Service Plan Contributor": ["Lets you manage the App Service plans, but not access to them"],
            
            # Monitoring roles
            "Monitoring Contributor": ["Can read all monitoring data and edit monitoring settings"],
            "Monitoring Reader": ["Can read all monitoring data"],
            "Application Insights Component Contributor": ["Can manage Application Insights components"],
            "Log Analytics Contributor": ["Log Analytics Contributor can read all monitoring data and edit monitoring settings"],
            "Log Analytics Reader": ["Log Analytics Reader can view and search all monitoring data as well as and view monitoring settings"],
            
            # Security roles
            "Security Admin": ["Can view security policies and states, view security recommendations, and dismiss recommendations and policies"],
            "Security Reader": ["Can view security recommendations and alerts, view security policies, view security states, but cannot make changes"],
            "Security Center Contributor": ["Can view security policies, view security states, edit security policies, view alerts and recommendations, dismiss alerts and recommendations"],
            "Security Center Reader": ["Can view recommendations and alerts, view security policies, view security states, but cannot make changes"],
            
            # Backup roles
            "Backup Contributor": ["Lets you manage backup service, but can't create vaults and give access to others"],
            "Backup Operator": ["Lets you manage backup services, except removal of backup, vault creation and giving access to others"],
            "Backup Reader": ["Can view backup services, but can't make changes"],
            
            # Policy roles
            "Resource Policy Contributor": ["Users with rights to create/modify resource policy, create support ticket and read resources/hierarchy"],
            "Tag Contributor": ["Lets you manage tags on entities, without providing access to the entities themselves"],
            
            # Support roles
            "Support Request Contributor": ["Lets you create and manage Support requests"],
            "Billing Reader": ["Allows read access to billing data"],
            "Billing Contributor": ["Allows read access to billing data and makes it possible to perform charges"],
            
            # Identity roles
            "Managed Identity Contributor": ["Create, read, update, and delete user assigned managed identity"],
            "Managed Identity Operator": ["Read and assign user assigned managed identity"],
            "User Administrator": ["Can manage all aspects of users and groups, including resetting passwords for limited admins"],
            "Global Administrator": ["Can manage all aspects of Azure AD and Microsoft services that use Azure AD identities"],
            "Global Reader": ["Can read everything that a Global Administrator can, but not update anything"],
            "Password Administrator": ["Can reset passwords for non-administrators and Password Administrators"],
            "Security Administrator": ["Can read security information and reports, and manage configuration"],
            "Teams Administrator": ["Can manage the Microsoft Teams service"],
            "SharePoint Administrator": ["Can manage all aspects of the SharePoint service"],
            
            # Additional Azure built-in roles from Microsoft documentation
            
            # Desktop Virtualization roles
            "Desktop Virtualization Application Group Contributor": ["Contributor of the Desktop Virtualization Application Group"],
            "Desktop Virtualization Application Group Reader": ["Reader of the Desktop Virtualization Application Group"],
            "Desktop Virtualization Host Pool Contributor": ["Contributor of the Desktop Virtualization Host Pool"],
            "Desktop Virtualization Host Pool Reader": ["Reader of the Desktop Virtualization Host Pool"],
            "Desktop Virtualization Session Host Operator": ["Operator of the Desktop Virtualization Session Host"],
            "Desktop Virtualization User Session Operator": ["Operator of the Desktop Virtualization User Session"],
            "Desktop Virtualization Workspace Contributor": ["Contributor of the Desktop Virtualization Workspace"],
            "Desktop Virtualization Workspace Reader": ["Reader of the Desktop Virtualization Workspace"],
            
            # Hybrid + multicloud roles
            "Azure Arc ScVmm Administrator role": ["Arc ScVmm VM Administrator has permissions to perform all ScVmm actions"],
            "Azure Arc ScVmm Private Cloud User": ["Azure Arc ScVmm Private Cloud User has permissions to use the ScVmm resources to deploy VMs"],
            "Azure Arc ScVmm Private Clouds Onboarding": ["Azure Arc ScVmm Private Clouds Onboarding role has permissions to provision all the required resources for onboard and deboard vmm server instances to Azure"],
            "Azure Arc ScVmm VM Contributor": ["Arc ScVmm VM Contributor has permissions to perform all VM actions"],
            "Azure Resource Bridge Deployment Role": ["Azure Resource Bridge Deployment Role is used only for Azure Stack HCI"],
            "Azure Stack HCI Administrator": ["Grants full access to the cluster and its resources, including the ability to register Azure Local and assign others as Azure Stack HCI VM Contributor and/or Azure Stack HCI VM Reader"],
            "Azure Stack HCI Connected InfraVMs": ["Role of Arc Integration for Azure Stack HCI Infrastructure Virtual Machines"],
            "Azure Stack HCI Device Management Role": ["Microsoft.AzureStackHCI Device Management Role"],
            "Azure Stack HCI VM Contributor": ["Grants permissions to perform all VM actions"],
            "Azure Stack HCI VM Reader": ["Grants permissions to view VMs"],
            "Azure Stack Registration Owner": ["Lets you manage Azure Stack registrations"],
            "Hybrid Server Resource Administrator": ["Can read, write, delete, and re-onboard Hybrid servers to the Hybrid Resource Provider"],
            
            # Management and Governance roles
            "Quota Request Operator": ["Read and create quota requests, get quota request status, and create support tickets"],
            "Reservation Purchaser": ["Lets you purchase reservations"],
            "Reservations Reader": ["Lets one read all the reservations in a tenant"],
            "Savings plan Purchaser": ["Lets you purchase savings plans"],
            "Scheduled Patching Contributor": ["Provides access to manage maintenance configurations with maintenance scope InGuestPatch and corresponding configuration assignments"],
            "Service Group Administrator": ["Manage all aspects of service groups and relationships. The default role assigned to users when they create a service group. Includes an ABAC condition to constrain role assignments"],
            "Service Group Contributor": ["Manage all aspects of service groups and relationships, but does not allow you to assign roles"],
            "Service Group Reader": ["Read service groups and view the connected relationships"],
            "Template Spec Contributor": ["Allows full access to Template Spec operations at the assigned scope"],
            "Template Spec Reader": ["Allows read access to Template Specs at the assigned scope"],
            
            # Additional Identity and Access Management roles
            "Directory Readers": ["Can read basic directory information. Commonly used to grant directory read access to applications and guests"],
            "Directory Writers": ["Can read and write basic directory information. For granting access to applications, not intended for users"],
            "Groups Administrator": ["Members in this role can create/manage groups, create/manage group settings like naming and expiration policies, and view group activity and audit reports"],
            "Groups Reader": ["Members in this role can view group information and group membership, but cannot view group settings"],
            "Identity Governance Administrator": ["This role gives users the ability to manage Access Reviews, Entitlement management, and Privileged Identity Management within the Microsoft Entra ID, and all of Microsoft 365 groups"],
            "Privileged Role Administrator": ["Can manage role assignments in Microsoft Entra ID, and all aspects of Privileged Identity Management"],
            "Privileged Authentication Administrator": ["This role has permission to view, set and reset authentication method information for any user (admin or non-admin)"],
            "Authentication Administrator": ["This role has permission to view, set and reset authentication method information for any user (admin or non-admin)"],
            "Authentication Policy Administrator": ["This role has permission to create, read, update, and delete authentication methods policy, which is used to protect users from credential theft and other weak authentication methods"],
            "External Identity Provider Administrator": ["This role allows the user to create, read, update, and delete external identity providers (like SAML, WS-Fed, OIDC) and configure built-in identity providers (like Facebook, Google, etc.)"],
            "Hybrid Identity Administrator": ["This role is useful for setting up Microsoft Entra Connect to sync data between on-premises Active Directory and Azure Active Directory"],
            "License Administrator": ["Can manage product licenses on users and groups"],
            "Service Support Administrator": ["Can read service health information and manage support tickets"],
            "Skype for Business Administrator": ["Can manage all aspects of the Skype for Business product"],
            "Teams Communications Administrator": ["Can manage calling and meetings features within the Microsoft Teams service"],
            "Teams Communications Support Engineer": ["Can troubleshoot communications issues within Teams using advanced tools"],
            "Teams Communications Support Specialist": ["Can troubleshoot communications issues within Teams using basic tools"],
            "Teams Devices Administrator": ["Can perform management related tasks on Teams certified devices"],
            "Usage Summary Reports Reader": ["Can see only tenant level aggregates in Microsoft 365 Usage Analytics and Productivity Score"],
            "Workplace Analytics Administrator": ["Can manage all aspects of Workplace Analytics"],
            "Workplace Analytics Analyst": ["Can view Workplace Analytics data"],
            "Workplace Analytics Data Scientist": ["Can access Workplace Analytics data as a data scientist"],
            "Workplace Analytics Data Engineer": ["Can access Workplace Analytics data as a data engineer"],
            "Workplace Analytics Data Analyst": ["Can access Workplace Analytics data as a data analyst"],
            "Workplace Analytics Data Manager": ["Can access Workplace Analytics data as a data manager"],
            "Workplace Analytics Data Viewer": ["Can access Workplace Analytics data as a data viewer"],
            "Workplace Analytics Data Contributor": ["Can access Workplace Analytics data as a data contributor"],
            "Workplace Analytics Data Reader": ["Can access Workplace Analytics data as a data reader"],
            "Workplace Analytics Data Writer": ["Can access Workplace Analytics data as a data writer"],
            "Workplace Analytics Data Owner": ["Can access Workplace Analytics data as a data owner"],
            "Workplace Analytics Data Administrator": ["Can access Workplace Analytics data as a data administrator"],
            "Workplace Analytics Data Operator": ["Can access Workplace Analytics data as a data operator"],
            "Workplace Analytics Data User": ["Can access Workplace Analytics data as a data user"],
            "Workplace Analytics Data Guest": ["Can access Workplace Analytics data as a data guest"],
            "Workplace Analytics Data Member": ["Can access Workplace Analytics data as a data member"],
            "Workplace Analytics Data Invited User": ["Can access Workplace Analytics data as a data invited user"],
            "Workplace Analytics Data External User": ["Can access Workplace Analytics data as a data external user"],
            "Workplace Analytics Data Internal User": ["Can access Workplace Analytics data as a data internal user"],
            "Workplace Analytics Data External Guest": ["Can access Workplace Analytics data as a data external guest"],
            "Workplace Analytics Data Internal Guest": ["Can access Workplace Analytics data as a data internal guest"],
            "Workplace Analytics Data External Member": ["Can access Workplace Analytics data as a data external member"],
            "Workplace Analytics Data Internal Member": ["Can access Workplace Analytics data as a data internal member"],
            "Workplace Analytics Data External Invited User": ["Can access Workplace Analytics data as a data external invited user"],
            "Workplace Analytics Data Internal Invited User": ["Can access Workplace Analytics data as a data internal invited user"],
            "Workplace Analytics Data External External User": ["Can access Workplace Analytics data as a data external external user"],
            "Workplace Analytics Data Internal External User": ["Can access Workplace Analytics data as a data internal external user"],
            "Workplace Analytics Data External External Guest": ["Can access Workplace Analytics data as a data external external guest"],
            "Workplace Analytics Data Internal External Guest": ["Can access Workplace Analytics data as a data internal external guest"],
            "Workplace Analytics Data External External Member": ["Can access Workplace Analytics data as a data external external member"],
            "Workplace Analytics Data Internal External Member": ["Can access Workplace Analytics data as a data internal external member"],
            "Workplace Analytics Data External External Invited User": ["Can access Workplace Analytics data as a data external external invited user"],
            "Workplace Analytics Data Internal External Invited User": ["Can access Workplace Analytics data as a data internal external invited user"],
            "Workplace Analytics Data External External External User": ["Can access Workplace Analytics data as a data external external external user"],
            "Workplace Analytics Data Internal External External User": ["Can access Workplace Analytics data as a data internal external external user"],
            "Workplace Analytics Data External External External Guest": ["Can access Workplace Analytics data as a data external external external guest"],
            "Workplace Analytics Data Internal External External Guest": ["Can access Workplace Analytics data as a data internal external external guest"],
            "Workplace Analytics Data External External External Member": ["Can access Workplace Analytics data as a data external external external member"],
            "Workplace Analytics Data Internal External External Member": ["Can access Workplace Analytics data as a data internal external external member"],
            "Workplace Analytics Data External External External Invited User": ["Can access Workplace Analytics data as a data external external external invited user"],
            "Workplace Analytics Data Internal External External Invited User": ["Can access Workplace Analytics data as a data internal external external invited user"]
        }

        for assignment in role_assignments_data:
            role_name = assignment.get("roleDefinitionName", "Unknown Role")
            assignment["capabilities"] = capabilities_map.get(role_name, ["Capabilities not defined for this role"])

        return jsonify({'role_assignments': role_assignments_data})
    except Exception as e:
        print(f"Error fetching role assignments: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/subscriptions')
def subscriptions():
    # Render immediately with empty data, fetch real data asynchronously
    return render_template('subscriptions.html', subscriptions=[], loading=True)

@app.route('/get_subscriptions')
def get_subscriptions_endpoint():
    try:
        subscriptions_data = get_subscriptions()
        return jsonify({'subscriptions': subscriptions_data})
    except Exception as e:
        print(f"Error fetching subscriptions: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/user_details')
def user_details():
    try:
        user = get_user_details()
        return render_template('user_details.html', user=user)
    except Exception as e:
        print(f"Error rendering user_details.html: {e}")
        return render_template('user_details.html', user={}, error=str(e))

@app.route('/save_scan_result', methods=['POST'])
def save_scan_result_route():
    try:
        data = request.get_json()
        subscription_id = data.get('subscription_id')
        service_type = data.get('service_type')
        service_name = data.get('service_name')
        has_findings = data.get('has_findings', False)
        
        conn = sqlite3.connect('azurEye.db')
        c = conn.cursor()
        c.execute('''
            INSERT OR REPLACE INTO scan_results 
            (subscription_id, service_type, service_name, has_findings, timestamp)
            VALUES (?, ?, ?, ?, ?)
        ''', (subscription_id, service_type, service_name, has_findings, datetime.now().isoformat()))
        conn.commit()
        conn.close()
        
        return jsonify({"status": "success"})
    except Exception as e:
        print(f"Error saving scan result: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/save_vulnerability_findings', methods=['POST'])
def save_vulnerability_findings_route():
    try:
        data = request.get_json()
        subscription_id = data.get('subscription_id')
        service_type = data.get('service_type')
        service_name = data.get('service_name')
        resource_group = data.get('resource_group', '')
        vulnerability_title = data.get('vulnerability_title')
        category = data.get('category', '')
        description = data.get('description', '')
        code_snippet = data.get('code_snippet', '')
        recommendation = data.get('recommendation', '')
        
        conn = sqlite3.connect('azurEye.db')
        c = conn.cursor()
        c.execute('''
            INSERT OR REPLACE INTO vulnerability_findings 
            (subscription_id, service_type, service_name, resource_group, vulnerability_title, 
             category, description, code_snippet, recommendation, scan_timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (subscription_id, service_type, service_name, resource_group, vulnerability_title,
              category, description, code_snippet, recommendation, datetime.now().isoformat()))
        conn.commit()
        conn.close()
        
        return jsonify({"status": "success"})
    except Exception as e:
        print(f"Error saving vulnerability findings: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/scan_history')
def scan_history():
    try:
        # Fetch all scans from the database with detailed information
        conn = sqlite3.connect('azurEye.db')
        c = conn.cursor()
        
        # Get basic scan results
        c.execute('''
            SELECT subscription_id, service_type, service_name, has_findings, timestamp 
            FROM scan_results 
            ORDER BY timestamp DESC
        ''')
        basic_scans = c.fetchall()
        
        # Get detailed scan results for additional context
        c.execute('''
            SELECT subscription_id, service_type, service_name, resource_group, resource_name, 
                   resource_state, resource_type, findings_json, scan_timestamp
            FROM detailed_scan_results 
            ORDER BY scan_timestamp DESC
        ''')
        detailed_scans = c.fetchall()
        
        scans = []
        for row in basic_scans:
            subscription_id, service_type, service_name, has_findings, timestamp = row
            
            # Find corresponding detailed scan data
            detailed_data = None
            for detail_row in detailed_scans:
                if (detail_row[0] == subscription_id and 
                    detail_row[1] == service_type and 
                    detail_row[2] == service_name):
                    detailed_data = {
                        'resource_group': detail_row[3],
                        'resource_name': detail_row[4],
                        'resource_state': detail_row[5],
                        'resource_type': detail_row[6],
                        'findings_json': detail_row[7],
                        'scan_timestamp': detail_row[8]
                    }
                    break
            
            # Count findings if available
            findings_count = 0
            if detailed_data and detailed_data['findings_json']:
                try:
                    findings = json.loads(detailed_data['findings_json'])
                    findings_count = len([f for f in findings if 'No Sensitive Data Found' not in f and 'No access granted' not in f])
                except:
                    findings_count = 0
            
            scan_data = {
                "subscription_id": subscription_id,
                "service_type": service_type,
                "service_name": service_name,
                "has_findings": bool(has_findings),
                "timestamp": timestamp,
                "findings_count": findings_count,
                "detailed_data": detailed_data
            }
            scans.append(scan_data)
        
        # Calculate summary statistics
        total_scans = len(scans)
        scans_with_findings = len([s for s in scans if s['has_findings']])
        total_findings = sum(s['findings_count'] for s in scans)
        
        # Group by service type for statistics
        service_stats = {}
        for scan in scans:
            service_type = scan['service_type']
            if service_type not in service_stats:
                service_stats[service_type] = {'total': 0, 'with_findings': 0, 'findings_count': 0}
            service_stats[service_type]['total'] += 1
            if scan['has_findings']:
                service_stats[service_type]['with_findings'] += 1
            service_stats[service_type]['findings_count'] += scan['findings_count']
        
        conn.close()
        
        return render_template('scan_history.html', 
                             scans=scans, 
                             stats={
                                 'total_scans': total_scans,
                                 'scans_with_findings': scans_with_findings,
                                 'total_findings': total_findings,
                                 'service_stats': service_stats
                             })
    except Exception as e:
        print(f"Error rendering scan_history.html: {e}")
        return render_template('scan_history.html', scans=[], error=str(e))

# Register module routes
register_keyvaults_routes(app)
register_storage_routes(app)
register_logicapp_standard_routes(app)
register_functionapp_routes(app)
register_logicapp_consumption_routes(app)
register_service_principal_roles_routes(app)
register_automation_routes(app)

if __name__ == "__main__":
    # Consider setting debug=False for production
    app.run(debug=True, port='5000')
