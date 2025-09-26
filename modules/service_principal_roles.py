import subprocess
import json
from flask import Flask, render_template, request, jsonify

def register_routes(app):
    def get_role_assignments(principal_id):
        try:
            # Run the az command to fetch role assignments
            command = f"az role assignment list --assignee {principal_id} -o json"
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
            if result.returncode == 0 and result.stdout:
                role_assignments = json.loads(result.stdout)
                # Group by principalId and principalName
                grouped_assignments = {}
                for assignment in role_assignments:
                    key = (assignment.get("principalId", "Unknown"), assignment.get("principalName", "Unknown"))
                    if key not in grouped_assignments:
                        grouped_assignments[key] = []
                    grouped_assignments[key].append(assignment.get("roleDefinitionName", "Unknown"))
                # Convert to table format
                table_data = [
                    {
                        "principalId": pid,
                        "principalName": pname,
                        "roles": ", ".join(roles)
                    }
                    for (pid, pname), roles in grouped_assignments.items()
                ]
                return table_data, None
            else:
                return [], f"Error fetching role assignments: {result.stderr}"
        except subprocess.TimeoutExpired:
            return [], "Command timed out while fetching role assignments."
        except json.JSONDecodeError:
            return [], "Error parsing role assignment data."
        except Exception as e:
            return [], f"Error: {str(e)}"

    @app.route('/service_principal_roles', methods=['GET', 'POST'])
    def service_principal_roles():
        if request.method == 'POST':
            principal_id = request.form.get('principal_id')
            if not principal_id:
                return render_template('service_principal_roles.html', error="Please provide a service principal identifier.", table_data=[])
            table_data, error = get_role_assignments(principal_id)
            return render_template('service_principal_roles.html', table_data=table_data, error=error)
        return render_template('service_principal_roles.html', table_data=[], error=None)
