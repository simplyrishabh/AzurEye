"""
Visualization Database Module
Handles all visualization data storage and retrieval
"""

import sqlite3
import json
from datetime import datetime

def init_visualization_db():
    """Initialize the visualization database with proper schema"""
    conn = sqlite3.connect('azurEye_visualization.db')
    c = conn.cursor()
    
    # Create vulnerability_findings table for visualization
    c.execute('''
        CREATE TABLE IF NOT EXISTS vulnerability_findings (
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
        )
    ''')
    
    # Create detailed_scan_results table for visualization
    c.execute('''
        CREATE TABLE IF NOT EXISTS detailed_scan_results (
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
        )
    ''')
    
    conn.commit()
    conn.close()

def save_vulnerability_findings(subscription_id, service_type, service_name, resource_group, vulnerability_title, category, description, code_snippet, recommendation):
    """Save detailed vulnerability findings to visualization database"""
    try:
        conn = sqlite3.connect('azurEye_visualization.db')
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
        print(f"Error saving vulnerability findings to visualization DB: {e}")
        return False

def save_detailed_scan_results(subscription_id, service_type, service_name, resource_group, resource_name, resource_state, resource_type, findings_json):
    """Save detailed scan results to visualization database"""
    try:
        conn = sqlite3.connect('azurEye_visualization.db')
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
        print(f"Error saving detailed scan results to visualization DB: {e}")
        return False

def get_all_vulnerability_data():
    """Get all vulnerability data for visualization"""
    try:
        conn = sqlite3.connect('azurEye_visualization.db')
        c = conn.cursor()
        c.execute('''
            SELECT 
                service_type,
                subscription_id,
                resource_group,
                service_name,
                vulnerability_title,
                category,
                description,
                code_snippet,
                recommendation,
                scan_timestamp
            FROM vulnerability_findings 
            ORDER BY service_type, subscription_id, resource_group, service_name
        ''')
        vulnerability_data = c.fetchall()
        conn.close()
        return vulnerability_data
    except Exception as e:
        print(f"Error getting vulnerability data from visualization DB: {e}")
        return []

def clear_visualization_data():
    """Clear all visualization data (useful for fresh scans)"""
    try:
        conn = sqlite3.connect('azurEye_visualization.db')
        c = conn.cursor()
        c.execute('DELETE FROM vulnerability_findings')
        c.execute('DELETE FROM detailed_scan_results')
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error clearing visualization data: {e}")
        return False

# Initialize the database when this module is imported
init_visualization_db()
