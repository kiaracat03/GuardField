#!/usr/bin/env python3

import requests
import json
import sys
import time
import urllib3
from datetime import datetime

# Disable SSL warnings

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# API Configuration
ACCESS_KEY = 'f444f1e3dd98c32b8f996882a4d0aeadf079e278e8139d9bf340c9608fc5460a'
SECRET_KEY = 'fd58c946dfcfbd3b2c4bef8dc751cd954643427b35dbb32621c9e66e8587bdc1'
BASE_URL = "https://raspberrypi:8834"
OTHER_URL = "https://raspberrypi:8834/#"

# Headers for API requests
HEADERS = {
    "X-ApiKeys": f"accessKey={ACCESS_KEY}; secretKey={SECRET_KEY}",
    "Content-Type": "application/json"
}

def make_request(endpoint, method="GET", data=None, params=None):
    """
    Make a request to the Nessus API
    
    Args:
        endpoint (str): API endpoint to call
        method (str): HTTP method (GET, POST, DELETE)
        data (dict): Data to send in request body
        params (dict): URL parameters
        
    Returns:
        dict or None: Response data or None on error
    """
    url = f"{BASE_URL}{endpoint}"
    print(f"[DEBUG] Making {method} request to: {url}")
    
    try:
        if method == "GET":
            response = requests.get(url, headers=HEADERS, params=params, verify=False)
        elif method == "POST":
            response = requests.post(url, headers=HEADERS, json=data, params=params, verify=False)
        elif method == "DELETE":
            response = requests.delete(url, headers=HEADERS, params=params, verify=False)
        elif method == "PUT":
            response = requests.put(url, headers=HEADERS, json=data, params=params, verify=False)
        else:
            print(f"[ERROR] Unsupported HTTP method: {method}")
            return None
        
        print(f"[DEBUG] Response status code: {response.status_code}")
        
        if response.status_code in [200, 201, 202]:
            if response.text:
                try:
                    return response.json()
                except json.JSONDecodeError:
                    print(f"[DEBUG] Response is not JSON: {response.text[:100]}")
                    return response.text
            return {}
        else:
            print(f"[ERROR] API Error: {response.status_code}")
            try:
                error_msg = response.json()
                print(f"[ERROR] Details: {json.dumps(error_msg, indent=2)}")
            except:
                print(f"[ERROR] Response: {response.text[:100]}")
            return None
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Request exception: {e}")
        return None

def get_scan_templates():
    """Get available scan templates"""
    return make_request("/editor/scan/templates")

def list_scans():
    """List all scans"""
    response = make_request("/scans")
    if response and 'scans' in response:
        if not response['scans']:
            print("No scans found.")
            return
        
        print("\nAvailable Scans:")
        print("-" * 80)
        print(f"{'ID':<8} {'Name':<30} {'Status':<15} {'Last Run':<20}")
        print("-" * 80)
        
        for scan in response['scans']:
            scan_id = scan.get('id', 'N/A')
            name = scan.get('name', 'N/A')
            status = scan.get('status', 'N/A')
            last_run = 'Never'
            
            if 'last_modification_date' in scan and scan['last_modification_date']:
                timestamp = scan['last_modification_date']
                last_run = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
                
            print(f"{scan_id:<8} {name[:30]:<30} {status:<15} {last_run:<20}")
        print("-" * 80)
    else:
        print("Failed to retrieve scans.")

def create_scan(name, targets, template_uuid=None, policy_id=None):
    """
    Create a new scan
    
    Args:
        name (str): Name of the scan
        targets (str): Target IP addresses or hostnames
        template_uuid (str, optional): UUID of scan template
        policy_id (int, optional): ID of policy to use
    """
    if not template_uuid and not policy_id:
        # Default to basic network scan if neither is provided
        template_uuid = "731a8e52-3ea6-a291-ec0a-d2ff0619c19d7bd788d6be818b65"
    
    settings = {
        "name": name,
        "text_targets": targets,
        "enabled": True
    }
    
    if policy_id:
        settings["policy_id"] = policy_id
    
    data = {
        "uuid": template_uuid,
        "settings": settings
    }
    
    response = make_request("/scans", method="POST", data=data)
    
    if response and 'scan' in response:
        scan_id = response['scan']['id']
        print(f"Scan created successfully with ID: {scan_id}")
        return scan_id
    else:
        print("Failed to create scan")
        return None

def launch_scan(scan_id):
    """Launch a scan by ID"""
    response = make_request(f"/scans/{scan_id}/launch", method="POST")
    
    if response:
        print(f"Scan {scan_id} launched successfully")
        return True
    else:
        print(f"Failed to launch scan {scan_id}")
        return False

def check_scan_status(scan_id):
    """Check the status of a scan"""
    response = make_request(f"/scans/{scan_id}")
    
    if response and 'info' in response:
        status = response['info'].get('status', 'unknown')
        print(f"Scan {scan_id} status: {status}")
        return status
    else:
        print(f"Failed to get status for scan {scan_id}")
        return None

def wait_for_scan_completion(scan_id, check_interval=10, timeout=3600):
    """
    Wait for a scan to complete
    
    Args:
        scan_id (int): ID of the scan
        check_interval (int): How often to check status in seconds
        timeout (int): Maximum time to wait in seconds
    
    Returns:
        bool: True if scan completed, False if timed out or error
    """
    start_time = time.time()
    print(f"Waiting for scan {scan_id} to complete...")
    
    while time.time() - start_time < timeout:
        status = check_scan_status(scan_id)
        
        if status == "completed":
            print(f"Scan {scan_id} completed successfully")
            return True
        elif status in ["error", "canceled"]:
            print(f"Scan {scan_id} ended with status: {status}")
            return False
        
        print(f"Waiting {check_interval} seconds...")
        time.sleep(check_interval)
    
    print(f"Timed out waiting for scan {scan_id} to complete")
    return False

def show_vulnerabilities(scan_id):
    """Show vulnerabilities from a scan"""
    response = make_request(f"/scans/{scan_id}")
    
    if not response or 'vulnerabilities' not in response:
        print(f"No vulnerability data available for scan {scan_id}")
        return
    
    vulnerabilities = response['vulnerabilities']
    
    if not vulnerabilities:
        print("No vulnerabilities found in scan.")
        return
    
    # Group vulnerabilities by severity
    severity_names = {
        4: "Critical",
        3: "High",
        2: "Medium",
        1: "Low",
        0: "Info"
    }
    
    # Count vulnerabilities by severity
    severity_counts = {sev: 0 for sev in range(5)}
    for vuln in vulnerabilities:
        severity = vuln.get('severity', 0)
        severity_counts[severity] += 1
    
    # Print summary
    print("\nVulnerability Summary:")
    print("-" * 50)
    for severity in sorted(severity_counts.keys(), reverse=True):
        if severity_counts[severity] > 0:
            print(f"{severity_names[severity]:<10}: {severity_counts[severity]}")
    print("-" * 50)
    
    # Print details
    print("\nVulnerability Details:")
    print("-" * 100)
    print(f"{'Severity':<10} {'Plugin ID':<12} {'Name':<50} {'Count':<10}")
    print("-" * 100)
    
    for vuln in sorted(vulnerabilities, key=lambda x: x.get('severity', 0), reverse=True):
        severity = vuln.get('severity', 0)
        plugin_id = vuln.get('plugin_id', 'N/A')
        name = vuln.get('plugin_name', 'Unknown')[:50]
        count = vuln.get('count', 0)
        
        print(f"{severity_names[severity]:<10} {plugin_id:<12} {name:<50} {count:<10}")
    print("-" * 100)

def run_quick_scan(target, name=None):
    """Run a quick scan on a target and display results"""
    if not name:
        name = f"Quick Scan - {target} - {datetime.now().strftime('%Y-%m-%d %H:%M')}"
    
    print(f"Setting up quick scan for {target}")
    scan_id = create_scan(name, target)
    
    if not scan_id:
        return
    
    if launch_scan(scan_id):
        print("Scan launched. This may take several minutes to complete.")
        
        if wait_for_scan_completion(scan_id):
            show_vulnerabilities(scan_id)
            print("\nTo get detailed results, use:")
            print(f"python3 {sys.argv[0]} get_results {scan_id}")
        else:
            print("Scan did not complete successfully.")
    else:
        print("Failed to launch scan.")

def show_help():
    """Show help information"""
    print("\nNessus Scanner - Python CLI for Nessus API")
    print("\nUsage:")
    print(f"  python3 {sys.argv[0]} <command> [options]")
    print("\nCommands:")
    print("  list                - List all existing scans")
    print("  launch SCAN_ID      - Launch an existing scan")
    print("  status SCAN_ID      - Check status of a scan")
    print("  results SCAN_ID     - Get and display scan results")
    print("  quick TARGET        - Create, run, and show results for a quick scan")

def main():
    """Main function to handle command line arguments"""
    if len(sys.argv) < 2 or sys.argv[1] in ['-h', '--help', 'help']:
        show_help()
        return
    
    command = sys.argv[1].lower()
    
    if command == "list":
        list_scans()
    
    elif command == "launch" and len(sys.argv) >= 3:
        scan_id = sys.argv[2]
        launch_scan(scan_id)
    
    elif command == "status" and len(sys.argv) >= 3:
        scan_id = sys.argv[2]
        check_scan_status(scan_id)
    
    elif command in ["results", "vulnerabilities"] and len(sys.argv) >= 3:
        scan_id = sys.argv[2]
        show_vulnerabilities(scan_id)
    
    elif command == "quick" and len(sys.argv) >= 3:
        target = sys.argv[2]
        name = sys.argv[3] if len(sys.argv) > 3 else None
        run_quick_scan(target, name)
    
    else:
        print(f"Unknown command or missing arguments: {command}")
        show_help()

if __name__ == "__main__":
    main()