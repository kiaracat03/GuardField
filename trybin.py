#!/usr/bin/env python3

import requests
import json
import sys
import time
import urllib3
import os
import configparser
import getpass
import socket
from pathlib import Path
from datetime import datetime

# Disable SSL warnings - necessary when working with self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Set default connection timeouts
socket.setdefaulttimeout(30)  # 30 seconds timeout for all socket operations

class NessusScanner:
    def __init__(self, config_file=None):
        """Initialize the Nessus scanner with configuration"""
        self.config_file = config_file or os.path.join(str(Path.home()), '.nessus_config.ini')
        self.config = self._load_config()
        self.headers = self._get_headers()
       
        # Check for minimal server configuration
        if not self.config.has_section('SERVER'):
            self.config.add_section('SERVER')
            self.config['SERVER']['url'] = 'https://localhost:8834'
            self.config['SERVER']['verify_ssl'] = 'False'
            self._save_config()
       
    def _load_config(self):
        """Load configuration from file or create if it doesn't exist"""
        config = configparser.ConfigParser()
       
        if os.path.exists(self.config_file):
            config.read(self.config_file)
        else:
            # Create default config
            config['DEFAULT'] = {
                'url': 'https://localhost:8834',
                'verify_ssl': 'False',
                'use_api_keys': 'False'
            }
           
            with open(self.config_file, 'w') as f:
                config.write(f)
               
        return config
       
    def _save_config(self):
        """Save configuration to file"""
        with open(self.config_file, 'w') as f:
            self.config.write(f)
        # Set secure permissions for config file
        os.chmod(self.config_file, 0o600)
        print(f"Configuration saved to {self.config_file}")
   
    def _get_headers(self):
        """Get headers for API requests based on authentication method"""
        if not self.config.has_section('AUTH'):
            return None
           
        auth_section = self.config['AUTH']
        if auth_section.get('use_api_keys', 'False') == 'True':
            if 'access_key' in auth_section and 'secret_key' in auth_section:
                return {
                    "X-ApiKeys": f"accessKey={auth_section['access_key']}; secretKey={auth_section['secret_key']}",
                    "Content-Type": "application/json"
                }
        elif 'token' in auth_section:
            return {
                "X-Cookie": f"token={auth_section['token']}",
                "Content-Type": "application/json"
            }
           
        return None
   
    def configure(self):
        """Interactive configuration setup"""
        print("\n=== Nessus Scanner Configuration ===")
       
        if not self.config.has_section('SERVER'):
            self.config.add_section('SERVER')
           
        server_section = self.config['SERVER']
        server_section['url'] = input(f"Nessus URL [default: {server_section.get('url', 'https://localhost:8834')}]: ") or server_section.get('url', 'https://localhost:8834')
       
        print("\nSSL Certificate Options:")
        print("1. Disable SSL verification (recommended for self-signed certificates)")
        print("2. Enable SSL verification (use only if you have a valid certificate)")
        ssl_option = input("Choose option (1/2) [default: 1]: ") or "1"
       
        if ssl_option == "1":
            server_section['verify_ssl'] = 'False'
            print("SSL verification disabled.")
        else:
            server_section['verify_ssl'] = 'True'
            print("SSL verification enabled.")
       
        if not self.config.has_section('AUTH'):
            self.config.add_section('AUTH')
           
        auth_section = self.config['AUTH']
       
        auth_type = input("\nChoose authentication method:\n1. Username/Password\n2. API Keys\nEnter choice (1/2): ")
       
        if auth_type == '1':
            auth_section['use_api_keys'] = 'False'
            username = input("Username: ")
            password = getpass.getpass("Password: ")
           
            # Get new session token
            try:
                login_data = {'username': username, 'password': password}
                response = requests.post(
                    f"{server_section['url']}/session",
                    json=login_data,
                    verify=server_section.get('verify_ssl', 'False').lower() == 'true'
                )
               
                if response.status_code == 200:
                    token = response.json().get('token')
                    if token:
                        auth_section['token'] = token
                        print("Login successful!")
                    else:
                        print("Error: No token received")
                        return False
                else:
                    print(f"Login failed with status {response.status_code}: {response.text}")
                    return False
            except Exception as e:
                print(f"Error during login: {e}")
                return False
        else:
            auth_section['use_api_keys'] = 'True'
            auth_section['access_key'] = input("Access Key: ")
            auth_section['secret_key'] = getpass.getpass("Secret Key: ")
       
        self._save_config()
        self.headers = self._get_headers()
        return True
       
    def make_request(self, endpoint, method="GET", data=None, params=None):
        """
        Args:
            endpoint (str): API endpoint to call
            method (str): HTTP method (GET, POST, DELETE)
            data (dict): Data to send in request body
            params (dict): URL parameters

        """
        if not self.headers:
            print("[ERROR] Not authenticated. Run 'configure' command first.")
            return None
           
        base_url = self.config['SERVER']['url']
        verify_ssl = self.config['SERVER'].getboolean('verify_ssl', fallback=False)
        url = f"{base_url}{endpoint}"
       
        try:
            # Set a longer timeout and add connection troubleshooting options
            request_kwargs = {
                'headers': self.headers,
                'verify': verify_ssl,
                'timeout': 30  # Increase timeout to 30 seconds
            }
           
            # Add params or json data if provided
            if params:
                request_kwargs['params'] = params
            if data and method in ["POST", "PUT"]:
                request_kwargs['json'] = data
               
            print(f"[DEBUG] Connecting to {url}")
           
            if method == "GET":
                response = requests.get(url, **request_kwargs)
            elif method == "POST":
                response = requests.post(url, **request_kwargs)
            elif method == "DELETE":
                response = requests.delete(url, **request_kwargs)
            elif method == "PUT":
                response = requests.put(url, **request_kwargs)
            else:
                print(f"[ERROR] Unsupported HTTP method: {method}")
                return None
           
            # Handle token expiration
            if response.status_code == 401 and 'token' in self.config.get('AUTH', {}):
                print("[INFO] Session token expired. Please run 'configure' to reauthenticate.")
                return None
               
            if response.status_code in [200, 201, 202]:
                if response.text:
                    try:
                        return response.json()
                    except json.JSONDecodeError:
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

    def list_scans(self):
        """List all scans"""
        response = self.make_request("/scans")
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

    def create_scan(self, name, targets, template_uuid=None, policy_id=None):
        """     
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
       
        response = self.make_request("/scans", method="POST", data=data)
       
        if response and 'scan' in response:
            scan_id = response['scan']['id']
            print(f"Scan created successfully with ID: {scan_id}")
            return scan_id
        else:
            print("Failed to create scan")
            return None

    def launch_scan(self, scan_id):
        """Launch a scan by ID"""
        response = self.make_request(f"/scans/{scan_id}/launch", method="POST")
       
        if response:
            print(f"Scan {scan_id} launched successfully")
            return True
        else:
            print(f"Failed to launch scan {scan_id}")
            return False

    def check_scan_status(self, scan_id):
        """Check the status of a scan"""
        response = self.make_request(f"/scans/{scan_id}")
       
        if response and 'info' in response:
            status = response['info'].get('status', 'unknown')
            print(f"Scan {scan_id} status: {status}")
            return status
        else:
            print(f"Failed to get status for scan {scan_id}")
            return None

    def wait_for_scan_completion(self, scan_id, check_interval=10, timeout=3600):
        """       
        Args:
            scan_id (int): ID of the scan
            check_interval (int): How often to check status in seconds
            timeout (int): Maximum time to wait in seconds
        """
        start_time = time.time()
        print(f"Waiting for scan {scan_id} to complete...")
       
        while time.time() - start_time < timeout:
            status = self.check_scan_status(scan_id)
           
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

    def show_vulnerabilities(self, scan_id):
        """Show vulnerabilities from a scan"""
        response = self.make_request(f"/scans/{scan_id}")
       
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

    def get_last_scan_vulnerabilities(self):
        """Retrieve vulnerabilities from the most recent scan"""
        # List all scans
        response = self.make_request("/scans")
        
        if response and 'scans' in response:
            if not response['scans']:
                print("No scans found.")
                return
            
            # Get the most recent scan by sorting based on 'last_modification_date'
            most_recent_scan = max(response['scans'], key=lambda x: x.get('last_modification_date', 0))
            scan_id = most_recent_scan['id']
            print(f"Most recent scan ID: {scan_id}")

            # Show vulnerabilities for the most recent scan
            self.show_vulnerabilities(scan_id)
        else:
            print("Failed to retrieve scans.")

    def run_quick_scan(self, target, name=None):
        """Run a quick scan on a target and display results"""
        if not name:
            name = f"Quick Scan - {target} - {datetime.now().strftime('%Y-%m-%d %H:%M')}"
       
        print(f"Setting up quick scan for {target}")
        scan_id = self.create_scan(name, target)
       
        if not scan_id:
            return
       
        if self.launch_scan(scan_id):
            print("Scan launched. This may take several minutes to complete.")
           
            if self.wait_for_scan_completion(scan_id):
                self.show_vulnerabilities(scan_id)
                print("\nTo get detailed results, use:")
                print(f"python3 {sys.argv[0]} get_results {scan_id}")
            else:
                print("Scan did not complete successfully.")
        else:
            print("Failed to launch scan.")

def main(): 
    scanner = NessusScanner()
    command = sys.argv[1].lower()
   
    # Check if --debug flag is present anywhere in arguments
    debug_mode = '--debug' in sys.argv
    if debug_mode:
        print("[DEBUG] Debug mode enabled")
        # Remove the debug flag from arguments
        sys.argv.remove('--debug')
   
    if command == "test_connection":
        # Simple test to check if the Nessus server is reachable
        try:
            base_url = scanner.config['SERVER']['url'] if 'SERVER' in scanner.config else "https://localhost:8834"
            verify_ssl = scanner.config['SERVER'].getboolean('verify_ssl', fallback=False) if 'SERVER' in scanner.config else False
           
            print(f"[INFO] Testing connection to {base_url}")
            print(f"[INFO] SSL verification is {'enabled' if verify_ssl else 'disabled'}")
           
            # First, try a simple connection to see if the server is reachable
            hostname = base_url.split("://")[1].split(":")[0]
            port = int(base_url.split(":")[-1]) if ":" in base_url.split("://")[1] else 8834
           
            print(f"[INFO] Checking if host {hostname} is reachable on port {port}...")
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            result = s.connect_ex((hostname, port))
            s.close()
           
            if result != 0:
                print(f"[ERROR] Cannot connect to {hostname} on port {port}")
                print("\nPossible causes:")
                print("- Nessus service is not running")
                print("- Firewall is blocking the connection")
                print("- Incorrect hostname/IP or port")
                return
            else:
                print(f"[INFO] Successfully connected to {hostname} on port {port}")
           
            # Now try with requests to check the API
            print(f"[INFO] Testing API connection...")
            headers = {"Content-Type": "application/json"}
            response = requests.get(f"{base_url}/server/status",
                                   headers=headers,
                                   verify=verify_ssl,
                                   timeout=10)
           
            print(f"[INFO] Connection successful! Status code: {response.status_code}")
            if response.status_code == 200:
                print(f"[INFO] Nessus API is responding properly")
                print(f"[INFO] Response: {response.text[:100]}")
            else:
                print(f"[WARNING] Received status code {response.status_code}")
                print(f"[WARNING] Response: {response.text[:100]}")
            return
        except requests.exceptions.SSLError as e:
            print(f"SSL Error: {e}")
            print("\nTIP: If you're using a self-signed certificate, set verify_ssl to False during configuration.")
            return
        except requests.exceptions.ConnectionError as e:
            print(f"Connection Error: {e}")
            print("\nTroubleshooting tips:")
            print("1. Verify the Nessus server is running")
            print("2. Check if the URL and port are correct")
            print("3. Ensure there are no firewall issues")
            print("4. Try with IP address instead of hostname")
            return
        except Exception as e:
            print(f"Error during connection test: {e}")
            return
   
    if command == "configure":
        scanner.configure()
        return
       
    if not scanner.headers and command != "configure":
        print("Not authenticated. Run 'configure' command first.")
        return
   
    if command == "list":
        scanner.list_scans()
   
    elif command == "create" and len(sys.argv) >= 4:
        name = sys.argv[2]
        target = sys.argv[3]
        template_uuid = sys.argv[4] if len(sys.argv) > 4 else None
        scanner.create_scan(name, target, template_uuid)
   
    elif command == "launch" and len(sys.argv) >= 3:
        scan_id = sys.argv[2]
        scanner.launch_scan(scan_id)
   
    elif command == "status" and len(sys.argv) >= 3:
        scan_id = sys.argv[2]
        scanner.check_scan_status(scan_id)
   
    elif command in ["results", "vulnerabilities"] and len(sys.argv) >= 3:
        scan_id = sys.argv[2]
        scanner.show_vulnerabilities(scan_id)

    if command == "last":
        scanner.get_last_scan_vulnerabilities()
   
    elif command == "quick" and len(sys.argv) >= 3:
        target = sys.argv[2]
        name = sys.argv[3] if len(sys.argv) > 3 else None
        scanner.run_quick_scan(target, name)


if __name__ == "__main__":
    main()