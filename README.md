"# GuardField" 

Available commands for Nessus scan:
	• list_scans
		○ Lists all current scans
	• create_scan "Scan Name" "192.168.1.10,192.168.1.20" "UUID_POLICY" "POLICY_ID"
		○ Parameters:
			§ Name of scan
			§ Targets - separated by commas
			§ UUID = UUID of policy you want to use
				□ Retrieve using list_policies
			§ Policy_id = ID of policy you want to use
				□ Retrieve using list_policies 
	• launch_scan <scan_id>
	• get_scan_results <scan_id>
	• delete_scan <scan_id>
	• list_policies 
		○ Display all available policies
		○ To choose appropriate uuid and policy_id

Website:
	• Only running vulnerability scan
	• User to create scan name
		○ User_scan_name
	• User to input IP addresses
		○ Maybe just one target for now
		○ User_target
	• Save them
	• create_scan user_scan_name user_target "UUID_POLICY" "POLICY_ID"
