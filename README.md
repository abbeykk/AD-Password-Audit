# Active Directory Password Audit Tool

# A Python-based security automation tool that identifies user accounts with 'Password Never Expires' enabled in Active Directory. This script uses LDAP queries to detect security misconfigurations that violate password policy best practices.

 ## Overview
This project was inspired by discovering several user accounts at work with the 'Password Never Expires' setting enabled - a security risk that undermines password rotation policies. Rather than performing manual audits, I built an automated solution that queries Active Directory and generates compliance reports.

## Requirements
- Python 3.x
- ldap3 library
- Access to an Active Directory Domain Controller
- Domain credentials with read access to AD

## Installation
pip install ldap3

## Usage

python ad_password_audit.py

When prompted, enter the Administrator password. The script will:
1. Connect to the Domain Controller
2. Query Active Directory using LDAP filters
3. Identify accounts with 'Password Never Expires' enabled
4. Generate a timestamped CSV report
5. Display results in the console

## Sample Output

======================================================================
Active Directory Password Audit Script
Scanning for accounts with 'Password Never Expires' enabled
======================================================================

[+] Successfully connected to AD-DC01
[*] Searching for user accounts in DC=lab,DC=local...
[*] Using LDAP filter: (&(objectClass=user)(!(objectClass=computer))(userAccountControl:1.2.840.113556.1.4.803:=65536))
[+] Report saved to: AD_Password_Audit_20250124_180530.csv

======================================================================
ACTIVE DIRECTORY PASSWORD AUDIT REPORT
======================================================================
Domain: lab.local
Audit Date: 2025-01-24 18:05:30
======================================================================

[!] Found 3 account(s) with 'Password Never Expires' enabled:

  Username: testuser1
  Display Name: Test User1
  UAC Value: 66048
  UPN: testuser1@lab.local
----------------------------------------------------------------------


## Lab Setup

A DC is a server that hosts AD.

1. I installed Windows Server 2022 on a Mac Apple Silicon using UTM.
2. I renamed the Windows Server. This is important because AD permanently binds the server name to its database. This ensures proper naming convention and prevents breaking of critical network services like DNS and replication.
3. Set a static IP as a DC must not rely on DHCP for stable DNS and authentication services.
4. Promoted the server to a DC by installing AD DS, installing DNS, enabling Kerberos, and marking the server as authoritative.
5. I created 5 test users and checked 'password never expires' for 3 of them.
6. Installed Python and the ldap3 library, a lightweight protocol to query AD and detect the setting.

## Technical Deep Dive
This was the most interesting part. 'Password never expires' is not just a policy or an ordinary checkbox, but a single bit flag stored in an attribute called userAccountControl. Checking 'password never expires' sets the value 65536 in userAccountControl.

To filter AD for this value, I used the LDAP filter:

**(&(objectClass=user)(!(objectClass=computer))(userAccountControl:1.2.840.113556.1.4.803:=65536))**

The filter searches for all user objects that are NOT computers AND have 'Password never expires' enabled.

- **userAccountControl**: the attribute being checked
- **1.2.840.113556.1.4.803**: Microsoft OID for LDAP bitwise AND matching rule
- **65536**: decimal value for 'password never expires' flag

Developed the Python script to automate the audit and generate CSV reports.

## Conclusion
This project demonstrates how security misconfigurations in Active Directory can be identified and remediated through automation. The script can be extended to audit for other security risks such as disabled accounts, accounts without password requirements, or stale credentials. In production environments, this type of automated auditing should run regularly as part of security compliance monitoring.

**Skills gained**: LDAP filtering, Python automation, and Active Directory security concepts.

## Author
Biodun - ICT Service Desk Analyst transitioning to Cybersecurity Operations

## License\
\
This project is open source and available for educational and professional use.}
