{\rtf1\ansi\ansicpg1252\cocoartf2822
\cocoatextscaling0\cocoaplatform0{\fonttbl\f0\fswiss\fcharset0 Helvetica;}
{\colortbl;\red255\green255\blue255;}
{\*\expandedcolortbl;;}
\paperw11900\paperh16840\margl1440\margr1440\vieww11520\viewh8400\viewkind0
\pard\tx720\tx1440\tx2160\tx2880\tx3600\tx4320\tx5040\tx5760\tx6480\tx7200\tx7920\tx8640\pardirnatural\partightenfactor0

\f0\fs24 \cf0 #!/usr/bin/env python3\
"""\
Active Directory Password Audit Script\
Identifies user accounts with 'Password Never Expires' enabled\
Author: Biodun\
"""\
\
from ldap3 import Server, Connection, ALL, SUBTREE\
import csv\
from datetime import datetime\
import getpass\
\
# Domain Configuration\
DC_HOST = "AD-DC01"\
DOMAIN = "lab.local"\
USERNAME = "Administrator"\
PASSWORD = getpass.getpass("Enter Administrator password: ")\
\
# LDAP Configuration\
LDAP_SERVER = f"ldap://\{DC_HOST\}"\
DOMAIN_DN = ",".join([f"DC=\{part\}" for part in DOMAIN.split(".")])\
USER_DN = f"CN=\{USERNAME\},CN=Users,\{DOMAIN_DN\}"\
\
# PASSWORD_NEVER_EXPIRES flag is 0x10000 (decimal 65536)\
# LDAP bitwise AND matching rule OID: 1.2.840.113556.1.4.803\
LDAP_FILTER = (\
    "(&(objectClass=user)"\
    "(!(objectClass=computer))"\
    "(userAccountControl:1.2.840.113556.1.4.803:=65536))"\
)\
\
def connect_to_ad():\
    """Establish connection to Active Directory"""\
    try:\
        server = Server(LDAP_SERVER, get_info=ALL)\
        conn = Connection(\
            server,\
            user=USER_DN,\
            password=PASSWORD,\
            auto_bind=True\
        )\
        print(f"[+] Successfully connected to \{DC_HOST\}")\
        return conn\
    except Exception as e:\
        print(f"[-] Connection failed: \{e\}")\
        return None\
\
def audit_password_policies(conn):\
    """Search for users with Password Never Expires enabled using LDAP filter"""\
    \
    attributes = [\
        'sAMAccountName',\
        'displayName',\
        'userAccountControl',\
        'pwdLastSet',\
        'whenCreated',\
        'userPrincipalName'\
    ]\
    \
    print(f"[*] Searching for user accounts in \{DOMAIN_DN\}...")\
    print(f"[*] Using LDAP filter: \{LDAP_FILTER\}")\
    \
    conn.search(\
        search_base=DOMAIN_DN,\
        search_filter=LDAP_FILTER,\
        search_scope=SUBTREE,\
        attributes=attributes\
    )\
    \
    results = []\
    \
    for entry in conn.entries:\
        username = str(entry.sAMAccountName.value) if entry.sAMAccountName else "N/A"\
        display_name = str(entry.displayName.value) if entry.displayName else "N/A"\
        uac = entry.userAccountControl.value if entry.userAccountControl else 0\
        upn = str(entry.userPrincipalName.value) if entry.userPrincipalName else "N/A"\
        \
        results.append(\{\
            'Username': username,\
            'Display Name': display_name,\
            'Password Never Expires': 'YES',\
            'User Account Control': uac,\
            'User Principal Name': upn\
        \})\
    \
    return results, len(results)\
\
def generate_report(results):\
    """Generate CSV report and console output"""\
    \
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")\
    filename = f"AD_Password_Audit_\{timestamp\}.csv"\
    \
    # Write to CSV\
    if results:\
        with open(filename, 'w', newline='') as csvfile:\
            fieldnames = ['Username', 'Display Name', 'Password Never Expires', 'User Account Control', 'User Principal Name']\
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)\
            \
            writer.writeheader()\
            writer.writerows(results)\
        \
        print(f"\\n[+] Report saved to: \{filename\}")\
    \
    # Console output\
    print("\\n" + "="*70)\
    print("ACTIVE DIRECTORY PASSWORD AUDIT REPORT")\
    print("="*70)\
    print(f"Domain: \{DOMAIN\}")\
    print(f"Audit Date: \{datetime.now().strftime('%Y-%m-%d %H:%M:%S')\}")\
    print("="*70)\
    \
    if results:\
        print(f"\\n[!] Found \{len(results)\} account(s) with 'Password Never Expires' enabled:\\n")\
        for account in results:\
            print(f"  Username: \{account['Username']\}")\
            print(f"  Display Name: \{account['Display Name']\}")\
            print(f"  UAC Value: \{account['User Account Control']\}")\
            print(f"  UPN: \{account['User Principal Name']\}")\
            print("-" * 70)\
    else:\
        print("\\n[+] No accounts found with 'Password Never Expires' enabled")\
    \
    print("\\n")\
\
def main():\
    """Main execution function"""\
    print("\\n" + "="*70)\
    print("Active Directory Password Audit Script")\
    print("Scanning for accounts with 'Password Never Expires' enabled")\
    print("="*70 + "\\n")\
    \
    # Connect to AD\
    conn = connect_to_ad()\
    if not conn:\
        return\
    \
    # Perform audit\
    results, count = audit_password_policies(conn)\
    \
    # Generate report\
    generate_report(results)\
    \
    # Close connection\
    conn.unbind()\
    print("[*] Audit complete. Connection closed.")\
\
if __name__ == "__main__":\
    main()}