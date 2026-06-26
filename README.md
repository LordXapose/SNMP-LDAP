
```markdown
# SNMP & LDAP Enumeration – Reconnaissance Guide

This document outlines techniques, tools, and countermeasures for enumerating **SNMP** (Simple Network Management Protocol) and **LDAP** (Lightweight Directory Access Protocol) during internal penetration tests or red team engagements. Both protocols often expose critical information that can be leveraged for lateral movement, privilege escalation, and domain compromise.

---

## Table of Contents

- [SNMP Enumeration](#snmp-enumeration)
  - [Overview](#overview)
  - [Why Enumerate SNMP?](#why-enumerate-snmp)
  - [SNMP Versions & Security](#snmp-versions--security)
  - [Key OIDs & Data Locations](#key-oids--data-locations)
  - [Enumeration Process & Tools](#enumeration-process--tools)
    - [1. Discovery](#1-discovery)
    - [2. Community String Brute-Force](#2-community-string-brute-force)
    - [3. Data Extraction](#3-data-extraction)
    - [4. Advanced & Write-Access](#4-advanced--write-access)
  - [Countermeasures](#countermeasures)
- [LDAP Enumeration](#ldap-enumeration)
  - [Overview](#overview-1)
  - [Why Enumerate LDAP?](#why-enumerate-ldap)
  - [Authentication & Access Levels](#authentication--access-levels)
  - [LDAP Query Basics](#ldap-query-basics)
  - [Enumeration Tools & Techniques](#enumeration-tools--techniques)
    - [1. Discovery](#1-discovery-1)
    - [2. Anonymous Enumeration](#2-anonymous-enumeration)
    - [3. Authenticated Enumeration](#3-authenticated-enumeration)
    - [4. High-Value Data Extraction](#4-high-value-data-extraction)
    - [5. Indirect Enumeration (Without Direct LDAP)](#5-indirect-enumeration-without-direct-ldap)
  - [Countermeasures](#countermeasures-1)
- [Quick Reference Table](#quick-reference-table)
- [Useful Command Cheat Sheet](#useful-command-cheat-sheet)

---

## SNMP Enumeration

### Overview
**SNMP** is a UDP-based protocol (ports 161/162) used to manage network devices. A manager queries agents for data stored in the **Management Information Base (MIB)**. Misconfigured SNMP services can leak a wealth of information.

### Why Enumerate SNMP?
- Discover device types, OS, and software versions
- Extract network information (IPs, MAC addresses, routing tables)
- List running processes and installed software
- Enumerate user accounts (especially on Windows with SNMP enabled)
- Identify shared resources and running services

### SNMP Versions & Security
| Version  | Authentication | Encryption       | Weaknesses                                  |
|----------|----------------|------------------|---------------------------------------------|
| SNMPv1   | Community string (plaintext) | None             | Default "public"/"private", no encryption   |
| SNMPv2c  | Community string (plaintext) | None             | Same as v1, slightly better performance     |
| SNMPv3   | User-based (MD5/SHA) | Optional (DES/AES) | Weak configs still possible but far stronger |

### Key OIDs & Data Locations
| Information                | OID (numeric)                        |
|----------------------------|--------------------------------------|
| System description         | `1.3.6.1.2.1.1.1`                  |
| Hostname                   | `1.3.6.1.2.1.1.5`                  |
| Uptime                     | `1.3.6.1.2.1.1.3`                  |
| Running processes          | `1.3.6.1.2.1.25.4.2.1.2`           |
| Installed software         | `1.3.6.1.2.1.25.6.3.1.2`           |
| TCP connections            | `1.3.6.1.2.1.6.13.1.3`             |
| UDP listeners              | `1.3.6.1.2.1.7.5.1.1`              |
| Windows user accounts      | `1.3.6.1.4.1.77.1.2.25` (Samba/LanManager) |

### Enumeration Process & Tools

#### 1. Discovery
```bash
nmap -sU -p 161 --open 192.168.1.0/24
```

#### 2. Community String Brute-Force
```bash
# onesixtyone – fast community string scan
onesixtyone -c community.txt 192.168.1.0/24

# Nmap script
nmap -sU -p 161 --script snmp-brute <target>

# Hydra
hydra -P community.txt <target> snmp

# Metasploit
use auxiliary/scanner/snmp/snmp_login
```

#### 3. Data Extraction
Once a read community string (`public`, etc.) is known:

```bash
# Walk the entire MIB tree
snmpwalk -v 2c -c public 192.168.1.10

# Focus on a specific OID subtree
snmpwalk -v 2c -c public 192.168.1.10 1.3.6.1.4.1.77.1.2.25

# snmp-check – structured output (users, network, processes)
snmp-check 192.168.1.10 -c public

# Metasploit modules
use auxiliary/scanner/snmp/snmp_enum
use auxiliary/scanner/snmp/snmp_enumusers
use auxiliary/scanner/snmp/snmp_enumshares
```

#### 4. Advanced & Write-Access
- **Write community** (`private`): use `snmpset` to modify configs, reboot devices, or change routes.
- **Extended OID walking**: some devices expose custom MIBs (e.g., Cisco, HP). Check vendor documentation.

### Countermeasures
- **Disable SNMP** if not required.
- Enforce **SNMPv3** with authentication and encryption.
- Change default community strings; use long, complex values.
- Apply **access control lists (ACLs)** to limit which IPs can query SNMP.
- Monitor for rapid SNMP walks (excessive `GETNEXT` requests) using SIEM/IDS.
- Block SNMP at the network perimeter.

---

## LDAP Enumeration

### Overview
**LDAP** (TCP/UDP 389, LDAPS 636, Global Catalog 3268/3269) provides access to directory services, most commonly Microsoft Active Directory. Even anonymous or low-privileged queries can expose massive amounts of AD data.

### Why Enumerate LDAP?
- Compile valid usernames for password spraying
- Map group memberships (domain admins, privileged groups)
- Extract domain structure (OUs, domains, trusts)
- Gather computer names and OS versions
- Retrieve password policy (lockout, complexity)
- Discover Service Principal Names (SPNs) for Kerberoasting
- Read descriptive fields that sometimes contain passwords

### Authentication & Access Levels
- **Anonymous bind** – No credentials; often disabled by default but still found in legacy environments.
- **Simple bind** – Uses a valid username/password; access is determined by the user’s group memberships.
- **Authenticated users** – In Active Directory, any domain user can read most attributes unless explicitly restricted.

### LDAP Query Basics
All queries use **LDAP search filters** (RFC 4515):
- `(objectClass=user)` – All user objects
- `(&(objectClass=user)(sAMAccountName=jdoe))` – Specific user
- `(memberOf=CN=Domain Admins,CN=Users,DC=domain,DC=com)` – Members of a group
- `(servicePrincipalName=*)` – All objects with an SPN (kerberoastable accounts)

### Enumeration Tools & Techniques

#### 1. Discovery
```bash
nmap -p 389,636,3268,3269 192.168.1.0/24

# Nmap LDAP scripts
nmap -p 389 --script ldap-search <target>
```

#### 2. Anonymous Enumeration
If anonymous bind is allowed, the directory can be scraped completely.

```bash
# ldapsearch (Linux)
ldapsearch -x -H ldap://dc.domain.com -b "DC=domain,DC=com"

# Extract all usernames
ldapsearch -x -H ldap://dc.domain.com -b "DC=domain,DC=com" "(objectClass=user)" sAMAccountName

# windapsearch (Python) – great for AD enumeration, supports anonymous
windapsearch --dc-ip 192.168.1.10 --module users

# Nmap NSE with empty credentials
nmap -p 389 --script ldap-search --script-args 'ldap.username="",ldap.password=""' <target>
```

#### 3. Authenticated Enumeration
With valid domain credentials (even a low-privileged user):

- **BloodHound / SharpHound** – Collects all AD objects and relationships; essential for finding attack paths.
- **ldapdomaindump** – Generates HTML/JSON/grepable reports of users, groups, computers, trusts.
  ```bash
  ldapdomaindump -u 'DOMAIN\user' -p 'password' dc.domain.com
  ```
- **PowerView (PowerShell)** – In-memory AD enumeration:
  ```powershell
  Get-NetUser | select samaccountname
  Get-NetGroup "Domain Admins" | select member
  Get-NetComputer | select name, operatingsystem
  ```
- **ADExplorer (Sysinternals)** – GUI snapshot of the entire domain.
- **Apache Directory Studio** – Cross-platform LDAP browser with GUI.

#### 4. High-Value Data Extraction
- **User descriptions** (`description` attribute) – often contain sensitive information.
- **Password policy** – `ldapsearch` on the `defaultNamingContext`; also `Get-ADDefaultDomainPasswordPolicy`.
- **SPN enumeration** – `(servicePrincipalName=*)` returns service accounts ripe for Kerberoasting.
- **AS-REP roastable users** – Users with `DONT_REQ_PREAUTH` (look for `userAccountControl: 1.2.840.113556.1.4.803:=4194304`).
- **Trust relationships** – Look for `trustedDomain` objects to map forest trusts.
- **Machine accounts with unconstrained delegation** – Often targeted for escalation.

#### 5. Indirect Enumeration (Without Direct LDAP)
If LDAP ports are filtered, you can still enumerate Active Directory via:
- **RPC** (135/445) – `rpcclient -U "" -N <DC>`, then `enumdomusers`
- **SMB** – `crackmapexec smb <target> --users` or `enum4linux`
- **Kerberos** – `kerbrute userenum` for username brute-forcing
- **DNS** – Zone transfer (rare) or brute-force hostnames

### Countermeasures
- **Disable anonymous binds** (default in modern AD, but verify).
- Restrict “Authenticated Users” from reading all attributes if possible (carefully test).
- Enable **LDAP signing** and **channel binding** to prevent NTLM relay.
- Monitor for bulk LDAP queries (e.g., a single IP requesting all user objects in a short time).
- Implement a strong password policy; the main risk from LDAP enumeration is username discovery for password attacks.
- Use **Protected Users** group for privileged accounts to prevent credential caching.

---

## Quick Reference Table

| Aspect               | SNMP                                          | LDAP                                           |
|----------------------|-----------------------------------------------|------------------------------------------------|
| **Default port(s)**  | 161/UDP (162 for traps)                       | 389/TCP, 636 (LDAPS), 3268/3269 (GC)          |
| **Primary use**      | Network device monitoring & management        | Directory services (authentication, authorisation) |
| **Common misconfig** | Default community strings, SNMPv1/v2c         | Anonymous bind, excessive default permissions  |
| **Key info leaked**  | Users, processes, network configs, routes     | Users, groups, SPNs, password policies, trusts |
| **Top tools**        | `snmpwalk`, `snmp-check`, `onesixtyone`       | `ldapsearch`, `windapsearch`, `BloodHound`     |

---

## Useful Command Cheat Sheet

### SNMP
```bash
# Scan for SNMP
nmap -sU -p 161 --open 192.168.1.0/24

# Brute-force community strings
onesixtyone -c community.txt 192.168.1.10

# Walk entire tree
snmpwalk -v 2c -c public 192.168.1.10

# Get structured info
snmp-check 192.168.1.10 -c public

# Windows users (if enabled)
snmpwalk -v 1 -c public 192.168.1.10 1.3.6.1.4.1.77.1.2.25

# Set value (write community required)
snmpset -v 2c -c private 192.168.1.10 1.3.6.1.something i 1
```

### LDAP
```bash
# Anonymous search
ldapsearch -x -H ldap://dc.domain.com -b "DC=domain,DC=com"

# Get all users
ldapsearch -x -H ldap://dc.domain.com -b "DC=domain,DC=com" "(objectClass=user)" sAMAccountName

# windapsearch (no creds)
windapsearch --dc-ip 10.10.10.10 --module users

# Authenticated dump
ldapdomaindump -u 'DOMAIN\user' -p 'pass' dc.domain.com

# BloodHound collector (SharpHound.exe on target)
SharpHound.exe --CollectionMethod All --Domain domain.com

# Kerberoasting candidates
ldapsearch -x -H ldap://dc.domain.com -D "user@domain.com" -w password -b "DC=domain,DC=com" "(servicePrincipalName=*)" sAMAccountName servicePrincipalName
```


This README covers everything from your detailed explanation in a clean, ready-to-use format. If you'd like to add a specific lab scenario, remove the disclaimer, or adjust formatting, let me know.
