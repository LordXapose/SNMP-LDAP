# SNMP & LDAP Enumeration

A focused, example-driven reference for **enumerating** SNMP and LDAP during authorized engagements.

Each step follows the same loop: **run the command → read the findings → note the one step ahead.** The "next step" pointers name the follow-on action so you know where the path leads — they intentionally stop at the enumeration boundary and do not include exploitation, cracking, or write/disruptive operations.

> Use only against systems you are explicitly authorized to test.

---

## Table of Contents

- [Lab Environment (Optional)](#lab-environment-optional)
- [SNMP Enumeration](#snmp-enumeration)
  - [How SNMP Works (In One Minute)](#how-snmp-works-in-one-minute)
  - [1. Discover SNMP Devices](#1-discover-snmp-devices)
  - [2. Find Valid Community Strings](#2-find-valid-community-strings)
  - [3. Dump System Information](#3-dump-system-information)
  - [4. Enumerate User Accounts (Windows)](#4-enumerate-user-accounts-windows)
  - [5. Enumerate Processes & Software](#5-enumerate-processes--software)
  - [6. Identify Write Access (RW Community)](#6-identify-write-access-rw-community)
- [LDAP Enumeration](#ldap-enumeration)
  - [How LDAP Works (In One Minute)](#how-ldap-works-in-one-minute)
  - [1. Discover Domain Controllers & LDAP Ports](#1-discover-domain-controllers--ldap-ports)
  - [2. Test for Anonymous Bind](#2-test-for-anonymous-bind)
  - [3. Enumerate Usernames](#3-enumerate-usernames)
  - [4. Read the Password Policy](#4-read-the-password-policy)
  - [5. Map Groups and Domain Admins](#5-map-groups-and-domain-admins)
  - [6. Identify Kerberoastable Accounts (SPNs)](#6-identify-kerberoastable-accounts-spns)
  - [7. Collect for BloodHound](#7-collect-for-bloodhound)
- [Indirect Enumeration (When LDAP is Blocked)](#indirect-enumeration-when-ldap-is-blocked)
- [Quick Command Cheat Sheet](#quick-command-cheat-sheet)
- [Countermeasures Summary](#countermeasures-summary)

---

## Lab Environment (Optional)

- **SNMP**: An Ubuntu VM with `snmpd` configured with a `public` community, or a Windows box with the SNMP service enabled.
- **LDAP**: A Windows Server with AD DS, or a lightweight lab using [GOAD](https://github.com/Orange-Cyberdefense/GOAD), [BadBlood](https://github.com/davidprowe/BadBlood), or [DetectionLab](https://github.com/clong/DetectionLab).

All examples assume you are on the same network as the targets.

---

## SNMP Enumeration

### How SNMP Works (In One Minute)
- A manager (you) queries an agent (the target) over **UDP 161**.
- The request carries a **community string** (acts like a password) and the **OID** you want.
- The agent returns the value of that OID.
- `snmpwalk` issues a chain of `GETNEXT` requests to walk the whole MIB tree.

**Target for this section:** `192.168.1.50` — Windows 10, SNMP enabled, community `public`.

---

### 1. Discover SNMP Devices

**Tools used:** `nmap` (port scanner), `onesixtyone` (fast SNMP sweeper).

#### Tool usage

```bash
nmap -sU -p 161 --open 192.168.1.0/24
```
What it does: scans the whole subnet for hosts answering on UDP port 161.
- `-sU` → use a **UDP** scan (SNMP runs over UDP, not TCP).
- `-p 161` → check only port **161** (the SNMP port) for speed.
- `--open` → show only hosts where the port is **open**, hiding the noise.
- `192.168.1.0/24` → the target range (all 256 addresses in the subnet).

Output:
```
Nmap scan report for 192.168.1.50
PORT    STATE SERVICE
161/udp open  snmp
```

```bash
onesixtyone 192.168.1.0/24 public
```
What it does: rapidly pings a whole range with one community string to find live SNMP agents in seconds (much faster than nmap for large ranges).
- `192.168.1.0/24` → the target range to sweep.
- `public` → the community string to test against every host.

**Findings:** A live SNMP agent on `192.168.1.50`.
**One step ahead →** A reachable agent is only useful with a valid community string — go find one.

---

### 2. Find Valid Community Strings
```bash
printf 'public\nprivate\nmanager\n' > community.txt
onesixtyone -c community.txt 192.168.1.50
```
```
Scanning 1 hosts, 3 communities
192.168.1.50 [public] Hardware: x86 Family 6 Model 158 ... Software: Windows Version 6.3 (Build 19044)
```

**Findings:** `public` is valid (read access). The banner already leaks the OS build.
**One step ahead →** With a read community confirmed, the next move is a full MIB walk to pull system, user, and process data.

---

### 3. Dump System Information
```bash
snmpwalk -v 2c -c public 192.168.1.50
```
```
SNMPv2-MIB::sysDescr.0    = STRING: ... Windows Version 6.3 (Build 19044)
SNMPv2-MIB::sysObjectID.0 = OID: windowsSnmpAgent
DISMAN-EXPRESSION-MIB::sysUpTimeInstance = Timeticks: (147259) 0:24:32.59
SNMPv2-MIB::sysName.0     = STRING: WIN10-PC
```

For a structured view:
```bash
snmp-check 192.168.1.50 -c public
```
`snmp-check` sections: system info (hostname, domain, users), network interfaces (IP/MAC), routes, TCP/UDP connections (open ports), processes, storage, shares.

**Findings:** OS = Windows 10 (Build 19044), hostname = `WIN10-PC`, uptime ≈ 24 min (freshly booted).
**One step ahead →** Use the same read community to pull the local user list and software inventory.

---

### 4. Enumerate User Accounts (Windows)
Windows SNMP agents (when configured) expose local users via the LAN Manager MIB:
```bash
snmpwalk -v 2c -c public 192.168.1.50 1.3.6.1.4.1.77.1.2.25
```
```
iso.3.6.1.4.1.77.1.2.25.1.1.5...  = STRING: "Administrator"
iso.3.6.1.4.1.77.1.2.25.1.1.6...  = STRING: "Guest"
iso.3.6.1.4.1.77.1.2.25.1.1.7...  = STRING: "jdoe"
```

**Findings:** Valid local usernames — `Administrator`, `Guest`, `jdoe`.
**One step ahead →** A confirmed username list is the input for later credential-based testing; record it and cross-reference with anything LDAP returns.

---

### 5. Enumerate Processes & Software
Running processes:
```bash
snmpwalk -v 2c -c public 192.168.1.50 1.3.6.1.2.1.25.4.2.1.2
```
```
HOST-RESOURCES-MIB::hrSWRunName.4   = STRING: "smss.exe"
HOST-RESOURCES-MIB::hrSWRunName.652 = STRING: "firefox.exe"
```
Installed software:
```bash
snmpwalk -v 2c -c public 192.168.1.50 1.3.6.1.2.1.25.6.3.1.2
```

**Findings:** Active processes and installed packages, including version strings.
**One step ahead →** Map any outdated versions against known CVEs to flag candidate weaknesses (assessment only at this stage).

---

### 6. Identify Write Access (RW Community)
A read-write community (often `private`) is itself a **critical finding** — it implies the agent can be reconfigured, not just read.

```bash
# Detection only: does the host answer to a candidate RW community?
onesixtyone -c community.txt 192.168.1.50
```

**Findings:** If a second community responds and the device is documented as RW-capable, you have a high-severity misconfiguration to report.
**One step ahead →** Document the RW community as a finding. Any actual `snmpset` write — reboot, route change, interface toggle — is disruptive and out of enumeration scope; only perform it with explicit written authorization and a change window.

---

## LDAP Enumeration

### How LDAP Works (In One Minute)
- Queries go to a domain controller over **TCP 389** (or **636** for LDAPS).
- You **bind** as a user, or attempt an **anonymous bind**.
- A search request carries a **base DN** (e.g., `DC=corp,DC=local`) and an **LDAP filter** (e.g., `(objectClass=user)`).
- The server returns matching objects with the attributes you asked for.

**Target for this section:** `dc.corp.local` (`192.168.1.10`), Windows Domain Controller.

---

### 1. Discover Domain Controllers & LDAP Ports

**Tools used:** `nmap` (port scanner), `nslookup` (DNS query tool).

#### Tool usage

```bash
nmap -p 389,636,3268,3269 192.168.1.10
```
What it does: checks the host for the four ports that identify a domain controller.
- `-p 389,636,3268,3269` → test exactly these ports: **389** (LDAP), **636** (LDAPS/encrypted), **3268** (Global Catalog), **3269** (Global Catalog over SSL).
- `192.168.1.10` → the host you suspect is a DC.

Output:
```
PORT     STATE SERVICE
389/tcp  open  ldap
636/tcp  open  ldapssl
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPssl
```

```bash
nslookup -type=SRV _ldap._tcp.corp.local
```
What it does: asks DNS where the domain's LDAP servers are, so you can find DCs by name instead of guessing IPs.
- `-type=SRV` → request an **SRV** record (the record type that points to a service's host).
- `_ldap._tcp.corp.local` → the standard SRV name AD publishes for its LDAP service.

**Findings:** An LDAP-listening DC at `192.168.1.10`, global catalog included.
**One step ahead →** Determine how much you can read without credentials — test anonymous bind.

---

### 2. Test for Anonymous Bind
```bash
ldapsearch -x -H ldap://192.168.1.10 -b "DC=corp,DC=local"
```

**Findings:**
- Returns directory data → **anonymous bind enabled** (critical finding).
- `inappropriate authentication` / `unwilling to perform` → anonymous disabled.

Most modern ADs disable anonymous bind, but a valid low-privileged user still reads most of the directory. The rest of this section assumes `corp\jdoe:Spring2024`.
**One step ahead →** With any read access established, enumerate the full user set.

---

### 3. Enumerate Usernames
```bash
ldapsearch -x -H ldap://192.168.1.10 \
  -D "cn=jdoe,cn=Users,dc=corp,dc=local" -w 'Spring2024' \
  -b "DC=corp,DC=local" "(objectClass=user)" sAMAccountName
```
```
sAMAccountName: jdoe
sAMAccountName: adunn
sAMAccountName: svc_backup
...
```
Faster equivalent:
```bash
windapsearch --dc-ip 192.168.1.10 -d corp.local -u jdoe -p Spring2024 --module users
```

**Findings:** A complete `sAMAccountName` list, including service accounts (`svc_*`).
**One step ahead →** Before any credential testing, read the lockout policy so you know your safe attempt budget.

---

### 4. Read the Password Policy
```bash
ldapsearch -x -H ldap://192.168.1.10 \
  -D "cn=jdoe,cn=Users,dc=corp,dc=local" -w 'Spring2024' \
  -b "DC=corp,DC=local" "(objectClass=domainDNS)" \
  lockoutThreshold lockoutDuration minPwdLength pwdProperties
```
```
lockoutThreshold: 5
lockoutDuration: -18000000000 (30 minutes)
minPwdLength: 7
pwdProperties: 1 (DOMAIN_PASSWORD_COMPLEX)
```

**Findings:** Lockout at 5 attempts, 30-minute window, 7-char minimum, complexity on.
**One step ahead →** These numbers define the lockout-safe envelope for any later authorized credential testing. Capture them; don't act on them here.

---

### 5. Map Groups and Domain Admins
```bash
ldapsearch -x -H ldap://192.168.1.10 \
  -D "cn=jdoe,cn=Users,dc=corp,dc=local" -w 'Spring2024' \
  -b "CN=Domain Admins,CN=Users,DC=corp,DC=local"
```
```
member: CN=Administrator,CN=Users,DC=corp,DC=local
member: CN=Alice Dunn,CN=Users,DC=corp,DC=local
```
Or:
```bash
windapsearch --dc-ip 192.168.1.10 -d corp.local -u jdoe -p Spring2024 --module domain-admins
```

**Findings:** `adunn` is a Domain Admin — a high-value account.
**One step ahead →** High-value accounts become priority items in the engagement plan; note who is privileged and where they might have sessions.

---

### 6. Identify Kerberoastable Accounts (SPNs)
```bash
ldapsearch -x -H ldap://192.168.1.10 \
  -D "cn=jdoe,cn=Users,dc=corp,dc=local" -w 'Spring2024' \
  -b "DC=corp,DC=local" "(servicePrincipalName=*)" \
  sAMAccountName servicePrincipalName
```
```
sAMAccountName: svc_sql
servicePrincipalName: MSSQLSvc/sql.corp.local:1433

sAMAccountName: svc_backup
servicePrincipalName: backup/backup.corp.local
```

**Findings:** Service accounts with SPNs set — i.e., **Kerberoastable** candidates.
**One step ahead →** This is the enumeration boundary. The follow-on (requesting TGS tickets and cracking them offline) is an exploitation step performed only under scope; here you simply record which accounts are exposed.

---

### 7. Collect for BloodHound
SharpHound is a **collection** tool — it gathers directory and session data into a graph you analyze offline.
```powershell
SharpHound.exe --CollectionMethod All --Domain corp.local
```
Load the resulting zip into BloodHound to review:
- Shortest paths to Domain Admins
- Kerberoastable users, unconstrained-delegation hosts, AS-REP-roastable accounts
- Admin sessions on workstations

**Findings:** A relationship graph of the domain’s privilege structure.
**One step ahead →** The graph tells you which attack paths *exist*. Walking any of them is a separate, authorized exploitation phase.

---

## Indirect Enumeration (When LDAP is Blocked)
If 389 is firewalled, similar directory data is often reachable elsewhere:

- **RPC (135/445)**
  ```bash
  rpcclient -U "" -N 192.168.1.10
  > enumdomusers
  ```
- **SMB**
  ```bash
  crackmapexec smb 192.168.1.10 --users
  ```
- **Kerberos username validation**
  ```bash
  kerbrute userenum -d corp.local --dc 192.168.1.10 users.txt
  ```
- **DNS zone transfer** (rare)
  ```bash
  dig axfr @192.168.1.10 corp.local
  ```

**One step ahead →** Use these to rebuild the user/host picture, then re-enter the LDAP flow above once you have a foothold or valid credentials.

---

## Quick Command Cheat Sheet

### SNMP
```bash
# Discover agents
nmap -sU -p 161 --open 192.168.1.0/24

# Community check
onesixtyone -c community.txt 192.168.1.50

# Full walk
snmpwalk -v 2c -c public 192.168.1.50

# Structured report
snmp-check 192.168.1.50 -c public

# Windows local users
snmpwalk -v 2c -c public 192.168.1.50 1.3.6.1.4.1.77.1.2.25
```

### LDAP
```bash
# Anonymous bind test
ldapsearch -x -H ldap://dc.corp.local -b "DC=corp,DC=local"

# Authenticated user dump
ldapsearch -x -H ldap://dc.corp.local -D "cn=jdoe,cn=Users,dc=corp,dc=local" -w 'pass' \
  -b "DC=corp,DC=local" "(objectClass=user)" sAMAccountName

# Domain admins
ldapsearch ... -b "CN=Domain Admins,CN=Users,DC=corp,DC=local"

# SPN discovery
ldapsearch ... "(servicePrincipalName=*)" sAMAccountName servicePrincipalName

# windapsearch
windapsearch --dc-ip 192.168.1.10 -d corp.local -u jdoe -p pass --module users
windapsearch --dc-ip 192.168.1.10 -d corp.local -u jdoe -p pass --module domain-admins

# BloodHound collection
SharpHound.exe --CollectionMethod All
```

---

## Countermeasures Summary
- **SNMP**: Disable if unused. Prefer SNMPv3 with auth + encryption. Rotate community strings off defaults. Restrict source IPs.
- **LDAP**: Disable anonymous bind. Alert on bulk queries (SIEM). Enforce LDAP signing & channel binding. Trim "Authenticated Users" read permissions. Apply a strong password/lockout policy. Place admins in the Protected Users group.
