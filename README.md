# 🛠️ NetExec Wrapper for Exegol-History

## Description

Is a wrapper for NXC and other tools (like secretsdump) designed to be used **inside an Exegol container**.  
It enhances your workflow by automatically syncing discovered credentials and hosts from NetExec and Impacket tools into [Exegol-History](https://github.com/ThePorgs/Exegol-history).

After executing any `nxc` or `secretsdump` command, it will:

- Add discovered or used **credentials** (plaintext or hashes) to Exegol-History
- Add **host IPs and hostnames** to Exegol-History
- Support multiple **workspaces** and **protocols** automatically

---
## Installation (my-ressources) :
```bash
echo 'curl -sSL https://raw.githubusercontent.com/Frozenka/nxcwrap/refs/heads/main/install_nxcwraper.sh | bash' >> ~/.exegol/my-resources/setup/load_user_setup.sh
```

## Installation (inside Exegol) :

```bash
bash <(curl -sSL https://raw.githubusercontent.com/Frozenka/nxcwrap/refs/heads/main/install_nxcwraper.sh)

```

## Demo :
[![Demo](https://img.youtube.com/vi/Li9In64pfbQ/maxresdefault.jpg)](https://www.youtube.com/watch?v=Li9In64pfbQ)

## Usage

### NetExec (nxc)

Run `nxc` as usual:

```bash
nxc smb 10.10.10.10 -u admin -p password123
```

### Secretsdump (Impacket)

Run `secretsdump` as usual, credentials will be automatically extracted:

```bash
secretsdump DOMAIN/user:pass@10.10.10.10
secretsdump -outputfile output.txt DOMAIN/user:pass@10.10.10.10
```

The wrapper will:
- Parse the output to extract NTLM hashes (format: `username:lm:ntlm`)
- Extract domain information
- Extract target IPs
- Automatically add all discovered credentials to Exegol-History
### 🔧 Disable the wrapper (Exegol-history sync)

```bash
sed -i 's/scrap *= *True/scrap = False/' /root/.nxc/nxc.conf
```
Or use alias :
`disablenxcwrapper`
`enablenxcwrapper`


This keeps nxcwrap active but disables automatic credential/host syncing.


This wrapper will:

1. Run the actual NetExec/Impacket command
2. Parse all available protocol databases (smb.db, mssql.db, ldap.db, etc.)
3. Detect and use the correct workspace (or scan all workspaces)
4. Auto-push new credentials and hosts into Exegol-History (if not already known)
5. For secretsdump: Parse output and output files to extract credentials

---
 
 
## Features

- ✅ Transparent execution of `nxc` and `secretsdump`
- ✅ Automatic credential and host sync with Exegol-History
- ✅ NTLM hash parsing support
- ✅ Multi-protocol support (SMB, MSSQL, LDAP, SSH, WinRM, RDP, VNC, FTP)
- ✅ Multi-workspace support (automatic detection)
- ✅ Support for secretsdump output files (`-outputfile`)
- ✅ Improved IP detection from command arguments
- ✅ Domain-aware credential deduplication

---

## Requirements

- Exegol container with:
  - NetExec installed in `/opt/tools/NetExec/`
  - Exegol-History installed in `/opt/tools/Exegol-history/`
- Python dependency: `colorama`

---

## Limitations

- Only works inside Exegol  

---

 
