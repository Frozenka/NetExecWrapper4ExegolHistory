# 🛠️ NetExec Wrapper for Exegol-History

## Description

Is a wrapper for NXC designed to be used **inside an Exegol container**.  
It enhances your workflow by automatically syncing discovered credentials and hosts from NetExec into [Exegol-History](https://github.com/ThePorgs/Exegol-history).

After executing any `nxc` command, it will:

- Add discovered or used **credentials** (plaintext or hashes) to Exegol-History
- Add **host IPs and hostnames** to Exegol-History

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

Run `nxc` as usual:

```bash
nxc smb 10.10.10.10 -u admin -p password123
```
### 🔧 Disable the wrapper (Exegol-history sync)

```bash
sed -i 's/scrap *= *True/scrap = False/' /root/.nxc/nxc.conf
```
Or use alias :
`disablenxcwrapper`
`enablenxcwrapper`


This keeps nxcwrap active but disables automatic credential/host syncing.


This wrapper will:

1. Run the actual NetExec command
2. Parse the local `smb.db` workspace
3. Auto-push new credentials and hosts into Exegol-History (if not already known)

---
 
 
## Features

- ✅ Transparent execution of `nxc`
- ✅ Automatic credential and host sync with Exegol-History
- ✅ NTLM hash parsing support

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

 
