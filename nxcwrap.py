#!/usr/bin/env python3
# By FrozenK for Exegol <3
# Wrapper nxc → sync auto Exegol-history (un seul fichier, pas d'exegol_sync)

import sys
import os
import subprocess
import sqlite3
import json
import tempfile
import configparser
import shutil
from colorama import Fore, init

init(autoreset=True)

REAL_NXC = "nxc"
EXEGOL_SCRIPT = "/opt/tools/Exegol-history/exegol-history.py"

# Commande pour lancer exegol-history (jamais le venv, souvent absent)
_exegol_base = None

def _exegol_cmd():
    """Liste pour lancer exegol-history : 'exegol-history' dans PATH ou script avec python courant."""
    global _exegol_base
    if _exegol_base is not None:
        return _exegol_base
    exe = shutil.which("exegol-history")
    if exe:
        _exegol_base = [exe]
        return _exegol_base
    if os.path.isfile(EXEGOL_SCRIPT):
        _exegol_base = [sys.executable, EXEGOL_SCRIPT]
        return _exegol_base
    _exegol_base = []
    return _exegol_base

def _nxc_conf():
    return os.environ.get("NXC_CONF") or os.path.join(os.path.expanduser("~"), ".nxc", "nxc.conf")

def _nxc_db():
    if os.environ.get("NXC_DB"):
        return os.environ.get("NXC_DB")
    base = os.path.join(os.path.expanduser("~"), ".nxc", "workspaces", "default", "smb.db")
    if os.path.isfile(base):
        return base
    if os.path.isfile("/root/.nxc/workspaces/default/smb.db"):
        return "/root/.nxc/workspaces/default/smb.db"
    return base

def clean_string(s):
    if not s:
        return ""
    return s.replace('\x00', '').strip().lower()

def extract_ntlm_hash(full_hash):
    if not full_hash:
        return ""
    parts = full_hash.split(':')
    return parts[1].lower().strip() if len(parts) == 2 else full_hash.lower().strip()

def is_scrap_enabled():
    try:
        config = configparser.ConfigParser()
        config.read(_nxc_conf())
        return config.getboolean("Exegol-History", "scrap", fallback=False)
    except Exception:
        return False

def get_existing_creds():
    """Export Exegol-history : --format JSON obligatoire (API actuelle)."""
    base = _exegol_cmd()
    if not base:
        return set()
    out = set()
    # Exegol-history exige --format. Essayer -f fichier puis stdout.
    for use_file in (True, False):
        try:
            if use_file:
                f = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
                tmp = f.name
                f.close()
                cmd = base + ["export", "creds", "--format", "JSON", "-f", tmp]
            else:
                cmd = base + ["export", "creds", "--format", "JSON"]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if r.returncode != 0:
                if use_file and os.path.isfile(tmp):
                    os.unlink(tmp)
                continue
            if use_file and os.path.isfile(tmp):
                with open(tmp, 'r', encoding='utf-8') as fp:
                    data = json.load(fp)
                os.unlink(tmp)
            else:
                raw = (r.stdout or "").strip()
                if not raw:
                    continue
                data = json.loads(raw)
            if not isinstance(data, list):
                data = data.get("creds", data.get("credentials", []))
            if not isinstance(data, list):
                continue
            for c in data:
                u = clean_string(c.get("username", ""))
                pwd = c.get("password", "")
                h = c.get("hash", "")
                secret = extract_ntlm_hash(h) if h else clean_string(pwd)
                if u and secret:
                    out.add((u, secret))
            return out
        except (json.JSONDecodeError, FileNotFoundError, subprocess.TimeoutExpired):
            pass
        except Exception:
            pass
    return out

def get_existing_hosts():
    base = _exegol_cmd()
    if not base:
        return set()
    out = set()
    for use_file in (True, False):
        try:
            if use_file:
                f = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
                tmp = f.name
                f.close()
                cmd = base + ["export", "hosts", "--format", "JSON", "-f", tmp]
            else:
                cmd = base + ["export", "hosts", "--format", "JSON"]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if r.returncode != 0:
                if use_file and os.path.isfile(tmp):
                    os.unlink(tmp)
                continue
            if use_file and os.path.isfile(tmp):
                with open(tmp, 'r', encoding='utf-8') as fp:
                    data = json.load(fp)
                os.unlink(tmp)
            else:
                raw = (r.stdout or "").strip()
                if not raw:
                    continue
                data = json.loads(raw)
            if not isinstance(data, list):
                data = data.get("hosts", [])
            if not isinstance(data, list):
                continue
            for h in data:
                ip = (h.get("ip", "") if isinstance(h, dict) else "") or ""
                if ip:
                    out.add(ip)
            return out
        except (json.JSONDecodeError, FileNotFoundError, subprocess.TimeoutExpired):
            pass
        except Exception:
            pass
    return out

def add_cred(username, password=None, hash_val=None, domain=None):
    base = _exegol_cmd()
    if not base:
        return False
    cmd = base + ["add", "creds", "-u", username]
    if domain and str(domain).strip():
        cmd += ["-d", str(domain).strip()]
    if hash_val:
        cmd += ["-H", extract_ntlm_hash(hash_val)]
    elif password is not None:
        cmd += ["-p", password]
    else:
        return False
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    return r.returncode == 0

def add_host(ip, hostname=None):
    base = _exegol_cmd()
    if not base or not ip:
        return False
    cmd = base + ["add", "hosts", "--ip", ip]
    if hostname and str(hostname).strip():
        cmd += ["-n", str(hostname).strip()]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    return r.returncode == 0

# --- main ---

if len(sys.argv) < 2:
    print(Fore.RED + "[!] Usage: nxc <protocol> <options>")
    sys.exit(1)

# Enlever le premier argument s'il est "nxc" (alias donne: nxc smb ... ou parfois nxc nxc smb ...)
nxc_args = list(sys.argv[1:])
if nxc_args and nxc_args[0].lower() == "nxc":
    nxc_args.pop(0)
if not nxc_args:
    print(Fore.RED + "[!] Usage: nxc <protocol> <options>")
    sys.exit(1)

scrap_enabled = is_scrap_enabled()
if scrap_enabled:
    print(Fore.LIGHTBLACK_EX + "[i] Exegol-history sync is enabled")

nxc_cmd = [REAL_NXC] + nxc_args

cli_user = None
cli_pass = None
if "-u" in nxc_args:
    try:
        i = nxc_args.index("-u")
        if i + 1 < len(nxc_args):
            cli_user = nxc_args[i + 1]
    except (ValueError, IndexError):
        pass
if "-p" in nxc_args:
    try:
        i = nxc_args.index("-p")
        if i + 1 < len(nxc_args):
            cli_pass = nxc_args[i + 1]
    except (ValueError, IndexError):
        pass

try:
    retcode = subprocess.call(nxc_cmd)
except Exception as e:
    print(Fore.RED + f"[!] Error running nxc: {e}")
    sys.exit(1)

if not scrap_enabled:
    sys.exit(retcode)

if not _exegol_cmd():
    sys.exit(retcode)

existing_creds = get_existing_creds()
existing_hosts = get_existing_hosts()
added_creds = []
added_hosts = []

if cli_user and cli_pass:
    key = (clean_string(cli_user), clean_string(cli_pass))
    if key not in existing_creds and add_cred(cli_user, password=cli_pass):
        added_creds.append(key)
        existing_creds.add(key)

try:
    conn = sqlite3.connect(_nxc_db())
    cur = conn.cursor()
    cur.execute("SELECT username, password, credtype, domain FROM users WHERE password IS NOT NULL")
    for username, pwd, credtype, domain in cur.fetchall():
        if not username or not pwd or username.endswith('$'):
            continue
        domain_clean = (domain or "").replace('\x00', '').strip()
        if credtype == "hash":
            pwd_clean = extract_ntlm_hash(pwd)
            ok = add_cred(username, hash_val=pwd, domain=domain_clean or None)
        else:
            pwd_clean = clean_string(pwd)
            ok = add_cred(username, password=pwd, domain=domain_clean or None)
        key = (clean_string(username), pwd_clean)
        if key in existing_creds:
            continue
        if ok:
            added_creds.append(key)
            existing_creds.add(key)

    cur.execute("SELECT DISTINCT ip, hostname FROM hosts WHERE ip IS NOT NULL")
    for ip, hostname in cur.fetchall():
        if not ip or ip in existing_hosts:
            continue
        if add_host(ip, hostname=hostname):
            added_hosts.append(ip)
            existing_hosts.add(ip)

    conn.close()
except Exception as e:
    print(Fore.RED + f"[!] DB processing error: {e}")

if added_creds or added_hosts:
    print()
    print(Fore.CYAN + "=" * 50)
    if added_creds:
        print(Fore.GREEN + f"✅ Successfully added {len(added_creds)} credential(s) in Exegol")
    if added_hosts:
        print(Fore.GREEN + f"✅ Successfully added {len(added_hosts)} IP(s) in Exegol")
    print(Fore.CYAN + "=" * 50)
    print()

sys.exit(retcode)
