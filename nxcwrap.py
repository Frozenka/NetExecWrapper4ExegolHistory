#!/usr/bin/env python3
# By FrozenK for Exegol <3

import sys
import subprocess
import sqlite3
import json
import configparser
from colorama import Fore, init

init(autoreset=True)

REAL_NXC = "nxc"
NXC_DB = "/root/.nxc/workspaces/default/smb.db"
NXC_CONF = "/root/.nxc/nxc.conf"
PYTHON = "/opt/tools/Exegol-history/venv/bin/python3"
EXEGOL = "/opt/tools/Exegol-history/exegol-history.py"

def clean_string(s):
    if not s:
        return ""
    return s.replace('\x00', '').strip().lower()

def extract_ntlm_hash(full_hash):
    parts = full_hash.split(':')
    if len(parts) == 2:
        return parts[1].lower().strip()
    return full_hash.lower().strip()

def is_scrap_enabled():
    config = configparser.ConfigParser()
    try:
        config.read(NXC_CONF)
        return config.getboolean("Exegol-History", "scrap", fallback=False)
    except Exception:
        return False

if len(sys.argv) < 2:
    print(Fore.RED + "[!] Usage: nxc <protocol> <options>")
    sys.exit(1)

scrap_enabled = is_scrap_enabled()
if scrap_enabled:
    print(Fore.LIGHTBLACK_EX + "[i] Exegol-history sync is enabled")

nxc_args = sys.argv[1:]
nxc_cmd = [REAL_NXC] + nxc_args

cli_user = None
cli_pass = None
if "-u" in nxc_args:
    try:
        cli_user = nxc_args[nxc_args.index("-u") + 1]
    except IndexError:
        pass
if "-p" in nxc_args:
    try:
        cli_pass = nxc_args[nxc_args.index("-p") + 1]
    except IndexError:
        pass

try:
    retcode = subprocess.call(nxc_cmd)
except Exception as e:
    print(Fore.RED + f"[!] Error running nxc: {e}")
    sys.exit(1)

if not scrap_enabled:
    sys.exit(retcode)

existing_creds = set()
try:
    export_cmd = [PYTHON, EXEGOL, "export", "creds"]
    export_proc = subprocess.run(export_cmd, capture_output=True, text=True, check=True)
    creds_json = json.loads(export_proc.stdout)
    for cred in creds_json:
        username = clean_string(cred.get("username", ""))
        password = cred.get("password", "")
        hashval = cred.get("hash", "")
        if hashval:
            secret = extract_ntlm_hash(hashval)
        else:
            secret = clean_string(password)
        if username and secret:
            existing_creds.add((username, secret))
except Exception:
    pass

existing_hosts = set()
try:
    export_cmd = [PYTHON, EXEGOL, "export", "hosts"]
    export_proc = subprocess.run(export_cmd, capture_output=True, text=True, check=True)
    hosts_json = json.loads(export_proc.stdout)
    for host in hosts_json:
        ip = host.get("ip", "")
        if ip:
            existing_hosts.add(ip)
except Exception:
    pass

added_creds = []
added_hosts = []

if cli_user and cli_pass:
    user_clean = clean_string(cli_user)
    pass_clean = clean_string(cli_pass)
    key = (user_clean, pass_clean)
    if key not in existing_creds:
        try:
            cmd = [PYTHON, EXEGOL, "add", "creds", "-u", cli_user, "-p", cli_pass]
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            added_creds.append(key)
            existing_creds.add(key)
        except subprocess.CalledProcessError:
            pass

try:
    conn = sqlite3.connect(NXC_DB)
    cursor = conn.cursor()

    cursor.execute("SELECT username, password, credtype, domain FROM users WHERE password IS NOT NULL")
    rows = cursor.fetchall()

    for username, pwd, credtype, domain in rows:
        if not username or not pwd or username.endswith('$'):
            continue

        username_clean = clean_string(username)
        domain_clean = domain.replace('\x00', '').strip() if domain else ''

        if credtype == "hash":
            pwd_clean = extract_ntlm_hash(pwd)
        else:
            pwd_clean = clean_string(pwd)

        key = (username_clean, pwd_clean)

        if key in existing_creds:
            continue

        base_cmd = [PYTHON, EXEGOL, "add", "creds", "-u", username]
        if domain_clean:
            base_cmd += ["-d", domain_clean]

        if credtype == "hash":
            cmd = base_cmd + ["-H", pwd_clean]
        else:
            cmd = base_cmd + ["-p", pwd_clean]

        try:
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            added_creds.append(key)
            existing_creds.add(key)
        except subprocess.CalledProcessError:
            pass

    cursor.execute("SELECT DISTINCT ip, hostname FROM hosts WHERE ip IS NOT NULL")
    ips = cursor.fetchall()
    for ip, hostname in ips:
        if ip and ip not in existing_hosts:
            cmd = [PYTHON, EXEGOL, "add", "hosts", "--ip", ip]
            if hostname and hostname.strip():
                cmd += ["-n", hostname.strip()]
            try:
                subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                added_hosts.append(ip)
                existing_hosts.add(ip)
            except subprocess.CalledProcessError:
                pass

    conn.close()
except Exception as e:
    print(Fore.RED + f"[!] DB processing error: {e}")

if added_creds or added_hosts:
    print()
    print(Fore.CYAN + "=" * 50)
    if added_creds:
        print(Fore.GREEN + f"✅ Successfully added {len(added_creds)} credential{'s' if len(added_creds) != 1 else ''} in Exegol")
    if added_hosts:
        print(Fore.GREEN + f"✅ Successfully added {len(added_hosts)} IP{'s' if len(added_hosts) != 1 else ''} in Exegol")
    print(Fore.CYAN + "=" * 50)
    print()

sys.exit(retcode)
