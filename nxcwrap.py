#!/usr/bin/env python3
# By FrozenK for Exegol <3

import sys
import os
import subprocess
import sqlite3
import configparser
from colorama import Fore, init

# Import du module de synchronisation
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from exegol_sync import (
        check_exegol_available, get_existing_creds, get_existing_hosts,
        add_cred_to_exegol, add_host_to_exegol, sync_summary,
        clean_string, extract_ntlm_hash, PYTHON, EXEGOL
    )
except ImportError:
    # Fallback si le module n'est pas disponible
    print(Fore.YELLOW + "[!] Warning: exegol_sync.py not found, using fallback functions")
    PYTHON = "/opt/tools/Exegol-history/venv/bin/python3"
    EXEGOL = "/opt/tools/Exegol-history/exegol-history.py"
    
    def clean_string(s):
        if not s:
            return ""
        return s.replace('\x00', '').strip().lower()
    
    def extract_ntlm_hash(full_hash):
        if not full_hash:
            return ""
        parts = full_hash.split(':')
        if len(parts) == 2:
            return parts[1].lower().strip()
        return full_hash.lower().strip()

init(autoreset=True)

REAL_NXC = "nxc"
NXC_DB = "/root/.nxc/workspaces/default/smb.db"
NXC_CONF = "/root/.nxc/nxc.conf"

# Protocoles supportés par NetExec avec leurs bases de données
PROTOCOL_DBS = {
    "smb": "smb.db",
    "mssql": "mssql.db",
    "ldap": "ldap.db",
    "ssh": "ssh.db",
    "winrm": "winrm.db",
    "rdp": "rdp.db",
    "vnc": "vnc.db",
    "ftp": "ftp.db",
}

# Les fonctions clean_string et extract_ntlm_hash sont maintenant importées depuis exegol_sync

def get_arg_value(args, short_flag, long_flag=None):
    """Récupère la valeur d'un argument CLI (support -u et --username)."""
    try:
        if short_flag in args:
            idx = args.index(short_flag)
            if idx + 1 < len(args):
                return args[idx + 1]
    except (ValueError, IndexError):
        pass
    
    if long_flag:
        try:
            if long_flag in args:
                idx = args.index(long_flag)
                if idx + 1 < len(args):
                    return args[idx + 1]
        except (ValueError, IndexError):
            pass
    
    return None

def check_file_exists(filepath, description, verbose=False):
    """Vérifie si un fichier existe et affiche un message d'erreur si nécessaire."""
    if not os.path.exists(filepath):
        if verbose:
            print(Fore.YELLOW + f"[!] {description} not found: {filepath}")
        return False
    return True

def get_protocol_from_args(args):
    """Détermine le protocole utilisé à partir des arguments."""
    if len(args) > 0:
        protocol = args[0].lower()
        if protocol in PROTOCOL_DBS:
            return protocol
    return "smb"  # Par défaut

def get_db_path(protocol="smb", workspace="default"):
    """Retourne le chemin de la base de données pour un protocole donné."""
    db_name = PROTOCOL_DBS.get(protocol, "smb.db")
    return f"/root/.nxc/workspaces/{workspace}/{db_name}"

def detect_workspace_from_args(args):
    """Détecte le workspace depuis les arguments (option -w ou --workspace)."""
    workspace = "default"
    workspace_flag = get_arg_value(args, "-w", "--workspace")
    if workspace_flag:
        workspace = workspace_flag
    return workspace

def get_all_workspaces():
    """Récupère la liste de tous les workspaces disponibles (sans doublon)."""
    seen = {"default"}
    workspaces = ["default"]
    workspaces_dir = "/root/.nxc/workspaces"
    if os.path.exists(workspaces_dir):
        try:
            for item in os.listdir(workspaces_dir):
                item_path = os.path.join(workspaces_dir, item)
                if os.path.isdir(item_path) and item not in seen:
                    seen.add(item)
                    workspaces.append(item)
        except Exception:
            pass
    return workspaces

def is_scrap_enabled():
    """Vérifie si le scraping est activé dans la configuration."""
    config = configparser.ConfigParser()
    try:
        if not os.path.exists(NXC_CONF):
            return False
        config.read(NXC_CONF)
        return config.getboolean("Exegol-History", "scrap", fallback=False)
    except Exception:
        return False

# La fonction check_exegol_available est maintenant importée depuis exegol_sync

if len(sys.argv) < 2:
    print(Fore.RED + "[!] Usage: nxc <protocol> <options>")
    sys.exit(1)

scrap_enabled = is_scrap_enabled()
if scrap_enabled:
    print(Fore.LIGHTBLACK_EX + "[i] Exegol-history sync is enabled")

nxc_args = sys.argv[1:]
nxc_cmd = [REAL_NXC] + nxc_args

# Détection améliorée des arguments CLI (support -u/--username et -p/--password)
cli_user = get_arg_value(nxc_args, "-u", "--username")
cli_pass = get_arg_value(nxc_args, "-p", "--password")
cli_hash = get_arg_value(nxc_args, "-H", "--hash")
cli_domain = get_arg_value(nxc_args, "-d", "--domain")

try:
    retcode = subprocess.call(nxc_cmd)
except Exception as e:
    print(Fore.RED + f"[!] Error running nxc: {e}")
    sys.exit(1)

if not scrap_enabled:
    sys.exit(retcode)

# Vérification de la disponibilité d'Exegol-History
if not check_exegol_available(verbose=True):
    print(Fore.YELLOW + "[!] Exegol-History not available, skipping sync")
    sys.exit(retcode)

# Récupération des identifiants et hôtes existants
existing_creds = get_existing_creds()
existing_hosts = get_existing_hosts()

added_creds = []
added_hosts = []

# Ajout des identifiants depuis la ligne de commande
if cli_user and (cli_pass or cli_hash):
    if add_cred_to_exegol(cli_user, password=cli_pass, hash_val=cli_hash, domain=cli_domain, existing_creds=existing_creds):
        user_clean = clean_string(cli_user)
        if cli_hash:
            secret_clean = extract_ntlm_hash(cli_hash)
        else:
            secret_clean = clean_string(cli_pass)
        added_creds.append((user_clean, secret_clean))
        existing_creds.add((user_clean, secret_clean))

# --- Logique identique au script d'origine : une seule DB (default/smb.db), clé (user, secret) ---
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
        domain_clean = clean_string(domain_clean) if domain_clean else ""

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
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if r.returncode == 0:
                added_creds.append(key)
                existing_creds.add(key)
            elif r.stderr:
                print(Fore.YELLOW + f"[!] Exegol add creds failed for {username}: {r.stderr.strip()}")
        except subprocess.TimeoutExpired:
            print(Fore.YELLOW + f"[!] Timeout adding credential for {username}")

    cursor.execute("SELECT DISTINCT ip, hostname FROM hosts WHERE ip IS NOT NULL")
    ips = cursor.fetchall()
    for ip, hostname in ips:
        if ip and ip not in existing_hosts:
            cmd = [PYTHON, EXEGOL, "add", "hosts", "--ip", ip]
            if hostname and hostname.strip():
                cmd += ["-n", hostname.strip()]
            try:
                subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
                added_hosts.append(ip)
                existing_hosts.add(ip)
            except subprocess.CalledProcessError:
                pass
            except subprocess.TimeoutExpired:
                print(Fore.YELLOW + f"[!] Timeout adding host {ip}")

    conn.close()
except sqlite3.Error as e:
    print(Fore.YELLOW + f"[!] DB error: {e}")
except Exception as e:
    print(Fore.YELLOW + f"[!] Error: {e}")

# Affichage du résumé
sync_summary(added_creds, added_hosts)

sys.exit(retcode)
