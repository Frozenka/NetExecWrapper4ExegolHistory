#!/usr/bin/env python3
# Module partagé pour la synchronisation avec Exegol-History
# By FrozenK for Exegol <3

import subprocess
import json
import os
import tempfile
from colorama import Fore

PYTHON = "/opt/tools/Exegol-history/venv/bin/python3"
EXEGOL = "/opt/tools/Exegol-history/exegol-history.py"

def clean_string(s):
    """Nettoie une chaîne de caractères."""
    if not s:
        return ""
    return s.replace('\x00', '').strip().lower()

def extract_ntlm_hash(full_hash):
    """Extrait le hash NTLM d'un format user:hash ou retourne le hash tel quel."""
    if not full_hash:
        return ""
    parts = full_hash.split(':')
    if len(parts) == 2:
        return parts[1].lower().strip()
    return full_hash.lower().strip()

def check_exegol_available(verbose=False):
    """Vérifie si Exegol-History est disponible."""
    if not os.path.exists(PYTHON):
        if verbose:
            print(Fore.YELLOW + f"[!] Python interpreter not found: {PYTHON}")
        return False
    if not os.path.exists(EXEGOL):
        if verbose:
            print(Fore.YELLOW + f"[!] Exegol-history script not found: {EXEGOL}")
        return False
    return True

def _parse_creds_json(creds_json):
    """Parse la liste JSON des creds et retourne un set de (username_clean, secret)."""
    out = set()
    for cred in creds_json:
        username = clean_string(cred.get("username", ""))
        password = cred.get("password", "")
        hashval = cred.get("hash", "")
        if hashval:
            secret = extract_ntlm_hash(hashval)
        else:
            secret = clean_string(password)
        if username and secret:
            out.add((username, secret))
    return out

def get_existing_creds():
    """Récupère les identifiants existants depuis Exegol-History.
    Compatible ancienne API (export creds → stdout JSON) et nouvelle (--format JSON -f file).
    """
    existing_creds = set()
    # 1) Nouvelle API : export creds --format JSON -f <fichier>
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            tmp_path = f.name
        try:
            export_cmd = [PYTHON, EXEGOL, "export", "creds", "--format", "JSON", "-f", tmp_path]
            export_proc = subprocess.run(export_cmd, capture_output=True, text=True, timeout=30)
            if export_proc.returncode == 0 and os.path.isfile(tmp_path):
                with open(tmp_path, 'r', encoding='utf-8') as fp:
                    creds_json = json.load(fp)
                return _parse_creds_json(creds_json)
        finally:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass
    except Exception:
        pass
    # 2) Ancienne API (comme ton repo d'origine) : export creds → JSON sur stdout
    try:
        export_cmd = [PYTHON, EXEGOL, "export", "creds"]
        export_proc = subprocess.run(export_cmd, capture_output=True, text=True, timeout=30)
        if export_proc.returncode == 0 and export_proc.stdout.strip():
            creds_json = json.loads(export_proc.stdout)
            return _parse_creds_json(creds_json)
    except subprocess.TimeoutExpired:
        print(Fore.YELLOW + "[!] Timeout while exporting credentials from Exegol-History")
    except json.JSONDecodeError:
        pass
    except Exception as e:
        print(Fore.YELLOW + f"[!] Error exporting credentials: {e}")
    return existing_creds

def get_existing_hosts():
    """Récupère les hôtes existants depuis Exegol-History.
    Compatible ancienne API (export hosts → stdout JSON) et nouvelle (--format JSON -f file).
    """
    existing_hosts = set()
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            tmp_path = f.name
        try:
            export_cmd = [PYTHON, EXEGOL, "export", "hosts", "--format", "JSON", "-f", tmp_path]
            export_proc = subprocess.run(export_cmd, capture_output=True, text=True, timeout=30)
            if export_proc.returncode == 0 and os.path.isfile(tmp_path):
                with open(tmp_path, 'r', encoding='utf-8') as fp:
                    hosts_json = json.load(fp)
                for host in hosts_json:
                    ip = host.get("ip", "")
                    if ip:
                        existing_hosts.add(ip)
                return existing_hosts
        finally:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass
    except Exception:
        pass
    try:
        export_cmd = [PYTHON, EXEGOL, "export", "hosts"]
        export_proc = subprocess.run(export_cmd, capture_output=True, text=True, timeout=30)
        if export_proc.returncode == 0 and export_proc.stdout.strip():
            hosts_json = json.loads(export_proc.stdout)
            for host in hosts_json:
                ip = host.get("ip", "")
                if ip:
                    existing_hosts.add(ip)
    except subprocess.TimeoutExpired:
        print(Fore.YELLOW + "[!] Timeout while exporting hosts from Exegol-History")
    except json.JSONDecodeError:
        pass
    except Exception as e:
        print(Fore.YELLOW + f"[!] Error exporting hosts: {e}")
    return existing_hosts

def add_cred_to_exegol(username, password=None, hash_val=None, domain=None, existing_creds=None):
    """Ajoute un identifiant à Exegol-History si il n'existe pas déjà."""
    if not check_exegol_available():
        return False
    
    if existing_creds is None:
        existing_creds = get_existing_creds()
    
    username_clean = clean_string(username)
    domain_clean = clean_string(domain) if domain else ""
    
    if hash_val:
        secret_clean = extract_ntlm_hash(hash_val)
    elif password:
        secret_clean = clean_string(password)
    else:
        return False
    
    # Clé en 2-tuple (user, secret) comme le script d'origine
    key = (username_clean, secret_clean)
    
    if key in existing_creds:
        return False
    
    try:
        cmd = [PYTHON, EXEGOL, "add", "creds", "-u", username]
        if domain_clean and domain:
            cmd += ["-d", domain]
        if hash_val:
            cmd += ["-H", secret_clean]
        else:
            # Utiliser le mot de passe original (pas lowercasé) pour Exegol
            cmd += ["-p", password]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            err = (result.stderr or result.stdout or "exit code %s" % result.returncode).strip()
            print(Fore.YELLOW + f"[!] Exegol add creds failed for {username}: {err}")
            return False
        return True
    except subprocess.TimeoutExpired:
        print(Fore.YELLOW + f"[!] Timeout while adding credential for {username}")
        return False
    except Exception as e:
        print(Fore.YELLOW + f"[!] Exegol add creds failed for {username}: {e}")
        return False

def add_host_to_exegol(ip, hostname=None, existing_hosts=None):
    """Ajoute un hôte à Exegol-History si il n'existe pas déjà."""
    if not check_exegol_available():
        return False
    
    if existing_hosts is None:
        existing_hosts = get_existing_hosts()
    
    if not ip or ip in existing_hosts:
        return False
    
    try:
        cmd = [PYTHON, EXEGOL, "add", "hosts", "--ip", ip]
        if hostname and hostname.strip():
            cmd += ["-n", hostname.strip()]
        
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
        return True
    except subprocess.TimeoutExpired:
        print(Fore.YELLOW + f"[!] Timeout while adding host {ip}")
        return False
    except subprocess.CalledProcessError:
        return False

def sync_summary(added_creds, added_hosts):
    """Affiche un résumé de la synchronisation."""
    if added_creds or added_hosts:
        print()
        print(Fore.CYAN + "=" * 50)
        if added_creds:
            print(Fore.GREEN + f"✅ Successfully added {len(added_creds)} credential{'s' if len(added_creds) != 1 else ''} in Exegol")
        if added_hosts:
            print(Fore.GREEN + f"✅ Successfully added {len(added_hosts)} IP{'s' if len(added_hosts) != 1 else ''} in Exegol")
        print(Fore.CYAN + "=" * 50)
        print()
