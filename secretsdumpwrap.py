#!/usr/bin/env python3
# Wrapper pour secretsdump (Impacket) pour Exegol-History
# By FrozenK for Exegol <3

import sys
import os
import subprocess
import re
from colorama import Fore, init

init(autoreset=True)

# Import du module de synchronisation
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from exegol_sync import (
        check_exegol_available, get_existing_creds, get_existing_hosts,
        add_cred_to_exegol, add_host_to_exegol, sync_summary
    )
except ImportError:
    print(Fore.RED + "[!] Error: exegol_sync.py not found")
    sys.exit(1)

# Essayer différents chemins possibles pour secretsdump
REAL_SECRETSDUMP = None
possible_paths = [
    "secretsdump.py",
    "/usr/local/bin/secretsdump.py",
    "/usr/bin/secretsdump.py",
    "/opt/tools/impacket/examples/secretsdump.py",
    "/opt/tools/Impacket/examples/secretsdump.py"
]

for path in possible_paths:
    if os.path.exists(path):
        REAL_SECRETSDUMP = path.split("/")[-1] if "/" in path else path
        break
    # Essayer avec which pour les chemins sans /
    if "/" not in path:
        which_result = subprocess.run(["which", path], 
                                      capture_output=True, stderr=subprocess.DEVNULL)
        if which_result.returncode == 0:
            REAL_SECRETSDUMP = path
            break

if not REAL_SECRETSDUMP:
    # Dernier recours : essayer de trouver secretsdump dans le PATH
    which_result = subprocess.run(["which", "secretsdump.py"], 
                                  capture_output=True, text=True)
    if which_result.returncode == 0:
        REAL_SECRETSDUMP = which_result.stdout.strip()
    else:
        REAL_SECRETSDUMP = "secretsdump.py"  # Par défaut

def extract_ip_from_args(args):
    """Extrait l'IP depuis les arguments de la commande."""
    ip_pattern = re.compile(r'\d+\.\d+\.\d+\.\d+')
    for arg in args:
        # Format: user:pass@ip ou domain/user:pass@ip
        if '@' in arg:
            ip_match = ip_pattern.search(arg)
            if ip_match:
                return ip_match.group(0)
        # Format: -targets ip ou --targets ip
        elif arg in ['-targets', '--targets']:
            idx = args.index(arg)
            if idx + 1 < len(args):
                ip_match = ip_pattern.search(args[idx + 1])
                if ip_match:
                    return ip_match.group(0)
        # Format: juste une IP
        elif ip_pattern.match(arg):
            return arg
    return None

def parse_secretsdump_output(output, cmd_args=None):
    """Parse la sortie de secretsdump pour extraire les identifiants."""
    creds = []
    hosts = set()
    
    lines = output.split('\n')
    current_domain = None
    
    # Extraire l'IP depuis les arguments de la commande
    if cmd_args:
        ip_from_args = extract_ip_from_args(cmd_args)
        if ip_from_args:
            hosts.add(ip_from_args)
    
    # Extraire l'IP depuis la sortie (dans stderr ou stdout)
    ip_from_cmd = re.search(r'@(\d+\.\d+\.\d+\.\d+)', output)
    if ip_from_cmd:
        hosts.add(ip_from_cmd.group(1))
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
        
        # Détection du domaine depuis les lignes de format
        # Ex: [*] Dumping Domain Credentials (domain\machine$)
        domain_match = re.search(r'Dumping.*?\(([^)]+)\)', line, re.IGNORECASE)
        if domain_match:
            domain_info = domain_match.group(1)
            if '\\' in domain_info:
                parts = domain_info.split('\\')
                current_domain = parts[0]
        
        # Pattern principal pour les identifiants: username:lm_hash:ntlm_hash
        # Format standard de secretsdump: username:aad3b435b51404eeaad3b435b51404ee:hash_ntlm
        ntlm_pattern = re.match(r'^([^:]+):([a-f0-9]{32}|[a-f0-9]{0,32}):([a-f0-9]{32})$', line, re.IGNORECASE)
        if ntlm_pattern:
            username = ntlm_pattern.group(1).strip()
            lm_hash = ntlm_pattern.group(2)
            ntlm_hash = ntlm_pattern.group(3)
            
            # Ignorer les hash LM vides ou aad3b435b51404ee (vide)
            if ntlm_hash and len(ntlm_hash) == 32 and ntlm_hash.lower() != 'aad3b435b51404eeaad3b435b51404ee':
                username_clean = username.split('\\')[-1] if '\\' in username else username
                domain_clean = username.split('\\')[0] if '\\' in username else current_domain
                
                creds.append({
                    'username': username_clean,
                    'hash': ntlm_hash.lower(),
                    'domain': domain_clean
                })
            continue
        
        # Pattern pour username:password (moins commun mais possible)
        # Seulement si ce n'est pas un hash et que la ligne semble être un identifiant
        simple_pattern = re.match(r'^([^:]+):(.+)$', line)
        if simple_pattern and not line.startswith('[*]') and not line.startswith('Impacket') and 'Dumping' not in line:
            username = simple_pattern.group(1).strip()
            secret = simple_pattern.group(2).strip()
            
            # Vérifier que ce n'est pas juste un hash NTLM seul
            if len(secret) == 32 and re.match(r'^[a-f0-9]{32}$', secret.lower()):
                # C'est un hash NTLM seul
                username_clean = username.split('\\')[-1] if '\\' in username else username
                domain_clean = username.split('\\')[0] if '\\' in username else current_domain
                
                creds.append({
                    'username': username_clean,
                    'hash': secret.lower(),
                    'domain': domain_clean
                })
            elif len(secret) > 3 and not re.match(r'^[a-f0-9]{32}$', secret.lower()):
                # Probablement un mot de passe
                username_clean = username.split('\\')[-1] if '\\' in username else username
                domain_clean = username.split('\\')[0] if '\\' in username else current_domain
                
                creds.append({
                    'username': username_clean,
                    'password': secret,
                    'domain': domain_clean
                })
        
        # Extraire l'IP depuis les lignes avec [*]
        if '[*]' in line:
            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
            if ip_match:
                hosts.add(ip_match.group(1))
    
    return creds, list(hosts)

def is_scrap_enabled():
    """Vérifie si le scraping est activé dans la configuration."""
    import configparser
    nxc_conf = "/root/.nxc/nxc.conf"
    config = configparser.ConfigParser()
    try:
        if not os.path.exists(nxc_conf):
            return False
        config.read(nxc_conf)
        return config.getboolean("Exegol-History", "scrap", fallback=False)
    except Exception:
        return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(Fore.RED + "[!] Usage: secretsdump <options>")
        sys.exit(1)
    
    scrap_enabled = is_scrap_enabled()
    if scrap_enabled:
        print(Fore.LIGHTBLACK_EX + "[i] Exegol-history sync is enabled")
    
    secretsdump_args = sys.argv[1:]
    secretsdump_cmd = [REAL_SECRETSDUMP] + secretsdump_args
    
    # Vérifier si un fichier de sortie est spécifié
    output_file = None
    if "-outputfile" in secretsdump_args or "--outputfile" in secretsdump_args:
        output_file_idx = secretsdump_args.index("-outputfile") if "-outputfile" in secretsdump_args else secretsdump_args.index("--outputfile")
        if output_file_idx + 1 < len(secretsdump_args):
            output_file = secretsdump_args[output_file_idx + 1]
    
    # Exécution de secretsdump avec capture de la sortie
    output_content = ""
    retcode = 0
    try:
        result = subprocess.run(
            secretsdump_cmd,
            capture_output=True,
            text=True,
            timeout=3600  # 1 heure max
        )
        
        # Afficher la sortie normale de secretsdump
        if result.stdout:
            print(result.stdout)
        if result.stderr:
            print(result.stderr, file=sys.stderr)
        
        retcode = result.returncode
        
        # Si un fichier de sortie est spécifié, lire aussi depuis ce fichier
        output_content = result.stdout + result.stderr
        if output_file and os.path.exists(output_file):
            try:
                with open(output_file, 'r', encoding='utf-8', errors='ignore') as f:
                    file_content = f.read()
                    output_content += "\n" + file_content
            except Exception as e:
                print(Fore.YELLOW + f"[!] Could not read output file {output_file}: {e}")
        
    except subprocess.TimeoutExpired:
        print(Fore.RED + "[!] secretsdump timeout")
        sys.exit(1)
    except Exception as e:
        print(Fore.RED + f"[!] Error running secretsdump: {e}")
        sys.exit(1)
    
    if not scrap_enabled:
        sys.exit(retcode)
    
    # Vérification de la disponibilité d'Exegol-History
    if not check_exegol_available(verbose=True):
        print(Fore.YELLOW + "[!] Exegol-History not available, skipping sync")
        sys.exit(retcode)
    
    # Parse de la sortie pour extraire les identifiants
    # output_content contient déjà stdout + stderr + contenu du fichier si spécifié
    creds, hosts = parse_secretsdump_output(output_content, secretsdump_args)
    
    # Récupération des identifiants et hôtes existants
    existing_creds = get_existing_creds()
    existing_hosts = get_existing_hosts()
    
    added_creds = []
    added_hosts = []
    
    # Ajout des identifiants trouvés
    for cred in creds:
        username = cred.get('username', '')
        password = cred.get('password')
        hash_val = cred.get('hash')
        domain = cred.get('domain')
        
        if username:
            if add_cred_to_exegol(username, password=password, hash_val=hash_val, domain=domain, existing_creds=existing_creds):
                added_creds.append((username, hash_val or password, domain or ''))
                # Mettre à jour le set pour éviter les doublons
                from exegol_sync import clean_string, extract_ntlm_hash
                username_clean = clean_string(username)
                domain_clean = clean_string(domain) if domain else ""
                if hash_val:
                    secret_clean = extract_ntlm_hash(hash_val)
                else:
                    secret_clean = clean_string(password)
                existing_creds.add((username_clean, secret_clean, domain_clean))
    
    # Ajout des hôtes trouvés
    for host in hosts:
        if add_host_to_exegol(host, existing_hosts=existing_hosts):
            added_hosts.append(host)
            existing_hosts.add(host)
    
    # Affichage du résumé
    sync_summary(added_creds, added_hosts)
    
    sys.exit(retcode)
