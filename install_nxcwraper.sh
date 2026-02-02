#!/bin/bash
pip install colorama >/dev/null 2>&1

# Installation des wrappers
INSTALL_DIR="/opt/tools/NetExec/nxc"
mkdir -p "$INSTALL_DIR"

# Téléchargement des fichiers
wget -qO "$INSTALL_DIR/nxcwrap.py" https://raw.githubusercontent.com/Frozenka/nxcwrap/main/nxcwrap.py
wget -qO "$INSTALL_DIR/exegol_sync.py" https://raw.githubusercontent.com/Frozenka/nxcwrap/main/exegol_sync.py
wget -qO "$INSTALL_DIR/secretsdumpwrap.py" https://raw.githubusercontent.com/Frozenka/nxcwrap/main/secretsdumpwrap.py

# Rendre les scripts exécutables
chmod +x "$INSTALL_DIR/nxcwrap.py"
chmod +x "$INSTALL_DIR/secretsdumpwrap.py"

CONF_PATH="/root/.nxc/nxc.conf"
mkdir -p "$(dirname "$CONF_PATH")"

if ! grep -q "\[Exegol-History\]" "$CONF_PATH" 2>/dev/null; then
    echo -e "\n[Exegol-History]\nscrap = True" >> "$CONF_PATH"
else
    sed -i '/\[Exegol-History\]/,/^\[/{s/^scrap *=.*/scrap = True/}' "$CONF_PATH"
fi

ALIAS_LINE="alias nxc=\"python3 /opt/tools/NetExec/nxc/nxcwrap.py\""
if ! grep -Fxq "$ALIAS_LINE" /root/.bashrc; then
    echo "$ALIAS_LINE" >> /root/.bashrc
fi

# Alias pour secretsdump (optionnel, peut être désactivé si secretsdump.py n'est pas disponible)
SECRETSDUMP_ALIAS="alias secretsdump=\"python3 /opt/tools/NetExec/nxc/secretsdumpwrap.py\""
if ! grep -Fxq "$SECRETSDUMP_ALIAS" /root/.bashrc; then
    echo "$SECRETSDUMP_ALIAS" >> /root/.bashrc
fi

DISABLE_ALIAS="alias disablenxcwrapper=\"sed -i 's/scrap *= *True/scrap = False/' /root/.nxc/nxc.conf\""
if ! grep -Fxq "$DISABLE_ALIAS" /root/.bashrc; then
    echo "$DISABLE_ALIAS" >> /root/.bashrc
fi

ENABLE_ALIAS="alias enablenxcwrapper=\"sed -i 's/scrap *= *False/scrap = True/' /root/.nxc/nxc.conf\""
if ! grep -Fxq "$ENABLE_ALIAS" /root/.bashrc; then
    echo "$ENABLE_ALIAS" >> /root/.bashrc
fi
