#!/bin/bash
pip install colorama >/dev/null 2>&1

wget -qO /opt/tools/NetExec/nxc/nxcwrap.py https://raw.githubusercontent.com/Frozenka/nxcwrap/main/nxcwrap.py
chmod +x /opt/tools/NetExec/nxc/nxcwrap.py

CONF_PATH="/root/.nxc/nxc.conf"
mkdir -p "$(dirname "$CONF_PATH")"

if ! grep -q "\[Exegol-History\]" "$CONF_PATH" 2>/dev/null; then
    echo -e "\n[Exegol-History]\nscrap = True" >> "$CONF_PATH"
else
    sed -i '/\[Exegol-History\]/,/^\[/{s/^scrap *=.*/scrap = True/}' "$CONF_PATH"
fi

ALIAS_LINE="alias nxc=\"python3 /opt/tools/NetExec/nxc/nxcwrap.py\""

# Bash
if ! grep -F "nxcwrap.py" /root/.bashrc 2>/dev/null | grep -q "alias nxc"; then
    echo "$ALIAS_LINE" >> /root/.bashrc
    echo "[*] Alias nxc ajouté dans ~/.bashrc"
fi
grep -q "disablenxcwrapper" /root/.bashrc 2>/dev/null || echo 'alias disablenxcwrapper="sed -i \"s/scrap *= *True/scrap = False/\" /root/.nxc/nxc.conf"' >> /root/.bashrc
grep -q "enablenxcwrapper" /root/.bashrc 2>/dev/null || echo 'alias enablenxcwrapper="sed -i \"s/scrap *= *False/scrap = True/\" /root/.nxc/nxc.conf"' >> /root/.bashrc

# Zsh
if [ -f /root/.zshrc ]; then
    if ! grep -F "nxcwrap.py" /root/.zshrc 2>/dev/null | grep -q "alias nxc"; then
        echo "$ALIAS_LINE" >> /root/.zshrc
        echo "[*] Alias nxc ajouté dans ~/.zshrc"
    fi
else
    echo "$ALIAS_LINE" >> /root/.zshrc
    echo "[*] Créé ~/.zshrc avec l'alias nxc"
fi
grep -q "disablenxcwrapper" /root/.zshrc 2>/dev/null || echo 'alias disablenxcwrapper="sed -i \"s/scrap *= *True/scrap = False/\" /root/.nxc/nxc.conf"' >> /root/.zshrc
grep -q "enablenxcwrapper" /root/.zshrc 2>/dev/null || echo 'alias enablenxcwrapper="sed -i \"s/scrap *= *False/scrap = True/\" /root/.nxc/nxc.conf"' >> /root/.zshrc

# Charger .bashrc au login (bash)
for f in /root/.profile /root/.bash_profile; do
    if [ ! -f "$f" ]; then
        printf '\n[ -f ~/.bashrc ] && . ~/.bashrc\n' >> "$f"
    elif ! grep -q '\.bashrc' "$f" 2>/dev/null; then
        printf '\n[ -f ~/.bashrc ] && . ~/.bashrc\n' >> "$f"
    fi
done
# Charger .zshrc au login (zsh)
for f in /root/.zprofile; do
    if [ ! -f "$f" ]; then
        printf '\n[ -f ~/.zshrc ] && . ~/.zshrc\n' >> "$f"
    elif ! grep -q '\.zshrc' "$f" 2>/dev/null; then
        printf '\n[ -f ~/.zshrc ] && . ~/.zshrc\n' >> "$f"
    fi
done

echo "[*] nxc = wrapper (bash + zsh). Dans CE terminal : source ~/.bashrc   ou   source ~/.zshrc"
