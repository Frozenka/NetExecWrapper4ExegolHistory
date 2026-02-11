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
if ! grep -Fxq "$ALIAS_LINE" /root/.bashrc; then
    echo "$ALIAS_LINE" >> /root/.bashrc
fi
alias disablenxcwrapper="sed -i 's/scrap *= *True/scrap = False/' /root/.nxc/nxc.conf"
alias enablenxcwrapper="sed -i 's/scrap *= *False/scrap = True/' /root/.nxc/nxc.conf"
