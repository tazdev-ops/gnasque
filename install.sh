#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

echo "[*] Installing Gnasque CLI/GUI entry points (pip user)"
python3 -m pip install --user -U .

echo "[*] Installing desktop file (GUI)"
desktop_file="aur/gnasque.desktop"
xdg_dir="${XDG_DATA_HOME:-$HOME/.local/share}"
install -Dm644 "$desktop_file" "$xdg_dir/applications/gnasque.desktop"

echo "Done. You can run 'gnasque' (CLI) or 'gnasque-gui' (GUI)."