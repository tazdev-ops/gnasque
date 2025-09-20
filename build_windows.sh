#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

py -3 -m pip install --upgrade pyinstaller

rm -rf build dist
# CLI
py -3 -m PyInstaller --noconfirm --console --onefile --name Gnasque gnasque/cli.py \
  --add-data "gnasque/webui/static;gnasque/webui/static"
# GUI
py -3 -m PyInstaller --noconfirm --noconsole --onefile --name GnasqueGUI gnasque/gui_tk.py \
  --add-data "gnasque/webui/static;gnasque/webui/static"

echo "Built:"
echo "  dist/Gnasque.exe"
echo "  dist/GnasqueGUI.exe"
echo "Place usque.exe, sing-box.exe and optional warp-plus.exe next to the EXEs or set paths in the GUI."