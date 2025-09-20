#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

# Use the virtual environment
source venv/bin/activate

rm -rf build dist
# CLI
python3 -m PyInstaller --noconfirm --console --onefile --name gnasque gnasque/cli.py \
  --add-data "gnasque/webui/static:gnasque/webui/static"
# GUI
python3 -m PyInstaller --noconfirm --noconsole --onefile --name gnasque-gui gnasque/gui_tk.py \
  --add-data "gnasque/webui/static:gnasque/webui/static"

echo "Built:"
echo "  dist/gnasque"
echo "  dist/gnasque-gui"
echo "Place usque/sing-box in PATH or next to the binaries."