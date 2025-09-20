@echo off
setlocal

echo [*] Installing Gnasque CLI/GUI entry points (pip user)
py -3 -m pip install --user -U .

echo [*] Installing desktop file (GUI) - Windows version
echo This step is not needed on Windows as the GUI will be accessible through the executable

echo Done. You can run 'gnasque' (CLI) or 'gnasque-gui' (GUI) after building.
pause