@echo off
setlocal

echo [*] Installing PyInstaller
py -3 -m pip install --upgrade pyinstaller

echo [*] Removing old build directories
rmdir /s /q build dist 2>nul

echo [*] Building CLI executable
py -3 -m PyInstaller --noconfirm --console --onefile --name Gnasque gnasque/cli.py --add-data "gnasque\webui\static;gnasque/webui/static"

echo [*] Building GUI executable
py -3 -m PyInstaller --noconfirm --noconsole --onefile --name GnasqueGUI gnasque/gui_tk.py --add-data "gnasque\webui\static;gnasque/webui/static"

echo.
echo Built:
echo   dist\Gnasque.exe
echo   dist\GnasqueGUI.exe
echo.
echo Place usque.exe, sing-box.exe and optional warp-plus.exe next to the EXEs or set paths in the GUI.
pause