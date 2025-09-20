# Gnasque (clean rewrite)

Gnasque is a MASQUE + WARP toolkit with CLI, Tk GUI, and a small Web UI.

- MASQUE via usque (SOCKS5 proxy)
- WARP via sing-box or Warp-Plus (SOCKS5 proxy)
- Resilient mode (MASQUE → WARP-over-MASQUE → direct)
- System proxy management with PAC
- Adblock (Ublock/Adblock format filter.txt)
- Iran sing-box rules (rule-set or db)
- Server tester for vmess/vless/ss/trojan/hysteria2 (Barry's lists supported)
- Web UI (localhost)

Requirements:
- curl (CLI checks and tests)
- usque / usque.exe (MASQUE)
- sing-box / sing-box.exe (WARP)
- wireguard-tools (wg) for WARP identity (Linux/BSD/mac), optional on Windows
- Optional: warp-plus / warp-plus.exe

Quick start:
- CLI default (MASQUE): `gnasque` (starts MASQUE at 162.159.198.2:443 binding 127.0.0.1:1080)
- GUI: `gnasque-gui`
- Web UI: `gnasque web --bind 127.0.0.1:8080` then open http://127.0.0.1:8080

Examples:
- Run MASQUE: `gnasque masque --endpoint 162.159.198.2:443 --bind 127.0.0.1:1080`
- Run WARP (sing-box): `gnasque warp --bind 127.0.0.1:8086 --sing-box-path ./sing-box`
- Test free servers (Barry): `gnasque servers test --url https://raw.githubusercontent.com/barry-far/V2ray-config/main/All_Configs_Sub.txt --bind 127.0.0.1:8090 --sing-box-path ./sing-box --concurrency 4 --timeout 15 --output results.csv`

Adblock:
- Place your Ublock/Adblock list at `filter.txt` and enable in GUI or use `--adblock --adblock-filter filter.txt` in CLI.

Packaging:
- Build binaries: `./build_linux.sh` (Linux), `./build_windows.sh` (Windows)
- Arch Linux: see aur/PKGBUILD (template)

License: MIT