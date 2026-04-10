# Google Play Assets

Upload-ready assets for the `vless-tun Android` Play Console listing live in `assets/`.

Files:
- `assets/app-icon/vless-tun-play-icon-512.png` — app icon, 512x512 PNG
- `assets/feature-graphic/vless-tun-feature-graphic-1024x500.png` — feature graphic, 1024x500 PNG
- `assets/phone-screenshots/01-home.png` — phone screenshot, 1080x2400 PNG
- `assets/phone-screenshots/02-add-tunnel.png` — phone screenshot, 1080x2400 PNG, subscription URL masked
- `assets/phone-screenshots/03-connected.png` — phone screenshot, 1080x2400 PNG

Suggested upload mapping in Play Console:
- `App icon` -> `assets/app-icon/vless-tun-play-icon-512.png`
- `Feature graphic` -> `assets/feature-graphic/vless-tun-feature-graphic-1024x500.png`
- `Phone screenshots` -> all files from `assets/phone-screenshots/`

Notes:
- Screenshots were selected from existing Android smoke-test artifacts in this repo.
- If you want a fresh set later, regenerate screenshots from the device smoke flow and replace the PNGs in `assets/phone-screenshots/`.
