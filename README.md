# CODING 2.0 — Web Desktop Script

A single‑file web desktop implemented in `coding.php` with a dock of app icons and draggable popup windows. Includes an app store popup "APPTools 1.0" to quickly launch apps. Designed to run under XAMPP or any PHP environment.

## Overview

- Desktop‑like UI: dock icons, popup windows with title bars, close buttons.
- Persistent state: reopens previously open apps on reload via `localStorage`.
- Self‑contained: HTML, CSS, and JS in `coding.php` for easy drop‑in use.
- Quick app launching: APPTools 1.0 store shows apps as cards.

## Quick Start

1. Place this folder under your web root (e.g., XAMPP `htdocs`).
2. Start a PHP dev server:
   - If you have system PHP: `php -S localhost:8000 -t /Applications/XAMPP/xamppfiles/htdocs/coding`
   - Using XAMPP’s PHP on macOS:
     `/Applications/XAMPP/xamppfiles/bin/php -S 127.0.0.1:8000 -t /Applications/XAMPP/xamppfiles/htdocs/coding`
3. Open `http://127.0.0.1:8000/coding.php` in your browser.

## Included Apps

- Notes — Simple notes popup; draggable; close button.
- Mailer — Compose and send email from a minimal UI.
- Browser — Minimal viewer with URL input; landing screen and controls.
- Wallpaper — Set wallpaper via image URL; uses green focus ring.
- CMD — Terminal‑style window; supports commands like `mkdir`, `mkfile`, `rm`, `mkup`, `rmdir` with feedback.
- Trash — Lists files deleted in the last hour; auto‑refresh every 5 seconds; persists position and open state.
- Clean OS — Clear browser storage and server artifacts; choose actions; verify; draggable.
- Settings — Password management (generate/copy/save), visibility toggles, toast notifications, position persistence.
- About — Overlay with project info.
- APPTools 1.0 — App store popup; click a card to open the app; the store hides itself after launch.

## APPTools 1.0

- Trigger: dock icon opens the store popup.
- Cards: each app shows an icon and name below it, like desktop apps.
- Behavior: clicking a card launches the app (via spawn function or dock trigger) and closes the store.
- Persistence: `localStorage` key `app.apptools.open` controls auto‑restore on reload.

## Persistence & Restore

- The script stores open state flags, e.g.: `app.browser.open`, `app.wallpaper.open`, `app.cmd.open`, `app.mailer.open`, `app.settings.open`, `app.trash.open`, `app.clean.open`, `app.apptools.open`.
- On load, `restoreOpenApps()` reopens apps flagged as open.

## UX & Interaction

- Drag windows by their title bar; movement is bounded to viewport.
- Close buttons remove the window and update persistence flags.
- Inputs use a unified LawnGreen focus ring for clarity.

## Server APIs

- `GET ?api=trash_recent` — Returns JSON of recently deleted items for the Trash window.
- `POST api=clean_server` — Performs selected cleanup actions on the server. Form params: `actions`, `confirm`.

## Screenshots

- Login: `screenshots/login.png`

Add more screenshots in the `screenshots/` folder and reference them below. Example:

```
![Login](screenshots/login.png)
![Desktop](screenshots/desktop.png)
```

## Contact

- Telegram: https://t.me/YOUR_TELEGRAM_USERNAME
- GitHub: https://github.com/YOUR_GITHUB_USERNAME

Replace the above links with your actual profiles.

## Copyright

Copyright © 2025 Mister Klio. All rights reserved.

