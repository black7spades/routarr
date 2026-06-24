# Changelog

All notable changes to Routarr are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [3.2.0] - 2026-06-24

### Added
- Logout button in the navbar (top-right, door-with-arrow icon)
- Rules page: sortable column headers — Rule name, Source, Library, Plays on, Priority
- Rules page: select all / none checkbox in the table header
- Rules page: per-page limiter (25 / 50 / 100 / All) with previous/next pagination
- Themes: "Generate from Channels" tile — fetches Tunarr lineup and shows an ident gallery
- Themes: hover-to-convert flow — roll over any ident card, click "Convert to theme?" to extract dominant colours via canvas
- Themes: dark and light variant auto-generated from each channel's dominant colour
- Themes: lock-in / try-again / cancel preview panel; custom palettes persist across sessions in localStorage
- Backend: `/api/proxy-image?url=` endpoint (auth-exempt) for CORS-safe image loading into the canvas

### Changed
- Themes section now ships with only the C64 default palette — all other hard-coded presets removed
- Generated custom palettes show a remove (×) button on their card

### Fixed
- JS syntax error in `_lockTheme` onclick handlers caused all tab navigation to break on first deploy

---

## [3.1.0] - 2026-06-23

### Added
- C64 Colodore colour palette as the default and only initial theme
- Full CSS custom-property theme system: accent, accent2, green, yellow, blue, surface (×3), text, muted, border
- `applyPalette(id)` saves to localStorage and re-applies on every page load
- Login page: rotating channel ident as background image (randomly selected from Tunarr lineup on each load)
- `/api/channel-idents` endpoint (auth-exempt) — returns channel id, name and ident URL; skips adult channels (69, 96, 97, 1069+) and ChatGPT-placeholder idents
- `/api/versions` endpoint — reports Routarr, Plex, Tunarr, and Jellyfin version strings
- Changelog section in Settings showing version history
- Nine additional palette presets: Powerbeam!, Channel Who, Channel X, Station 666, Station 42, Station 1845, Cigarette Burns, Sugoi!, Midnight

### Security
- SSH / SFTP credentials no longer stored in the database after deploy

---

## [3.0.0] - 2026-06-22

### Added
- Channel health monitor: detects when a channel stream stalls and logs events to the Log tab
- Media page filter: single search input with a content-type dropdown (All / Movie / Episode / etc.)
- Login authentication: username + bcrypt-hashed password stored in SQLite; session cookie issued on success
- `/login` and `/logout` routes; all other routes require a valid session
- Guided setup tour: 7 steps walking through Connections, Rules, Media routing, and Channels

### Fixed
- Channel filter returning incorrect matches on partial strings
- Progress bar not showing Plex library names during sync

### Changed
- "Route" tab renamed to "Media"
- Versioning system introduced (SemVer)

---

## [2.3.0] - 2026-06-XX

### Added
- Bulk operations on Media page: select-all checkbox, bulk-route action bar
- Pagination on Media page with All-time / date-range toggle
- Process presets: saved per-channel processing configurations stored in SQLite

---

## [2.0.0] - 2026-06-XX

### Added
- Jellyfin as a second media source alongside Plex
- APScheduler background scan with configurable interval and Check Now button
- Help page with setup guide and keyboard shortcuts
- Usability pass: sub-headers, section descriptions, improved empty states

### Changed
- Rules page: added Source column (Plex / Jellyfin badge), genre-exclusion support
- Channels page: Process All button, sync health indicator

---

## [1.0.0] - 2026-06-XX

### Added
- Initial Routarr web app
- Plex → Tunarr routing engine with SQLite-backed routing rules
- Rules page: priority-ordered rules, genre/label include and exclude filters, source and library targeting; first match wins
- Channels page: sync Tunarr channel lineup, per-channel processing
- Log tab: activity history
- Settings page: connection config (Plex, Tunarr), display preferences (font size, bar height)
- Single-file FastAPI app running on port 6942; state persists in SQLite at `/data/routarr.db`
