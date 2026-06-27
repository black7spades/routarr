# Routarr

Tunarr turns your Plex or Jellyfin library into fake cable channels you can stream with any IPTV client. The catch: you have to manually drag content into each channel. Routarr removes that step. You define routing rules (match by genre, label, or library) and Routarr automatically drops matched items into the right Tunarr channel whenever something new lands on your server. Set up an auto-flow and it happens without you touching anything.

---

## Quick start

**Prerequisites:** Docker, a running [Plex](https://www.plex.tv/) or [Jellyfin](https://jellyfin.org/) server, a running [Tunarr](https://github.com/chrisbenincasa/tunarr) instance.

```bash
curl -O https://raw.githubusercontent.com/black7spades/routarr/main/docker-compose.yml
docker compose up -d
```

Open **http://localhost:6942** and complete setup in Settings.

---

## docker-compose.yml

```yaml
services:
  routarr:
    image: ghcr.io/black7spades/routarr:latest
    container_name: routarr
    restart: unless-stopped
    ports:
      - "6942:6942"
    volumes:
      - routarr-data:/data
    environment:
      # Required
      - TUNARR_URL=          # e.g. http://192.168.1.10:8000
      # Fill in whichever you use (at least one required)
      - PLEX_URL=            # e.g. http://192.168.1.10:32400
      - PLEX_TOKEN=          # your Plex auth token
      - JELLYFIN_URL=        # e.g. http://192.168.1.10:8096
      - JELLYFIN_API_KEY=    # your Jellyfin API key

volumes:
  routarr-data:
```

All environment variables are optional: you can enter everything through the Settings UI instead. The database persists in the `routarr-data` volume at `/data/routarr.db`.

---

## First-run setup

1. **Settings → Connections**: enter your Tunarr URL and your Plex URL + token and/or Jellyfin URL + API key, then click **Test connections**.
2. **Settings → Library Mapping**: click **Auto-configure from Tunarr** to map your libraries to Tunarr's library IDs.
3. **Rules**: create at least one routing rule. Each rule targets a library and filters by genre or label; the first matching rule wins.
4. **Media**: hit **Scan Now** to run the first scan and see what's pending.
5. **Flows**: optionally activate a flow on any channel to have matched items routed automatically on each scan.

### Getting your Plex token

In Plex Web, open any item → ··· → Get Info → **View XML**. The token is the `X-Plex-Token` query parameter in the URL.

### Instant routing via Plex webhooks (Plex Pass required)

Routarr normally scans on a schedule. To make it react the moment something lands:

1. In Routarr go to **Settings → Connections** and copy the **Plex webhook URL**.
2. In Plex: **Settings → Webhooks → Add Webhook** and paste the URL.

---

## Features

- **Routing rules**: match by Plex/Jellyfin library, genre include/exclude, label include/exclude, title pattern; priority-ordered, first match wins
- **Auto-flows**: activate a flow on any channel and Routarr routes matched items automatically on every scan
- **Filler list support**: route to Tunarr filler lists as well as regular channels
- **Plex and Jellyfin**: use either or both as your media source
- **Process presets**: save per-channel processing configs (codec, resolution, etc.) and apply them in bulk
- **Themes**: generate a colour palette from your channel idents or pick from built-in presets
- **Authentication**: optional username + password login
- **Guided setup tour**: walks through first-time configuration in the UI

---

## Upgrading

```bash
docker compose pull && docker compose up -d
```

The database schema is migrated automatically on startup. A backup copy is written to `/data/routarr.db.bak` before each migration.

---

## License

MIT
