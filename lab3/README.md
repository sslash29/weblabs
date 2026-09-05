# Lab 3 — Meridian Global Freight Portal

An intentionally vulnerable web application built for authorized personal
pentest practice (eJPT / CJCA / CWES track). See **[SCOPE.md](SCOPE.md)**
for the full rules of engagement before you start — read that first.

This lab chains five distinct vulnerability classes into one realistic
attack path, from an anonymous customer registration all the way to code
execution on a segmented internal service. It's meant to be genuinely hard:
no vulnerability is directly exploitable without information or access
gained from the previous stage.

## Architecture

```
                 host:8080
                     |
              +-------------+        "front" network
              | meridian-web |
              | (Node/Express)|
              +-------------+
                     |
              "back" network (not published to host)
                     |
              +----------------+
              | meridian-internal |
              | (Python, port 5000)|
              +----------------+
```

- `web/` — the public-facing customer & ops portal (Node.js/Express/EJS/SQLite via sql.js).
- `internal/` — an "internal ops" service reachable **only** from inside the Docker network, not from your host. You have to find a way in through the web app.

## Running it

Requires Docker and Docker Compose.

```bash
docker compose up --build
```

The portal will be available at **http://localhost:8080**. The internal
service is intentionally *not* exposed to your host — if you can reach it,
it's because you found a way to do so through the web app.

To reset to a clean state at any point:

```bash
docker compose down
docker compose up --build
```

Each restart re-seeds the database from scratch (nothing persists across restarts by design).

## Getting started

You're testing as an anonymous user of a freight-tracking web portal. Self-registration is open — there are no credentials to "find" to get your first foothold. From there, standard web app testing methodology (recon, authenticated enumeration, injection testing, etc.) applies.

Five flags are hidden across the chain, format `MERIDIAN{...}`. See [SCOPE.md](SCOPE.md) §4 for what each one represents at a high level.

If you get stuck, `walkthrough/` has a full spoiler-gated solution guide — try not to open it until you've genuinely hit a wall.

## Notes

- This app uses real, unpatched vulnerability patterns (string-concatenated SQL, unsanitized shell exec, unrestricted SSRF, `pickle.loads` on untrusted input). It is not a simulation — the exploits are real and the RCE is real code execution inside the container.
- Everything is isolated to the Docker containers defined here. Don't run this on a shared or internet-facing host.
