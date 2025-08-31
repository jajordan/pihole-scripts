## add-local-dns.sh — Script to manage Pi-hole custom DNS records via API

### Overview
`add-local-dns.sh` creates or updates local DNS A records on one or more Pi-hole servers using Pi-hole’s HTTP API. It authenticates to each server, checks whether the record exists, removes an outdated mapping if needed, and adds the new mapping.

### Requirements
- Bash (tested on macOS)
- `curl`
- `jq`

### Configuration
The script reads configuration from a `.env` file in the repository directory (next to the script). Values can also be exported in your shell environment.

Create `.env` from the provided example:
```bash
cp .env.example .env
```

Supported variables:
- `PIHOLES` (required): CSV list of Pi-hole hosts, e.g. `10.10.0.2,10.10.0.3`
- `USE_HTTPS` (optional): `true` to use HTTPS, default `false`
- `INSECURE` (optional): `-k` to allow self-signed certs; set to empty to enforce TLS verification
- Password sources (choose one or mix per-host):
  - `PIHOLE_PASSWORD_<HOST>`: environment variables per host. Example for host `10.10.0.2` → `PIHOLE_PASSWORD_10_10_0_2`.
  - `PASSWORDS`: CSV aligned with `PIHOLES`. Least secure; avoid committing.
  - macOS Keychain via `KEYCHAIN_SERVICE`: fetches password where Keychain item has service=`$KEYCHAIN_SERVICE`, account=`<host>`.

Example `.env`:
```bash
PIHOLES="10.10.0.2,10.10.0.3"
USE_HTTPS=false
INSECURE="-k"
# Prefer per-host env vars or Keychain over PASSWORDS
# PIHOLE_PASSWORD_10_10_0_2=changeme
# PIHOLE_PASSWORD_10_10_0_3=changeme
# PASSWORDS=changeme_for_10_10_0_2,changeme_for_10_10_0_3
# KEYCHAIN_SERVICE=pihole-api
```

### Usage
```bash
./add-local-dns.sh <fqdn> <ip>
```
Examples:
```bash
./add-local-dns.sh host.local 192.168.1.50
./add-local-dns.sh server.example.com 10.10.30.10
```

### What the script does
- Authenticates: `POST /api/auth` with JSON `{ "password": "..." }`, reads `session.sid`.
- Reads current DNS config: `GET /api/config/dns` (used to detect an existing `hosts` entry).
- If an entry exists with a different IP, removes it via:
  - `DELETE /api/config/dns/hosts/{encodeURIComponent("<ip> <fqdn>")}`
- Adds the new mapping via:
  - `PUT /api/config/dns/hosts/{encodeURIComponent("<ip> <fqdn>")}`

The web UI uses the same path-based pattern for DNS record changes. See the reference below.

### Behavior
- Idempotent: If a server already has the exact `IP FQDN` record, no change is made.
- Multi-server: Applies to each `PIHOLES[i]` with `PASSWORDS[i]`.
- Exit code: `0` only if all servers are updated successfully; `1` otherwise.
- Output: Clear progress and debug messages per server.

### Troubleshooting
- "URL rejected: Malformed input to a URL function"
  - Cause: Unencoded space in path. This script URL-encodes the `"IP FQDN"` segment.
- `404 Not Found` on `/api/config/dns/hosts`
  - Ensure you are on a recent Pi-hole Web version with the REST API and path endpoints.
- `400 Bad Request` with hint "Invalid path depth"
  - Use path-based endpoints (PUT/DELETE on `/api/config/dns/hosts/{encoded}`) instead of PUTting the entire config object.
- `Bad request: The API is hosted at pi.hole/api, not pi.hole/admin/api`
  - You are hitting legacy endpoints; this script uses the modern `/api`.
- Auth succeeds on one server but fails on another
  - Verify `PASSWORDS` order matches `PIHOLES`. Different servers can have different passwords.
- HTTPS/self-signed certs
  - Set `USE_HTTPS=true` and, if needed for self-signed, keep `INSECURE="-k"`. For trusted certs, set `INSECURE` to empty.

### Security notes
- Avoid storing passwords in the script or committing them in `.env`.
- Prefer per-host env vars (`PIHOLE_PASSWORD_<HOST>`) or macOS Keychain.
- To add passwords to Keychain (recommended on macOS):
  ```bash
  KEYCHAIN_SERVICE=pihole-api
  # For host 10.10.0.2
  security add-generic-password -s "$KEYCHAIN_SERVICE" -a "10.10.0.2" -w '<password>'
  # For host 10.10.0.3
  security add-generic-password -s "$KEYCHAIN_SERVICE" -a "10.10.0.3" -w '<password>'
  ```
  In `.env`, set `KEYCHAIN_SERVICE=pihole-api`.
- The session ID (`sid`) is short-lived; the script uses it only for the duration of the run.

### References
- Pi-hole Web code for DNS record actions (shows the encode-and-path approach used by the UI): [settings-dns-records.js](https://github.com/pi-hole/web/blob/25441178f7dcc365c5a553a86b23eeed0573938f/scripts/js/settings-dns-records.js#L215-L224)

### License
MIT
