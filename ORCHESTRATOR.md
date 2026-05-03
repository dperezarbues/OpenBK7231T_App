# OpenBK Orchestrator — Specification

A lightweight HTTP service that provisions OpenBK7231T devices on boot.
Devices call it with `sendGetAuth http://orchestrator/$ShortName cmd`; the
orchestrator verifies the device's JWT, fetches the matching config template
from a private GitHub repository, injects secrets, and returns plain-text
OpenBK commands.

---

## Architecture

```
                ┌──────────────┐
                │  Step CA     │  issues JWTs to devices and users
                └──────┬───────┘
                       │ CA public key (PEM)
          ┌────────────┼────────────────────┐
          │            │                    │
  ┌───────┴──────┐  ┌──┴──────────┐  ┌─────┴──────────┐
  │ OpenBK device│  │ Orchestrator│  │ Private GitHub  │
  │  (BK7231N)   │  │  (NAS/RPi)  │  │  config repo   │
  └──────────────┘  └─────────────┘  └────────────────┘
        │                  │
        │ GET /$ShortName   │  fetch /$ShortName.txt
        │ Authorization:    │  inject secrets from env
        │  Bearer <jwt>     │  return OBK commands
        └──────────────────┘
```

**Flow:**

1. Device boots, runs `autoexec.bat`:
   ```
   sendGetAuth http://orchestrator.home/$ShortName?fw=$Version cmd
   ```
2. Orchestrator receives request, extracts JWT from `Authorization: Bearer`
   header (or `?token=` query param appended by `sendGetAuth`).
3. Orchestrator verifies JWT ES256 signature against the Step CA public key.
4. Orchestrator fetches `$ShortName.txt` from the private GitHub config repo.
5. Orchestrator substitutes `{{VAR}}` placeholders with secrets from env.
6. If the device token expires within 7 days, orchestrator prepends a fresh
   `setDeviceToken <new_jwt>` line to auto-rotate the token.
7. If the `fw` version is outdated, orchestrator prepends
   `ota_http http://orchestrator.home/$ShortName/firmware?token=<jwt>`
   embedding the device's own JWT so the binary endpoint can verify it.
8. Orchestrator returns the rendered config as `text/plain`.
9. Device executes lines top-to-bottom: token rotation → OTA (reboots) → config.

---

## API

### `GET /:device_name[?fw=<version>]`

Provision a device.

**Query parameters:**

| Parameter | Required | Description |
|-----------|----------|-------------|
| `token`   | Yes (if no Bearer header) | Device JWT; appended automatically by `sendGetAuth` |
| `fw`      | No | Firmware version string (`$Version`); orchestrator can use this to decide whether to add an OTA command |

**Request headers:**
```
Authorization: Bearer <device_jwt>
```

The JWT is issued by Step CA for this specific device (subject = device short
name). The `sendGetAuth` OpenBK command appends `&token=<jwt>` automatically
(using `&` since `?fw=...` already starts the query string).

**Successful response** `200 text/plain`:
```
# 1. optional token rotation (only when expiry < 7 days away)
setDeviceToken eyJhbGci...

# 2. optional OTA (only when fw param is outdated)
#    token is embedded by the orchestrator — no new firmware command needed
ota_http http://orchestrator.home/kitchen-switch/firmware?token=eyJhbGci...

# 3. device config (only reached if no OTA, since ota_http reboots)
MqttHost 192.168.1.10
MqttPort 1883
MqttUser kitchen-switch
MqttPassword s3cr3t
DevName Kitchen Switch
Topic kitchen/switch
backlog channel 1 1; channel 2 0
```

**Response line ordering matters.** The device executes lines top-to-bottom:
1. `setDeviceToken` — persists new token to flash before any reboot
2. `ota_http` — downloads binary and reboots; lines after this do not execute
3. Config commands — only run on the current (up-to-date) firmware boot

**Error responses:**

| Code | Reason |
|------|--------|
| 401  | Missing or invalid JWT |
| 404  | No config template for this device name |
| 502  | GitHub fetch failed |

---

### `GET /:device_name/firmware?token=<jwt>`

Serve the firmware binary for a device. The token is embedded in the URL by
the orchestrator itself when it generates the `ota_http` line — the device
never needs to construct this URL manually.

**No new firmware command required.** The device uses the plain `ota_http`
command with the full URL (including token) that the orchestrator provided.

**Verification:** same JWT ES256 check as the config endpoint. The `sub` claim
must match `:device_name`.

**Successful response** `200 application/octet-stream`:
Raw `.rbl` binary streamed directly. `Content-Length` must be set so the OTA
client knows when the download is complete.

**Error responses:**

| Code | Reason |
|------|--------|
| 401  | Missing or invalid JWT, or `sub` mismatch |
| 404  | No firmware configured for this device |
| 503  | Upstream firmware source unavailable |

**Where the orchestrator fetches the binary from** (in order of preference):
1. Local filesystem (`./firmware/<platform>/<version>.rbl`) — fastest, works offline
2. GitHub release asset — version-pinned, audit trail in git
3. Official OpenBK GitHub releases — for unmodified firmware

---

## JWT Verification

The orchestrator verifies `ES256` JWTs issued by Step CA.

**Algorithm:** ECDSA P-256 + SHA-256 (ES256 per RFC 7518)

**Verification steps:**
1. Split JWT at dots: `header.payload.signature`
2. Decode `payload` (base64url) and parse JSON.
3. Check `exp` claim against current UTC time — reject if expired.
4. Check `sub` claim matches the requested `:device_name` path segment.
5. Compute `SHA-256(header_b64url + "." + payload_b64url)`.
6. base64url-decode the signature → 64 bytes (r || s in IEEE P1363 format).
7. Verify ECDSA signature using the Step CA public key (P-256).

**Recommended libraries:**
- Node.js: `jose` (`npm install jose`)
- Python: `python-jose` or `joserfc`
- Go: `golang-jwt/jwt`

**CA public key** is loaded from the path set in `STEP_CA_PUBKEY_PEM`
(PEM-encoded EC P-256 public key).

---

## Config Template Format

Templates live in the GitHub repo at `devices/<device_name>.txt`.

Each line is either a comment (`#`), a blank line, or an OpenBK command.
Secrets are substituted using `{{VAR_NAME}}` placeholders (double braces).

**Example** — `devices/kitchen-switch.txt`:
```
# Kitchen switch config
MqttHost {{MQTT_HOST}}
MqttPort {{MQTT_PORT}}
MqttUser {{MQTT_USER_KITCHEN}}
MqttPassword {{MQTT_PASS_KITCHEN}}
DevName Kitchen Switch
Topic kitchen/switch
backlog channel 1 1; channel 2 0
```

**Substitution rules:**
- `{{VAR}}` is replaced with the environment variable `VAR`.
- Unknown placeholders cause a `500` response (no partial config).
- Template comments (`# ...`) are stripped before sending.

---

## Firmware OTA Updates

The device reports its current version in `?fw=<version>` (the `$Version`
variable expanded by the OpenBK tokenizer). The orchestrator compares this
against the target version and, if outdated, prepends an `ota_http` line to
the config response.

**Why the orchestrator serves the binary (not a separate file server):**
- `ota_http` is a plain HTTP GET — it has no built-in header support, so it
  cannot add an `Authorization: Bearer` header itself.
- Solution: the orchestrator embeds the device's own JWT into the URL it
  generates, so `ota_http` fetches an authenticated URL without any firmware
  changes:
  ```
  ota_http http://orchestrator.home/kitchen-switch/firmware?token=eyJ...
  ```
  The orchestrator composes this URL using the JWT it just verified from the
  incoming request — the device never constructs it.

**Versioning strategy** — pick one:

| Approach | Description |
|----------|-------------|
| `FW_TARGET_DEFAULT` env var | Single version for the whole fleet |
| `FW_TARGET_<device>` env var | Per-device override |
| `devices/versions.json` in GitHub repo | Version pinning in git, auditable |

**`devices/versions.json` example:**
```json
{
  "_default": "1.2.4",
  "kitchen-switch": "1.2.3",
  "office-plug": "1.2.4"
}
```

**Firmware binary sources** (orchestrator fetches from one of):
1. Local volume mount — `./firmware/bk7231n/<version>.rbl` — fastest, offline-capable
2. GitHub release asset — version-pinned, public audit trail
3. Official OpenBK GitHub releases — for stock firmware

**Orchestrator logic (Node.js sketch):**
```javascript
// config endpoint — decide whether OTA is needed
const currentFw = new URL(req.url, "http://x").searchParams.get("fw") ?? "";
const targetFw  = getTargetVersion(deviceName);  // from env or versions.json

if (targetFw && currentFw !== targetFw) {
  // embed the device's own JWT so the /firmware endpoint can verify it
  const fwUrl = `http://orchestrator.home/${deviceName}/firmware?token=${rawJwt}`;
  lines.unshift(`ota_http ${fwUrl}`);
}

// ---

// firmware endpoint  GET /:device_name/firmware?token=<jwt>
app.get("/:name/firmware", async (req, res) => {
  const { name } = req.params;
  const token = req.query.token;
  if (!token) return res.status(401).send("no token");

  let payload;
  try {
    ({ payload } = await jwtVerify(token, CA_KEY, { algorithms: ["ES256"] }));
  } catch (e) {
    return res.status(401).send("invalid token");
  }
  if (payload.sub !== name) return res.status(401).send("subject mismatch");

  const version = getTargetVersion(name);
  if (!version) return res.status(404).send("no firmware configured");

  const fwPath = path.join(process.env.FIRMWARE_DIR, `${version}.rbl`);
  if (!fs.existsSync(fwPath)) return res.status(503).send("firmware file missing");

  res.setHeader("Content-Type", "application/octet-stream");
  res.setHeader("Content-Length", fs.statSync(fwPath).size);
  fs.createReadStream(fwPath).pipe(res);
});
```

---

## Token Auto-Rotation

The orchestrator checks the device JWT's `exp` claim after successful
verification. If the token expires within `TOKEN_ROTATION_THRESHOLD_DAYS`
(default 7 days):

1. The orchestrator issues a new JWT via the Step CA provisioner API:
   ```
   POST https://ca.home/1.0/sign
   {
     "csr": "...",
     "ott": "<one-time token for device provisioner>"
   }
   ```
   Or simpler: use `step ca token --provisioner device-provisioner <subject>`.

2. Prepend `setDeviceToken <new_jwt>` as the first line of the response.

3. The device executes `setDeviceToken`, which writes the new JWT to
   LittleFS. On next boot it will use the fresh token automatically.

---

## Step CA Setup

```bash
# 1. Install Smallstep CLI
curl -fsSL https://dl.smallstep.com/cli/install.sh | sh

# 2. Initialise the CA (run once, store root key securely)
step ca init \
  --name "HomeCA" \
  --dns ca.home,192.168.1.5 \
  --address :9000 \
  --provisioner admin@home

# 3. Add a device provisioner using EC P-256 JWK keys
step ca provisioner add device-provisioner \
  --type JWK --key-type EC --crv P-256

# 4. Issue a device token (30-day expiry)
step ca token \
  --provisioner device-provisioner \
  --expire 720h \
  kitchen-switch

# 5. Export the CA public key for the orchestrator and devices
step crypto key inspect --public $(step path)/certs/root_ca.crt \
  | step crypto key format --pem > ca_pubkey.pem

# 6. Upload ca_pubkey.pem to each device via the web UI (LittleFS upload)
#    or via MQTT/HTTP:  setCAKey <pem_content>
```

The device token is uploaded once via:
```
setDeviceToken <jwt_from_step_4>
```
Subsequent rotations happen automatically via orchestrator responses.

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `STEP_CA_PUBKEY_PEM` | Yes | Path to the CA P-256 public key PEM file |
| `GITHUB_TOKEN` | Yes | PAT with `contents:read` on the config repo |
| `GITHUB_REPO` | Yes | `owner/repo` of the config template repository |
| `GITHUB_BRANCH` | No | Branch to fetch from (default: `main`) |
| `GITHUB_TEMPLATE_PATH` | No | Path prefix (default: `devices`) |
| `LISTEN_PORT` | No | HTTP listen port (default: `8080`) |
| `LISTEN_ADDR` | No | Bind address (default: `0.0.0.0`) |
| `TOKEN_ROTATION_THRESHOLD_DAYS` | No | Days before expiry to rotate token (default: `7`) |
| `STEP_CA_URL` | No | Step CA URL for token rotation (e.g. `https://ca.home:9000`) |
| `STEP_PROVISIONER` | No | Provisioner name for rotation (default: `device-provisioner`) |
| `FIRMWARE_DIR` | No | Local path to `.rbl` firmware binaries (e.g. `/firmware/bk7231n`) |
| `ORCHESTRATOR_BASE_URL` | Yes (if OTA used) | Public URL of the orchestrator itself (e.g. `http://orchestrator.home`), used to build `ota_http` URLs |
| `FW_TARGET_DEFAULT` | No | Default target firmware version for all devices |
| `FW_TARGET_<DEVICE>` | No | Per-device firmware version override (e.g. `FW_TARGET_kitchen-switch=1.2.3`) |

---

## Docker Deployment

```yaml
# docker-compose.yml
services:
  orchestrator:
    image: node:20-alpine       # or python:3.12-slim, etc.
    restart: unless-stopped
    ports:
      - "8080:8080"
    volumes:
      - ./ca_pubkey.pem:/etc/orchestrator/ca_pubkey.pem:ro
      - ./app:/app
    working_dir: /app
    command: node index.js
    environment:
      STEP_CA_PUBKEY_PEM: /etc/orchestrator/ca_pubkey.pem
      GITHUB_TOKEN: ${GITHUB_TOKEN}
      GITHUB_REPO: ${GITHUB_REPO}
      LISTEN_PORT: "8080"
```

Store secrets in a `.env` file (not committed):
```
GITHUB_TOKEN=ghp_...
GITHUB_REPO=youruser/openbk-configs
```

---

## Reference Implementation Sketch (Node.js)

```javascript
import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { importSPKI, jwtVerify } from "jose";   // npm install jose
import { Octokit } from "@octokit/rest";         // npm install @octokit/rest

const CA_PEM   = readFileSync(process.env.STEP_CA_PUBKEY_PEM, "utf8");
const CA_KEY   = await importSPKI(CA_PEM, "ES256");
const octokit  = new Octokit({ auth: process.env.GITHUB_TOKEN });
const [GH_OWNER, GH_REPO] = process.env.GITHUB_REPO.split("/");
const GH_BRANCH = process.env.GITHUB_BRANCH ?? "main";
const TEMPLATE_PATH = process.env.GITHUB_TEMPLATE_PATH ?? "devices";
const ROTATION_DAYS = parseInt(process.env.TOKEN_ROTATION_THRESHOLD_DAYS ?? "7");

createServer(async (req, res) => {
  const deviceName = req.url.split("?")[0].slice(1);
  if (!deviceName) return send(res, 400, "missing device name");

  // extract JWT
  const authHeader = req.headers["authorization"] ?? "";
  const urlToken   = new URL(req.url, "http://x").searchParams.get("token");
  const rawJwt     = authHeader.startsWith("Bearer ")
    ? authHeader.slice(7)
    : urlToken;

  if (!rawJwt) return send(res, 401, "no token");

  // verify
  let payload;
  try {
    ({ payload } = await jwtVerify(rawJwt, CA_KEY, { algorithms: ["ES256"] }));
  } catch (e) {
    return send(res, 401, `invalid token: ${e.message}`);
  }
  if (payload.sub !== deviceName)
    return send(res, 401, "token subject mismatch");

  // fetch template
  let template;
  try {
    const { data } = await octokit.repos.getContent({
      owner: GH_OWNER, repo: GH_REPO,
      path:  `${TEMPLATE_PATH}/${deviceName}.txt`,
      ref:   GH_BRANCH,
    });
    template = Buffer.from(data.content, "base64").toString("utf8");
  } catch (e) {
    return send(res, e.status === 404 ? 404 : 502, e.message);
  }

  // substitute secrets
  try {
    template = template.replace(/\{\{(\w+)\}\}/g, (_, v) => {
      if (!(v in process.env)) throw new Error(`missing env var: ${v}`);
      return process.env[v];
    });
  } catch (e) {
    return send(res, 500, e.message);
  }

  // strip comment lines
  const lines = template.split("\n")
    .filter(l => !l.trimStart().startsWith("#") && l.trim() !== "");

  // token rotation
  const now  = Math.floor(Date.now() / 1000);
  const exp  = payload.exp ?? 0;
  if (exp > 0 && exp - now < ROTATION_DAYS * 86400) {
    const newToken = await issueToken(deviceName);  // implement via step CLI
    if (newToken) lines.unshift(`setDeviceToken ${newToken}`);
  }

  send(res, 200, lines.join("\n"), "text/plain");
}).listen(parseInt(process.env.LISTEN_PORT ?? "8080"));

function send(res, code, body, type = "text/plain") {
  res.writeHead(code, { "Content-Type": type });
  res.end(body);
}
```

---

## Device autoexec.bat Example

```
# Call orchestrator on boot — device authenticates with its JWT.
# sendGetAuth appends &token=<device_jwt> automatically (uses & because
# ?fw=$Version already starts the query string).
sendGetAuth http://orchestrator.home/$ShortName?fw=$Version cmd
```

The orchestrator can read `fw` to decide whether to include an OTA update
command in the response, and the token is appended as `&token=<jwt>` since
`?` is already present in the URL.

---

## Initial Device Provisioning

Do this once per device, before autoexec.bat relies on `sendGetAuth`.

**Step 1 — Store the CA public key on the device**

Export the CA public key from Smallstep:
```bash
step ca root | step crypto key inspect --public | step crypto key format --pem > ca_pubkey.pem
```

Upload via the OpenBK web UI (LittleFS → Upload → `ca_pubkey`), or run
the scripting command (paste the PEM content as a single escaped string):
```
setCAKey "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZI...\n-----END PUBLIC KEY-----\n"
```

**Step 2 — Issue and store the first device token**

```bash
# 30-day token for "kitchen-switch"
step ca token \
  --provisioner device-provisioner \
  --expire 720h \
  kitchen-switch
```

Paste the output JWT into the device console or MQTT:
```
setDeviceToken eyJhbGci...
```

From this point on, the orchestrator will rotate the token automatically
whenever it has less than 7 days remaining.

**Step 3 — Verify**

```
getDeviceToken
```
Logs should show: `getDeviceToken: token valid, expires in ~30 days`

The orchestrator responds with commands that are saved to `cmd` and executed.
The device is fully configured within 1-2 seconds of boot without storing any
MQTT credentials on the device itself.

---

## Security Notes

- **No HTTPS on the device side**: JWT signatures remain valid regardless of
  transport, but are vulnerable to replay within the token's validity window.
  Use short-lived tokens (≤24h) or add a `jti` nonce claim with one-time
  validation on the orchestrator.
- **Secret injection via env only**: never commit secrets to the GitHub repo.
  Use a secrets manager (Vault, Doppler, Docker secrets) to populate env vars.
- **Restrict orchestrator network access**: bind to the management VLAN only;
  IoT devices and the orchestrator should be on the same isolated network
  segment, not exposed to the internet.
- **CA key backup**: the Step CA root private key must be backed up securely.
  Loss of the CA key requires re-provisioning all devices.
