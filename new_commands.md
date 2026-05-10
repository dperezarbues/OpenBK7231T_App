# New Commands

Commands and features added in this branch on top of the upstream OpenBK7231T firmware.

---

## Power Management

### `PowerSave <0|1>`

Existing command — behaviour fixed for BL0937, HLW8112, and BL0942 devices.

**Bug fixed:** calling `PowerSave 1` with a power-metering driver active previously
enabled WiFi RF sleep even though the app believed sleep was off.
RF sleep causes the radio to wake every ~100 ms to check for buffered packets, generating
periodic 200–400 mA current bursts. The PSU electrolytic capacitor absorbs each spike;
the ripple-current stress accelerates ageing and causes premature failure.

**If you have BL0937, HLW8112, BL0942, or BL0942SPI configured, always use:**

```
PowerSave 0
```

When a protected driver is active the firmware now logs a diagnostic message and leaves
all sleep modes disabled rather than silently enabling RF sleep.

**Detection method per driver:**

| Driver | Detection | Requirement |
|---|---|---|
| BL0937 | Pin roles (CF/CF1/SEL) | Works at any time |
| HLW8112 | Pin role (SCSN) | Works at any time |
| BL0942 | `DRV_IsRunning("BL0942")` | `startDriver BL0942` must run before `PowerSave` |
| BL0942SPI | `DRV_IsRunning("BL0942SPI")` | `startDriver BL0942SPI` must run before `PowerSave` |

---

## Connectivity Recovery

### `MQTTReconnect`

Forces an immediate MQTT reconnect. Useful after credential changes or a network blip.

```
MQTTReconnect
```

Typical use — trigger on button double-press:

```
addEventHandler OnDblClick 0 MQTTReconnect
```

### `WiFiReconnect`

Disconnects from the current WiFi network and reconnects using the stored credentials.
A 3-second countdown is used so the command itself returns immediately.

```
WiFiReconnect
```

Typical use — trigger on button long-hold as a recovery action:

```
addEventHandler OnHoldStart 0 WiFiReconnect
```

---

## MQTT Configuration via Script

These commands mirror the Tasmota naming convention. They were previously only
settable through the web UI.

### `MqttPort <port>`

Sets the MQTT broker port (1–65535).

```
MqttPort 1883
MqttPort 8883
```

### `SSID2 <name>`

Sets the fallback WiFi SSID used when the primary network is unreachable.
Requires the `ALLOW_SSID2` build flag to take effect at runtime.

```
SSID2 BackupNetwork
SSID2 "My Backup Network"
```

### `Password2 <password>`

Sets the fallback WiFi password.

```
Password2 mysecret
Password2 "my secret passphrase"
```

---

## URL Variable Expansion

### `$Version` / `${Version}`

Expands to the firmware version string in any command that supports variable
expansion (e.g. `sendGet`, `sendGetAuth`).

```
sendGet http://nas/ota?device=$ShortName&fw=$Version cmd
```

---

## Orchestrator / Auth Commands

These commands support a boot-time orchestrator pattern: the device calls a
central server (NAS, RPi) on startup to receive its full configuration — MQTT
credentials, device name, OTA URL, and a fresh JWT token.

See `ORCHESTRATOR.md` for the full server-side specification.

### `sendGetAuth <url> [targetFile] [command]`

Like the existing `sendGet` but automatically appends `?token=<device_jwt>`
(or `&token=` if the URL already contains a query string) so the orchestrator
can verify the device's identity without a separate handshake.

Falls back to a plain GET if no device token is stored.

```
sendGetAuth http://192.168.1.100:3000/$ShortName cmd
sendGetAuth http://nas/$ShortName?fw=$Version cmd
```

### `setCAKey "<pem>"`

Stores the Step CA public key (EC P-256, PEM format) used to verify inbound
JWTs on the web UI. Run once during initial provisioning; the key is persisted
to LittleFS and loaded at every boot.

```
setCAKey "-----BEGIN PUBLIC KEY-----\nMFkw...\n-----END PUBLIC KEY-----\n"
```

Requires `MQTT_USE_TLS` build flag.

### `setDeviceToken <jwt>`

Stores a Step CA issued JWT as this device's identity token. The orchestrator
typically returns a fresh `setDeviceToken <jwt>` command on each boot to
auto-rotate the token before it expires.

```
setDeviceToken eyJhbGciOiJFUzI1NiJ9...
```

Requires `MQTT_USE_TLS` build flag.

### `getDeviceToken`

Logs the status of the stored device JWT — whether one is loaded, and how many
days until it expires. Does **not** print the token value.

```
getDeviceToken
```

---

## Security Flag

### `SetFlag 52 1` — Block MQTT OTA (`OBK_FLAG_MQTT_BLOCK_OTA`)

When set, the `ota_http` command is rejected if it arrives via MQTT. OTA
updates initiated from the web UI or console are unaffected.

```
SetFlag 52 1   // enable block
SetFlag 52 0   // disable block (default)
```

### `SetFlag 53 1` — Disable Web UI (`OBK_FLAG_DISABLE_WEB_UI`)

When set, all HTML page endpoints (`/index`, `/cfg_*`, `/about`, `/cmd_tool`,
`/ota`, etc.) return 404. The `/cm` endpoint and all `/api/*` registered
callbacks remain fully accessible, so Ansible / openbekenctl provisioning
continues to work normally. Basic auth still applies.

Use this on fully-provisioned devices to eliminate the browser UI as an
attack surface while keeping programmatic management intact.

```
SetFlag 53 1   // disable web UI
SetFlag 53 0   // enable web UI (default)
```

### `SetFlag 54 1` — Disable `/cm` endpoint (`OBK_FLAG_DISABLE_CM`)

When set, the `/cm?cmnd=...` endpoint returns 404. Combine with flag 53
for a "deep freeze" mode where only `/api/*` registered callbacks respond.

**Warning:** setting flag 54 without the IP allowlist (feature 12) in place
will lock you out of command-based management. Only set this on devices that
are fully configured and reachable exclusively through the REST API.

```
SetFlag 54 1   // disable /cm
SetFlag 54 0   // enable /cm (default)
```

---

## autoexec.bat Template

Ready-to-use starting point. Adjust the orchestrator URL and button index to
match your device.

```bat
// ── Power ────────────────────────────────────────────────────────────
// BL0937/HLW8112 devices: keep sleep disabled to protect the PSU capacitor
PowerSave 0

// ── Security ─────────────────────────────────────────────────────────
// Reject OTA arriving via MQTT; web UI / console OTA still works
SetFlag 52 1

// ── Fallback WiFi ────────────────────────────────────────────────────
SSID2 "BackupNetwork"
Password2 "backuppassword"

// ── Orchestrator boot call ───────────────────────────────────────────
// Server responds with plain OpenBK commands:
//   MqttHost / MqttPort / MqttUser / MqttPassword / DevName / setDeviceToken ...
// sendGetAuth appends ?token=<jwt> so the server can identify this device.
// Use plain sendGet if JWT auth is not set up yet.
sendGetAuth http://192.168.1.100:3000/$ShortName cmd

// ── Button recovery actions ──────────────────────────────────────────
// Double-press → reconnect MQTT
addEventHandler OnDblClick 0 MQTTReconnect
// Long-hold (~5 s) → reconnect WiFi
addEventHandler OnHoldStart 0 WiFiReconnect
```

---

## Notes

- `setCAKey` and `setDeviceToken` only need to be run **once** during initial
  provisioning — they persist to LittleFS and are not needed in `autoexec.bat`.
- `MqttHost`, `MqttUser`, `MqttPassword` are pre-existing Tasmota-compatible
  commands. Add them directly to `autoexec.bat` or let the orchestrator send
  them on boot.
- `sendGetAuth` requires `ENABLE_SEND_POSTANDGET` build flag (enabled by default
  in standard builds). JWT token appending additionally requires `MQTT_USE_TLS`.
- The web UI runs on plain HTTP (port 80). JWT tokens are cryptographically
  signed so they cannot be forged, but they are visible in transit on the local
  network. For most home LAN setups this is an acceptable trade-off.
- Button index `0` refers to the first configured button. Adjust to match your
  device's pin layout if needed.
