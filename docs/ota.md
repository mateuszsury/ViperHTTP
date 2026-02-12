# OTA Updates

ViperHTTP provides over-the-air (OTA) firmware update support for ESP32 devices. Updates follow a three-phase lifecycle with SHA256 integrity verification.

## Overview

OTA updates write new firmware to the inactive partition on the ESP32. After verification, the device reboots into the updated firmware. If the update fails, the device continues running the current firmware.

## Enabling OTA

Enable OTA routes when starting the server:

```python
app.run(port=8080, ota=True, ota_token="your-secure-token")
```

This installs the OTA route handlers automatically. The `ota_token` is required for authentication — all OTA requests must include this token.

## Update Lifecycle

### Phase 1: Begin

Start an OTA session:

```
POST /ota/begin
Authorization: Bearer <ota_token>
Content-Type: application/json

{"size": 1048576}
```

The server:
- Validates the OTA token
- Checks that OTA is supported (ESP32 with dual partitions)
- Initializes the OTA session
- Returns a session identifier

### Phase 2: Write

Upload firmware in chunks:

```
POST /ota/write
Authorization: Bearer <ota_token>
Content-Type: application/octet-stream

<binary firmware chunk>
```

The server:
- Validates the active OTA session
- Writes the chunk to the inactive partition
- Updates SHA256 hash incrementally
- Tracks progress (bytes written / total size)

### Phase 3: Finalize

Complete the update and verify:

```
POST /ota/finalize
Authorization: Bearer <ota_token>
Content-Type: application/json

{"sha256": "expected_hash_hex"}
```

The server:
- Compares computed SHA256 against the expected hash
- Marks the new partition as bootable
- Returns success status
- Optionally triggers a reboot

## SHA256 Verification

Every byte written during the upload is fed into a SHA256 hash. On finalize, the computed hash is compared against the client-provided expected hash. If they don't match, the update is rejected and the device continues running the current firmware.

## OTA Session Management

- Only one OTA session can be active at a time
- Sessions have a timeout — if no write arrives within the timeout, the session is cancelled
- Progress is tracked via sequence numbers and byte counters
- The last result and any error details are available via status endpoints

## Error Handling

| Error | Cause |
|---|---|
| `400 Bad Request` | Missing parameters, invalid session state |
| `401 Unauthorized` | Invalid or missing OTA token |
| `409 Conflict` | OTA session already active |
| `500 Internal Server Error` | Partition write failure |

## Client Example

A simple Python client for uploading firmware:

```python
import requests
import hashlib

DEVICE = "http://192.168.1.100:8080"
TOKEN = "your-secure-token"
FIRMWARE = "firmware.bin"

headers = {"Authorization": f"Bearer {TOKEN}"}

# Read firmware
with open(FIRMWARE, "rb") as f:
    data = f.read()

sha256 = hashlib.sha256(data).hexdigest()

# Begin
requests.post(f"{DEVICE}/ota/begin",
    json={"size": len(data)}, headers=headers)

# Write in chunks
CHUNK = 4096
for i in range(0, len(data), CHUNK):
    chunk = data[i:i+CHUNK]
    requests.post(f"{DEVICE}/ota/write",
        data=chunk, headers={**headers, "Content-Type": "application/octet-stream"})

# Finalize
requests.post(f"{DEVICE}/ota/finalize",
    json={"sha256": sha256}, headers=headers)
```

## Platform Requirements

- ESP32 with dual OTA partitions in the partition table
- `esp32.Partition` API available in the MicroPython build
- Sufficient flash storage for two firmware images

## Security Considerations

1. **Always use HTTPS** for OTA — firmware uploads over unencrypted HTTP are vulnerable to tampering
2. **Use strong OTA tokens** — generate with `os.urandom(32).hex()`
3. **Verify SHA256** — never skip hash verification
4. **Restrict network access** — OTA endpoints should only be accessible from trusted networks
