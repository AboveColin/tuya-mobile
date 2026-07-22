# tuya-mobile

Pure-Python reimplementation of Tuya's **mobile-app** API security layer —
request signing (`thing_security`), the encrypted mobile API client, and the
MQTT signaling credential derivation.

Tuya apps sign their mobile API requests with a native library
(`libthing_security.so`). This package reimplements that algorithm in pure
Python (HMAC-SHA256 / SHA256 / MD5 over ASCII) — so you can call the Tuya mobile
API with **no external signer service, no qemu, and no native `.so`**.

It is **generic across Tuya-based apps**: only a handful of *application*
constants differ per app (extracted from that app's APK). Supply them and it
works.

## What it provides

- **`PurePythonTuyaSigner(app_id, app_secret, cert_sha256_hex, app_key, package)`**
  — `sign(canonical)`, `derive_key(request_id, ecode)`, `channel_key()`.
- **`TuyaMobileClient(signer, session)`** — the encrypted mobile API flow
  (`thing.m.user.third.login`, signed/encrypted `_call`, local-key retrieval,
  cloud DP get/publish).
- **`mqtt_credentials(signer, uid=…, ecode=…, partner_id=…)`** — MQTT broker
  username/password + signaling topics for the `smart/mb` channel.
- **`mqtt_client_id(package)`** — isolated mobile-format client ID for a
  secondary client such as a local bridge.
- **`NativeTuyaSigner`** — optional legacy fallback that shells out to an
  external signer (executable or HTTP), for parity/testing.

## App credentials

The five app constants (`app_id`, `app_secret`, `cert_sha256_hex`, `app_key`,
`package`) are the only app-specific inputs; the algorithm is identical across
Tuya apps. This package intentionally ships **no** vendor credentials — the
caller supplies them (e.g. `petsseries` supplies the Philips Pet Series values).

## Usage

```python
import aiohttp
from tuya_mobile import PurePythonTuyaSigner, TuyaMobileClient

signer = PurePythonTuyaSigner(
    app_id="…", app_secret="…", cert_sha256_hex="…", app_key="…",
    package="com.example.app",
)
async with aiohttp.ClientSession() as session:
    client = TuyaMobileClient(signer, session)
    await client.login_with_jwt(id_token, country_code="1", platform="…")
    status = await client.get_device_status(device_id)
```

## License

MIT.
