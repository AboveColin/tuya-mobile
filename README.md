# tuya-mobile

Pure-Python reimplementation of Tuya's **mobile-app** API security layer —
request signing (`thing_security`), the encrypted mobile API client, and the
MQTT signaling credential derivation.

Tuya apps sign their mobile API requests with a native library
(`libthing_security.so`). This package reimplements that algorithm in pure
Python (HMAC-SHA256 / SHA256 / MD5 over ASCII) — so you can call the Tuya mobile
API with **no external signer service, no qemu, and no native `.so`**.

It is **generic across Tuya-based apps**: only a handful of *application*
constants differ per app. Versioned Smart Life and Tuya Smart profiles are
included; callers can supply a profile for any other Tuya-based application.

## What it provides

- **`PurePythonTuyaSigner(app_id, app_secret, cert_sha256_hex, app_key, package)`**
  — `sign(canonical)`, `derive_key(request_id, ecode)`, `channel_key()`.
- **`TuyaMobileClient(signer, session)`** — the encrypted mobile API flow
  (`thing.m.user.third.login`, signed/encrypted `_call`, local-key retrieval,
  cloud DP get/publish).
- **`TuyaPasswordClient(profile, session, username=…)`** — email/telephone
  password login and atomic `localKey` + `secKey` retrieval for a specific
  device. Passwords and session tokens are never written to durable storage;
  authenticated session state is retained only in memory for subsequent calls.
- **`TuyaPasswordClient.for_application(application, …)`** — create that client
  directly from an explicitly selected bundled application profile.
- **`get_mobile_app_profile(application)`** — explicit selection of a bundled,
  versioned Smart Life or Tuya Smart application identity.
- **`mqtt_credentials(signer, uid=…, ecode=…, partner_id=…)`** — MQTT broker
  username/password + signaling topics for the `smart/mb` channel.
- **`mqtt_client_id(package)`** — isolated mobile-format client ID for a
  secondary client such as a local bridge.
- **`NativeTuyaSigner`** — optional legacy fallback that shells out to an
  external signer (executable or HTTP), for parity/testing.

## Application profiles

Smart Life and Tuya Smart use different signing identities and request
metadata, so callers select the application explicitly. The package never
probes another application profile after an authentication failure.

```python
from tuya_mobile import TuyaMobileApp, get_mobile_app_profile

profile = get_mobile_app_profile(TuyaMobileApp.SMART_LIFE)
```

Each bundled profile is an immutable snapshot of one public Android application
build. The profile carries its app and SDK versions because those values may
rotate in a future build. The five signing constants (`app_id`, `app_secret`,
`cert_sha256_hex`, `app_key`, and `package`) are application-level inputs, not
user credentials. They come from public Android builds and are already published
in several open-source projects, so this package is not a user credential store.

Other Tuya-based applications remain supported through a caller-supplied
`TuyaMobileAppProfile`; for example, `petsseries` supplies the Philips Pet
Series values.

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

Password login uses a caller-supplied `TuyaMobileAppProfile`. Application
profiles contain the version-specific APK constants used to identify and sign
as that application: `app_id`, `app_secret`, certificate SHA-256, `app_key`, and
package name. They also carry the request's app version, SDK/core versions,
channel, platform, `ttid`, `et`, optional React Native version, and optional
business domain. Callers can use a bundled profile or construct their own.
`TuyaPasswordClient` passes the profile inputs to `PurePythonTuyaSigner`, which
remains the sole implementation of derived global material and `chKey`.

```python
import aiohttp
from tuya_mobile import TuyaMobileApp, TuyaPasswordClient

async with aiohttp.ClientSession() as session:
    client = TuyaPasswordClient.for_application(
        TuyaMobileApp.SMART_LIFE,
        session,
        username="owner@example.com",
    )
    await client.login_with_password(password, country_code="33")
    credentials = await client.get_device_credentials(device_id)
```

Telephone endpoint probing is bounded to three password submissions by default.
Every permitted variant receives a fresh short-lived token, and only an
explicit "unsupported API" response permits another password submission.
Transport failures after submission are fatal because the server-side outcome
is unknowable. Callers can lower the budget with `max_login_attempts`.

Interactive captcha, MFA, QR, and social logins raise typed exceptions so a
caller can safely offer manual device credentials instead.

## License

MIT.
