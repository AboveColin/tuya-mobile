"""Typed models for Tuya mobile password authentication."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib

from .signer import colon_hex


@dataclass(frozen=True)
class TuyaMobileAppProfile:
    """Versioned identity of a Tuya-powered Android application."""

    name: str
    app_id: str
    app_secret: str = field(repr=False)
    cert_sha256_hex: str = field(repr=False)
    app_key: str = field(repr=False)
    package: str
    app_version: str
    channel_key: str
    ttid: str
    sdk_version: str
    device_core_version: str
    os_system: str = "14"
    platform: str = "Android"
    channel: str = "oem"
    app_rn_version: str = ""
    et: str = "0"
    endpoints: tuple[str, ...] = (
        "https://a1.tuyaeu.com/api.json",
        "https://a1.tuyaus.com/api.json",
        "https://a1-sg.iotbing.com/api.json",
        "https://a1.tuyacn.com/api.json",
        "https://a1.tuyain.com/api.json",
    )

    @property
    def native_key(self) -> bytes:
        """Return the request-signing key used by the Android application."""
        material = (
            f"{self.package}_{colon_hex(self.cert_sha256_hex)}_"
            f"{self.app_key}_{self.app_secret}"
        )
        return material.encode("ascii")

    def stable_device_id(self, username: str) -> str:
        """Return a stable, account-scoped installation identifier."""
        material = f"{self.package}|{self.app_id}|{username.strip()}".encode()
        return hashlib.sha256(material).hexdigest()[:44]


@dataclass(frozen=True)
class TuyaMobileSession:
    """Ephemeral authenticated Tuya mobile session."""

    sid: str = field(repr=False)
    ecode: str | None = field(default=None, repr=False)
    uid: str | None = None
    endpoint: str = ""


@dataclass(frozen=True)
class TuyaDeviceCredentials:
    """Atomic credential pair returned for one exact Tuya device."""

    device_id: str
    local_key: str = field(repr=False)
    sec_key: str = field(repr=False)
    uuid: str | None = None
    product_id: str | None = None
