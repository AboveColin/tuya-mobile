"""Versioned application profiles for official Tuya mobile applications."""

from __future__ import annotations

from collections.abc import Mapping
from enum import Enum
from types import MappingProxyType

from .models import TuyaMobileAppProfile

__all__ = ["TuyaMobileApp", "get_mobile_app_profile"]


class TuyaMobileApp(str, Enum):
    """Official Tuya mobile applications with bundled profiles."""

    SMART_LIFE = "smart_life"
    TUYA_SMART = "tuya_smart"


# These values identify public Android application builds. They are not user
# credentials, but they are version-specific and may rotate in a future build.
_SMART_LIFE_PROFILE = TuyaMobileAppProfile(
    name="Smart Life",
    app_id="ekmnwp9f5pnh3trdtpgy",
    app_secret="r3me7ghmxjevrvnpemwmhw3fxtacphyg",  # noqa: S106
    cert_sha256_hex=(
        "0FC361999CC0C35BA8ACA57DAA5593A2" "0CF55727702EA85AD7B3228949F888FE"
    ),
    app_key="jfg5rs5kkmrj5mxahugvucrsvw43t48x",
    package="com.tuya.smartlife",
    app_version="7.10.0",
    ttid="sdk_international@ekmnwp9f5pnh3trdtpgy",
    sdk_version="7.9.0",
    device_core_version="7.9.0",
    os_system="14",
    platform="SM-M115F",
    channel="sdk",
    app_rn_version="7.8",
    et="3",
)

_TUYA_SMART_PROFILE = TuyaMobileAppProfile(
    name="Tuya Smart",
    app_id="3cxxt3au9x33ytvq3h9j",
    app_secret="5gdtanjtf38vyxkqh87cjwfcqjhvjjqa",  # noqa: S106
    cert_sha256_hex=(
        "93219FC273E2200F4ADEE5F7191DC656" "BA2A2D7B2FF5D24CD55C4B6155001E40"
    ),
    app_key="f3hd7pet4p83kemjdf5wqsa5tavrv579",
    package="com.tuya.smart",
    app_version="7.8.6",
    ttid="international",
    sdk_version="5.24.0",
    device_core_version="5.17.0",
    os_system="15",
    platform="y",
    channel="sdk",
    app_rn_version="5.84",
    et="3",
)

_MOBILE_APP_PROFILES: Mapping[TuyaMobileApp, TuyaMobileAppProfile] = MappingProxyType(
    {
        TuyaMobileApp.SMART_LIFE: _SMART_LIFE_PROFILE,
        TuyaMobileApp.TUYA_SMART: _TUYA_SMART_PROFILE,
    }
)


def get_mobile_app_profile(
    application: TuyaMobileApp | str,
) -> TuyaMobileAppProfile:
    """Return the bundled profile selected explicitly by the caller."""
    try:
        selected = TuyaMobileApp(application)
    except ValueError as error:
        raise ValueError(
            f"Unsupported Tuya mobile application: {application!r}"
        ) from error
    return _MOBILE_APP_PROFILES[selected]
