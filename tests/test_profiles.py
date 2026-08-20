"""Tests for the bundled Smart Life and Tuya Smart application profiles."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from unittest.mock import Mock

import pytest

from tuya_mobile import (
    TuyaMobileApp,
    TuyaPasswordClient,
    get_mobile_app_profile,
)
from tuya_mobile.profiles import _MOBILE_APP_PROFILES


@pytest.mark.parametrize(
    ("application", "name", "package", "version"),
    [
        (
            TuyaMobileApp.SMART_LIFE,
            "Smart Life",
            "com.tuya.smartlife",
            "7.10.0",
        ),
        (
            TuyaMobileApp.TUYA_SMART,
            "Tuya Smart",
            "com.tuya.smart",
            "7.8.6",
        ),
    ],
)
def test_builtin_profiles_are_versioned_and_complete(
    application: TuyaMobileApp,
    name: str,
    package: str,
    version: str,
) -> None:
    """Each supported application resolves to one complete versioned identity."""
    profile = get_mobile_app_profile(application)
    assert get_mobile_app_profile(application) is profile
    assert get_mobile_app_profile(application.value) is profile
    assert _MOBILE_APP_PROFILES[application] is profile
    assert profile.name == name
    assert profile.package == package
    assert profile.app_version == version
    assert profile.app_id
    assert profile.app_secret
    assert profile.app_key
    assert len(profile.cert_sha256_hex) == 64
    int(profile.cert_sha256_hex, 16)
    assert profile.ttid
    assert profile.sdk_version
    assert profile.device_core_version
    assert profile.channel == "sdk"
    assert profile.et == "3"
    assert profile.endpoints


def test_builtin_profile_registry_is_read_only() -> None:
    """Callers cannot replace a process-wide application identity accidentally."""
    with pytest.raises(TypeError):
        _MOBILE_APP_PROFILES[TuyaMobileApp.SMART_LIFE] = get_mobile_app_profile(
            TuyaMobileApp.TUYA_SMART
        )


def test_builtin_profiles_are_immutable_and_redacted() -> None:
    """Versioned identities cannot be mutated and hide reusable key material."""
    smart_life = get_mobile_app_profile(TuyaMobileApp.SMART_LIFE)
    with pytest.raises(FrozenInstanceError):
        smart_life.app_version = "newer"

    for profile in _MOBILE_APP_PROFILES.values():
        rendered = repr(profile)
        assert profile.app_secret not in rendered
        assert profile.app_key not in rendered
        assert profile.cert_sha256_hex not in rendered


def test_password_client_resolves_a_bundled_application_profile() -> None:
    """Official applications need no caller-constructed profile."""
    client = TuyaPasswordClient.for_application(
        TuyaMobileApp.SMART_LIFE,
        Mock(),
        username="owner@example.com",
        endpoint="https://example.invalid/api.json",
        request_timeout=7,
        max_login_attempts=2,
    )

    assert client.profile is get_mobile_app_profile(TuyaMobileApp.SMART_LIFE)
    assert client.mobile_url == "https://example.invalid/api.json"
    assert client.request_timeout == 7
    assert client.max_login_attempts == 2


def test_unknown_application_is_rejected_without_fallback() -> None:
    """Profile selection remains explicit and never probes another application."""
    with pytest.raises(ValueError, match="Unsupported Tuya mobile application"):
        get_mobile_app_profile("unknown")
