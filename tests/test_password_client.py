"""Offline tests for Tuya mobile password login and BLE credentials."""

from __future__ import annotations

from unittest.mock import AsyncMock, Mock

from cryptography.hazmat.primitives.asymmetric import rsa
import pytest

from tuya_mobile import (
    PurePythonTuyaSigner,
    TuyaDeviceCredentials,
    TuyaMobileAccountLocked,
    TuyaMobileAppProfile,
    TuyaMobileCaptchaRequired,
    TuyaMobileDeviceNotFound,
    TuyaMobileInvalidAuth,
    TuyaMobileInvalidCredentials,
    TuyaMobileMFARequired,
    TuyaMobileProfileExpired,
    TuyaMobileSession,
    TuyaPasswordClient,
)


@pytest.fixture
def profile() -> TuyaMobileAppProfile:
    """Return an inert application profile containing obvious fake values."""
    return TuyaMobileAppProfile(
        name="Fixture app",
        app_id="fixture-app-id",
        app_secret="fixture-app-secret",
        cert_sha256_hex="11" * 32,
        app_key="fixture-app-key",
        package="com.example.fixture",
        app_version="7.9.0",
        channel_key="12345678",
        ttid="sdk_fixture",
        sdk_version="7.9.0",
        device_core_version="7.9.0",
        endpoints=("https://a1.tuyaeu.com/api.json",),
    )


@pytest.fixture
def token_result() -> dict[str, str]:
    """Return a valid RSA login-token fixture."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    numbers = key.public_key().public_numbers()
    return {
        "token": "fixture-token",
        "publicKey": str(numbers.n),
        "exponent": str(numbers.e),
    }


def _client(profile: TuyaMobileAppProfile, username: str) -> TuyaPasswordClient:
    return TuyaPasswordClient(profile, Mock(), username=username)


def _login_result() -> dict:
    return {
        "sid": "fixture-session",
        "ecode": "fixture-ecode",
        "uid": "fixture-uid",
        "domain": {"mobileApiUrl": "https://a1.tuyaeu.com"},
    }


async def test_email_login_and_device_credentials_are_atomic(
    profile: TuyaMobileAppProfile, token_result: dict[str, str]
) -> None:
    """Email login retrieves one exact, validated credential pair."""
    client = _client(profile, "owner@example.com")
    client._call = AsyncMock(
        side_effect=[
            token_result,
            _login_result(),
            {
                "devId": "device-1",
                "uuid": "device-uuid",
                "productId": "product-1",
                "localKey": "0123456789abcdef",
                "secKey": "fedcba9876543210",
            },
        ]
    )

    mobile_session = await client.login_with_password("private-password", "33")
    credentials = await client.get_device_credentials("device-1")

    assert mobile_session.uid == "fixture-uid"
    assert credentials == TuyaDeviceCredentials(
        device_id="device-1",
        uuid="device-uuid",
        product_id="product-1",
        local_key="0123456789abcdef",
        sec_key="fedcba9876543210",
    )
    actions = [call.args[0] for call in client._call.await_args_list]
    assert actions == [
        "thing.m.user.username.token.get",
        "thing.m.user.email.password.login",
        "thing.m.device.get",
    ]
    login_payload = client._call.await_args_list[1].args[1]
    assert "private-password" not in str(login_payload)
    assert client.sid == "fixture-session"
    assert client.ecode == "fixture-ecode"


async def test_phone_login_uses_controlled_endpoint_fallback(
    profile: TuyaMobileAppProfile, token_result: dict[str, str]
) -> None:
    """Phone login retries protocol variants but preserves account safety."""
    client = _client(profile, "+33 6 12 34 56 78")
    client._call = AsyncMock(
        side_effect=[
            token_result,
            {"success": False, "errorCode": "API_NOT_SUPPORTED"},
            _login_result(),
        ]
    )

    await client.login_with_password("private-password", "33")

    first = client._call.await_args_list[1]
    second = client._call.await_args_list[2]
    assert first.args[0] == second.args[0] == "thing.m.user.mobile.passwd.login"
    assert first.args[1]["mobile"] == "612345678"
    assert "options" in first.args[1]
    assert "extInfo" in second.args[1]


async def test_interactive_error_stops_phone_fallbacks(
    profile: TuyaMobileAppProfile, token_result: dict[str, str]
) -> None:
    """MFA/captcha-style responses never cause repeated login attempts."""
    client = _client(profile, "0612345678")
    client._call = AsyncMock(
        side_effect=[
            token_result,
            {"success": False, "errorCode": "MFA_REQUIRED"},
        ]
    )

    with pytest.raises(TuyaMobileMFARequired):
        await client.login_with_password("private-password", "33")

    assert client._call.await_count == 2


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("localKey", "too-short"),
        ("secKey", "too-short"),
        ("secKey", "123456789012345é"),
    ),
)
async def test_device_credentials_validate_both_keys(
    profile: TuyaMobileAppProfile,
    field: str,
    value: str,
) -> None:
    """A partial or malformed pair is never returned to a caller."""
    device = {
        "devId": "device-1",
        "localKey": "0123456789abcdef",
        "secKey": "fedcba9876543210",
    }
    device[field] = value
    client = _client(profile, "owner@example.com")
    client.mobile_session = _test_session()
    client._call = AsyncMock(return_value=device)

    with pytest.raises(TuyaMobileInvalidCredentials):
        await client.get_device_credentials("device-1")


async def test_device_credentials_require_exact_device_match(
    profile: TuyaMobileAppProfile,
) -> None:
    """Credentials for another device cannot be imported accidentally."""
    client = _client(profile, "owner@example.com")
    client.mobile_session = _test_session()
    client._call = AsyncMock(
        return_value={
            "devId": "other-device",
            "localKey": "0123456789abcdef",
            "secKey": "fedcba9876543210",
        }
    )

    with pytest.raises(TuyaMobileDeviceNotFound):
        await client.get_device_credentials("device-1")


@pytest.mark.parametrize(
    ("code", "exception"),
    (
        ("PASSWORD_ERROR", TuyaMobileInvalidAuth),
        ("CAPTCHA_REQUIRED", TuyaMobileCaptchaRequired),
        ("ACCOUNT_LOCKED", TuyaMobileAccountLocked),
        ("ILLEGAL_CLIENT", TuyaMobileProfileExpired),
    ),
)
async def test_login_errors_are_typed_and_redacted(
    profile: TuyaMobileAppProfile,
    token_result: dict[str, str],
    code: str,
    exception: type[Exception],
) -> None:
    """Expected failures are actionable without echoing server messages."""
    client = _client(profile, "owner@example.com")
    client._call = AsyncMock(
        side_effect=[
            token_result,
            {
                "success": False,
                "errorCode": code,
                "errorMsg": "private-password fixture-session",
            },
        ]
    )

    with pytest.raises(exception) as raised:
        await client.login_with_password("private-password", "33")

    assert "private-password" not in str(raised.value)
    assert "fixture-session" not in str(raised.value)


def test_client_uses_encrypted_signer_and_stable_installation_id(
    profile: TuyaMobileAppProfile,
) -> None:
    """Password flows reuse the proven encrypted mobile transport."""
    first = _client(profile, "owner@example.com")
    second = _client(profile, "owner@example.com")

    assert isinstance(first.signer, PurePythonTuyaSigner)
    assert (
        first.device_id
        == second.device_id
        == profile.stable_device_id("owner@example.com")
    )
    assert first.APP_VERSION == profile.app_version
    assert first.request_timeout == 20


def test_models_redact_all_secret_material(profile: TuyaMobileAppProfile) -> None:
    """Dataclass representations do not expose reusable secret values."""
    credentials = TuyaDeviceCredentials(
        device_id="device-1",
        local_key="0123456789abcdef",
        sec_key="fedcba9876543210",
    )
    mobile_session = _test_session()

    for rendered in (repr(profile), repr(credentials), repr(mobile_session)):
        assert "fixture-app-secret" not in rendered
        assert "fixture-app-key" not in rendered
        assert "0123456789abcdef" not in rendered
        assert "fedcba9876543210" not in rendered
        assert "fixture-session" not in rendered
        assert "fixture-ecode" not in rendered


def _test_session() -> TuyaMobileSession:
    return TuyaMobileSession(
        sid="fixture-session",
        ecode="fixture-ecode",
        uid="fixture-uid",
        endpoint="https://a1.tuyaeu.com/api.json",
    )
