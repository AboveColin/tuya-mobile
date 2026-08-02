"""Offline tests for Tuya mobile password login and BLE credentials."""

from __future__ import annotations

import asyncio
from dataclasses import replace
import hashlib
from unittest.mock import AsyncMock, Mock

import aiohttp
from cryptography.hazmat.primitives.asymmetric import padding, rsa
import pytest

from tuya_mobile import (
    PurePythonTuyaSigner,
    TuyaMobileApiError,
    TuyaDeviceCredentials,
    TuyaMobileAccountLocked,
    TuyaMobileAppProfile,
    TuyaMobileCaptchaRequired,
    TuyaMobileDeviceNotFound,
    TuyaMobileInvalidAuth,
    TuyaMobileInvalidCredentials,
    TuyaMobileLoginAttemptsExceeded,
    TuyaMobileMFARequired,
    TuyaMobileProfileExpired,
    TuyaMobileSession,
    TuyaMobileTransportError,
    TuyaPasswordClient,
)
from tuya_mobile.client import TuyaMobileClient, _decrypt, _encrypt
from tuya_mobile.password_client import _rsa_encrypt_password


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
        ttid="fixture-ttid",
        sdk_version="fixture-sdk",
        device_core_version="fixture-core",
        os_system="fixture-os",
        platform="fixture-platform",
        channel="fixture-channel",
        app_rn_version="fixture-rn",
        et="7",
        business_domain="fixture-domain",
        endpoints=("https://a1.tuyaeu.com/api.json",),
    )


@pytest.fixture
def token_result() -> dict[str, str]:
    """Return a valid RSA login-token fixture."""
    # A small key keeps this protocol-fixture test fast; it protects no data.
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)  # noqa: S505
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
    versions = [call.kwargs["version"] for call in client._call.await_args_list]
    assert actions == [
        "thing.m.user.username.token.get",
        "thing.m.user.email.password.login",
        "thing.m.device.get",
    ]
    assert versions == ["2.0", "3.0", "4.1"]
    login_payload = client._call.await_args_list[1].args[1]
    assert "private-password" not in str(login_payload)
    assert client.sid == "fixture-session"
    assert client.ecode == "fixture-ecode"


async def test_phone_login_retries_api_variants(
    profile: TuyaMobileAppProfile, token_result: dict[str, str]
) -> None:
    """Phone login retries protocol variants but preserves account safety."""
    client = _client(profile, "+33 6 12 34 56 78")
    client._call = AsyncMock(
        side_effect=[
            token_result,
            {"success": False, "errorCode": "API_NOT_SUPPORTED"},
            token_result,
            _login_result(),
        ]
    )

    await client.login_with_password("private-password", "33")

    first = client._call.await_args_list[1]
    second = client._call.await_args_list[3]
    assert first.args[0] == second.args[0] == "thing.m.user.mobile.passwd.login"
    assert first.args[1]["mobile"] == "612345678"
    assert second.args[1]["mobile"] == "612345678"
    assert "options" in first.args[1]
    assert "extInfo" in second.args[1]
    assert [call.kwargs["version"] for call in (first, second)] == ["4.0", "4.0"]


async def test_unclassified_phone_rejection_is_not_retried(
    profile: TuyaMobileAppProfile, token_result: dict[str, str]
) -> None:
    """Only an explicit unsupported-API response permits another submission."""
    client = _client(profile, "0612345678")
    client._call = AsyncMock(
        side_effect=[
            token_result,
            {"success": False, "errorCode": "UNCLASSIFIED_REJECTION"},
        ]
    )

    with pytest.raises(TuyaMobileApiError):
        await client.login_with_password("private-password", "33")

    assert client._call.await_count == 2


async def test_phone_login_has_a_hard_attempt_budget(
    profile: TuyaMobileAppProfile, token_result: dict[str, str]
) -> None:
    """Variant probing cannot exceed the configured password-attempt budget."""
    client = TuyaPasswordClient(
        profile,
        Mock(),
        username="0612345678",
        max_login_attempts=3,
    )
    unsupported = {"success": False, "errorCode": "API_NOT_SUPPORTED"}
    client._call = AsyncMock(
        side_effect=[
            token_result,
            unsupported,
            token_result,
            unsupported,
            token_result,
            unsupported,
        ]
    )

    with pytest.raises(TuyaMobileLoginAttemptsExceeded, match="3 of 3"):
        await client.login_with_password("private-password", "33")

    assert client._call.await_count == 6


@pytest.mark.parametrize(
    "timeout",
    (asyncio.TimeoutError(), aiohttp.ServerTimeoutError()),
)
async def test_timeout_is_typed_and_never_retries_a_password_submission(
    profile: TuyaMobileAppProfile,
    token_result: dict[str, str],
    timeout: BaseException,
) -> None:
    """Ambiguous transport outcomes after a password submission are fatal."""
    client = _client(profile, "owner@example.com")
    client._call = AsyncMock(side_effect=[token_result, timeout])

    with pytest.raises(TuyaMobileTransportError):
        await client.login_with_password("private-password", "33")

    assert client._call.await_count == 2


async def test_token_transport_fallback_precedes_single_password_attempt(
    profile: TuyaMobileAppProfile, token_result: dict[str, str]
) -> None:
    """Regional probing is safe only before any password has been submitted."""
    profile = replace(
        profile,
        endpoints=(
            "https://unavailable.example/api.json",
            "https://working.example/api.json",
        ),
    )
    client = _client(profile, "owner@example.com")
    client._call = AsyncMock(
        side_effect=[
            aiohttp.ClientConnectionError(),
            token_result,
            _login_result(),
        ]
    )

    await client.login_with_password("private-password", "33")

    assert client._call.await_count == 3
    assert [call.args[0] for call in client._call.await_args_list].count(
        "thing.m.user.email.password.login"
    ) == 1


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


async def test_login_accepts_tuya_session_aliases(
    profile: TuyaMobileAppProfile, token_result: dict[str, str]
) -> None:
    """Password login matches the aliases accepted by the existing JWT flow."""
    client = _client(profile, "owner@example.com")
    client._call = AsyncMock(
        side_effect=[
            token_result,
            {
                "sessionId": "fixture-session",
                "encryptCode": "fixture-ecode",
                "userId": "fixture-uid",
            },
        ]
    )

    mobile_session = await client.login_with_password("private-password", "33")

    assert mobile_session.uid == "fixture-uid"
    assert client.sid == "fixture-session"
    assert client.ecode == "fixture-ecode"


async def test_incomplete_response_is_not_misreported_as_expired_profile(
    profile: TuyaMobileAppProfile,
) -> None:
    """Missing response fields remain distinct from rejected app identity."""
    client = _client(profile, "owner@example.com")
    client._call = AsyncMock(return_value={"token": "fixture-token"})

    with pytest.raises(TuyaMobileApiError, match="missing required fields") as raised:
        await client.login_with_password("private-password", "33")

    assert not isinstance(raised.value, TuyaMobileProfileExpired)


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


async def test_key_length_error_reports_only_safe_dimensions(
    profile: TuyaMobileAppProfile,
) -> None:
    """Length failures are actionable without including credential material."""
    client = _client(profile, "owner@example.com")
    client.mobile_session = _test_session()
    client._call = AsyncMock(
        return_value={
            "devId": "device-1",
            "localKey": "fixture-key-with-24-chars",
            "secKey": "fedcba9876543210",
        }
    )

    with pytest.raises(
        TuyaMobileInvalidCredentials,
        match="localKey length 25; expected 16 ASCII characters",
    ) as raised:
        await client.get_device_credentials("device-1")

    assert "fixture-key" not in str(raised.value)


async def test_key_length_can_be_explicit_for_another_device_contract(
    profile: TuyaMobileAppProfile,
) -> None:
    """A documented device class can override the protocol-v2 default."""
    client = _client(profile, "owner@example.com")
    client.mobile_session = _test_session()
    client._call = AsyncMock(
        return_value={
            "devId": "device-1",
            "localKey": "0123456789abcdefghijklmn",
            "secKey": "abcdefghijklmnopqrstuvwx",
        }
    )

    credentials = await client.get_device_credentials(
        "device-1", expected_key_length=24
    )

    assert credentials.device_id == "device-1"


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


def test_password_wire_encoding_is_md5_then_rsa_pkcs1v15() -> None:
    """The password payload matches the documented mobile login encoding."""
    # A small key keeps this protocol-fixture test fast; it protects no data.
    private_key = rsa.generate_private_key(  # noqa: S505
        public_exponent=65537, key_size=1024
    )
    numbers = private_key.public_key().public_numbers()
    encrypted = _rsa_encrypt_password(
        "private-password",
        {
            "publicKey": str(numbers.n),
            "exponent": str(numbers.e),
        },
    )

    decrypted = private_key.decrypt(bytes.fromhex(encrypted), padding.PKCS1v15())

    assert decrypted == hashlib.md5(b"private-password").hexdigest().encode("ascii")


async def test_transport_uses_every_versioned_profile_wire_field(
    profile: TuyaMobileAppProfile,
) -> None:
    """Application-profile values reach the signed mobile request unchanged."""
    signer = _FixtureSigner()
    session = _RecordingSession()
    client = TuyaMobileClient(
        signer,
        session,
        device_id="fixture-device-id",
        profile=profile,
    )

    result = await client._call(
        "fixture.mobile.action", {"fixture": "payload"}, version="4.1"
    )

    params = session.data
    assert result == {"success": True}
    assert session.url == "https://a1.tuyaeu.com/api.json"
    assert params["a"] == "fixture.mobile.action"
    assert params["v"] == "4.1"
    assert params["appVersion"] == profile.app_version
    assert params["ttid"] == profile.ttid
    assert params["sdkVersion"] == profile.sdk_version
    assert params["deviceCoreVersion"] == profile.device_core_version
    assert params["osSystem"] == profile.os_system
    assert params["platform"] == profile.platform
    assert params["channel"] == profile.channel
    assert params["appRnVersion"] == profile.app_rn_version
    assert params["et"] == profile.et
    assert params["bizDM"] == profile.business_domain
    assert params["chKey"] == "fixture-channel-key"
    assert "appVersion=7.9.0" in signer.canonical
    assert "et=7" in signer.canonical
    assert "ttid=fixture-ttid" in signer.canonical
    assert _decrypt(_FixtureSigner.key, params["postData"]) == {"fixture": "payload"}


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


class _FixtureSigner:
    """Deterministic signer used to inspect one real transport envelope."""

    app_id = "fixture-app-id"
    key = b"0123456789abcdef"

    def __init__(self) -> None:
        self.canonical = ""

    def derive_key(self, request_id: str, ecode: str | None) -> bytes:
        return self.key

    def channel_key(self) -> str:
        return "fixture-channel-key"

    def sign(self, canonical: str) -> str:
        self.canonical = canonical
        return "fixture-signature"


class _RecordingResponse:
    async def __aenter__(self) -> _RecordingResponse:
        return self

    async def __aexit__(self, *args: object) -> None:
        return None

    async def json(self, *, content_type: None = None) -> dict[str, str]:
        return {"result": _encrypt(_FixtureSigner.key, {"success": True})}


class _RecordingSession:
    url: str = ""
    data: dict[str, str]

    def post(
        self,
        url: str,
        *,
        data: dict[str, str],
        timeout: aiohttp.ClientTimeout,
    ) -> _RecordingResponse:
        self.url = url
        self.data = data
        assert timeout.total == 20
        return _RecordingResponse()
