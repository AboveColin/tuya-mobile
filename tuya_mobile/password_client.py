"""Password login and device-credential retrieval for Tuya mobile APIs."""

from __future__ import annotations

import hashlib
import re
from typing import Any, Iterable

import aiohttp
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .client import TuyaMobileClient
from .errors import (
    TuyaMobileAccountLocked,
    TuyaMobileApiError,
    TuyaMobileCaptchaRequired,
    TuyaMobileDeviceNotFound,
    TuyaMobileInvalidAuth,
    TuyaMobileInvalidCredentials,
    TuyaMobileMFARequired,
    TuyaMobileProfileExpired,
    TuyaMobileTransportError,
)
from .models import (
    TuyaDeviceCredentials,
    TuyaMobileAppProfile,
    TuyaMobileSession,
)
from .signer import PurePythonTuyaSigner

TOKEN_API = ("thing.m.user.username.token.get", "2.0")
EMAIL_LOGIN_API = ("thing.m.user.email.password.login", "3.0")
MOBILE_LOGIN_APIS = (
    ("thing.m.user.mobile.passwd.login", "4.0", "options"),
    ("thing.m.user.mobile.passwd.login", "4.0", "extInfo"),
    ("smartlife.m.user.mobile.passwd.login", "4.0", "options"),
    ("smartlife.m.user.mobile.passwd.login", "4.0", "extInfo"),
)
DEVICE_CREDENTIALS_API = ("thing.m.device.get", "4.1")
LOGIN_OPTIONS = '{"group":1,"mfaCode":""}'


def _walk(value: Any) -> Iterable[dict[str, Any]]:
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk(child)


def _business_error(value: Any, context: str) -> TuyaMobileApiError | None:
    for response in _walk(value):
        if response.get("success") is not False and not response.get("errorCode"):
            continue
        code = str(response.get("errorCode") or response.get("code") or "unknown")
        message = str(response.get("errorMsg") or response.get("msg") or "")
        marker = f"{code}:{message}".upper()
        safe_message = f"Tuya mobile {context} failed ({code})"
        if "CAPTCHA" in marker:
            return TuyaMobileCaptchaRequired(safe_message)
        if any(item in marker for item in ("MFA", "VERIFYCODE", "VERIFY_CODE")):
            return TuyaMobileMFARequired(safe_message)
        if any(item in marker for item in ("LOCK", "FROZEN", "TOO MANY")):
            return TuyaMobileAccountLocked(safe_message)
        if any(
            item in marker
            for item in ("CLIENT", "SIGN", "APP VERSION", "ILLEGAL APP", "APPKEY")
        ):
            return TuyaMobileProfileExpired(safe_message)
        if any(
            item in marker
            for item in ("PASSWORD", "PASSWD", "INVALID CREDENTIAL", "USER_NOT_EXIST")
        ):
            return TuyaMobileInvalidAuth(safe_message)
        return TuyaMobileApiError(safe_message)
    return None


def _required_dict(value: Any, fields: set[str], context: str) -> dict[str, Any]:
    if error := _business_error(value, context):
        raise error
    for candidate in _walk(value):
        if fields.issubset(candidate):
            return candidate
    raise TuyaMobileProfileExpired(f"Tuya mobile {context} response is incomplete")


def _mobile_candidates(username: str, country_code: str) -> tuple[str, ...]:
    mobile = re.sub(r"[\s\-()]", "", username.strip())
    code = country_code.strip().lstrip("+")
    if mobile.startswith("+"):
        mobile = mobile[1:]
        if code and mobile.startswith(code):
            mobile = mobile[len(code) :]
    elif code and mobile.startswith(f"00{code}"):
        mobile = mobile[len(code) + 2 :]
    candidates = [mobile]
    if mobile.startswith("0") and len(mobile) > 1:
        candidates.append(mobile[1:])
    return tuple(dict.fromkeys(candidates))


def _rsa_encrypt_password(password: str, token: dict[str, Any]) -> str:
    try:
        public_key = rsa.RSAPublicNumbers(
            int(token["exponent"]), int(token["publicKey"])
        ).public_key()
    except (KeyError, TypeError, ValueError) as error:
        raise TuyaMobileProfileExpired(
            "Tuya mobile login token returned an invalid public key"
        ) from error
    digest = hashlib.md5(password.encode()).hexdigest().encode("ascii")
    return public_key.encrypt(digest, padding.PKCS1v15()).hex()


class TuyaPasswordClient(TuyaMobileClient):
    """Encrypted Tuya mobile client with password authentication."""

    def __init__(
        self,
        profile: TuyaMobileAppProfile,
        session: aiohttp.ClientSession,
        *,
        username: str,
        endpoint: str | None = None,
        request_timeout: float = 20,
    ) -> None:
        signer = PurePythonTuyaSigner(
            app_id=profile.app_id,
            app_secret=profile.app_secret,
            cert_sha256_hex=profile.cert_sha256_hex,
            app_key=profile.app_key,
            package=profile.package,
        )
        super().__init__(
            signer,
            session,
            device_id=profile.stable_device_id(username),
            request_timeout=request_timeout,
        )
        self.profile = profile
        self.username = username.strip()
        self.APP_VERSION = profile.app_version
        self.mobile_url = endpoint or profile.endpoints[0]
        self.mobile_session: TuyaMobileSession | None = None

    async def _mobile_call(
        self,
        action: str,
        version: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        try:
            return await self._call(action, payload, version=version)
        except (aiohttp.ClientError, TimeoutError, ValueError) as error:
            raise TuyaMobileTransportError(
                f"Tuya mobile endpoint failed for {action}"
            ) from error
        except RuntimeError as error:
            typed = _business_error(
                {"errorCode": "MOBILE_API", "errorMsg": str(error)}, action
            )
            raise typed or TuyaMobileApiError(
                f"Tuya mobile request failed for {action}"
            ) from error

    async def login_with_password(
        self, password: str, country_code: str
    ) -> TuyaMobileSession:
        """Authenticate an email or telephone account without retaining password."""
        endpoints = tuple(dict.fromkeys((self.mobile_url, *self.profile.endpoints)))
        last_transport: TuyaMobileTransportError | None = None
        for endpoint in endpoints:
            self.mobile_url = endpoint
            try:
                mobile_session = await self._login_once(password, country_code)
            except TuyaMobileTransportError as error:
                last_transport = error
                continue
            self.mobile_session = mobile_session
            return mobile_session
        raise last_transport or TuyaMobileTransportError(
            "No Tuya mobile endpoint accepted the request"
        )

    async def _login_once(self, password: str, country_code: str) -> TuyaMobileSession:
        token_envelope = await self._mobile_call(
            *TOKEN_API,
            {
                "countryCode": country_code,
                "username": self.username,
                "isUid": False,
            },
        )
        token = _required_dict(
            token_envelope, {"publicKey", "exponent", "token"}, "login token"
        )
        encrypted_password = _rsa_encrypt_password(password, token)
        if "@" in self.username:
            login_envelope = await self._mobile_call(
                *EMAIL_LOGIN_API,
                {
                    "countryCode": country_code,
                    "email": self.username,
                    "passwd": encrypted_password,
                    "options": LOGIN_OPTIONS,
                    "token": str(token["token"]),
                    "ifencrypt": 1,
                },
            )
            login = _required_dict(
                login_envelope, {"sid", "ecode", "uid"}, "email password login"
            )
        else:
            login = await self._login_mobile(
                encrypted_password, str(token["token"]), country_code
            )
        self.sid = str(login["sid"])
        self.ecode = str(login["ecode"])
        self.uid = str(login["uid"])
        if endpoint := self._endpoint_from_login(login):
            self.mobile_url = endpoint
        return TuyaMobileSession(
            sid=self.sid,
            ecode=self.ecode,
            uid=self.uid,
            endpoint=self.mobile_url,
        )

    async def _login_mobile(
        self,
        encrypted_password: str,
        token: str,
        country_code: str,
    ) -> dict[str, Any]:
        last_error: TuyaMobileApiError | None = None
        for mobile in _mobile_candidates(self.username, country_code):
            for action, version, options_field in MOBILE_LOGIN_APIS:
                response = await self._mobile_call(
                    action,
                    version,
                    {
                        "countryCode": country_code,
                        "mobile": mobile,
                        "passwd": encrypted_password,
                        options_field: LOGIN_OPTIONS,
                        "token": token,
                        "ifencrypt": 1,
                    },
                )
                try:
                    return _required_dict(
                        response, {"sid", "ecode", "uid"}, "mobile password login"
                    )
                except (
                    TuyaMobileMFARequired,
                    TuyaMobileCaptchaRequired,
                    TuyaMobileAccountLocked,
                    TuyaMobileInvalidAuth,
                ):
                    raise
                except TuyaMobileApiError as error:
                    last_error = error
        raise last_error or TuyaMobileInvalidAuth("Tuya mobile password login failed")

    @staticmethod
    def _endpoint_from_login(result: dict[str, Any]) -> str | None:
        domain = result.get("domain")
        if isinstance(domain, dict) and domain.get("mobileApiUrl"):
            return str(domain["mobileApiUrl"]).rstrip("/") + "/api.json"
        if result.get("mobileApiUrl"):
            return str(result["mobileApiUrl"]).rstrip("/") + "/api.json"
        return None

    async def get_device_credentials(self, device_id: str) -> TuyaDeviceCredentials:
        """Return a validated localKey/SecKey pair for one exact device."""
        if self.mobile_session is None:
            raise TuyaMobileInvalidAuth("Tuya mobile client is not authenticated")
        response = await self._mobile_call(
            *DEVICE_CREDENTIALS_API,
            {"devId": device_id},
        )
        if error := _business_error(response, "device credentials"):
            raise error
        device = next(
            (
                candidate
                for candidate in _walk(response)
                if str(
                    candidate.get("devId")
                    or candidate.get("deviceId")
                    or candidate.get("id")
                    or ""
                )
                == str(device_id)
                and (candidate.get("secKey") or candidate.get("sec_key"))
            ),
            None,
        )
        if device is None:
            raise TuyaMobileDeviceNotFound(
                "Tuya mobile response did not match the requested device"
            )
        local_key = device.get("localKey") or device.get("local_key")
        sec_key = device.get("secKey") or device.get("sec_key")
        self._validate_key(local_key, "localKey")
        self._validate_key(sec_key, "secKey")
        return TuyaDeviceCredentials(
            device_id=str(
                device.get("devId") or device.get("deviceId") or device.get("id")
            ),
            local_key=local_key,
            sec_key=sec_key,
            uuid=device.get("uuid"),
            product_id=device.get("productId") or device.get("product_id"),
        )

    @staticmethod
    def _validate_key(value: Any, name: str) -> None:
        if not isinstance(value, str) or len(value) != 16:
            raise TuyaMobileInvalidCredentials(
                f"Tuya mobile device returned an invalid {name}"
            )
        try:
            value.encode("ascii")
        except UnicodeEncodeError as error:
            raise TuyaMobileInvalidCredentials(
                f"Tuya mobile device returned a non-ASCII {name}"
            ) from error
