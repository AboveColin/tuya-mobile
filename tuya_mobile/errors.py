"""Public exception hierarchy for Tuya mobile authentication."""


class TuyaMobileError(RuntimeError):
    """Base class for expected Tuya mobile failures."""


class TuyaMobileApiError(TuyaMobileError):
    """The Tuya mobile API rejected a request."""


class TuyaMobileInvalidAuth(TuyaMobileApiError):
    """The account identifier or password was rejected."""


class TuyaMobileMFARequired(TuyaMobileApiError):
    """Interactive multi-factor authentication is required."""


class TuyaMobileCaptchaRequired(TuyaMobileApiError):
    """Interactive captcha verification is required."""


class TuyaMobileAccountLocked(TuyaMobileApiError):
    """The Tuya account is temporarily locked."""


class TuyaMobileProfileExpired(TuyaMobileApiError):
    """The supplied Android application profile is no longer accepted."""


class TuyaMobileTransportError(TuyaMobileError):
    """The mobile endpoint could not be reached or decoded."""


class TuyaMobileDeviceNotFound(TuyaMobileApiError):
    """The requested device was not returned by the authenticated account."""


class TuyaMobileInvalidCredentials(TuyaMobileApiError):
    """The device returned incomplete or malformed BLE credentials."""
