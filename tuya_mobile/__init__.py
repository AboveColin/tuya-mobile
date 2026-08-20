"""tuya-mobile: pure-Python Tuya *mobile* API signer + client.

A dependency-free reimplementation of Tuya's ``thing_security`` mobile-app
request signing, the encrypted mobile API client, and the MQTT signaling
credential derivation. It includes versioned Smart Life and Tuya Smart profiles
and accepts caller-supplied profiles for other Tuya-based applications.
"""

from .signer import (
    NativeSignerError,
    NativeTuyaSigner,
    PurePythonTuyaSigner,
    colon_hex,
)
from .client import TuyaMobileClient, canonical_string
from .errors import (
    TuyaMobileAccountLocked,
    TuyaMobileApiError,
    TuyaMobileCaptchaRequired,
    TuyaMobileDeviceNotFound,
    TuyaMobileEndpointUnsupported,
    TuyaMobileError,
    TuyaMobileInvalidAuth,
    TuyaMobileInvalidCredentials,
    TuyaMobileLoginAttemptsExceeded,
    TuyaMobileMFARequired,
    TuyaMobileProfileExpired,
    TuyaMobileTransportError,
)
from .models import (
    TuyaDeviceCredentials,
    TuyaMobileAppProfile,
    TuyaMobileSession,
)
from .mqtt_auth import mqtt_client_id, mqtt_credentials, mqtt_password, mqtt_username
from .password_client import TuyaPasswordClient
from .profiles import (
    TuyaMobileApp,
    get_mobile_app_profile,
)

__all__ = [
    "PurePythonTuyaSigner",
    "NativeTuyaSigner",
    "NativeSignerError",
    "colon_hex",
    "TuyaMobileClient",
    "canonical_string",
    "TuyaPasswordClient",
    "TuyaMobileApp",
    "TuyaMobileAppProfile",
    "get_mobile_app_profile",
    "TuyaMobileSession",
    "TuyaDeviceCredentials",
    "TuyaMobileError",
    "TuyaMobileApiError",
    "TuyaMobileInvalidAuth",
    "TuyaMobileLoginAttemptsExceeded",
    "TuyaMobileEndpointUnsupported",
    "TuyaMobileMFARequired",
    "TuyaMobileCaptchaRequired",
    "TuyaMobileAccountLocked",
    "TuyaMobileProfileExpired",
    "TuyaMobileTransportError",
    "TuyaMobileDeviceNotFound",
    "TuyaMobileInvalidCredentials",
    "mqtt_credentials",
    "mqtt_client_id",
    "mqtt_username",
    "mqtt_password",
]

__version__ = "1.1.0"
