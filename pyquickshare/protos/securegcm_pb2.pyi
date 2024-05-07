from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Optional as _Optional, Union as _Union

ANDROID: DeviceType
APPLE_PAD: AppleDeviceDiagonalMils
APPLE_PHONE: AppleDeviceDiagonalMils
BETTER_TOGETHER_CLIENT: SoftwareFeature
BETTER_TOGETHER_HOST: SoftwareFeature
BROWSER: DeviceType
CHROME: DeviceType
DESCRIPTOR: _descriptor.FileDescriptor
DEVICE_INFO_UPDATE: Type
DEVICE_PROXIMITY_CALLBACK: Type
DEVICE_TO_DEVICE_MESSAGE: Type
DEVICE_TO_DEVICE_RESPONDER_HELLO_PAYLOAD: Type
EASY_UNLOCK_CLIENT: SoftwareFeature
EASY_UNLOCK_HOST: SoftwareFeature
ENROLLMENT: Type
GCMV1_IDENTITY_ASSERTION: Type
IOS: DeviceType
LOGIN_NOTIFICATION: Type
MAGIC_TETHER_CLIENT: SoftwareFeature
MAGIC_TETHER_HOST: SoftwareFeature
OSX: DeviceType
PROXIMITYAUTH_PAIRING: Type
REASON_ADDRESS_CHANGE: InvocationReason
REASON_CHANGED_ACCOUNT: InvocationReason
REASON_CUSTOM_KEY_INVALIDATION: InvocationReason
REASON_EXPIRATION: InvocationReason
REASON_FAILURE_RECOVERY: InvocationReason
REASON_FAST_PERIODIC: InvocationReason
REASON_FEATURE_TOGGLED: InvocationReason
REASON_INITIALIZATION: InvocationReason
REASON_MANUAL: InvocationReason
REASON_NEW_ACCOUNT: InvocationReason
REASON_PERIODIC: InvocationReason
REASON_PROXIMITY_PERIODIC: InvocationReason
REASON_SERVER_INITIATED: InvocationReason
REASON_SLOW_PERIODIC: InvocationReason
REASON_SOFTWARE_UPDATE: InvocationReason
REASON_UNKNOWN: InvocationReason
SMS_CONNECT_CLIENT: SoftwareFeature
SMS_CONNECT_HOST: SoftwareFeature
TICKLE: Type
TX_CANCEL_REQUEST: Type
TX_PING: Type
TX_REPLY: Type
TX_REQUEST: Type
TX_SYNC_REQUEST: Type
TX_SYNC_RESPONSE: Type
UNKNOWN: DeviceType
UNKNOWN_FEATURE: SoftwareFeature
UNLOCK_KEY_SIGNED_CHALLENGE: Type

class GcmDeviceInfo(_message.Message):
    __slots__ = ["android_device_id", "apn_registration_id", "arc_plus_plus", "auto_unlock_screenlock_enabled", "auto_unlock_screenlock_supported", "ble_radio_supported", "bluetooth_mac_address", "bluetooth_radio_enabled", "bluetooth_radio_supported", "counter", "device_authzen_version", "device_display_diagonal_mils", "device_manufacturer", "device_master_key_hash", "device_model", "device_os_codename", "device_os_release", "device_os_version", "device_os_version_code", "device_software_package", "device_software_version", "device_software_version_code", "device_type", "enabled_software_features", "enrollment_session_id", "gcm_registration_id", "is_screenlock_state_flaky", "key_handle", "locale", "long_device_id", "mobile_data_supported", "notification_enabled", "oauth_token", "pixel_experience", "supported_software_features", "tethering_supported", "user_public_key", "using_secure_screenlock"]
    ANDROID_DEVICE_ID_FIELD_NUMBER: _ClassVar[int]
    APN_REGISTRATION_ID_FIELD_NUMBER: _ClassVar[int]
    ARC_PLUS_PLUS_FIELD_NUMBER: _ClassVar[int]
    AUTO_UNLOCK_SCREENLOCK_ENABLED_FIELD_NUMBER: _ClassVar[int]
    AUTO_UNLOCK_SCREENLOCK_SUPPORTED_FIELD_NUMBER: _ClassVar[int]
    BLE_RADIO_SUPPORTED_FIELD_NUMBER: _ClassVar[int]
    BLUETOOTH_MAC_ADDRESS_FIELD_NUMBER: _ClassVar[int]
    BLUETOOTH_RADIO_ENABLED_FIELD_NUMBER: _ClassVar[int]
    BLUETOOTH_RADIO_SUPPORTED_FIELD_NUMBER: _ClassVar[int]
    COUNTER_FIELD_NUMBER: _ClassVar[int]
    DEVICE_AUTHZEN_VERSION_FIELD_NUMBER: _ClassVar[int]
    DEVICE_DISPLAY_DIAGONAL_MILS_FIELD_NUMBER: _ClassVar[int]
    DEVICE_MANUFACTURER_FIELD_NUMBER: _ClassVar[int]
    DEVICE_MASTER_KEY_HASH_FIELD_NUMBER: _ClassVar[int]
    DEVICE_MODEL_FIELD_NUMBER: _ClassVar[int]
    DEVICE_OS_CODENAME_FIELD_NUMBER: _ClassVar[int]
    DEVICE_OS_RELEASE_FIELD_NUMBER: _ClassVar[int]
    DEVICE_OS_VERSION_CODE_FIELD_NUMBER: _ClassVar[int]
    DEVICE_OS_VERSION_FIELD_NUMBER: _ClassVar[int]
    DEVICE_SOFTWARE_PACKAGE_FIELD_NUMBER: _ClassVar[int]
    DEVICE_SOFTWARE_VERSION_CODE_FIELD_NUMBER: _ClassVar[int]
    DEVICE_SOFTWARE_VERSION_FIELD_NUMBER: _ClassVar[int]
    DEVICE_TYPE_FIELD_NUMBER: _ClassVar[int]
    ENABLED_SOFTWARE_FEATURES_FIELD_NUMBER: _ClassVar[int]
    ENROLLMENT_SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    GCM_REGISTRATION_ID_FIELD_NUMBER: _ClassVar[int]
    IS_SCREENLOCK_STATE_FLAKY_FIELD_NUMBER: _ClassVar[int]
    KEY_HANDLE_FIELD_NUMBER: _ClassVar[int]
    LOCALE_FIELD_NUMBER: _ClassVar[int]
    LONG_DEVICE_ID_FIELD_NUMBER: _ClassVar[int]
    MOBILE_DATA_SUPPORTED_FIELD_NUMBER: _ClassVar[int]
    NOTIFICATION_ENABLED_FIELD_NUMBER: _ClassVar[int]
    OAUTH_TOKEN_FIELD_NUMBER: _ClassVar[int]
    PIXEL_EXPERIENCE_FIELD_NUMBER: _ClassVar[int]
    SUPPORTED_SOFTWARE_FEATURES_FIELD_NUMBER: _ClassVar[int]
    TETHERING_SUPPORTED_FIELD_NUMBER: _ClassVar[int]
    USER_PUBLIC_KEY_FIELD_NUMBER: _ClassVar[int]
    USING_SECURE_SCREENLOCK_FIELD_NUMBER: _ClassVar[int]
    android_device_id: int
    apn_registration_id: bytes
    arc_plus_plus: bool
    auto_unlock_screenlock_enabled: bool
    auto_unlock_screenlock_supported: bool
    ble_radio_supported: bool
    bluetooth_mac_address: str
    bluetooth_radio_enabled: bool
    bluetooth_radio_supported: bool
    counter: int
    device_authzen_version: int
    device_display_diagonal_mils: int
    device_manufacturer: str
    device_master_key_hash: bytes
    device_model: str
    device_os_codename: str
    device_os_release: str
    device_os_version: str
    device_os_version_code: int
    device_software_package: str
    device_software_version: str
    device_software_version_code: int
    device_type: DeviceType
    enabled_software_features: _containers.RepeatedScalarFieldContainer[SoftwareFeature]
    enrollment_session_id: bytes
    gcm_registration_id: bytes
    is_screenlock_state_flaky: bool
    key_handle: bytes
    locale: str
    long_device_id: bytes
    mobile_data_supported: bool
    notification_enabled: bool
    oauth_token: str
    pixel_experience: bool
    supported_software_features: _containers.RepeatedScalarFieldContainer[SoftwareFeature]
    tethering_supported: bool
    user_public_key: bytes
    using_secure_screenlock: bool
    def __init__(self, android_device_id: _Optional[int] = ..., gcm_registration_id: _Optional[bytes] = ..., apn_registration_id: _Optional[bytes] = ..., notification_enabled: bool = ..., bluetooth_mac_address: _Optional[str] = ..., device_master_key_hash: _Optional[bytes] = ..., user_public_key: _Optional[bytes] = ..., device_model: _Optional[str] = ..., locale: _Optional[str] = ..., key_handle: _Optional[bytes] = ..., counter: _Optional[int] = ..., device_os_version: _Optional[str] = ..., device_os_version_code: _Optional[int] = ..., device_os_release: _Optional[str] = ..., device_os_codename: _Optional[str] = ..., device_software_version: _Optional[str] = ..., device_software_version_code: _Optional[int] = ..., device_software_package: _Optional[str] = ..., device_display_diagonal_mils: _Optional[int] = ..., device_authzen_version: _Optional[int] = ..., long_device_id: _Optional[bytes] = ..., device_manufacturer: _Optional[str] = ..., device_type: _Optional[_Union[DeviceType, str]] = ..., using_secure_screenlock: bool = ..., auto_unlock_screenlock_supported: bool = ..., auto_unlock_screenlock_enabled: bool = ..., bluetooth_radio_supported: bool = ..., bluetooth_radio_enabled: bool = ..., mobile_data_supported: bool = ..., tethering_supported: bool = ..., ble_radio_supported: bool = ..., pixel_experience: bool = ..., arc_plus_plus: bool = ..., is_screenlock_state_flaky: bool = ..., supported_software_features: _Optional[_Iterable[_Union[SoftwareFeature, str]]] = ..., enabled_software_features: _Optional[_Iterable[_Union[SoftwareFeature, str]]] = ..., enrollment_session_id: _Optional[bytes] = ..., oauth_token: _Optional[str] = ...) -> None: ...

class GcmMetadata(_message.Message):
    __slots__ = ["type", "version"]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    type: Type
    version: int
    def __init__(self, type: _Optional[_Union[Type, str]] = ..., version: _Optional[int] = ...) -> None: ...

class LoginNotificationInfo(_message.Message):
    __slots__ = ["creation_time", "email", "event_type", "host", "source"]
    CREATION_TIME_FIELD_NUMBER: _ClassVar[int]
    EMAIL_FIELD_NUMBER: _ClassVar[int]
    EVENT_TYPE_FIELD_NUMBER: _ClassVar[int]
    HOST_FIELD_NUMBER: _ClassVar[int]
    SOURCE_FIELD_NUMBER: _ClassVar[int]
    creation_time: int
    email: str
    event_type: str
    host: str
    source: str
    def __init__(self, creation_time: _Optional[int] = ..., email: _Optional[str] = ..., host: _Optional[str] = ..., source: _Optional[str] = ..., event_type: _Optional[str] = ...) -> None: ...

class Tickle(_message.Message):
    __slots__ = ["expiry_time"]
    EXPIRY_TIME_FIELD_NUMBER: _ClassVar[int]
    expiry_time: int
    def __init__(self, expiry_time: _Optional[int] = ...) -> None: ...

class AppleDeviceDiagonalMils(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []

class DeviceType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []

class SoftwareFeature(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []

class InvocationReason(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []

class Type(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
