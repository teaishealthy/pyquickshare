from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class CertificateInfoFrame(_message.Message):
    __slots__ = ["public_certificate"]
    PUBLIC_CERTIFICATE_FIELD_NUMBER: _ClassVar[int]
    public_certificate: _containers.RepeatedCompositeFieldContainer[PublicCertificate]
    def __init__(self, public_certificate: _Optional[_Iterable[_Union[PublicCertificate, _Mapping]]] = ...) -> None: ...

class ConnectionResponseFrame(_message.Message):
    __slots__ = ["status"]
    class Status(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = []
    ACCEPT: ConnectionResponseFrame.Status
    NOT_ENOUGH_SPACE: ConnectionResponseFrame.Status
    REJECT: ConnectionResponseFrame.Status
    STATUS_FIELD_NUMBER: _ClassVar[int]
    TIMED_OUT: ConnectionResponseFrame.Status
    UNKNOWN: ConnectionResponseFrame.Status
    UNSUPPORTED_ATTACHMENT_TYPE: ConnectionResponseFrame.Status
    status: ConnectionResponseFrame.Status
    def __init__(self, status: _Optional[_Union[ConnectionResponseFrame.Status, str]] = ...) -> None: ...

class FileMetadata(_message.Message):
    __slots__ = ["id", "mime_type", "name", "payload_id", "size", "type"]
    class Type(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = []
    APP: FileMetadata.Type
    AUDIO: FileMetadata.Type
    ID_FIELD_NUMBER: _ClassVar[int]
    IMAGE: FileMetadata.Type
    MIME_TYPE_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    PAYLOAD_ID_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    UNKNOWN: FileMetadata.Type
    VIDEO: FileMetadata.Type
    id: int
    mime_type: str
    name: str
    payload_id: int
    size: int
    type: FileMetadata.Type
    def __init__(self, name: _Optional[str] = ..., type: _Optional[_Union[FileMetadata.Type, str]] = ..., payload_id: _Optional[int] = ..., size: _Optional[int] = ..., mime_type: _Optional[str] = ..., id: _Optional[int] = ...) -> None: ...

class Frame(_message.Message):
    __slots__ = ["v1", "version"]
    class Version(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = []
    UNKNOWN_VERSION: Frame.Version
    V1: Frame.Version
    V1_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    v1: V1Frame
    version: Frame.Version
    def __init__(self, version: _Optional[_Union[Frame.Version, str]] = ..., v1: _Optional[_Union[V1Frame, _Mapping]] = ...) -> None: ...

class IntroductionFrame(_message.Message):
    __slots__ = ["file_metadata", "required_package", "text_metadata", "wifi_credentials_metadata"]
    FILE_METADATA_FIELD_NUMBER: _ClassVar[int]
    REQUIRED_PACKAGE_FIELD_NUMBER: _ClassVar[int]
    TEXT_METADATA_FIELD_NUMBER: _ClassVar[int]
    WIFI_CREDENTIALS_METADATA_FIELD_NUMBER: _ClassVar[int]
    file_metadata: _containers.RepeatedCompositeFieldContainer[FileMetadata]
    required_package: str
    text_metadata: _containers.RepeatedCompositeFieldContainer[TextMetadata]
    wifi_credentials_metadata: _containers.RepeatedCompositeFieldContainer[WifiCredentialsMetadata]
    def __init__(self, file_metadata: _Optional[_Iterable[_Union[FileMetadata, _Mapping]]] = ..., text_metadata: _Optional[_Iterable[_Union[TextMetadata, _Mapping]]] = ..., required_package: _Optional[str] = ..., wifi_credentials_metadata: _Optional[_Iterable[_Union[WifiCredentialsMetadata, _Mapping]]] = ...) -> None: ...

class PairedKeyEncryptionFrame(_message.Message):
    __slots__ = ["optional_signed_data", "secret_id_hash", "signed_data"]
    OPTIONAL_SIGNED_DATA_FIELD_NUMBER: _ClassVar[int]
    SECRET_ID_HASH_FIELD_NUMBER: _ClassVar[int]
    SIGNED_DATA_FIELD_NUMBER: _ClassVar[int]
    optional_signed_data: bytes
    secret_id_hash: bytes
    signed_data: bytes
    def __init__(self, signed_data: _Optional[bytes] = ..., secret_id_hash: _Optional[bytes] = ..., optional_signed_data: _Optional[bytes] = ...) -> None: ...

class PairedKeyResultFrame(_message.Message):
    __slots__ = ["status"]
    class Status(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = []
    FAIL: PairedKeyResultFrame.Status
    STATUS_FIELD_NUMBER: _ClassVar[int]
    SUCCESS: PairedKeyResultFrame.Status
    UNABLE: PairedKeyResultFrame.Status
    UNKNOWN: PairedKeyResultFrame.Status
    status: PairedKeyResultFrame.Status
    def __init__(self, status: _Optional[_Union[PairedKeyResultFrame.Status, str]] = ...) -> None: ...

class PublicCertificate(_message.Message):
    __slots__ = ["authenticity_key", "encrypted_metadata_bytes", "end_time", "metadata_encryption_key_tag", "public_key", "secret_id", "start_time"]
    AUTHENTICITY_KEY_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTED_METADATA_BYTES_FIELD_NUMBER: _ClassVar[int]
    END_TIME_FIELD_NUMBER: _ClassVar[int]
    METADATA_ENCRYPTION_KEY_TAG_FIELD_NUMBER: _ClassVar[int]
    PUBLIC_KEY_FIELD_NUMBER: _ClassVar[int]
    SECRET_ID_FIELD_NUMBER: _ClassVar[int]
    START_TIME_FIELD_NUMBER: _ClassVar[int]
    authenticity_key: bytes
    encrypted_metadata_bytes: bytes
    end_time: int
    metadata_encryption_key_tag: bytes
    public_key: bytes
    secret_id: bytes
    start_time: int
    def __init__(self, secret_id: _Optional[bytes] = ..., authenticity_key: _Optional[bytes] = ..., public_key: _Optional[bytes] = ..., start_time: _Optional[int] = ..., end_time: _Optional[int] = ..., encrypted_metadata_bytes: _Optional[bytes] = ..., metadata_encryption_key_tag: _Optional[bytes] = ...) -> None: ...

class TextMetadata(_message.Message):
    __slots__ = ["id", "payload_id", "size", "text_title", "type"]
    class Type(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = []
    ADDRESS: TextMetadata.Type
    ID_FIELD_NUMBER: _ClassVar[int]
    PAYLOAD_ID_FIELD_NUMBER: _ClassVar[int]
    PHONE_NUMBER: TextMetadata.Type
    SIZE_FIELD_NUMBER: _ClassVar[int]
    TEXT: TextMetadata.Type
    TEXT_TITLE_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    UNKNOWN: TextMetadata.Type
    URL: TextMetadata.Type
    id: int
    payload_id: int
    size: int
    text_title: str
    type: TextMetadata.Type
    def __init__(self, text_title: _Optional[str] = ..., type: _Optional[_Union[TextMetadata.Type, str]] = ..., payload_id: _Optional[int] = ..., size: _Optional[int] = ..., id: _Optional[int] = ...) -> None: ...

class V1Frame(_message.Message):
    __slots__ = ["certificate_info", "connection_response", "introduction", "paired_key_encryption", "paired_key_result", "type"]
    class FrameType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = []
    CANCEL: V1Frame.FrameType
    CERTIFICATE_INFO: V1Frame.FrameType
    CERTIFICATE_INFO_FIELD_NUMBER: _ClassVar[int]
    CONNECTION_RESPONSE_FIELD_NUMBER: _ClassVar[int]
    INTRODUCTION: V1Frame.FrameType
    INTRODUCTION_FIELD_NUMBER: _ClassVar[int]
    PAIRED_KEY_ENCRYPTION: V1Frame.FrameType
    PAIRED_KEY_ENCRYPTION_FIELD_NUMBER: _ClassVar[int]
    PAIRED_KEY_RESULT: V1Frame.FrameType
    PAIRED_KEY_RESULT_FIELD_NUMBER: _ClassVar[int]
    RESPONSE: V1Frame.FrameType
    TYPE_FIELD_NUMBER: _ClassVar[int]
    UNKNOWN_FRAME_TYPE: V1Frame.FrameType
    certificate_info: CertificateInfoFrame
    connection_response: ConnectionResponseFrame
    introduction: IntroductionFrame
    paired_key_encryption: PairedKeyEncryptionFrame
    paired_key_result: PairedKeyResultFrame
    type: V1Frame.FrameType
    def __init__(self, type: _Optional[_Union[V1Frame.FrameType, str]] = ..., introduction: _Optional[_Union[IntroductionFrame, _Mapping]] = ..., connection_response: _Optional[_Union[ConnectionResponseFrame, _Mapping]] = ..., paired_key_encryption: _Optional[_Union[PairedKeyEncryptionFrame, _Mapping]] = ..., paired_key_result: _Optional[_Union[PairedKeyResultFrame, _Mapping]] = ..., certificate_info: _Optional[_Union[CertificateInfoFrame, _Mapping]] = ...) -> None: ...

class WifiCredentials(_message.Message):
    __slots__ = ["hidden_ssid", "password"]
    HIDDEN_SSID_FIELD_NUMBER: _ClassVar[int]
    PASSWORD_FIELD_NUMBER: _ClassVar[int]
    hidden_ssid: bool
    password: str
    def __init__(self, password: _Optional[str] = ..., hidden_ssid: bool = ...) -> None: ...

class WifiCredentialsMetadata(_message.Message):
    __slots__ = ["id", "payload_id", "security_type", "ssid"]
    class SecurityType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = []
    ID_FIELD_NUMBER: _ClassVar[int]
    OPEN: WifiCredentialsMetadata.SecurityType
    PAYLOAD_ID_FIELD_NUMBER: _ClassVar[int]
    SECURITY_TYPE_FIELD_NUMBER: _ClassVar[int]
    SSID_FIELD_NUMBER: _ClassVar[int]
    UNKNOWN_SECURITY_TYPE: WifiCredentialsMetadata.SecurityType
    WEP: WifiCredentialsMetadata.SecurityType
    WPA_PSK: WifiCredentialsMetadata.SecurityType
    id: int
    payload_id: int
    security_type: WifiCredentialsMetadata.SecurityType
    ssid: str
    def __init__(self, ssid: _Optional[str] = ..., security_type: _Optional[_Union[WifiCredentialsMetadata.SecurityType, str]] = ..., payload_id: _Optional[int] = ..., id: _Optional[int] = ...) -> None: ...
