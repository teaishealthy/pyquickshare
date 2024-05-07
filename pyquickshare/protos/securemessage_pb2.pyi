from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Mapping as _Mapping, Optional as _Optional, Union as _Union

AES_256_CBC: EncScheme
DESCRIPTOR: _descriptor.FileDescriptor
DH2048_MODP: PublicKeyType
ECDSA_P256_SHA256: SigScheme
EC_P256: PublicKeyType
HMAC_SHA256: SigScheme
NONE: EncScheme
RSA2048: PublicKeyType
RSA2048_SHA256: SigScheme

class DhPublicKey(_message.Message):
    __slots__ = ["y"]
    Y_FIELD_NUMBER: _ClassVar[int]
    y: bytes
    def __init__(self, y: _Optional[bytes] = ...) -> None: ...

class EcP256PublicKey(_message.Message):
    __slots__ = ["x", "y"]
    X_FIELD_NUMBER: _ClassVar[int]
    Y_FIELD_NUMBER: _ClassVar[int]
    x: bytes
    y: bytes
    def __init__(self, x: _Optional[bytes] = ..., y: _Optional[bytes] = ...) -> None: ...

class GenericPublicKey(_message.Message):
    __slots__ = ["dh2048_public_key", "ec_p256_public_key", "rsa2048_public_key", "type"]
    DH2048_PUBLIC_KEY_FIELD_NUMBER: _ClassVar[int]
    EC_P256_PUBLIC_KEY_FIELD_NUMBER: _ClassVar[int]
    RSA2048_PUBLIC_KEY_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    dh2048_public_key: DhPublicKey
    ec_p256_public_key: EcP256PublicKey
    rsa2048_public_key: SimpleRsaPublicKey
    type: PublicKeyType
    def __init__(self, type: _Optional[_Union[PublicKeyType, str]] = ..., ec_p256_public_key: _Optional[_Union[EcP256PublicKey, _Mapping]] = ..., rsa2048_public_key: _Optional[_Union[SimpleRsaPublicKey, _Mapping]] = ..., dh2048_public_key: _Optional[_Union[DhPublicKey, _Mapping]] = ...) -> None: ...

class Header(_message.Message):
    __slots__ = ["associated_data_length", "decryption_key_id", "encryption_scheme", "iv", "public_metadata", "signature_scheme", "verification_key_id"]
    ASSOCIATED_DATA_LENGTH_FIELD_NUMBER: _ClassVar[int]
    DECRYPTION_KEY_ID_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTION_SCHEME_FIELD_NUMBER: _ClassVar[int]
    IV_FIELD_NUMBER: _ClassVar[int]
    PUBLIC_METADATA_FIELD_NUMBER: _ClassVar[int]
    SIGNATURE_SCHEME_FIELD_NUMBER: _ClassVar[int]
    VERIFICATION_KEY_ID_FIELD_NUMBER: _ClassVar[int]
    associated_data_length: int
    decryption_key_id: bytes
    encryption_scheme: EncScheme
    iv: bytes
    public_metadata: bytes
    signature_scheme: SigScheme
    verification_key_id: bytes
    def __init__(self, signature_scheme: _Optional[_Union[SigScheme, str]] = ..., encryption_scheme: _Optional[_Union[EncScheme, str]] = ..., verification_key_id: _Optional[bytes] = ..., decryption_key_id: _Optional[bytes] = ..., iv: _Optional[bytes] = ..., public_metadata: _Optional[bytes] = ..., associated_data_length: _Optional[int] = ...) -> None: ...

class HeaderAndBody(_message.Message):
    __slots__ = ["body", "header"]
    BODY_FIELD_NUMBER: _ClassVar[int]
    HEADER_FIELD_NUMBER: _ClassVar[int]
    body: bytes
    header: Header
    def __init__(self, header: _Optional[_Union[Header, _Mapping]] = ..., body: _Optional[bytes] = ...) -> None: ...

class HeaderAndBodyInternal(_message.Message):
    __slots__ = ["body", "header"]
    BODY_FIELD_NUMBER: _ClassVar[int]
    HEADER_FIELD_NUMBER: _ClassVar[int]
    body: bytes
    header: bytes
    def __init__(self, header: _Optional[bytes] = ..., body: _Optional[bytes] = ...) -> None: ...

class SecureMessage(_message.Message):
    __slots__ = ["header_and_body", "signature"]
    HEADER_AND_BODY_FIELD_NUMBER: _ClassVar[int]
    SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    header_and_body: bytes
    signature: bytes
    def __init__(self, header_and_body: _Optional[bytes] = ..., signature: _Optional[bytes] = ...) -> None: ...

class SimpleRsaPublicKey(_message.Message):
    __slots__ = ["e", "n"]
    E_FIELD_NUMBER: _ClassVar[int]
    N_FIELD_NUMBER: _ClassVar[int]
    e: int
    n: bytes
    def __init__(self, n: _Optional[bytes] = ..., e: _Optional[int] = ...) -> None: ...

class SigScheme(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []

class EncScheme(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []

class PublicKeyType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
