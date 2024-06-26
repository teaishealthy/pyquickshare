import securemessage_pb2 as _securemessage_pb2
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor
ED_25519: Curve

class DeviceToDeviceMessage(_message.Message):
    __slots__ = ["message", "sequence_number"]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    SEQUENCE_NUMBER_FIELD_NUMBER: _ClassVar[int]
    message: bytes
    sequence_number: int
    def __init__(self, message: _Optional[bytes] = ..., sequence_number: _Optional[int] = ...) -> None: ...

class EcPoint(_message.Message):
    __slots__ = ["curve", "x", "y"]
    CURVE_FIELD_NUMBER: _ClassVar[int]
    X_FIELD_NUMBER: _ClassVar[int]
    Y_FIELD_NUMBER: _ClassVar[int]
    curve: Curve
    x: bytes
    y: bytes
    def __init__(self, curve: _Optional[_Union[Curve, str]] = ..., x: _Optional[bytes] = ..., y: _Optional[bytes] = ...) -> None: ...

class InitiatorHello(_message.Message):
    __slots__ = ["protocol_version", "public_dh_key"]
    PROTOCOL_VERSION_FIELD_NUMBER: _ClassVar[int]
    PUBLIC_DH_KEY_FIELD_NUMBER: _ClassVar[int]
    protocol_version: int
    public_dh_key: _securemessage_pb2.GenericPublicKey
    def __init__(self, public_dh_key: _Optional[_Union[_securemessage_pb2.GenericPublicKey, _Mapping]] = ..., protocol_version: _Optional[int] = ...) -> None: ...

class ResponderHello(_message.Message):
    __slots__ = ["protocol_version", "public_dh_key"]
    PROTOCOL_VERSION_FIELD_NUMBER: _ClassVar[int]
    PUBLIC_DH_KEY_FIELD_NUMBER: _ClassVar[int]
    protocol_version: int
    public_dh_key: _securemessage_pb2.GenericPublicKey
    def __init__(self, public_dh_key: _Optional[_Union[_securemessage_pb2.GenericPublicKey, _Mapping]] = ..., protocol_version: _Optional[int] = ...) -> None: ...

class SpakeHandshakeMessage(_message.Message):
    __slots__ = ["ec_point", "flow_number", "hash_value", "payload"]
    EC_POINT_FIELD_NUMBER: _ClassVar[int]
    FLOW_NUMBER_FIELD_NUMBER: _ClassVar[int]
    HASH_VALUE_FIELD_NUMBER: _ClassVar[int]
    PAYLOAD_FIELD_NUMBER: _ClassVar[int]
    ec_point: EcPoint
    flow_number: int
    hash_value: bytes
    payload: bytes
    def __init__(self, flow_number: _Optional[int] = ..., ec_point: _Optional[_Union[EcPoint, _Mapping]] = ..., hash_value: _Optional[bytes] = ..., payload: _Optional[bytes] = ...) -> None: ...

class Curve(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
