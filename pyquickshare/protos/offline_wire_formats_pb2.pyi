from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class OfflineFrame(_message.Message):
    __slots__ = ("version", "v1")
    class Version(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNKNOWN_VERSION: _ClassVar[OfflineFrame.Version]
        V1: _ClassVar[OfflineFrame.Version]
    UNKNOWN_VERSION: OfflineFrame.Version
    V1: OfflineFrame.Version
    VERSION_FIELD_NUMBER: _ClassVar[int]
    V1_FIELD_NUMBER: _ClassVar[int]
    version: OfflineFrame.Version
    v1: V1Frame
    def __init__(self, version: _Optional[_Union[OfflineFrame.Version, str]] = ..., v1: _Optional[_Union[V1Frame, _Mapping]] = ...) -> None: ...

class V1Frame(_message.Message):
    __slots__ = ("type", "connection_request", "connection_response", "payload_transfer", "bandwidth_upgrade_negotiation", "keep_alive", "disconnection", "paired_key_encryption")
    class FrameType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNKNOWN_FRAME_TYPE: _ClassVar[V1Frame.FrameType]
        CONNECTION_REQUEST: _ClassVar[V1Frame.FrameType]
        CONNECTION_RESPONSE: _ClassVar[V1Frame.FrameType]
        PAYLOAD_TRANSFER: _ClassVar[V1Frame.FrameType]
        BANDWIDTH_UPGRADE_NEGOTIATION: _ClassVar[V1Frame.FrameType]
        KEEP_ALIVE: _ClassVar[V1Frame.FrameType]
        DISCONNECTION: _ClassVar[V1Frame.FrameType]
        PAIRED_KEY_ENCRYPTION: _ClassVar[V1Frame.FrameType]
    UNKNOWN_FRAME_TYPE: V1Frame.FrameType
    CONNECTION_REQUEST: V1Frame.FrameType
    CONNECTION_RESPONSE: V1Frame.FrameType
    PAYLOAD_TRANSFER: V1Frame.FrameType
    BANDWIDTH_UPGRADE_NEGOTIATION: V1Frame.FrameType
    KEEP_ALIVE: V1Frame.FrameType
    DISCONNECTION: V1Frame.FrameType
    PAIRED_KEY_ENCRYPTION: V1Frame.FrameType
    TYPE_FIELD_NUMBER: _ClassVar[int]
    CONNECTION_REQUEST_FIELD_NUMBER: _ClassVar[int]
    CONNECTION_RESPONSE_FIELD_NUMBER: _ClassVar[int]
    PAYLOAD_TRANSFER_FIELD_NUMBER: _ClassVar[int]
    BANDWIDTH_UPGRADE_NEGOTIATION_FIELD_NUMBER: _ClassVar[int]
    KEEP_ALIVE_FIELD_NUMBER: _ClassVar[int]
    DISCONNECTION_FIELD_NUMBER: _ClassVar[int]
    PAIRED_KEY_ENCRYPTION_FIELD_NUMBER: _ClassVar[int]
    type: V1Frame.FrameType
    connection_request: ConnectionRequestFrame
    connection_response: ConnectionResponseFrame
    payload_transfer: PayloadTransferFrame
    bandwidth_upgrade_negotiation: BandwidthUpgradeNegotiationFrame
    keep_alive: KeepAliveFrame
    disconnection: DisconnectionFrame
    paired_key_encryption: PairedKeyEncryptionFrame
    def __init__(self, type: _Optional[_Union[V1Frame.FrameType, str]] = ..., connection_request: _Optional[_Union[ConnectionRequestFrame, _Mapping]] = ..., connection_response: _Optional[_Union[ConnectionResponseFrame, _Mapping]] = ..., payload_transfer: _Optional[_Union[PayloadTransferFrame, _Mapping]] = ..., bandwidth_upgrade_negotiation: _Optional[_Union[BandwidthUpgradeNegotiationFrame, _Mapping]] = ..., keep_alive: _Optional[_Union[KeepAliveFrame, _Mapping]] = ..., disconnection: _Optional[_Union[DisconnectionFrame, _Mapping]] = ..., paired_key_encryption: _Optional[_Union[PairedKeyEncryptionFrame, _Mapping]] = ...) -> None: ...

class ConnectionRequestFrame(_message.Message):
    __slots__ = ("endpoint_id", "endpoint_name", "handshake_data", "nonce", "mediums", "endpoint_info", "medium_metadata", "keep_alive_interval_millis", "keep_alive_timeout_millis", "device_type", "device_info")
    class Medium(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNKNOWN_MEDIUM: _ClassVar[ConnectionRequestFrame.Medium]
        MDNS: _ClassVar[ConnectionRequestFrame.Medium]
        BLUETOOTH: _ClassVar[ConnectionRequestFrame.Medium]
        WIFI_HOTSPOT: _ClassVar[ConnectionRequestFrame.Medium]
        BLE: _ClassVar[ConnectionRequestFrame.Medium]
        WIFI_LAN: _ClassVar[ConnectionRequestFrame.Medium]
        WIFI_AWARE: _ClassVar[ConnectionRequestFrame.Medium]
        NFC: _ClassVar[ConnectionRequestFrame.Medium]
        WIFI_DIRECT: _ClassVar[ConnectionRequestFrame.Medium]
        WEB_RTC: _ClassVar[ConnectionRequestFrame.Medium]
        BLE_L2CAP: _ClassVar[ConnectionRequestFrame.Medium]
        USB: _ClassVar[ConnectionRequestFrame.Medium]
    UNKNOWN_MEDIUM: ConnectionRequestFrame.Medium
    MDNS: ConnectionRequestFrame.Medium
    BLUETOOTH: ConnectionRequestFrame.Medium
    WIFI_HOTSPOT: ConnectionRequestFrame.Medium
    BLE: ConnectionRequestFrame.Medium
    WIFI_LAN: ConnectionRequestFrame.Medium
    WIFI_AWARE: ConnectionRequestFrame.Medium
    NFC: ConnectionRequestFrame.Medium
    WIFI_DIRECT: ConnectionRequestFrame.Medium
    WEB_RTC: ConnectionRequestFrame.Medium
    BLE_L2CAP: ConnectionRequestFrame.Medium
    USB: ConnectionRequestFrame.Medium
    ENDPOINT_ID_FIELD_NUMBER: _ClassVar[int]
    ENDPOINT_NAME_FIELD_NUMBER: _ClassVar[int]
    HANDSHAKE_DATA_FIELD_NUMBER: _ClassVar[int]
    NONCE_FIELD_NUMBER: _ClassVar[int]
    MEDIUMS_FIELD_NUMBER: _ClassVar[int]
    ENDPOINT_INFO_FIELD_NUMBER: _ClassVar[int]
    MEDIUM_METADATA_FIELD_NUMBER: _ClassVar[int]
    KEEP_ALIVE_INTERVAL_MILLIS_FIELD_NUMBER: _ClassVar[int]
    KEEP_ALIVE_TIMEOUT_MILLIS_FIELD_NUMBER: _ClassVar[int]
    DEVICE_TYPE_FIELD_NUMBER: _ClassVar[int]
    DEVICE_INFO_FIELD_NUMBER: _ClassVar[int]
    endpoint_id: str
    endpoint_name: str
    handshake_data: bytes
    nonce: int
    mediums: _containers.RepeatedScalarFieldContainer[ConnectionRequestFrame.Medium]
    endpoint_info: bytes
    medium_metadata: MediumMetadata
    keep_alive_interval_millis: int
    keep_alive_timeout_millis: int
    device_type: int
    device_info: bytes
    def __init__(self, endpoint_id: _Optional[str] = ..., endpoint_name: _Optional[str] = ..., handshake_data: _Optional[bytes] = ..., nonce: _Optional[int] = ..., mediums: _Optional[_Iterable[_Union[ConnectionRequestFrame.Medium, str]]] = ..., endpoint_info: _Optional[bytes] = ..., medium_metadata: _Optional[_Union[MediumMetadata, _Mapping]] = ..., keep_alive_interval_millis: _Optional[int] = ..., keep_alive_timeout_millis: _Optional[int] = ..., device_type: _Optional[int] = ..., device_info: _Optional[bytes] = ...) -> None: ...

class ConnectionResponseFrame(_message.Message):
    __slots__ = ("status", "handshake_data", "response", "os_info", "multiplex_socket_bitmask", "nearby_connections_version")
    class ResponseStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNKNOWN_RESPONSE_STATUS: _ClassVar[ConnectionResponseFrame.ResponseStatus]
        ACCEPT: _ClassVar[ConnectionResponseFrame.ResponseStatus]
        REJECT: _ClassVar[ConnectionResponseFrame.ResponseStatus]
    UNKNOWN_RESPONSE_STATUS: ConnectionResponseFrame.ResponseStatus
    ACCEPT: ConnectionResponseFrame.ResponseStatus
    REJECT: ConnectionResponseFrame.ResponseStatus
    STATUS_FIELD_NUMBER: _ClassVar[int]
    HANDSHAKE_DATA_FIELD_NUMBER: _ClassVar[int]
    RESPONSE_FIELD_NUMBER: _ClassVar[int]
    OS_INFO_FIELD_NUMBER: _ClassVar[int]
    MULTIPLEX_SOCKET_BITMASK_FIELD_NUMBER: _ClassVar[int]
    NEARBY_CONNECTIONS_VERSION_FIELD_NUMBER: _ClassVar[int]
    status: int
    handshake_data: bytes
    response: ConnectionResponseFrame.ResponseStatus
    os_info: OsInfo
    multiplex_socket_bitmask: int
    nearby_connections_version: int
    def __init__(self, status: _Optional[int] = ..., handshake_data: _Optional[bytes] = ..., response: _Optional[_Union[ConnectionResponseFrame.ResponseStatus, str]] = ..., os_info: _Optional[_Union[OsInfo, _Mapping]] = ..., multiplex_socket_bitmask: _Optional[int] = ..., nearby_connections_version: _Optional[int] = ...) -> None: ...

class PayloadTransferFrame(_message.Message):
    __slots__ = ("packet_type", "payload_header", "payload_chunk", "control_message")
    class PacketType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNKNOWN_PACKET_TYPE: _ClassVar[PayloadTransferFrame.PacketType]
        DATA: _ClassVar[PayloadTransferFrame.PacketType]
        CONTROL: _ClassVar[PayloadTransferFrame.PacketType]
    UNKNOWN_PACKET_TYPE: PayloadTransferFrame.PacketType
    DATA: PayloadTransferFrame.PacketType
    CONTROL: PayloadTransferFrame.PacketType
    class PayloadHeader(_message.Message):
        __slots__ = ("id", "type", "total_size", "is_sensitive", "file_name", "parent_folder")
        class PayloadType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            UNKNOWN_PAYLOAD_TYPE: _ClassVar[PayloadTransferFrame.PayloadHeader.PayloadType]
            BYTES: _ClassVar[PayloadTransferFrame.PayloadHeader.PayloadType]
            FILE: _ClassVar[PayloadTransferFrame.PayloadHeader.PayloadType]
            STREAM: _ClassVar[PayloadTransferFrame.PayloadHeader.PayloadType]
        UNKNOWN_PAYLOAD_TYPE: PayloadTransferFrame.PayloadHeader.PayloadType
        BYTES: PayloadTransferFrame.PayloadHeader.PayloadType
        FILE: PayloadTransferFrame.PayloadHeader.PayloadType
        STREAM: PayloadTransferFrame.PayloadHeader.PayloadType
        ID_FIELD_NUMBER: _ClassVar[int]
        TYPE_FIELD_NUMBER: _ClassVar[int]
        TOTAL_SIZE_FIELD_NUMBER: _ClassVar[int]
        IS_SENSITIVE_FIELD_NUMBER: _ClassVar[int]
        FILE_NAME_FIELD_NUMBER: _ClassVar[int]
        PARENT_FOLDER_FIELD_NUMBER: _ClassVar[int]
        id: int
        type: PayloadTransferFrame.PayloadHeader.PayloadType
        total_size: int
        is_sensitive: bool
        file_name: str
        parent_folder: str
        def __init__(self, id: _Optional[int] = ..., type: _Optional[_Union[PayloadTransferFrame.PayloadHeader.PayloadType, str]] = ..., total_size: _Optional[int] = ..., is_sensitive: _Optional[bool] = ..., file_name: _Optional[str] = ..., parent_folder: _Optional[str] = ...) -> None: ...
    class PayloadChunk(_message.Message):
        __slots__ = ("flags", "offset", "body")
        class Flags(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            LAST_CHUNK: _ClassVar[PayloadTransferFrame.PayloadChunk.Flags]
        LAST_CHUNK: PayloadTransferFrame.PayloadChunk.Flags
        FLAGS_FIELD_NUMBER: _ClassVar[int]
        OFFSET_FIELD_NUMBER: _ClassVar[int]
        BODY_FIELD_NUMBER: _ClassVar[int]
        flags: int
        offset: int
        body: bytes
        def __init__(self, flags: _Optional[int] = ..., offset: _Optional[int] = ..., body: _Optional[bytes] = ...) -> None: ...
    class ControlMessage(_message.Message):
        __slots__ = ("event", "offset")
        class EventType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            UNKNOWN_EVENT_TYPE: _ClassVar[PayloadTransferFrame.ControlMessage.EventType]
            PAYLOAD_ERROR: _ClassVar[PayloadTransferFrame.ControlMessage.EventType]
            PAYLOAD_CANCELED: _ClassVar[PayloadTransferFrame.ControlMessage.EventType]
            PAYLOAD_RECEIVED_ACK: _ClassVar[PayloadTransferFrame.ControlMessage.EventType]
        UNKNOWN_EVENT_TYPE: PayloadTransferFrame.ControlMessage.EventType
        PAYLOAD_ERROR: PayloadTransferFrame.ControlMessage.EventType
        PAYLOAD_CANCELED: PayloadTransferFrame.ControlMessage.EventType
        PAYLOAD_RECEIVED_ACK: PayloadTransferFrame.ControlMessage.EventType
        EVENT_FIELD_NUMBER: _ClassVar[int]
        OFFSET_FIELD_NUMBER: _ClassVar[int]
        event: PayloadTransferFrame.ControlMessage.EventType
        offset: int
        def __init__(self, event: _Optional[_Union[PayloadTransferFrame.ControlMessage.EventType, str]] = ..., offset: _Optional[int] = ...) -> None: ...
    PACKET_TYPE_FIELD_NUMBER: _ClassVar[int]
    PAYLOAD_HEADER_FIELD_NUMBER: _ClassVar[int]
    PAYLOAD_CHUNK_FIELD_NUMBER: _ClassVar[int]
    CONTROL_MESSAGE_FIELD_NUMBER: _ClassVar[int]
    packet_type: PayloadTransferFrame.PacketType
    payload_header: PayloadTransferFrame.PayloadHeader
    payload_chunk: PayloadTransferFrame.PayloadChunk
    control_message: PayloadTransferFrame.ControlMessage
    def __init__(self, packet_type: _Optional[_Union[PayloadTransferFrame.PacketType, str]] = ..., payload_header: _Optional[_Union[PayloadTransferFrame.PayloadHeader, _Mapping]] = ..., payload_chunk: _Optional[_Union[PayloadTransferFrame.PayloadChunk, _Mapping]] = ..., control_message: _Optional[_Union[PayloadTransferFrame.ControlMessage, _Mapping]] = ...) -> None: ...

class BandwidthUpgradeNegotiationFrame(_message.Message):
    __slots__ = ("event_type", "upgrade_path_info", "client_introduction", "client_introduction_ack")
    class EventType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNKNOWN_EVENT_TYPE: _ClassVar[BandwidthUpgradeNegotiationFrame.EventType]
        UPGRADE_PATH_AVAILABLE: _ClassVar[BandwidthUpgradeNegotiationFrame.EventType]
        LAST_WRITE_TO_PRIOR_CHANNEL: _ClassVar[BandwidthUpgradeNegotiationFrame.EventType]
        SAFE_TO_CLOSE_PRIOR_CHANNEL: _ClassVar[BandwidthUpgradeNegotiationFrame.EventType]
        CLIENT_INTRODUCTION: _ClassVar[BandwidthUpgradeNegotiationFrame.EventType]
        UPGRADE_FAILURE: _ClassVar[BandwidthUpgradeNegotiationFrame.EventType]
        CLIENT_INTRODUCTION_ACK: _ClassVar[BandwidthUpgradeNegotiationFrame.EventType]
    UNKNOWN_EVENT_TYPE: BandwidthUpgradeNegotiationFrame.EventType
    UPGRADE_PATH_AVAILABLE: BandwidthUpgradeNegotiationFrame.EventType
    LAST_WRITE_TO_PRIOR_CHANNEL: BandwidthUpgradeNegotiationFrame.EventType
    SAFE_TO_CLOSE_PRIOR_CHANNEL: BandwidthUpgradeNegotiationFrame.EventType
    CLIENT_INTRODUCTION: BandwidthUpgradeNegotiationFrame.EventType
    UPGRADE_FAILURE: BandwidthUpgradeNegotiationFrame.EventType
    CLIENT_INTRODUCTION_ACK: BandwidthUpgradeNegotiationFrame.EventType
    class UpgradePathInfo(_message.Message):
        __slots__ = ("medium", "wifi_hotspot_credentials", "wifi_lan_socket", "bluetooth_credentials", "wifi_aware_credentials", "wifi_direct_credentials", "web_rtc_credentials", "supports_disabling_encryption", "supports_client_introduction_ack")
        class Medium(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            UNKNOWN_MEDIUM: _ClassVar[BandwidthUpgradeNegotiationFrame.UpgradePathInfo.Medium]
            MDNS: _ClassVar[BandwidthUpgradeNegotiationFrame.UpgradePathInfo.Medium]
            BLUETOOTH: _ClassVar[BandwidthUpgradeNegotiationFrame.UpgradePathInfo.Medium]
            WIFI_HOTSPOT: _ClassVar[BandwidthUpgradeNegotiationFrame.UpgradePathInfo.Medium]
            BLE: _ClassVar[BandwidthUpgradeNegotiationFrame.UpgradePathInfo.Medium]
            WIFI_LAN: _ClassVar[BandwidthUpgradeNegotiationFrame.UpgradePathInfo.Medium]
            WIFI_AWARE: _ClassVar[BandwidthUpgradeNegotiationFrame.UpgradePathInfo.Medium]
            NFC: _ClassVar[BandwidthUpgradeNegotiationFrame.UpgradePathInfo.Medium]
            WIFI_DIRECT: _ClassVar[BandwidthUpgradeNegotiationFrame.UpgradePathInfo.Medium]
            WEB_RTC: _ClassVar[BandwidthUpgradeNegotiationFrame.UpgradePathInfo.Medium]
            USB: _ClassVar[BandwidthUpgradeNegotiationFrame.UpgradePathInfo.Medium]
        UNKNOWN_MEDIUM: BandwidthUpgradeNegotiationFrame.UpgradePathInfo.Medium
        MDNS: BandwidthUpgradeNegotiationFrame.UpgradePathInfo.Medium
        BLUETOOTH: BandwidthUpgradeNegotiationFrame.UpgradePathInfo.Medium
        WIFI_HOTSPOT: BandwidthUpgradeNegotiationFrame.UpgradePathInfo.Medium
        BLE: BandwidthUpgradeNegotiationFrame.UpgradePathInfo.Medium
        WIFI_LAN: BandwidthUpgradeNegotiationFrame.UpgradePathInfo.Medium
        WIFI_AWARE: BandwidthUpgradeNegotiationFrame.UpgradePathInfo.Medium
        NFC: BandwidthUpgradeNegotiationFrame.UpgradePathInfo.Medium
        WIFI_DIRECT: BandwidthUpgradeNegotiationFrame.UpgradePathInfo.Medium
        WEB_RTC: BandwidthUpgradeNegotiationFrame.UpgradePathInfo.Medium
        USB: BandwidthUpgradeNegotiationFrame.UpgradePathInfo.Medium
        class WifiHotspotCredentials(_message.Message):
            __slots__ = ("ssid", "password", "port", "gateway", "frequency")
            SSID_FIELD_NUMBER: _ClassVar[int]
            PASSWORD_FIELD_NUMBER: _ClassVar[int]
            PORT_FIELD_NUMBER: _ClassVar[int]
            GATEWAY_FIELD_NUMBER: _ClassVar[int]
            FREQUENCY_FIELD_NUMBER: _ClassVar[int]
            ssid: str
            password: str
            port: int
            gateway: str
            frequency: int
            def __init__(self, ssid: _Optional[str] = ..., password: _Optional[str] = ..., port: _Optional[int] = ..., gateway: _Optional[str] = ..., frequency: _Optional[int] = ...) -> None: ...
        class WifiLanSocket(_message.Message):
            __slots__ = ("ip_address", "wifi_port")
            IP_ADDRESS_FIELD_NUMBER: _ClassVar[int]
            WIFI_PORT_FIELD_NUMBER: _ClassVar[int]
            ip_address: bytes
            wifi_port: int
            def __init__(self, ip_address: _Optional[bytes] = ..., wifi_port: _Optional[int] = ...) -> None: ...
        class BluetoothCredentials(_message.Message):
            __slots__ = ("service_name", "mac_address")
            SERVICE_NAME_FIELD_NUMBER: _ClassVar[int]
            MAC_ADDRESS_FIELD_NUMBER: _ClassVar[int]
            service_name: str
            mac_address: str
            def __init__(self, service_name: _Optional[str] = ..., mac_address: _Optional[str] = ...) -> None: ...
        class WifiAwareCredentials(_message.Message):
            __slots__ = ("service_id", "service_info", "password")
            SERVICE_ID_FIELD_NUMBER: _ClassVar[int]
            SERVICE_INFO_FIELD_NUMBER: _ClassVar[int]
            PASSWORD_FIELD_NUMBER: _ClassVar[int]
            service_id: str
            service_info: bytes
            password: str
            def __init__(self, service_id: _Optional[str] = ..., service_info: _Optional[bytes] = ..., password: _Optional[str] = ...) -> None: ...
        class WifiDirectCredentials(_message.Message):
            __slots__ = ("ssid", "password", "port", "frequency", "gateway")
            SSID_FIELD_NUMBER: _ClassVar[int]
            PASSWORD_FIELD_NUMBER: _ClassVar[int]
            PORT_FIELD_NUMBER: _ClassVar[int]
            FREQUENCY_FIELD_NUMBER: _ClassVar[int]
            GATEWAY_FIELD_NUMBER: _ClassVar[int]
            ssid: str
            password: str
            port: int
            frequency: int
            gateway: str
            def __init__(self, ssid: _Optional[str] = ..., password: _Optional[str] = ..., port: _Optional[int] = ..., frequency: _Optional[int] = ..., gateway: _Optional[str] = ...) -> None: ...
        class WebRtcCredentials(_message.Message):
            __slots__ = ("peer_id", "location_hint")
            PEER_ID_FIELD_NUMBER: _ClassVar[int]
            LOCATION_HINT_FIELD_NUMBER: _ClassVar[int]
            peer_id: str
            location_hint: LocationHint
            def __init__(self, peer_id: _Optional[str] = ..., location_hint: _Optional[_Union[LocationHint, _Mapping]] = ...) -> None: ...
        MEDIUM_FIELD_NUMBER: _ClassVar[int]
        WIFI_HOTSPOT_CREDENTIALS_FIELD_NUMBER: _ClassVar[int]
        WIFI_LAN_SOCKET_FIELD_NUMBER: _ClassVar[int]
        BLUETOOTH_CREDENTIALS_FIELD_NUMBER: _ClassVar[int]
        WIFI_AWARE_CREDENTIALS_FIELD_NUMBER: _ClassVar[int]
        WIFI_DIRECT_CREDENTIALS_FIELD_NUMBER: _ClassVar[int]
        WEB_RTC_CREDENTIALS_FIELD_NUMBER: _ClassVar[int]
        SUPPORTS_DISABLING_ENCRYPTION_FIELD_NUMBER: _ClassVar[int]
        SUPPORTS_CLIENT_INTRODUCTION_ACK_FIELD_NUMBER: _ClassVar[int]
        medium: BandwidthUpgradeNegotiationFrame.UpgradePathInfo.Medium
        wifi_hotspot_credentials: BandwidthUpgradeNegotiationFrame.UpgradePathInfo.WifiHotspotCredentials
        wifi_lan_socket: BandwidthUpgradeNegotiationFrame.UpgradePathInfo.WifiLanSocket
        bluetooth_credentials: BandwidthUpgradeNegotiationFrame.UpgradePathInfo.BluetoothCredentials
        wifi_aware_credentials: BandwidthUpgradeNegotiationFrame.UpgradePathInfo.WifiAwareCredentials
        wifi_direct_credentials: BandwidthUpgradeNegotiationFrame.UpgradePathInfo.WifiDirectCredentials
        web_rtc_credentials: BandwidthUpgradeNegotiationFrame.UpgradePathInfo.WebRtcCredentials
        supports_disabling_encryption: bool
        supports_client_introduction_ack: bool
        def __init__(self, medium: _Optional[_Union[BandwidthUpgradeNegotiationFrame.UpgradePathInfo.Medium, str]] = ..., wifi_hotspot_credentials: _Optional[_Union[BandwidthUpgradeNegotiationFrame.UpgradePathInfo.WifiHotspotCredentials, _Mapping]] = ..., wifi_lan_socket: _Optional[_Union[BandwidthUpgradeNegotiationFrame.UpgradePathInfo.WifiLanSocket, _Mapping]] = ..., bluetooth_credentials: _Optional[_Union[BandwidthUpgradeNegotiationFrame.UpgradePathInfo.BluetoothCredentials, _Mapping]] = ..., wifi_aware_credentials: _Optional[_Union[BandwidthUpgradeNegotiationFrame.UpgradePathInfo.WifiAwareCredentials, _Mapping]] = ..., wifi_direct_credentials: _Optional[_Union[BandwidthUpgradeNegotiationFrame.UpgradePathInfo.WifiDirectCredentials, _Mapping]] = ..., web_rtc_credentials: _Optional[_Union[BandwidthUpgradeNegotiationFrame.UpgradePathInfo.WebRtcCredentials, _Mapping]] = ..., supports_disabling_encryption: _Optional[bool] = ..., supports_client_introduction_ack: _Optional[bool] = ...) -> None: ...
    class ClientIntroduction(_message.Message):
        __slots__ = ("endpoint_id", "supports_disabling_encryption")
        ENDPOINT_ID_FIELD_NUMBER: _ClassVar[int]
        SUPPORTS_DISABLING_ENCRYPTION_FIELD_NUMBER: _ClassVar[int]
        endpoint_id: str
        supports_disabling_encryption: bool
        def __init__(self, endpoint_id: _Optional[str] = ..., supports_disabling_encryption: _Optional[bool] = ...) -> None: ...
    class ClientIntroductionAck(_message.Message):
        __slots__ = ()
        def __init__(self) -> None: ...
    EVENT_TYPE_FIELD_NUMBER: _ClassVar[int]
    UPGRADE_PATH_INFO_FIELD_NUMBER: _ClassVar[int]
    CLIENT_INTRODUCTION_FIELD_NUMBER: _ClassVar[int]
    CLIENT_INTRODUCTION_ACK_FIELD_NUMBER: _ClassVar[int]
    event_type: BandwidthUpgradeNegotiationFrame.EventType
    upgrade_path_info: BandwidthUpgradeNegotiationFrame.UpgradePathInfo
    client_introduction: BandwidthUpgradeNegotiationFrame.ClientIntroduction
    client_introduction_ack: BandwidthUpgradeNegotiationFrame.ClientIntroductionAck
    def __init__(self, event_type: _Optional[_Union[BandwidthUpgradeNegotiationFrame.EventType, str]] = ..., upgrade_path_info: _Optional[_Union[BandwidthUpgradeNegotiationFrame.UpgradePathInfo, _Mapping]] = ..., client_introduction: _Optional[_Union[BandwidthUpgradeNegotiationFrame.ClientIntroduction, _Mapping]] = ..., client_introduction_ack: _Optional[_Union[BandwidthUpgradeNegotiationFrame.ClientIntroductionAck, _Mapping]] = ...) -> None: ...

class KeepAliveFrame(_message.Message):
    __slots__ = ("ack",)
    ACK_FIELD_NUMBER: _ClassVar[int]
    ack: bool
    def __init__(self, ack: _Optional[bool] = ...) -> None: ...

class DisconnectionFrame(_message.Message):
    __slots__ = ("request_safe_to_disconnect", "ack_safe_to_disconnect")
    REQUEST_SAFE_TO_DISCONNECT_FIELD_NUMBER: _ClassVar[int]
    ACK_SAFE_TO_DISCONNECT_FIELD_NUMBER: _ClassVar[int]
    request_safe_to_disconnect: bool
    ack_safe_to_disconnect: bool
    def __init__(self, request_safe_to_disconnect: _Optional[bool] = ..., ack_safe_to_disconnect: _Optional[bool] = ...) -> None: ...

class PairedKeyEncryptionFrame(_message.Message):
    __slots__ = ("signed_data",)
    SIGNED_DATA_FIELD_NUMBER: _ClassVar[int]
    signed_data: bytes
    def __init__(self, signed_data: _Optional[bytes] = ...) -> None: ...

class MediumMetadata(_message.Message):
    __slots__ = ("supports_5_ghz", "bssid", "ip_address", "supports_6_ghz", "mobile_radio", "ap_frequency", "available_channels", "wifi_direct_cli_usable_channels", "wifi_lan_usable_channels", "wifi_aware_usable_channels", "wifi_hotspot_sta_usable_channels")
    SUPPORTS_5_GHZ_FIELD_NUMBER: _ClassVar[int]
    BSSID_FIELD_NUMBER: _ClassVar[int]
    IP_ADDRESS_FIELD_NUMBER: _ClassVar[int]
    SUPPORTS_6_GHZ_FIELD_NUMBER: _ClassVar[int]
    MOBILE_RADIO_FIELD_NUMBER: _ClassVar[int]
    AP_FREQUENCY_FIELD_NUMBER: _ClassVar[int]
    AVAILABLE_CHANNELS_FIELD_NUMBER: _ClassVar[int]
    WIFI_DIRECT_CLI_USABLE_CHANNELS_FIELD_NUMBER: _ClassVar[int]
    WIFI_LAN_USABLE_CHANNELS_FIELD_NUMBER: _ClassVar[int]
    WIFI_AWARE_USABLE_CHANNELS_FIELD_NUMBER: _ClassVar[int]
    WIFI_HOTSPOT_STA_USABLE_CHANNELS_FIELD_NUMBER: _ClassVar[int]
    supports_5_ghz: bool
    bssid: str
    ip_address: bytes
    supports_6_ghz: bool
    mobile_radio: bool
    ap_frequency: int
    available_channels: AvailableChannels
    wifi_direct_cli_usable_channels: WifiDirectCliUsableChannels
    wifi_lan_usable_channels: WifiLanUsableChannels
    wifi_aware_usable_channels: WifiAwareUsableChannels
    wifi_hotspot_sta_usable_channels: WifiHotspotStaUsableChannels
    def __init__(self, supports_5_ghz: _Optional[bool] = ..., bssid: _Optional[str] = ..., ip_address: _Optional[bytes] = ..., supports_6_ghz: _Optional[bool] = ..., mobile_radio: _Optional[bool] = ..., ap_frequency: _Optional[int] = ..., available_channels: _Optional[_Union[AvailableChannels, _Mapping]] = ..., wifi_direct_cli_usable_channels: _Optional[_Union[WifiDirectCliUsableChannels, _Mapping]] = ..., wifi_lan_usable_channels: _Optional[_Union[WifiLanUsableChannels, _Mapping]] = ..., wifi_aware_usable_channels: _Optional[_Union[WifiAwareUsableChannels, _Mapping]] = ..., wifi_hotspot_sta_usable_channels: _Optional[_Union[WifiHotspotStaUsableChannels, _Mapping]] = ...) -> None: ...

class AvailableChannels(_message.Message):
    __slots__ = ("channels",)
    CHANNELS_FIELD_NUMBER: _ClassVar[int]
    channels: _containers.RepeatedScalarFieldContainer[int]
    def __init__(self, channels: _Optional[_Iterable[int]] = ...) -> None: ...

class WifiDirectCliUsableChannels(_message.Message):
    __slots__ = ("channels",)
    CHANNELS_FIELD_NUMBER: _ClassVar[int]
    channels: _containers.RepeatedScalarFieldContainer[int]
    def __init__(self, channels: _Optional[_Iterable[int]] = ...) -> None: ...

class WifiLanUsableChannels(_message.Message):
    __slots__ = ("channels",)
    CHANNELS_FIELD_NUMBER: _ClassVar[int]
    channels: _containers.RepeatedScalarFieldContainer[int]
    def __init__(self, channels: _Optional[_Iterable[int]] = ...) -> None: ...

class WifiAwareUsableChannels(_message.Message):
    __slots__ = ("channels",)
    CHANNELS_FIELD_NUMBER: _ClassVar[int]
    channels: _containers.RepeatedScalarFieldContainer[int]
    def __init__(self, channels: _Optional[_Iterable[int]] = ...) -> None: ...

class WifiHotspotStaUsableChannels(_message.Message):
    __slots__ = ("channels",)
    CHANNELS_FIELD_NUMBER: _ClassVar[int]
    channels: _containers.RepeatedScalarFieldContainer[int]
    def __init__(self, channels: _Optional[_Iterable[int]] = ...) -> None: ...

class LocationHint(_message.Message):
    __slots__ = ("location", "format")
    LOCATION_FIELD_NUMBER: _ClassVar[int]
    FORMAT_FIELD_NUMBER: _ClassVar[int]
    location: str
    format: LocationStandard.Format
    def __init__(self, location: _Optional[str] = ..., format: _Optional[_Union[LocationStandard.Format, str]] = ...) -> None: ...

class LocationStandard(_message.Message):
    __slots__ = ()
    class Format(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNKNOWN: _ClassVar[LocationStandard.Format]
        E164_CALLING: _ClassVar[LocationStandard.Format]
        ISO_3166_1_ALPHA_2: _ClassVar[LocationStandard.Format]
    UNKNOWN: LocationStandard.Format
    E164_CALLING: LocationStandard.Format
    ISO_3166_1_ALPHA_2: LocationStandard.Format
    def __init__(self) -> None: ...

class OsInfo(_message.Message):
    __slots__ = ("type",)
    class OsType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNKNOWN_OS_TYPE: _ClassVar[OsInfo.OsType]
        ANDROID: _ClassVar[OsInfo.OsType]
        CHROME_OS: _ClassVar[OsInfo.OsType]
        WINDOWS: _ClassVar[OsInfo.OsType]
        APPLE: _ClassVar[OsInfo.OsType]
        LINUX: _ClassVar[OsInfo.OsType]
    UNKNOWN_OS_TYPE: OsInfo.OsType
    ANDROID: OsInfo.OsType
    CHROME_OS: OsInfo.OsType
    WINDOWS: OsInfo.OsType
    APPLE: OsInfo.OsType
    LINUX: OsInfo.OsType
    TYPE_FIELD_NUMBER: _ClassVar[int]
    type: OsInfo.OsType
    def __init__(self, type: _Optional[_Union[OsInfo.OsType, str]] = ...) -> None: ...
