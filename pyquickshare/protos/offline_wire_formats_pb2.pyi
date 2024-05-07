from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class AvailableChannels(_message.Message):
    __slots__ = ["channels"]
    CHANNELS_FIELD_NUMBER: _ClassVar[int]
    channels: _containers.RepeatedScalarFieldContainer[int]
    def __init__(self, channels: _Optional[_Iterable[int]] = ...) -> None: ...

class BandwidthUpgradeNegotiationFrame(_message.Message):
    __slots__ = ["client_introduction", "client_introduction_ack", "event_type", "upgrade_path_info"]
    class EventType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = []
    class ClientIntroduction(_message.Message):
        __slots__ = ["endpoint_id", "supports_disabling_encryption"]
        ENDPOINT_ID_FIELD_NUMBER: _ClassVar[int]
        SUPPORTS_DISABLING_ENCRYPTION_FIELD_NUMBER: _ClassVar[int]
        endpoint_id: str
        supports_disabling_encryption: bool
        def __init__(self, endpoint_id: _Optional[str] = ..., supports_disabling_encryption: bool = ...) -> None: ...
    class ClientIntroductionAck(_message.Message):
        __slots__ = []
        def __init__(self) -> None: ...
    class UpgradePathInfo(_message.Message):
        __slots__ = ["bluetooth_credentials", "medium", "supports_client_introduction_ack", "supports_disabling_encryption", "web_rtc_credentials", "wifi_aware_credentials", "wifi_direct_credentials", "wifi_hotspot_credentials", "wifi_lan_socket"]
        class Medium(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = []
        class BluetoothCredentials(_message.Message):
            __slots__ = ["mac_address", "service_name"]
            MAC_ADDRESS_FIELD_NUMBER: _ClassVar[int]
            SERVICE_NAME_FIELD_NUMBER: _ClassVar[int]
            mac_address: str
            service_name: str
            def __init__(self, service_name: _Optional[str] = ..., mac_address: _Optional[str] = ...) -> None: ...
        class WebRtcCredentials(_message.Message):
            __slots__ = ["location_hint", "peer_id"]
            LOCATION_HINT_FIELD_NUMBER: _ClassVar[int]
            PEER_ID_FIELD_NUMBER: _ClassVar[int]
            location_hint: LocationHint
            peer_id: str
            def __init__(self, peer_id: _Optional[str] = ..., location_hint: _Optional[_Union[LocationHint, _Mapping]] = ...) -> None: ...
        class WifiAwareCredentials(_message.Message):
            __slots__ = ["password", "service_id", "service_info"]
            PASSWORD_FIELD_NUMBER: _ClassVar[int]
            SERVICE_ID_FIELD_NUMBER: _ClassVar[int]
            SERVICE_INFO_FIELD_NUMBER: _ClassVar[int]
            password: str
            service_id: str
            service_info: bytes
            def __init__(self, service_id: _Optional[str] = ..., service_info: _Optional[bytes] = ..., password: _Optional[str] = ...) -> None: ...
        class WifiDirectCredentials(_message.Message):
            __slots__ = ["frequency", "gateway", "password", "port", "ssid"]
            FREQUENCY_FIELD_NUMBER: _ClassVar[int]
            GATEWAY_FIELD_NUMBER: _ClassVar[int]
            PASSWORD_FIELD_NUMBER: _ClassVar[int]
            PORT_FIELD_NUMBER: _ClassVar[int]
            SSID_FIELD_NUMBER: _ClassVar[int]
            frequency: int
            gateway: str
            password: str
            port: int
            ssid: str
            def __init__(self, ssid: _Optional[str] = ..., password: _Optional[str] = ..., port: _Optional[int] = ..., frequency: _Optional[int] = ..., gateway: _Optional[str] = ...) -> None: ...
        class WifiHotspotCredentials(_message.Message):
            __slots__ = ["frequency", "gateway", "password", "port", "ssid"]
            FREQUENCY_FIELD_NUMBER: _ClassVar[int]
            GATEWAY_FIELD_NUMBER: _ClassVar[int]
            PASSWORD_FIELD_NUMBER: _ClassVar[int]
            PORT_FIELD_NUMBER: _ClassVar[int]
            SSID_FIELD_NUMBER: _ClassVar[int]
            frequency: int
            gateway: str
            password: str
            port: int
            ssid: str
            def __init__(self, ssid: _Optional[str] = ..., password: _Optional[str] = ..., port: _Optional[int] = ..., gateway: _Optional[str] = ..., frequency: _Optional[int] = ...) -> None: ...
        class WifiLanSocket(_message.Message):
            __slots__ = ["ip_address", "wifi_port"]
            IP_ADDRESS_FIELD_NUMBER: _ClassVar[int]
            WIFI_PORT_FIELD_NUMBER: _ClassVar[int]
            ip_address: bytes
            wifi_port: int
            def __init__(self, ip_address: _Optional[bytes] = ..., wifi_port: _Optional[int] = ...) -> None: ...
        BLE: BandwidthUpgradeNegotiationFrame.UpgradePathInfo.Medium
        BLUETOOTH: BandwidthUpgradeNegotiationFrame.UpgradePathInfo.Medium
        BLUETOOTH_CREDENTIALS_FIELD_NUMBER: _ClassVar[int]
        MDNS: BandwidthUpgradeNegotiationFrame.UpgradePathInfo.Medium
        MEDIUM_FIELD_NUMBER: _ClassVar[int]
        NFC: BandwidthUpgradeNegotiationFrame.UpgradePathInfo.Medium
        SUPPORTS_CLIENT_INTRODUCTION_ACK_FIELD_NUMBER: _ClassVar[int]
        SUPPORTS_DISABLING_ENCRYPTION_FIELD_NUMBER: _ClassVar[int]
        UNKNOWN_MEDIUM: BandwidthUpgradeNegotiationFrame.UpgradePathInfo.Medium
        USB: BandwidthUpgradeNegotiationFrame.UpgradePathInfo.Medium
        WEB_RTC: BandwidthUpgradeNegotiationFrame.UpgradePathInfo.Medium
        WEB_RTC_CREDENTIALS_FIELD_NUMBER: _ClassVar[int]
        WIFI_AWARE: BandwidthUpgradeNegotiationFrame.UpgradePathInfo.Medium
        WIFI_AWARE_CREDENTIALS_FIELD_NUMBER: _ClassVar[int]
        WIFI_DIRECT: BandwidthUpgradeNegotiationFrame.UpgradePathInfo.Medium
        WIFI_DIRECT_CREDENTIALS_FIELD_NUMBER: _ClassVar[int]
        WIFI_HOTSPOT: BandwidthUpgradeNegotiationFrame.UpgradePathInfo.Medium
        WIFI_HOTSPOT_CREDENTIALS_FIELD_NUMBER: _ClassVar[int]
        WIFI_LAN: BandwidthUpgradeNegotiationFrame.UpgradePathInfo.Medium
        WIFI_LAN_SOCKET_FIELD_NUMBER: _ClassVar[int]
        bluetooth_credentials: BandwidthUpgradeNegotiationFrame.UpgradePathInfo.BluetoothCredentials
        medium: BandwidthUpgradeNegotiationFrame.UpgradePathInfo.Medium
        supports_client_introduction_ack: bool
        supports_disabling_encryption: bool
        web_rtc_credentials: BandwidthUpgradeNegotiationFrame.UpgradePathInfo.WebRtcCredentials
        wifi_aware_credentials: BandwidthUpgradeNegotiationFrame.UpgradePathInfo.WifiAwareCredentials
        wifi_direct_credentials: BandwidthUpgradeNegotiationFrame.UpgradePathInfo.WifiDirectCredentials
        wifi_hotspot_credentials: BandwidthUpgradeNegotiationFrame.UpgradePathInfo.WifiHotspotCredentials
        wifi_lan_socket: BandwidthUpgradeNegotiationFrame.UpgradePathInfo.WifiLanSocket
        def __init__(self, medium: _Optional[_Union[BandwidthUpgradeNegotiationFrame.UpgradePathInfo.Medium, str]] = ..., wifi_hotspot_credentials: _Optional[_Union[BandwidthUpgradeNegotiationFrame.UpgradePathInfo.WifiHotspotCredentials, _Mapping]] = ..., wifi_lan_socket: _Optional[_Union[BandwidthUpgradeNegotiationFrame.UpgradePathInfo.WifiLanSocket, _Mapping]] = ..., bluetooth_credentials: _Optional[_Union[BandwidthUpgradeNegotiationFrame.UpgradePathInfo.BluetoothCredentials, _Mapping]] = ..., wifi_aware_credentials: _Optional[_Union[BandwidthUpgradeNegotiationFrame.UpgradePathInfo.WifiAwareCredentials, _Mapping]] = ..., wifi_direct_credentials: _Optional[_Union[BandwidthUpgradeNegotiationFrame.UpgradePathInfo.WifiDirectCredentials, _Mapping]] = ..., web_rtc_credentials: _Optional[_Union[BandwidthUpgradeNegotiationFrame.UpgradePathInfo.WebRtcCredentials, _Mapping]] = ..., supports_disabling_encryption: bool = ..., supports_client_introduction_ack: bool = ...) -> None: ...
    CLIENT_INTRODUCTION: BandwidthUpgradeNegotiationFrame.EventType
    CLIENT_INTRODUCTION_ACK: BandwidthUpgradeNegotiationFrame.EventType
    CLIENT_INTRODUCTION_ACK_FIELD_NUMBER: _ClassVar[int]
    CLIENT_INTRODUCTION_FIELD_NUMBER: _ClassVar[int]
    EVENT_TYPE_FIELD_NUMBER: _ClassVar[int]
    LAST_WRITE_TO_PRIOR_CHANNEL: BandwidthUpgradeNegotiationFrame.EventType
    SAFE_TO_CLOSE_PRIOR_CHANNEL: BandwidthUpgradeNegotiationFrame.EventType
    UNKNOWN_EVENT_TYPE: BandwidthUpgradeNegotiationFrame.EventType
    UPGRADE_FAILURE: BandwidthUpgradeNegotiationFrame.EventType
    UPGRADE_PATH_AVAILABLE: BandwidthUpgradeNegotiationFrame.EventType
    UPGRADE_PATH_INFO_FIELD_NUMBER: _ClassVar[int]
    client_introduction: BandwidthUpgradeNegotiationFrame.ClientIntroduction
    client_introduction_ack: BandwidthUpgradeNegotiationFrame.ClientIntroductionAck
    event_type: BandwidthUpgradeNegotiationFrame.EventType
    upgrade_path_info: BandwidthUpgradeNegotiationFrame.UpgradePathInfo
    def __init__(self, event_type: _Optional[_Union[BandwidthUpgradeNegotiationFrame.EventType, str]] = ..., upgrade_path_info: _Optional[_Union[BandwidthUpgradeNegotiationFrame.UpgradePathInfo, _Mapping]] = ..., client_introduction: _Optional[_Union[BandwidthUpgradeNegotiationFrame.ClientIntroduction, _Mapping]] = ..., client_introduction_ack: _Optional[_Union[BandwidthUpgradeNegotiationFrame.ClientIntroductionAck, _Mapping]] = ...) -> None: ...

class ConnectionRequestFrame(_message.Message):
    __slots__ = ["device_info", "device_type", "endpoint_id", "endpoint_info", "endpoint_name", "handshake_data", "keep_alive_interval_millis", "keep_alive_timeout_millis", "medium_metadata", "mediums", "nonce"]
    class Medium(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = []
    BLE: ConnectionRequestFrame.Medium
    BLE_L2CAP: ConnectionRequestFrame.Medium
    BLUETOOTH: ConnectionRequestFrame.Medium
    DEVICE_INFO_FIELD_NUMBER: _ClassVar[int]
    DEVICE_TYPE_FIELD_NUMBER: _ClassVar[int]
    ENDPOINT_ID_FIELD_NUMBER: _ClassVar[int]
    ENDPOINT_INFO_FIELD_NUMBER: _ClassVar[int]
    ENDPOINT_NAME_FIELD_NUMBER: _ClassVar[int]
    HANDSHAKE_DATA_FIELD_NUMBER: _ClassVar[int]
    KEEP_ALIVE_INTERVAL_MILLIS_FIELD_NUMBER: _ClassVar[int]
    KEEP_ALIVE_TIMEOUT_MILLIS_FIELD_NUMBER: _ClassVar[int]
    MDNS: ConnectionRequestFrame.Medium
    MEDIUMS_FIELD_NUMBER: _ClassVar[int]
    MEDIUM_METADATA_FIELD_NUMBER: _ClassVar[int]
    NFC: ConnectionRequestFrame.Medium
    NONCE_FIELD_NUMBER: _ClassVar[int]
    UNKNOWN_MEDIUM: ConnectionRequestFrame.Medium
    USB: ConnectionRequestFrame.Medium
    WEB_RTC: ConnectionRequestFrame.Medium
    WIFI_AWARE: ConnectionRequestFrame.Medium
    WIFI_DIRECT: ConnectionRequestFrame.Medium
    WIFI_HOTSPOT: ConnectionRequestFrame.Medium
    WIFI_LAN: ConnectionRequestFrame.Medium
    device_info: bytes
    device_type: int
    endpoint_id: str
    endpoint_info: bytes
    endpoint_name: str
    handshake_data: bytes
    keep_alive_interval_millis: int
    keep_alive_timeout_millis: int
    medium_metadata: MediumMetadata
    mediums: _containers.RepeatedScalarFieldContainer[ConnectionRequestFrame.Medium]
    nonce: int
    def __init__(self, endpoint_id: _Optional[str] = ..., endpoint_name: _Optional[str] = ..., handshake_data: _Optional[bytes] = ..., nonce: _Optional[int] = ..., mediums: _Optional[_Iterable[_Union[ConnectionRequestFrame.Medium, str]]] = ..., endpoint_info: _Optional[bytes] = ..., medium_metadata: _Optional[_Union[MediumMetadata, _Mapping]] = ..., keep_alive_interval_millis: _Optional[int] = ..., keep_alive_timeout_millis: _Optional[int] = ..., device_type: _Optional[int] = ..., device_info: _Optional[bytes] = ...) -> None: ...

class ConnectionResponseFrame(_message.Message):
    __slots__ = ["handshake_data", "multiplex_socket_bitmask", "nearby_connections_version", "os_info", "response", "status"]
    class ResponseStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = []
    ACCEPT: ConnectionResponseFrame.ResponseStatus
    HANDSHAKE_DATA_FIELD_NUMBER: _ClassVar[int]
    MULTIPLEX_SOCKET_BITMASK_FIELD_NUMBER: _ClassVar[int]
    NEARBY_CONNECTIONS_VERSION_FIELD_NUMBER: _ClassVar[int]
    OS_INFO_FIELD_NUMBER: _ClassVar[int]
    REJECT: ConnectionResponseFrame.ResponseStatus
    RESPONSE_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    UNKNOWN_RESPONSE_STATUS: ConnectionResponseFrame.ResponseStatus
    handshake_data: bytes
    multiplex_socket_bitmask: int
    nearby_connections_version: int
    os_info: OsInfo
    response: ConnectionResponseFrame.ResponseStatus
    status: int
    def __init__(self, status: _Optional[int] = ..., handshake_data: _Optional[bytes] = ..., response: _Optional[_Union[ConnectionResponseFrame.ResponseStatus, str]] = ..., os_info: _Optional[_Union[OsInfo, _Mapping]] = ..., multiplex_socket_bitmask: _Optional[int] = ..., nearby_connections_version: _Optional[int] = ...) -> None: ...

class DisconnectionFrame(_message.Message):
    __slots__ = ["ack_safe_to_disconnect", "request_safe_to_disconnect"]
    ACK_SAFE_TO_DISCONNECT_FIELD_NUMBER: _ClassVar[int]
    REQUEST_SAFE_TO_DISCONNECT_FIELD_NUMBER: _ClassVar[int]
    ack_safe_to_disconnect: bool
    request_safe_to_disconnect: bool
    def __init__(self, request_safe_to_disconnect: bool = ..., ack_safe_to_disconnect: bool = ...) -> None: ...

class KeepAliveFrame(_message.Message):
    __slots__ = ["ack"]
    ACK_FIELD_NUMBER: _ClassVar[int]
    ack: bool
    def __init__(self, ack: bool = ...) -> None: ...

class LocationHint(_message.Message):
    __slots__ = ["format", "location"]
    FORMAT_FIELD_NUMBER: _ClassVar[int]
    LOCATION_FIELD_NUMBER: _ClassVar[int]
    format: LocationStandard.Format
    location: str
    def __init__(self, location: _Optional[str] = ..., format: _Optional[_Union[LocationStandard.Format, str]] = ...) -> None: ...

class LocationStandard(_message.Message):
    __slots__ = []
    class Format(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = []
    E164_CALLING: LocationStandard.Format
    ISO_3166_1_ALPHA_2: LocationStandard.Format
    UNKNOWN: LocationStandard.Format
    def __init__(self) -> None: ...

class MediumMetadata(_message.Message):
    __slots__ = ["ap_frequency", "available_channels", "bssid", "ip_address", "mobile_radio", "supports_5_ghz", "supports_6_ghz", "wifi_aware_usable_channels", "wifi_direct_cli_usable_channels", "wifi_hotspot_sta_usable_channels", "wifi_lan_usable_channels"]
    AP_FREQUENCY_FIELD_NUMBER: _ClassVar[int]
    AVAILABLE_CHANNELS_FIELD_NUMBER: _ClassVar[int]
    BSSID_FIELD_NUMBER: _ClassVar[int]
    IP_ADDRESS_FIELD_NUMBER: _ClassVar[int]
    MOBILE_RADIO_FIELD_NUMBER: _ClassVar[int]
    SUPPORTS_5_GHZ_FIELD_NUMBER: _ClassVar[int]
    SUPPORTS_6_GHZ_FIELD_NUMBER: _ClassVar[int]
    WIFI_AWARE_USABLE_CHANNELS_FIELD_NUMBER: _ClassVar[int]
    WIFI_DIRECT_CLI_USABLE_CHANNELS_FIELD_NUMBER: _ClassVar[int]
    WIFI_HOTSPOT_STA_USABLE_CHANNELS_FIELD_NUMBER: _ClassVar[int]
    WIFI_LAN_USABLE_CHANNELS_FIELD_NUMBER: _ClassVar[int]
    ap_frequency: int
    available_channels: AvailableChannels
    bssid: str
    ip_address: bytes
    mobile_radio: bool
    supports_5_ghz: bool
    supports_6_ghz: bool
    wifi_aware_usable_channels: WifiAwareUsableChannels
    wifi_direct_cli_usable_channels: WifiDirectCliUsableChannels
    wifi_hotspot_sta_usable_channels: WifiHotspotStaUsableChannels
    wifi_lan_usable_channels: WifiLanUsableChannels
    def __init__(self, supports_5_ghz: bool = ..., bssid: _Optional[str] = ..., ip_address: _Optional[bytes] = ..., supports_6_ghz: bool = ..., mobile_radio: bool = ..., ap_frequency: _Optional[int] = ..., available_channels: _Optional[_Union[AvailableChannels, _Mapping]] = ..., wifi_direct_cli_usable_channels: _Optional[_Union[WifiDirectCliUsableChannels, _Mapping]] = ..., wifi_lan_usable_channels: _Optional[_Union[WifiLanUsableChannels, _Mapping]] = ..., wifi_aware_usable_channels: _Optional[_Union[WifiAwareUsableChannels, _Mapping]] = ..., wifi_hotspot_sta_usable_channels: _Optional[_Union[WifiHotspotStaUsableChannels, _Mapping]] = ...) -> None: ...

class OfflineFrame(_message.Message):
    __slots__ = ["v1", "version"]
    class Version(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = []
    UNKNOWN_VERSION: OfflineFrame.Version
    V1: OfflineFrame.Version
    V1_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    v1: V1Frame
    version: OfflineFrame.Version
    def __init__(self, version: _Optional[_Union[OfflineFrame.Version, str]] = ..., v1: _Optional[_Union[V1Frame, _Mapping]] = ...) -> None: ...

class OsInfo(_message.Message):
    __slots__ = ["type"]
    class OsType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = []
    ANDROID: OsInfo.OsType
    APPLE: OsInfo.OsType
    CHROME_OS: OsInfo.OsType
    LINUX: OsInfo.OsType
    TYPE_FIELD_NUMBER: _ClassVar[int]
    UNKNOWN_OS_TYPE: OsInfo.OsType
    WINDOWS: OsInfo.OsType
    type: OsInfo.OsType
    def __init__(self, type: _Optional[_Union[OsInfo.OsType, str]] = ...) -> None: ...

class PairedKeyEncryptionFrame(_message.Message):
    __slots__ = ["signed_data"]
    SIGNED_DATA_FIELD_NUMBER: _ClassVar[int]
    signed_data: bytes
    def __init__(self, signed_data: _Optional[bytes] = ...) -> None: ...

class PayloadTransferFrame(_message.Message):
    __slots__ = ["control_message", "packet_type", "payload_chunk", "payload_header"]
    class PacketType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = []
    class ControlMessage(_message.Message):
        __slots__ = ["event", "offset"]
        class EventType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = []
        EVENT_FIELD_NUMBER: _ClassVar[int]
        OFFSET_FIELD_NUMBER: _ClassVar[int]
        PAYLOAD_CANCELED: PayloadTransferFrame.ControlMessage.EventType
        PAYLOAD_ERROR: PayloadTransferFrame.ControlMessage.EventType
        PAYLOAD_RECEIVED_ACK: PayloadTransferFrame.ControlMessage.EventType
        UNKNOWN_EVENT_TYPE: PayloadTransferFrame.ControlMessage.EventType
        event: PayloadTransferFrame.ControlMessage.EventType
        offset: int
        def __init__(self, event: _Optional[_Union[PayloadTransferFrame.ControlMessage.EventType, str]] = ..., offset: _Optional[int] = ...) -> None: ...
    class PayloadChunk(_message.Message):
        __slots__ = ["body", "flags", "offset"]
        class Flags(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = []
        BODY_FIELD_NUMBER: _ClassVar[int]
        FLAGS_FIELD_NUMBER: _ClassVar[int]
        LAST_CHUNK: PayloadTransferFrame.PayloadChunk.Flags
        OFFSET_FIELD_NUMBER: _ClassVar[int]
        body: bytes
        flags: int
        offset: int
        def __init__(self, flags: _Optional[int] = ..., offset: _Optional[int] = ..., body: _Optional[bytes] = ...) -> None: ...
    class PayloadHeader(_message.Message):
        __slots__ = ["file_name", "id", "is_sensitive", "parent_folder", "total_size", "type"]
        class PayloadType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = []
        BYTES: PayloadTransferFrame.PayloadHeader.PayloadType
        FILE: PayloadTransferFrame.PayloadHeader.PayloadType
        FILE_NAME_FIELD_NUMBER: _ClassVar[int]
        ID_FIELD_NUMBER: _ClassVar[int]
        IS_SENSITIVE_FIELD_NUMBER: _ClassVar[int]
        PARENT_FOLDER_FIELD_NUMBER: _ClassVar[int]
        STREAM: PayloadTransferFrame.PayloadHeader.PayloadType
        TOTAL_SIZE_FIELD_NUMBER: _ClassVar[int]
        TYPE_FIELD_NUMBER: _ClassVar[int]
        UNKNOWN_PAYLOAD_TYPE: PayloadTransferFrame.PayloadHeader.PayloadType
        file_name: str
        id: int
        is_sensitive: bool
        parent_folder: str
        total_size: int
        type: PayloadTransferFrame.PayloadHeader.PayloadType
        def __init__(self, id: _Optional[int] = ..., type: _Optional[_Union[PayloadTransferFrame.PayloadHeader.PayloadType, str]] = ..., total_size: _Optional[int] = ..., is_sensitive: bool = ..., file_name: _Optional[str] = ..., parent_folder: _Optional[str] = ...) -> None: ...
    CONTROL: PayloadTransferFrame.PacketType
    CONTROL_MESSAGE_FIELD_NUMBER: _ClassVar[int]
    DATA: PayloadTransferFrame.PacketType
    PACKET_TYPE_FIELD_NUMBER: _ClassVar[int]
    PAYLOAD_CHUNK_FIELD_NUMBER: _ClassVar[int]
    PAYLOAD_HEADER_FIELD_NUMBER: _ClassVar[int]
    UNKNOWN_PACKET_TYPE: PayloadTransferFrame.PacketType
    control_message: PayloadTransferFrame.ControlMessage
    packet_type: PayloadTransferFrame.PacketType
    payload_chunk: PayloadTransferFrame.PayloadChunk
    payload_header: PayloadTransferFrame.PayloadHeader
    def __init__(self, packet_type: _Optional[_Union[PayloadTransferFrame.PacketType, str]] = ..., payload_header: _Optional[_Union[PayloadTransferFrame.PayloadHeader, _Mapping]] = ..., payload_chunk: _Optional[_Union[PayloadTransferFrame.PayloadChunk, _Mapping]] = ..., control_message: _Optional[_Union[PayloadTransferFrame.ControlMessage, _Mapping]] = ...) -> None: ...

class V1Frame(_message.Message):
    __slots__ = ["bandwidth_upgrade_negotiation", "connection_request", "connection_response", "disconnection", "keep_alive", "paired_key_encryption", "payload_transfer", "type"]
    class FrameType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = []
    BANDWIDTH_UPGRADE_NEGOTIATION: V1Frame.FrameType
    BANDWIDTH_UPGRADE_NEGOTIATION_FIELD_NUMBER: _ClassVar[int]
    CONNECTION_REQUEST: V1Frame.FrameType
    CONNECTION_REQUEST_FIELD_NUMBER: _ClassVar[int]
    CONNECTION_RESPONSE: V1Frame.FrameType
    CONNECTION_RESPONSE_FIELD_NUMBER: _ClassVar[int]
    DISCONNECTION: V1Frame.FrameType
    DISCONNECTION_FIELD_NUMBER: _ClassVar[int]
    KEEP_ALIVE: V1Frame.FrameType
    KEEP_ALIVE_FIELD_NUMBER: _ClassVar[int]
    PAIRED_KEY_ENCRYPTION: V1Frame.FrameType
    PAIRED_KEY_ENCRYPTION_FIELD_NUMBER: _ClassVar[int]
    PAYLOAD_TRANSFER: V1Frame.FrameType
    PAYLOAD_TRANSFER_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    UNKNOWN_FRAME_TYPE: V1Frame.FrameType
    bandwidth_upgrade_negotiation: BandwidthUpgradeNegotiationFrame
    connection_request: ConnectionRequestFrame
    connection_response: ConnectionResponseFrame
    disconnection: DisconnectionFrame
    keep_alive: KeepAliveFrame
    paired_key_encryption: PairedKeyEncryptionFrame
    payload_transfer: PayloadTransferFrame
    type: V1Frame.FrameType
    def __init__(self, type: _Optional[_Union[V1Frame.FrameType, str]] = ..., connection_request: _Optional[_Union[ConnectionRequestFrame, _Mapping]] = ..., connection_response: _Optional[_Union[ConnectionResponseFrame, _Mapping]] = ..., payload_transfer: _Optional[_Union[PayloadTransferFrame, _Mapping]] = ..., bandwidth_upgrade_negotiation: _Optional[_Union[BandwidthUpgradeNegotiationFrame, _Mapping]] = ..., keep_alive: _Optional[_Union[KeepAliveFrame, _Mapping]] = ..., disconnection: _Optional[_Union[DisconnectionFrame, _Mapping]] = ..., paired_key_encryption: _Optional[_Union[PairedKeyEncryptionFrame, _Mapping]] = ...) -> None: ...

class WifiAwareUsableChannels(_message.Message):
    __slots__ = ["channels"]
    CHANNELS_FIELD_NUMBER: _ClassVar[int]
    channels: _containers.RepeatedScalarFieldContainer[int]
    def __init__(self, channels: _Optional[_Iterable[int]] = ...) -> None: ...

class WifiDirectCliUsableChannels(_message.Message):
    __slots__ = ["channels"]
    CHANNELS_FIELD_NUMBER: _ClassVar[int]
    channels: _containers.RepeatedScalarFieldContainer[int]
    def __init__(self, channels: _Optional[_Iterable[int]] = ...) -> None: ...

class WifiHotspotStaUsableChannels(_message.Message):
    __slots__ = ["channels"]
    CHANNELS_FIELD_NUMBER: _ClassVar[int]
    channels: _containers.RepeatedScalarFieldContainer[int]
    def __init__(self, channels: _Optional[_Iterable[int]] = ...) -> None: ...

class WifiLanUsableChannels(_message.Message):
    __slots__ = ["channels"]
    CHANNELS_FIELD_NUMBER: _ClassVar[int]
    channels: _containers.RepeatedScalarFieldContainer[int]
    def __init__(self, channels: _Optional[_Iterable[int]] = ...) -> None: ...
