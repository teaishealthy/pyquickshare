# the UKEY2 Key Exchange in Quick Share

from __future__ import annotations

import binascii
import hashlib
import os
from logging import getLogger
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .common import Keychain
from .protos import securemessage_pb2, ukey_pb2

if TYPE_CHECKING:
    from .backend import ConnectionBackend

KEYCHAIN_SALT = hashlib.sha256(b"SecureMessage").digest()
D2D_SALT = binascii.unhexlify(
    "82AA55A0D397F88346CA1CEE8D3909B95F13FA7DEB1D4AB38376B8256DA85510",
)  # fmt: off
EXPECTED_RANDOM_LENGTH = 32

SUPPORTED_PROTOCOLS = [
    "AES_256_CBC-HMAC_SHA256",
]

logger = getLogger(__name__)


def to_twos_complement(n: int) -> bytes:
    """Convert an integer to a two's complement byte array.

    Args:
        n (int): The integer to convert

    Returns:
        bytes: The two's complement byte array
    """
    return n.to_bytes(((n.bit_length() + 7) // 8) + 1, "big", signed=True)


def from_twos_complement(data: bytes) -> int:
    """Convert a two's complement byte array to an integer.

    Args:
        data (bytes): The two's complement byte array

    Returns:
        int: The integer
    """
    return int.from_bytes(data, "big", signed=True)


async def parse_client_init(
    ukey_client_init: ukey_pb2.Ukey2ClientInit,
    backend: ConnectionBackend,
) -> tuple[str, ukey_pb2.Ukey2ClientInit.CipherCommitment] | None:
    """Parse a CLIENT_INIT message.

    Args:
        ukey_client_init (ukey_pb2.Ukey2ClientInit): The CLIENT_INIT message
        backend (ConnectionBackend): The backend to send alerts to

    Returns:
        tuple[str, ukey_pb2.Ukey2ClientInit.CipherCommitment] | None: The next protocol and cipher commitment, or None if the message is invalid
    """  # noqa: E501
    if ukey_client_init.version != 1:
        return await ukey_alert(
            alert_type=ukey_pb2.Ukey2Alert.BAD_VERSION,
            alert_message="Expected version 1",
            backend=backend,
        )

    if len(ukey_client_init.random) != EXPECTED_RANDOM_LENGTH:
        return await ukey_alert(
            alert_type=ukey_pb2.Ukey2Alert.BAD_RANDOM,
            alert_message="Expected 32 bytes of random",
            backend=backend,
        )

    cipher_commitment = ukey_client_init.cipher_commitments[0]

    # What protocol the client want's to speak next
    next_proto = ukey_client_init.next_protocol

    logger.debug("Received CLIENT_INIT")

    if next_proto not in SUPPORTED_PROTOCOLS:
        logger.error(
            "Client wants to speak %s, but we only support %s",
            next_proto,
            SUPPORTED_PROTOCOLS,
        )
        return await ukey_alert(
            alert_type=ukey_pb2.Ukey2Alert.BAD_NEXT_PROTOCOL,
            alert_message="Unsupported protocol",
            backend=backend,
        )

    logger.debug(
        "CLIENT_INIT accepted with protocol %s and cipher %s",
        next_proto,
        cipher_commitment.handshake_cipher,
    )

    return next_proto, cipher_commitment


async def send_server_init(
    private_key: ec.EllipticCurvePrivateKey,
    cipher_commitment: ukey_pb2.Ukey2ClientInit.CipherCommitment,
    backend: ConnectionBackend,
) -> bytes:
    """Send a SERVER_INIT message.

    Args:
        private_key (ec.EllipticCurvePrivateKey): The server's private key
        cipher_commitment (ukey_pb2.Ukey2ClientInit.CipherCommitment): The cipher commitment from the client
        backend (ConnectionBackend): The backend to send the message to

    Returns:
        bytes: The serialized SERVER_INIT message (for key derivation)
    """  # noqa: E501
    server_init = ukey_pb2.Ukey2ServerInit()

    server_init.version = 1
    server_init.random = os.urandom(32)
    server_init.handshake_cipher = cipher_commitment.handshake_cipher

    public_key = private_key.public_key()

    generic_key = encode_public_key(public_key)

    server_init.public_key = generic_key.SerializeToString()

    logger.debug("Sending SERVER_INIT")

    server_message = ukey_pb2.Ukey2Message()
    server_message.message_type = ukey_pb2.Ukey2Message.SERVER_INIT
    server_message.message_data = server_init.SerializeToString()

    data = server_message.SerializeToString()

    await backend.send(data)

    logger.debug("Sent SERVER_INIT")

    return data


async def parse_client_finished(
    raw_message: bytes,
    commitment: ukey_pb2.Ukey2ClientInit.CipherCommitment,
    backend: ConnectionBackend,
) -> ec.EllipticCurvePublicKey | None:
    """Parse a CLIENT_FINISH message.

    Args:
        raw_message (bytes): The raw CLIENT_FINISH message
        commitment (ukey_pb2.Ukey2ClientInit.CipherCommitment): The cipher commitment from the client
        backend (ConnectionBackend): The backend to close on failure

    Returns:
        ec.EllipticCurvePublicKey | None: The client's public key, or None if the message is invalid
    """  # noqa: E501
    # There are a lot of things that need to be checked here
    # that's why we accept a raw message

    logger.debug("Parsing CLIENT_FINISH")

    ukey_message = ukey_pb2.Ukey2Message()
    ukey_message.ParseFromString(raw_message)

    if ukey_message.message_type != ukey_pb2.Ukey2Message.CLIENT_FINISH:
        # reference tells us to not send an alert here and just close the connection
        logger.debug("Expected CLIENT_FINISH")
        backend.writer.close()
        return None

    hashed = hashlib.sha512(raw_message).digest()

    if hashed != commitment.commitment:
        # like above, we just close the connection
        logger.debug("Bad commitment")
        backend.writer.close()
        return None

    client_finished = ukey_pb2.Ukey2ClientFinished()
    client_finished.ParseFromString(ukey_message.message_data)

    public_key = securemessage_pb2.GenericPublicKey()
    public_key.ParseFromString(client_finished.public_key)

    key = decode_public_key(public_key)

    logger.debug("Accepted CLIENT_FINISH")

    return key


def encode_public_key(
    public_key: ec.EllipticCurvePublicKey,
) -> securemessage_pb2.GenericPublicKey:
    """Encode an EllipticCurvePublicKey as a GenericPublicKey.

    Args:
        public_key (ec.EllipticCurvePublicKey): The public key to encode

    Returns:
        securemessage_pb2.GenericPublicKey: The encoded public key
    """
    public_numbers = public_key.public_numbers()

    generic_key = securemessage_pb2.GenericPublicKey()
    generic_key.type = securemessage_pb2.EC_P256
    generic_key.ec_p256_public_key.x = to_twos_complement(public_numbers.x)
    generic_key.ec_p256_public_key.y = to_twos_complement(public_numbers.y)

    return generic_key


def decode_public_key(
    generic_key: securemessage_pb2.GenericPublicKey,
) -> ec.EllipticCurvePublicKey:
    """Decode a GenericPublicKey as an EllipticCurvePublicKey.

    Args:
        generic_key (securemessage_pb2.GenericPublicKey): The public key to decode

    Raises:
        ValueError: If the key is not EC_P256

    Returns:
        ec.EllipticCurvePublicKey: The decoded public key
    """
    if generic_key.type != securemessage_pb2.EC_P256:
        msg = "Expected EC_P256"
        raise ValueError(msg)

    public_numbers = ec.EllipticCurvePublicNumbers(
        from_twos_complement(generic_key.ec_p256_public_key.x),
        from_twos_complement(generic_key.ec_p256_public_key.y),
        ec.SECP256R1(),
    )

    return public_numbers.public_key()


def derive_keys(
    m1: bytes,
    m2: bytes,
    private_key: ec.EllipticCurvePrivateKey,
    peer_public_key: ec.EllipticCurvePublicKey,
) -> Keychain:
    """Derive the keys for a session.

    Args:
        m1 (bytes): The first message (CLIENT_INIT or SERVER_INIT)
        m2 (bytes): The second message (SERVER_INIT or CLIENT_INIT)
        private_key (ec.EllipticCurvePrivateKey): Our private key
        peer_public_key (ec.EllipticCurvePublicKey): The peer's public key

    Returns:
        Keychain: The derived keys
    """
    dhs = hashlib.sha256(private_key.exchange(ec.ECDH(), peer_public_key)).digest()

    next_secret = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"UKEY2 v1 next",
        info=m1 + m2,
    ).derive(dhs)

    auth_string = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"UKEY2 v1 auth",
        info=m1 + m2,
    ).derive(dhs)

    d2d_server_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=D2D_SALT,
        info=b"server",
    ).derive(next_secret)

    d2d_client_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=D2D_SALT,
        info=b"client",
    ).derive(next_secret)

    # now we can derive the four keys

    decrypt_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=KEYCHAIN_SALT,
        info=b"ENC:2",
    ).derive(d2d_client_key)

    receive_hmac_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=KEYCHAIN_SALT,
        info=b"SIG:1",
    ).derive(d2d_client_key)

    encrypt_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=KEYCHAIN_SALT,
        info=b"ENC:2",
    ).derive(d2d_server_key)

    send_hmac_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=KEYCHAIN_SALT,
        info=b"SIG:1",
    ).derive(d2d_server_key)

    # this is from the server POV
    return Keychain(
        decrypt_key=decrypt_key,
        receive_hmac_key=receive_hmac_key,
        encrypt_key=encrypt_key,
        send_hmac_key=send_hmac_key,
        auth_string=auth_string,
    )


def swap_keychain(keychain: Keychain) -> Keychain:
    """Swap the perspective of a keychain.

    Args:
        keychain (Keychain): The keychain to swap

    Returns:
        Keychain: The swapped keychain
    """
    return Keychain(
        decrypt_key=keychain.encrypt_key,
        receive_hmac_key=keychain.send_hmac_key,
        encrypt_key=keychain.decrypt_key,
        send_hmac_key=keychain.receive_hmac_key,
        auth_string=keychain.auth_string,
    )


async def do_server_key_exchange(backend: ConnectionBackend) -> Keychain | None:
    """Perform a server key exchange.

    Args:
        backend (ConnectionBackend): The protocol backend

    Returns:
        Keychain | None: The keychain, or None if the exchange failed
    """
    ukey_message = ukey_pb2.Ukey2Message()

    m1 = await backend.recv()

    ukey_message.ParseFromString(m1)

    if ukey_message.message_type != ukey_pb2.Ukey2Message.CLIENT_INIT:
        return await ukey_alert(
            alert_type=ukey_pb2.Ukey2Alert.BAD_MESSAGE_TYPE,
            alert_message="Expected CLIENT_INIT",
            backend=backend,
        )

    ukey_client_init = ukey_pb2.Ukey2ClientInit()

    ukey_client_init.ParseFromString(ukey_message.message_data)

    maybe_result = await parse_client_init(ukey_client_init, backend)

    if not maybe_result:
        return None

    _next_protocol, cipher_commitment = maybe_result

    # TODO: Support CURVE25519 when requsted
    private_key = ec.generate_private_key(ec.SECP256R1())

    m2 = await send_server_init(private_key, cipher_commitment, backend)

    peer_public_key = await parse_client_finished(
        await backend.recv(),
        cipher_commitment,
        backend,
    )

    if not peer_public_key:
        # parse_client_finished() rejected the CLIENT_FINISH message
        return None

    return derive_keys(m1, m2, private_key, peer_public_key)


async def do_client_key_exchange(backend: ConnectionBackend) -> Keychain | None:
    """Perform a client key exchange.

    Args:
        backend (ConnectionBackend): The protocol backend

    Returns:
        Keychain | None: The keychain, or None if the exchange failed
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    ukey_client_finished = ukey_pb2.Ukey2ClientFinished()
    ukey_client_finished.public_key = encode_public_key(public_key).SerializeToString()

    ukey_client_finished_framing = ukey_pb2.Ukey2Message()
    ukey_client_finished_framing.message_type = ukey_pb2.Ukey2Message.CLIENT_FINISH
    ukey_client_finished_framing.message_data = ukey_client_finished.SerializeToString()

    serialized_ukey_client_finished_framed = ukey_client_finished_framing.SerializeToString()

    ukey_client_init = ukey_pb2.Ukey2ClientInit()
    ukey_client_init.version = 1
    ukey_client_init.random = os.urandom(32)
    ukey_client_init.next_protocol = "AES_256_CBC-HMAC_SHA256"  # TODO: hardcoded
    ukey_client_init.cipher_commitments.append(
        ukey_pb2.Ukey2ClientInit.CipherCommitment(
            handshake_cipher=ukey_pb2.P256_SHA512,
            commitment=hashlib.sha512(serialized_ukey_client_finished_framed).digest(),
        ),
    )

    message_framing = ukey_pb2.Ukey2Message()
    message_framing.message_type = ukey_pb2.Ukey2Message.CLIENT_INIT
    message_framing.message_data = ukey_client_init.SerializeToString()

    m1 = message_framing.SerializeToString()
    await backend.send(m1)

    # SERVER_INIT
    m2 = await backend.recv()

    message_framing = ukey_pb2.Ukey2Message()
    message_framing.ParseFromString(m2)

    server_init = ukey_pb2.Ukey2ServerInit()
    server_init.ParseFromString(message_framing.message_data)

    generic_key = securemessage_pb2.GenericPublicKey()
    generic_key.ParseFromString(server_init.public_key)

    peer_public_key = decode_public_key(generic_key)

    await backend.send(serialized_ukey_client_finished_framed)

    return swap_keychain(derive_keys(m1, m2, private_key, peer_public_key))


async def ukey_alert(
    *,
    alert_type: ukey_pb2.Ukey2Alert.AlertType,
    alert_message: str,
    backend: ConnectionBackend,
) -> None:
    """Send an alert message and close the connection.

    Args:
        alert_type (ukey_pb2.Ukey2Alert.AlertType): The alert type
        alert_message (str): The alert message
        backend (ConnectionBackend): The backend to send the alert to
    """
    # Sends an alert over the wire without length-prefix framing, then closes
    message = make_alert(alert_type, alert_message)

    backend.writer.write(message.SerializeToString())
    await backend.writer.drain()
    backend.writer.close()


def make_alert(
    alert_type: ukey_pb2.Ukey2Alert.AlertType,
    error_message: str,
) -> ukey_pb2.Ukey2Message:
    """Construct an alert message.

    Args:
        alert_type (ukey_pb2.Ukey2Alert.AlertType): The alert type
        error_message (str): The error message

    Returns:
        ukey_pb2.Ukey2Message: The constructed alert message
    """
    # Constructs an alert message
    alert = ukey_pb2.Ukey2Alert()
    alert.type = alert_type
    alert.error_message = error_message

    message = ukey_pb2.Ukey2Message()

    message.message_type = ukey_pb2.Ukey2Message.ALERT

    return message
