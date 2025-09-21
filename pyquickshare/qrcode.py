from __future__ import annotations

import struct
import typing

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .common import to_url64


class QRCode(typing.NamedTuple):
    """A Quick Share QR code."""

    url: str
    key: bytes
    private_key: ec.EllipticCurvePrivateKey

    def keychain(self) -> HiddenKeychain:
        """Derive the hidden keychain from the QR code's key. Internal use only.

        Returns:
            HiddenKeychain: The derived hidden keychain.
        """
        advertising_token = HKDF(
            algorithm=hashes.SHA256(),
            length=16,
            salt=None,
            info=b"advertisingContext",
        ).derive(self.key)

        name_encryption_token = HKDF(
            algorithm=hashes.SHA256(),
            length=16,
            salt=None,
            info=b"encryptionKey",
        ).derive(self.key)

        return HiddenKeychain(
            advertising_token=advertising_token,
            name_encryption_token=name_encryption_token,
        )

    def print(self) -> None:
        """Print the QR code to the terminal in ASCII art form.

        Requires the `qrcode` extra to be installed.
        """
        import qrcode  # noqa: PLC0415

        qr = qrcode.QRCode(box_size=10, border=4)
        qr.add_data(self.url)
        qr.make(fit=True)
        qr.print_ascii(invert=True)

    def qr_code_handshake_data(self, auth_key: bytes) -> bytes:
        """Internal use only."""
        signature = self.private_key.sign(
            auth_key,
            ec.ECDSA(hashes.SHA256()),
        )
        (r, s) = utils.decode_dss_signature(signature)
        return r.to_bytes(32, byteorder="big") + s.to_bytes(32, byteorder="big")


class HiddenKeychain(typing.NamedTuple):
    advertising_token: bytes
    name_encryption_token: bytes


def generate_qr() -> QRCode:
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    x_value_bytes = public_key.public_numbers().x.to_bytes(32, "big")

    # 2-byte version number of 0, 1-byte version of 2, public key
    qr_payload = struct.pack(">H", 0) + struct.pack("B", 2) + x_value_bytes
    url = f"https://quickshare.google/qrcode#key={to_url64(qr_payload)}"

    return QRCode(url=url, key=qr_payload, private_key=private_key)


def decrypt_qrcode_record(buffer: bytes, keychain: HiddenKeychain) -> bytes:
    iv = buffer[:12]
    tag = buffer[-16:]
    ciphertext = buffer[12:-16]

    decryptor = Cipher(
        algorithms.AES(keychain.name_encryption_token),
        modes.GCM(iv, tag),
    ).decryptor()

    decryptor.authenticate_additional_data(keychain.advertising_token)
    return decryptor.update(ciphertext) + decryptor.finalize()
