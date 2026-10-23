
import os
import hashlib
import hmac
import base64

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class TLSSimulator:
    """Educational simulation of an RSA-based TLS handshake."""

    def __init__(self):
        self.reset()

    def reset(self):
        self.step = 0
        self.transcript = []
        self.server_private_key = None
        self.server_public_key = None
        self.premaster_secret = None
        self.encrypted_premaster_secret = None
        self.client_master_secret = None
        self.server_master_secret = None
        self.client_session_key = None
        self.server_session_key = None
        self.client_finished = None
        self.server_finished = None

    def client_hello(self):
        if self.step != 0:
            raise ValueError("Reset the handshake before starting again.")

        self.transcript.append("Client Hello")
        self.step = 1

        return {
            "step": 1,
            "name": "Client Hello",
            "sender": "Client",
            "supported_cipher_suites": [
                "RSA + AES-256 (educational simulation)"
            ],
            "explanation": (
                "The client announces its supported cipher suites "
                "and starts the TLS handshake."
            ),
        }

    def server_hello(self):
        if self.step != 1:
            raise ValueError("Complete Client Hello first.")

        self.server_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.server_public_key = self.server_private_key.public_key()

        public_key_pem = self.server_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        self.transcript.append("Server Hello")
        self.step = 2

        return {
            "step": 2,
            "name": "Server Hello + Certificate",
            "sender": "Server",
            "selected_cipher_suite": "RSA + AES-256 (educational)",
            "public_key": public_key_pem,
            "explanation": (
                "The server selects a cipher suite and shares its "
                "public key. This is a simulated certificate exchange; "
                "a real certificate must be validated against a trusted "
                "certificate authority."
            ),
        }

    def client_key_exchange(self):
        if self.step != 2:
            raise ValueError("Complete Server Hello first.")

        # The client creates a random 48-byte pre-master secret.
        self.premaster_secret = os.urandom(48)

        # Encrypt it with the server's public key.
        self.encrypted_premaster_secret = (
            self.server_public_key.encrypt(
                self.premaster_secret,
                padding.PKCS1v15(),
            )
        )

        self.transcript.append("Client Key Exchange")
        self.step = 3

        return {
            "step": 3,
            "name": "Client Key Exchange",
            "sender": "Client",
            "encrypted_premaster_secret": base64.b64encode(
                self.encrypted_premaster_secret
            ).decode("utf-8"),
            "explanation": (
                "The client generates a random pre-master secret "
                "and encrypts it with the server's RSA public key. "
                "Only the matching private key can decrypt it."
            ),
        }

    @staticmethod
    def derive_master_secret(premaster_secret, transcript_hash):
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=transcript_hash,
            info=b"SecureTunnel educational master secret",
        ).derive(premaster_secret)

    @staticmethod
    def derive_session_key(master_secret):
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"SecureTunnel educational session key",
        ).derive(master_secret)

    def generate_session_keys(self):
        if self.step != 3:
            raise ValueError("Complete Client Key Exchange first.")

        # The client derives its master secret from the original secret.
        transcript_hash = hashlib.sha256(
            "|".join(self.transcript[:2]).encode("utf-8")
        ).digest()

        self.client_master_secret = self.derive_master_secret(
            self.premaster_secret,
            transcript_hash,
        )

        # The server independently decrypts the encrypted secret.
        server_premaster_secret = (
            self.server_private_key.decrypt(
                self.encrypted_premaster_secret,
                padding.PKCS1v15(),
            )
        )

        self.server_master_secret = self.derive_master_secret(
            server_premaster_secret,
            transcript_hash,
        )

        # Both sides independently derive their session keys.
        self.client_session_key = self.derive_session_key(
            self.client_master_secret
        )
        self.server_session_key = self.derive_session_key(
            self.server_master_secret
        )

        self.transcript.append("Session Keys Generated")
        self.step = 4

        return {
            "step": 4,
            "name": "Session Key Generation",
            "client_master_secret_match": hmac.compare_digest(
                self.client_master_secret,
                self.server_master_secret,
            ),
            "session_keys_match": hmac.compare_digest(
                self.client_session_key,
                self.server_session_key,
            ),
            "explanation": (
                "The server decrypts the pre-master secret using its "
                "private key. The client and server independently "
                "derive matching master secrets and session keys."
            ),
        }

    def finished(self):
        if self.step != 4:
            raise ValueError("Generate session keys first.")

        # Distinct confirmation values for each direction.
        client_message = (
            b"client finished|"
            + "|".join(self.transcript).encode("utf-8")
        )
        server_message = (
            b"server finished|"
            + "|".join(self.transcript).encode("utf-8")
        )

        self.client_finished = hmac.new(
            self.client_session_key,
            client_message,
            hashlib.sha256,
        ).hexdigest()

        self.server_finished = hmac.new(
            self.server_session_key,
            server_message,
            hashlib.sha256,
        ).hexdigest()

        finished_valid = (
            hmac.compare_digest(
                self.client_finished,
                hmac.new(
                    self.server_session_key,
                    client_message,
                    hashlib.sha256,
                ).hexdigest(),
            )
            and hmac.compare_digest(
                self.server_finished,
                hmac.new(
                    self.client_session_key,
                    server_message,
                    hashlib.sha256,
                ).hexdigest(),
            )
        )

        self.transcript.append("Finished")
        self.step = 5

        return {
            "step": 5,
            "name": "Finished",
            "client_finished_verified": finished_valid,
            "server_finished_verified": finished_valid,
            "secure_channel_established": finished_valid,
            "explanation": (
                "Both parties verify handshake confirmation messages "
                "using HMAC and their derived session keys."
            ),
        }
