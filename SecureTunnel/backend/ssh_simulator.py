
import hashlib
import hmac
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class SSHSimulator:
    """Educational simulation of a five-step SSH connection."""

    def __init__(self):
        self.reset()

    def reset(self):
        self.step = 0
        self.client_version = None
        self.server_version = None

        self.parameters = None
        self.client_private_key = None
        self.server_private_key = None
        self.client_shared_key = None
        self.server_shared_key = None

        self.server_signing_key = None
        self.server_public_key_bytes = None
        self.server_fingerprint = None
        self.client_verified_server = False

        self.user_authenticated = False
        self.username = None
        self.client_session_key = None
        self.server_session_key = None

    def version_exchange(self):
        if self.step != 0:
            raise ValueError("Reset the SSH simulation first.")

        self.client_version = "SSH-2.0-SecureTunnelClient"
        self.server_version = "SSH-2.0-SecureTunnelServer"

        self.step = 1

        return {
            "step": 1,
            "name": "Protocol Version Exchange",
            "client_version": self.client_version,
            "server_version": self.server_version,
            "explanation": (
                "The client and server announce their SSH protocol "
                "versions before negotiating the connection."
            ),
        }

    def key_exchange(self):
        if self.step != 1:
            raise ValueError("Complete protocol version exchange first.")

        # Generate ephemeral Diffie-Hellman parameters and keys.
        # 2048-bit parameters are suitable for this educational demo.
        self.parameters = dh.generate_parameters(
            generator=2,
            key_size=2048,
        )

        self.client_private_key = self.parameters.generate_private_key()
        self.server_private_key = self.parameters.generate_private_key()

        client_public_key = self.client_private_key.public_key()
        server_public_key = self.server_private_key.public_key()

        # Each side calculates the shared secret independently.
        self.client_shared_key = (
            self.client_private_key.exchange(server_public_key)
        )
        self.server_shared_key = (
            self.server_private_key.exchange(client_public_key)
        )

        self.step = 2

        return {
            "step": 2,
            "name": "Diffie-Hellman Key Exchange",
            "client_public_key": client_public_key.public_numbers().y,
            "server_public_key": server_public_key.public_numbers().y,
            "shared_secret_match": hmac.compare_digest(
                self.client_shared_key,
                self.server_shared_key,
            ),
            "explanation": (
                "Both sides exchange public DH values and independently "
                "derive the same shared secret. The private values remain "
                "secret."
            ),
        }

    def server_authentication(self):
        if self.step != 2:
            raise ValueError("Complete Diffie-Hellman key exchange first.")

        # Create a server identity key for this simulation.
        self.server_signing_key = ed25519.Ed25519PrivateKey.generate()
        public_key = self.server_signing_key.public_key()

        self.server_public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        self.server_fingerprint = hashlib.sha256(
            self.server_public_key_bytes
        ).hexdigest()

        # Sign the handshake transcript to demonstrate server identity.
        transcript = (
            f"{self.client_version}|{self.server_version}"
        ).encode() + self.server_public_key_bytes

        signature = self.server_signing_key.sign(transcript)

        # In this demo, the client receives the expected fingerprint
        # through a trusted local value. Real SSH requires a trusted
        # host key or a verified host certificate.
        received_public_key = ed25519.Ed25519PublicKey.from_public_bytes(
            self.server_public_key_bytes
        )

        received_public_key.verify(signature, transcript)

        received_fingerprint = hashlib.sha256(
            self.server_public_key_bytes
        ).hexdigest()

        self.client_verified_server = hmac.compare_digest(
            self.server_fingerprint,
            received_fingerprint,
        )

        self.step = 3

        return {
            "step": 3,
            "name": "Server Authentication",
            "server_public_key": self.server_public_key_bytes.hex(),
            "server_fingerprint": self.server_fingerprint,
            "signature_valid": self.client_verified_server,
            "explanation": (
                "The server signs handshake data using its Ed25519 "
                "identity key. The client verifies the signature and "
                "compares the fingerprint. A real SSH client must also "
                "establish trust in the host key."
            ),
        }

    def user_authentication(self, username="student", password="demo-password"):
        if self.step != 3:
            raise ValueError("Complete server authentication first.")

        # Demo credentials only. Never use these as real credentials.
        expected_username = "student"
        expected_password = "demo-password"

        username_ok = hmac.compare_digest(
            username.encode(), expected_username.encode()
        )
        password_ok = hmac.compare_digest(
            password.encode(), expected_password.encode()
        )

        self.user_authenticated = (
            username_ok and password_ok and self.client_verified_server
        )

        if not self.user_authenticated:
            raise ValueError(
                "Authentication failed. For this demo, use "
                "username 'student' and password 'demo-password'."
            )

        self.username = username
        self.step = 4

        return {
            "step": 4,
            "name": "User Authentication",
            "username": self.username,
            "authenticated": True,
            "method": "Simulated password authentication",
            "explanation": (
                "The server checks the supplied demo credentials. "
                "No real account is created and no password is stored."
            ),
        }

    def establish_secure_channel(self):
        if self.step != 4:
            raise ValueError("Complete user authentication first.")

        if not self.client_verified_server or not self.user_authenticated:
            raise ValueError("Authentication requirements are not satisfied.")

        # Both sides derive keys independently from their DH secret.
        self.client_session_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"SecureTunnel SSH educational session",
        ).derive(self.client_shared_key)

        self.server_session_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"SecureTunnel SSH educational session",
        ).derive(self.server_shared_key)

        keys_match = hmac.compare_digest(
            self.client_session_key,
            self.server_session_key,
        )

        self.step = 5

        return {
            "step": 5,
            "name": "Secure Channel Established",
            "session_keys_match": keys_match,
            "secure_channel_established": keys_match,
            "explanation": (
                "Both sides derive matching session keys from their "
                "Diffie-Hellman shared secret. This demonstrates the "
                "concept of establishing a secure channel."
            ),
        }
