
import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("utf-8")

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")

    return {
        "public_key": public_pem,
        "private_key": private_pem
    }


def load_public_key(public_key_pem):
    return serialization.load_pem_public_key(
        public_key_pem.encode("utf-8")
    )


def load_private_key(private_key_pem):
    return serialization.load_pem_private_key(
        private_key_pem.encode("utf-8"),
        password=None
    )


def encrypt_message(message, public_key_pem):
    public_key = load_public_key(public_key_pem)

    ciphertext = public_key.encrypt(
        message.encode("utf-8"),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return base64.b64encode(ciphertext).decode("utf-8")


def decrypt_message(ciphertext, private_key_pem):
    private_key = load_private_key(private_key_pem)

    encrypted_bytes = base64.b64decode(ciphertext, validate=True)

    plaintext = private_key.decrypt(
        encrypted_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return plaintext.decode("utf-8")


def sign_message(message, private_key_pem):
    private_key = load_private_key(private_key_pem)

    signature = private_key.sign(
        message.encode("utf-8"),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return base64.b64encode(signature).decode("utf-8")


def verify_signature(message, signature, public_key_pem):
    public_key = load_public_key(public_key_pem)

    signature_bytes = base64.b64decode(signature, validate=True)

    try:
        public_key.verify(
            signature_bytes,
            message.encode("utf-8"),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False

import secrets


def generate_dh_parameters():
    return {
        "p": 23,
        "g": 5
    }


def perform_dh_exchange():
    p = 23
    g = 5

    # Alice and Bob choose their private keys
    a = secrets.randbelow(10) + 2
    b = secrets.randbelow(10) + 2

    # Calculate public keys
    A = pow(g, a, p)
    B = pow(g, b, p)

    # Calculate the shared secret independently
    alice_secret = pow(B, a, p)
    bob_secret = pow(A, b, p)

    return {
        "p": p,
        "g": g,
        "alice_private": a,
        "bob_private": b,
        "alice_public": A,
        "bob_public": B,
        "alice_shared_secret": alice_secret,
        "bob_shared_secret": bob_secret,
        "match": alice_secret == bob_secret
    }

import hashlib
import math
import secrets


def generate_elgamal_keys():
    # Small educational parameters only; not secure for real use.
    p = 467
    g = 2
    x = secrets.randbelow(p - 2) + 1
    y = pow(g, x, p)

    return {
        "p": p,
        "g": g,
        "private_key": x,
        "public_key": y
    }


def elgamal_sign(message, p, g, x):
    message_hash = hashlib.sha512(
        message.encode("utf-8")
    ).hexdigest()

    h = int(message_hash, 16) % (p - 1)

    while True:
        k = secrets.randbelow(p - 2) + 1

        if math.gcd(k, p - 1) == 1:
            break

    r = pow(g, k, p)
    k_inverse = pow(k, -1, p - 1)
    s = (k_inverse * (h - x * r)) % (p - 1)

    return {
        "hash": message_hash,
        "r": r,
        "s": s
    }


def elgamal_verify(message, p, g, y, r, s):
    if not (0 < r < p and 0 <= s < p - 1):
        return False

    message_hash = hashlib.sha512(
        message.encode("utf-8")
    ).hexdigest()

    h = int(message_hash, 16) % (p - 1)

    left = pow(g, h, p)
    right = (pow(y, r, p) * pow(r, s, p)) % p

    return left == right

from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization


def generate_x509_certificate(username, private_key_pem):
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode("utf-8"),
        password=None
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, username),
        x509.NameAttribute(
            NameOID.ORGANIZATION_NAME,
            "CryptoVault"
        ),
    ])

    now = datetime.now(timezone.utc)

    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        )
        .sign(private_key, hashes.SHA256())
    )

    return certificate.public_bytes(
        serialization.Encoding.PEM
    ).decode("utf-8")
