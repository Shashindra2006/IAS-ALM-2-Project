
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy.orm import Session
from fastapi import Depends
from fastapi.responses import Response
from crypto_utils import generate_x509_certificate
from pwdlib import PasswordHash

from database import Base, engine, get_db
from models import User

password_hash = PasswordHash.recommended()

Base.metadata.create_all(bind=engine)
from crypto_utils import (
    generate_rsa_keys,
    encrypt_message,
    decrypt_message,
    sign_message,
    verify_signature,
    generate_dh_parameters,
    perform_dh_exchange,
    generate_elgamal_keys,
    elgamal_sign,
    elgamal_verify
)

app = FastAPI(
    title="CryptoVault API",
    description="Public-Key Cryptography and Digital Signature Toolkit",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class EncryptRequest(BaseModel):
    message: str
    public_key: str


class DecryptRequest(BaseModel):
    ciphertext: str
    private_key: str


class SignRequest(BaseModel):
    message: str
    private_key: str


class VerifyRequest(BaseModel):
    message: str
    signature: str
    public_key: str


@app.get("/")
def home():
    return {
        "message": "Welcome to CryptoVault!",
        "status": "running"
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "project": "CryptoVault"
    }


@app.post("/rsa/generate-keys")
def generate_keys():
    return generate_rsa_keys()


@app.post("/rsa/encrypt")
def rsa_encrypt(request: EncryptRequest):
    try:
        ciphertext = encrypt_message(
            request.message,
            request.public_key
        )
        return {"ciphertext": ciphertext}
    except Exception as error:
        raise HTTPException(
            status_code=400,
            detail=f"Encryption failed: {error}"
        )


@app.post("/rsa/decrypt")
def rsa_decrypt(request: DecryptRequest):
    try:
        plaintext = decrypt_message(
            request.ciphertext,
            request.private_key
        )
        return {"plaintext": plaintext}
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Decryption failed. Check the ciphertext and private key."
        )


@app.post("/rsa/sign")
def rsa_sign(request: SignRequest):
    try:
        signature = sign_message(
            request.message,
            request.private_key
        )
        return {"signature": signature}
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Signing failed. Check the private key and message."
        )


@app.post("/rsa/verify")
def rsa_verify(request: VerifyRequest):
    try:
        valid = verify_signature(
            request.message,
            request.signature,
            request.public_key
        )
        return {
            "valid": valid,
            "message": (
                "Signature is valid"
                if valid
                else "Signature is invalid"
            )
        }
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Verification failed. Check the supplied inputs."
        )

@app.get("/dh/parameters")
def dh_parameters():
    return generate_dh_parameters()


@app.post("/dh/exchange")
def dh_exchange():
    return perform_dh_exchange()

from pydantic import BaseModel


class ElGamalSignRequest(BaseModel):
    message: str
    p: int
    g: int
    private_key: int


class ElGamalVerifyRequest(BaseModel):
    message: str
    p: int
    g: int
    public_key: int
    r: int
    s: int

class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str


class LoginRequest(BaseModel):
    username: str
    password: str



@app.post("/elgamal/generate-keys")
def elgamal_generate_keys():
    return generate_elgamal_keys()


@app.post("/elgamal/sign")
def elgamal_sign_endpoint(request: ElGamalSignRequest):
    try:
        return elgamal_sign(
            request.message,
            request.p,
            request.g,
            request.private_key
        )
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="ElGamal signing failed. Check the parameters."
        )


@app.post("/elgamal/verify")
def elgamal_verify_endpoint(request: ElGamalVerifyRequest):
    try:
        valid = elgamal_verify(
            request.message,
            request.p,
            request.g,
            request.public_key,
            request.r,
            request.s
        )
        return {
            "valid": valid,
            "message": (
                "Signature is valid"
                if valid
                else "Signature is invalid"
            )
        }
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="ElGamal verification failed. Check the inputs."
        )

@app.post("/auth/register")
def register_user(
    request: RegisterRequest,
    db: Session = Depends(get_db)
):
    if db.query(User).filter(
        (User.username == request.username) |
        (User.email == request.email)
    ).first():
        raise HTTPException(
            status_code=409,
            detail="Username or email already exists"
        )

    if len(request.password) < 8:
        raise HTTPException(
            status_code=400,
            detail="Password must contain at least 8 characters"
        )

    keys = generate_rsa_keys()

    user = User(
        username=request.username,
        email=request.email,
        password_hash=password_hash.hash(request.password),
        public_key=keys["public_key"],
        private_key=keys["private_key"]
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    return {
        "message": "Registration successful",
        "user_id": user.id,
        "username": user.username,
        "public_key": user.public_key
    }


@app.post("/auth/login")
def login_user(
    request: LoginRequest,
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(
        User.username == request.username
    ).first()

    if not user or not password_hash.verify(
        request.password,
        user.password_hash
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password"
        )

    return {
        "message": "Login successful",
        "user_id": user.id,
        "username": user.username,
        "public_key": user.public_key
    }

@app.get("/certificates/{user_id}/download")
def download_certificate(
    user_id: int,
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(
        User.id == user_id
    ).first()

    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    try:
        certificate_pem = generate_x509_certificate(
            user.username,
            user.private_key
        )
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Certificate generation failed"
        )

    return Response(
        content=certificate_pem,
        media_type="application/x-pem-file",
        headers={
            "Content-Disposition":
                f'attachment; filename="{user.username}.crt.pem"'
        }
    )
