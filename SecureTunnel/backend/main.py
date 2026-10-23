
from uuid import uuid4
import hmac
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from tls_simulator import TLSSimulator
from ssh_simulator import SSHSimulator

app = FastAPI(
    title="SecureTunnel API",
    description="Educational TLS, SSH and IPsec visualizer",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory handshake sessions for this educational project.
tls_sessions = {}
ssh_sessions = {}

@app.get("/")
def home():
    return {
        "project": "SecureTunnel",
        "message": "SecureTunnel backend is running!",
        "modules": ["TLS", "SSH", "IPsec"],
    }


@app.get("/health")
def health_check():
    return {"status": "healthy"}


@app.post("/tls/start")
def start_tls():
    session_id = str(uuid4())
    tls_sessions[session_id] = TLSSimulator()

    return {
        "session_id": session_id,
        "message": "TLS simulation started",
        "current_step": 0,
    }


@app.post("/tls/{session_id}/step/{step_number}")
def advance_tls(session_id: str, step_number: int):
    tls = tls_sessions.get(session_id)

    if tls is None:
        raise HTTPException(
            status_code=404,
            detail="TLS session not found. Start a new handshake.",
        )

    steps = {
        1: tls.client_hello,
        2: tls.server_hello,
        3: tls.client_key_exchange,
        4: tls.generate_session_keys,
        5: tls.finished,
    }

    if step_number not in steps:
        raise HTTPException(
            status_code=400,
            detail="Step number must be between 1 and 5.",
        )

    if step_number != tls.step + 1:
        raise HTTPException(
            status_code=409,
            detail=f"Expected step {tls.step + 1}, not {step_number}.",
        )

    try:
        result = steps[step_number]()
        return {
            "session_id": session_id,
            "current_step": tls.step,
            "result": result,
        }
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/tls/{session_id}/status")
def tls_status(session_id: str):
    tls = tls_sessions.get(session_id)

    if tls is None:
        raise HTTPException(status_code=404, detail="TLS session not found.")

    return {
        "session_id": session_id,
        "current_step": tls.step,
        "complete": tls.step == 5,
        "session_keys_match": (
            tls.client_session_key == tls.server_session_key
            if tls.step >= 4
            else None
        ),
    }


@app.post("/tls/{session_id}/reset")
def reset_tls(session_id: str):
    if session_id not in tls_sessions:
        raise HTTPException(status_code=404, detail="TLS session not found.")

    tls_sessions[session_id].reset()

    return {
        "session_id": session_id,
        "current_step": 0,
        "message": "TLS simulation reset",
    }

@app.post("/ssh/start")
def start_ssh():
    session_id = str(uuid4())
    ssh_sessions[session_id] = SSHSimulator()

    return {
        "session_id": session_id,
        "message": "SSH simulation started",
        "current_step": 0,
    }


@app.post("/ssh/{session_id}/step/{step_number}")
def advance_ssh(session_id: str, step_number: int):
    ssh = ssh_sessions.get(session_id)

    if ssh is None:
        raise HTTPException(status_code=404, detail="SSH session not found.")

    steps = {
        1: ssh.version_exchange,
        2: ssh.key_exchange,
        3: ssh.server_authentication,
        4: ssh.user_authentication,
        5: ssh.establish_secure_channel,
    }

    if step_number not in steps:
        raise HTTPException(
            status_code=400,
            detail="Step number must be between 1 and 5.",
        )

    if step_number != ssh.step + 1:
        raise HTTPException(
            status_code=409,
            detail=f"Expected step {ssh.step + 1}, not {step_number}.",
        )

    try:
        result = steps[step_number]()
        return {
            "session_id": session_id,
            "current_step": ssh.step,
            "result": result,
        }
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/ssh/{session_id}/status")
def ssh_status(session_id: str):
    ssh = ssh_sessions.get(session_id)

    if ssh is None:
        raise HTTPException(status_code=404, detail="SSH session not found.")

    return {
        "session_id": session_id,
        "current_step": ssh.step,
        "complete": ssh.step == 5,
        "session_keys_match": (
            hmac.compare_digest(
                ssh.client_session_key,
                ssh.server_session_key,
            )
            if ssh.step == 5
            else None
        ),
    }


@app.post("/ssh/{session_id}/reset")
def reset_ssh(session_id: str):
    if session_id not in ssh_sessions:
        raise HTTPException(status_code=404, detail="SSH session not found.")

    ssh_sessions[session_id].reset()

    return {
        "session_id": session_id,
        "current_step": 0,
        "message": "SSH simulation reset",
    }
