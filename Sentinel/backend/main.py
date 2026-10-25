
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Literal

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from database import Base, engine, get_db
from firewall import process_packet
from ids import detector
from models import FirewallRule, IDSAlert


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title="Sentinel IDS & Firewall Simulator",
    description="Educational simulation of firewall and IDS concepts.",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5174",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class FirewallRuleInput(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    source_ip: str = "*"
    destination_ip: str = "*"
    port: int | None = Field(default=None, ge=1, le=65535)
    protocol: Literal["ANY", "TCP", "UDP", "ICMP"] = "ANY"
    action: Literal["ALLOW", "BLOCK"]
    priority: int = Field(default=100, ge=1, le=10000)
    enabled: bool = True


class PacketInput(BaseModel):
    source_ip: str = "192.168.1.10"
    destination_ip: str = "192.168.1.20"
    port: int = Field(default=80, ge=1, le=65535)
    protocol: Literal["TCP", "UDP", "ICMP"] = "TCP"
    event_type: Literal[
        "normal",
        "failed_ssh_login",
        "port_scan",
    ] = "normal"


def rule_to_dict(rule):
    return {
        "id": rule.id,
        "name": rule.name,
        "source_ip": rule.source_ip,
        "destination_ip": rule.destination_ip,
        "port": rule.port,
        "protocol": rule.protocol,
        "action": rule.action,
        "priority": rule.priority,
        "enabled": rule.enabled,
    }


@app.get("/")
def root():
    return {"message": "Sentinel API is running"}


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.get("/firewall/rules")
def list_rules(db: Session = Depends(get_db)):
    rules = (
        db.query(FirewallRule)
        .order_by(FirewallRule.priority, FirewallRule.id)
        .all()
    )
    return [rule_to_dict(rule) for rule in rules]


@app.post("/firewall/rules", status_code=201)
def create_rule(
    data: FirewallRuleInput,
    db: Session = Depends(get_db),
):
    rule = FirewallRule(**data.model_dump())
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return rule_to_dict(rule)


@app.put("/firewall/rules/{rule_id}")
def update_rule(
    rule_id: int,
    data: FirewallRuleInput,
    db: Session = Depends(get_db),
):
    rule = db.get(FirewallRule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    for key, value in data.model_dump().items():
        setattr(rule, key, value)

    db.commit()
    db.refresh(rule)
    return rule_to_dict(rule)


@app.delete("/firewall/rules/{rule_id}")
def delete_rule(rule_id: int, db: Session = Depends(get_db)):
    rule = db.get(FirewallRule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    db.delete(rule)
    db.commit()
    return {"message": "Firewall rule deleted"}


@app.post("/traffic/simulate")
def simulate_packet(
    packet: PacketInput,
    db: Session = Depends(get_db),
):
    packet_data = packet.model_dump()

    # IDS inspects the simulated event and records alerts.
    ids_result = detector.inspect(packet_data, db)

    # Firewall independently evaluates the packet against saved rules.
    rules = (
        db.query(FirewallRule)
        .filter(FirewallRule.enabled.is_(True))
        .order_by(FirewallRule.priority, FirewallRule.id)
        .all()
    )
    firewall_result = process_packet(packet_data, rules)

    return {
        "timestamp": datetime.utcnow().isoformat(),
        "packet": packet_data,
        "firewall": firewall_result,
        "ids": ids_result,
    }


@app.get("/ids/alerts")
def list_alerts(
    limit: int = 100,
    db: Session = Depends(get_db),
):
    if not 1 <= limit <= 500:
        raise HTTPException(
            status_code=400,
            detail="limit must be between 1 and 500",
        )

    alerts = (
        db.query(IDSAlert)
        .order_by(IDSAlert.created_at.desc())
        .limit(limit)
        .all()
    )

    return [
        {
            "id": alert.id,
            "severity": alert.severity,
            "category": alert.category,
            "source_ip": alert.source_ip,
            "message": alert.message,
            "created_at": alert.created_at.isoformat(),
        }
        for alert in alerts
    ]


@app.delete("/ids/alerts")
def clear_alerts(db: Session = Depends(get_db)):
    db.query(IDSAlert).delete()
    db.commit()
    return {"message": "IDS alerts cleared"}
