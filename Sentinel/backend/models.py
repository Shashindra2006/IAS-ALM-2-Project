
from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Integer,
    String,
    Text,
)

from database import Base


class FirewallRule(Base):
    __tablename__ = "firewall_rules"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    source_ip = Column(String(45), default="*")
    destination_ip = Column(String(45), default="*")
    port = Column(Integer, nullable=True)
    protocol = Column(String(10), default="ANY")
    action = Column(String(10), nullable=False)  # ALLOW or BLOCK
    priority = Column(Integer, default=100)
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class IDSAlert(Base):
    __tablename__ = "ids_alerts"

    id = Column(Integer, primary_key=True, index=True)
    severity = Column(String(20), nullable=False)
    category = Column(String(50), nullable=False)
    source_ip = Column(String(45), nullable=False)
    message = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
