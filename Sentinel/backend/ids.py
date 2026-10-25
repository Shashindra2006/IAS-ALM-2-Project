
from collections import defaultdict, deque
from datetime import datetime, timedelta
from statistics import mean, pstdev

from models import IDSAlert


class IntrusionDetector:
    def __init__(self):
        self.failed_logins = defaultdict(deque)
        self.port_history = defaultdict(deque)
        self.packet_history = defaultdict(deque)
        self.rate_baseline = defaultdict(lambda: deque(maxlen=100))

    def inspect(self, packet, db):
        alerts = []
        now = datetime.utcnow()
        source_ip = packet["source_ip"]
        protocol = packet["protocol"].upper()
        port = packet["port"]

        # Rule 1: Suspicious Telnet traffic.
        if port == 23:
            alerts.append((
                "MEDIUM",
                "SUSPICIOUS_PORT",
                f"Telnet traffic detected from {source_ip}.",
            ))

        # Rule 2: Five failed SSH logins in one minute.
        if packet.get("event_type") == "failed_ssh_login":
            attempts = self.failed_logins[source_ip]
            attempts.append(now)

            cutoff = now - timedelta(minutes=1)
            while attempts and attempts[0] < cutoff:
                attempts.popleft()

            if len(attempts) == 5:
                alerts.append((
                    "HIGH",
                    "BRUTE_FORCE",
                    f"Five failed SSH logins in one minute from {source_ip}.",
                ))

        # Rule 3: Many destination ports in a short window.
        if packet.get("event_type") == "port_scan":
            history = self.port_history[source_ip]
            history.append((now, port))

            cutoff = now - timedelta(seconds=30)
            while history and history[0][0] < cutoff:
                history.popleft()

            distinct_ports = {item[1] for item in history}
            if len(distinct_ports) >= 10:
                alerts.append((
                    "HIGH",
                    "PORT_SCAN",
                    f"Simulated port scan detected from {source_ip}.",
                ))

        # Statistical anomaly: packet rate compared with baseline.
        history = self.packet_history[source_ip]
        history.append(now)

        cutoff = now - timedelta(seconds=1)
        while history and history[0] < cutoff:
            history.popleft()

        current_rate = len(history)
        baseline = list(self.rate_baseline[source_ip])

        if len(baseline) >= 10:
            baseline_mean = mean(baseline)
            baseline_std = pstdev(baseline)

            if current_rate > baseline_mean + 3 * baseline_std:
                alerts.append((
                    "HIGH",
                    "TRAFFIC_ANOMALY",
                    f"Unusual packet rate from {source_ip}: "
                    f"{current_rate} packets in the last second.",
                ))

        self.rate_baseline[source_ip].append(current_rate)

        created_alerts = []
        for severity, category, message in alerts:
            alert = IDSAlert(
                severity=severity,
                category=category,
                source_ip=source_ip,
                message=message,
            )
            db.add(alert)
            created_alerts.append(alert)

        if created_alerts:
            db.commit()
            for alert in created_alerts:
                db.refresh(alert)

        return {
            "current_packets_per_second": current_rate,
            "alerts": [
                {
                    "id": alert.id,
                    "severity": alert.severity,
                    "category": alert.category,
                    "source_ip": alert.source_ip,
                    "message": alert.message,
                    "created_at": alert.created_at.isoformat(),
                }
                for alert in created_alerts
            ],
        }


detector = IntrusionDetector()
