
import { useEffect, useState } from "react";
import axios from "axios";
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
} from "recharts";
import "./App.css";

const API = "http://127.0.0.1:8000";

function App() {
  const [tab, setTab] = useState("overview");
  const [rules, setRules] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [traffic, setTraffic] = useState([]);
  const [message, setMessage] = useState("");
  const [loading, setLoading] = useState(false);
  const [ruleForm, setRuleForm] = useState({
    name: "Allow HTTP",
    source_ip: "*",
    destination_ip: "*",
    port: 80,
    protocol: "TCP",
    action: "ALLOW",
    priority: 10,
    enabled: true,
  });
  const [packet, setPacket] = useState({
    source_ip: "192.168.1.10",
    destination_ip: "192.168.1.20",
    port: 80,
    protocol: "TCP",
    event_type: "normal",
  });

  async function loadData() {
    try {
      const [ruleResponse, alertResponse] = await Promise.all([
        axios.get(`${API}/firewall/rules`),
        axios.get(`${API}/ids/alerts`),
      ]);
      setRules(ruleResponse.data);
      setAlerts(alertResponse.data);
    } catch {
      setMessage("Backend unavailable. Start FastAPI on port 8000.");
    }
  }

  useEffect(() => {
    loadData();
    const timer = setInterval(loadData, 3000);
    return () => clearInterval(timer);
  }, []);

  async function addRule(event) {
    event.preventDefault();
    setLoading(true);
    try {
      await axios.post(`${API}/firewall/rules`, {
        ...ruleForm,
        port: ruleForm.port === "" ? null : Number(ruleForm.port),
        priority: Number(ruleForm.priority),
      });
      setMessage("Firewall rule added successfully.");
      await loadData();
    } catch (error) {
      setMessage(error.response?.data?.detail
        ? JSON.stringify(error.response.data.detail)
        : "Could not add firewall rule.");
    } finally {
      setLoading(false);
    }
  }

  async function deleteRule(id) {
    try {
      await axios.delete(`${API}/firewall/rules/${id}`);
      setMessage("Firewall rule deleted.");
      await loadData();
    } catch {
      setMessage("Could not delete firewall rule.");
    }
  }

  async function simulateTraffic(eventType = packet.event_type) {
    setLoading(true);
    try {
      const payload = {
        ...packet,
        port: Number(packet.port),
        event_type: eventType,
      };
      const response = await axios.post(`${API}/traffic/simulate`, payload);
      const result = response.data;

      setTraffic((previous) => [
        {
          time: new Date().toLocaleTimeString(),
          rate: result.ids.current_packets_per_second,
        },
        ...previous,
      ].slice(0, 20));

      setMessage(
        `Firewall: ${result.firewall.decision} — ${result.firewall.reason}`
      );
      await loadData();
    } catch {
      setMessage("Traffic simulation failed. Check the backend.");
    } finally {
      setLoading(false);
    }
  }

  async function simulateBurst() {
    setLoading(true);
    try {
      for (let i = 0; i < 10; i++) {
        await axios.post(`${API}/traffic/simulate`, {
          source_ip: "192.168.1.100",
          destination_ip: "192.168.1.20",
          port: 22,
          protocol: "TCP",
          event_type: "failed_ssh_login",
        });
      }
      setMessage("Simulated 10 failed SSH login attempts.");
      await loadData();
    } catch {
      setMessage("Could not run the simulated SSH burst.");
    } finally {
      setLoading(false);
    }
  }

  const stats = [
    { label: "Firewall rules", value: rules.length },
    { label: "IDS alerts", value: alerts.length },
    { label: "High severity", value: alerts.filter((a) => a.severity === "HIGH").length },
    { label: "Traffic events", value: traffic.length },
  ];

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-icon">S</div>
          <div>
            <h2>SENTINEL</h2>
            <span>NETWORK DEFENSE</span>
          </div>
        </div>

        <div className="side-label">MONITORING</div>
        {[
          ["overview", "▦", "Overview"],
          ["firewall", "◈", "Firewall Rules"],
          ["traffic", "⌁", "Traffic Simulator"],
          ["alerts", "⚠", "IDS Alerts"],
          ["threats", "⬡", "Threat Encyclopedia"],
        ].map(([id, icon, label]) => (
          <button
            key={id}
            className={`nav-item ${tab === id ? "active" : ""}`}
            onClick={() => setTab(id)}
          >
            <span>{icon}</span>{label}
            {id === "alerts" && alerts.length > 0 &&
              <span className="nav-count">{alerts.length}</span>}
          </button>
        ))}

        <div className="sidebar-bottom">
          <span className="live-dot" />
          SIMULATION MODE
          <p>Educational network security lab</p>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div>
            <div className="eyebrow">SECURITY OPERATIONS CENTER / LAB</div>
            <h1>
              {tab === "overview" ? "Security Overview" :
               tab === "firewall" ? "Firewall Management" :
               tab === "traffic" ? "Network Traffic Simulator" :
               tab === "alerts" ? "Intrusion Detection" : "Threat Encyclopedia"}
            </h1>
          </div>
          <div className="system-status"><span className="live-dot" /> LOCAL LAB</div>
        </header>

        {message && (
          <div className="notice">
            <span>{message}</span>
            <button onClick={() => setMessage("")}>×</button>
          </div>
        )}

        {tab === "overview" && (
          <>
            <section className="welcome-panel">
              <div>
                <span className="pill">● SYSTEM SIMULATION ACTIVE</span>
                <h2>See threats. Understand risk.<br />Control the traffic.</h2>
                <p>Simulate network activity and observe how firewall policies and intrusion detection respond.</p>
                <button className="primary-btn" onClick={() => setTab("traffic")}>
                  Launch traffic simulator →
                </button>
              </div>
              <div className="shield-art">⬡</div>
            </section>

            <section className="stat-grid">
              {stats.map((stat, index) => (
                <div className="stat-card" key={stat.label}>
                  <div className={`stat-symbol symbol-${index}`}>{["◈", "⚠", "!", "⌁"][index]}</div>
                  <p>{stat.label}</p>
                  <h2>{stat.value}</h2>
                  <span className="stat-caption">CURRENT SESSION DATA</span>
                </div>
              ))}
            </section>

            <section className="content-grid">
              <div className="panel">
                <div className="panel-heading">
                  <div><h3>Traffic rate monitor</h3><p>Packets observed in the latest one-second window</p></div>
                  <span className="small-tag">LIVE DEMO</span>
                </div>
                <div className="chart-area">
                  {traffic.length > 1 ? (
                    <ResponsiveContainer width="100%" height={230}>
                      <LineChart data={[...traffic].reverse()}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#263246" />
                        <XAxis dataKey="time" stroke="#7f8da5" />
                        <YAxis stroke="#7f8da5" />
                        <Tooltip />
                        <Line type="monotone" dataKey="rate" stroke="#38d9a9" strokeWidth={3} dot={false} />
                      </LineChart>
                    </ResponsiveContainer>
                  ) : (
                    <div className="empty-chart">
                      <span>⌁</span>
                      <p>Waiting for simulated traffic</p>
                      <button className="secondary-btn" onClick={() => setTab("traffic")}>Generate first event</button>
                    </div>
                  )}
                </div>
              </div>

              <div className="panel">
                <div className="panel-heading">
                  <div><h3>Recent IDS alerts</h3><p>Latest detections from the backend</p></div>
                  <button className="text-btn" onClick={() => setTab("alerts")}>View all →</button>
                </div>
                <AlertList alerts={alerts.slice(0, 5)} />
              </div>
            </section>
          </>
        )}

        {tab === "firewall" && (
          <section className="panel">
            <div className="panel-heading">
              <div><h3>Firewall rule manager</h3><p>Lower priority numbers are evaluated first. Unmatched packets are blocked.</p></div>
              <span className="small-tag">{rules.length} RULES</span>
            </div>

            <form className="rule-form" onSubmit={addRule}>
              <label>Rule name<input required value={ruleForm.name} onChange={(e) => setRuleForm({...ruleForm, name: e.target.value})} /></label>
              <label>Source IP<input value={ruleForm.source_ip} onChange={(e) => setRuleForm({...ruleForm, source_ip: e.target.value || "*"})} /></label>
              <label>Destination IP<input value={ruleForm.destination_ip} onChange={(e) => setRuleForm({...ruleForm, destination_ip: e.target.value || "*"})} /></label>
              <label>Port<input type="number" min="1" max="65535" placeholder="Any port" value={ruleForm.port} onChange={(e) => setRuleForm({...ruleForm, port: e.target.value})} /></label>
              <label>Protocol<select value={ruleForm.protocol} onChange={(e) => setRuleForm({...ruleForm, protocol: e.target.value})}><option>ANY</option><option>TCP</option><option>UDP</option><option>ICMP</option></select></label>
              <label>Action<select value={ruleForm.action} onChange={(e) => setRuleForm({...ruleForm, action: e.target.value})}><option>ALLOW</option><option>BLOCK</option></select></label>
              <label>Priority<input type="number" min="1" value={ruleForm.priority} onChange={(e) => setRuleForm({...ruleForm, priority: e.target.value})} /></label>
              <button className="primary-btn" disabled={loading}>+ Add firewall rule</button>
            </form>

            <div className="table-wrap">
              <table>
                <thead><tr><th>PRIORITY</th><th>RULE</th><th>SOURCE</th><th>DESTINATION</th><th>PORT</th><th>PROTOCOL</th><th>ACTION</th><th>MANAGE</th></tr></thead>
                <tbody>
                  {rules.map((rule) => (
                    <tr key={rule.id}>
                      <td>{rule.priority}</td><td>{rule.name}</td><td>{rule.source_ip}</td><td>{rule.destination_ip}</td><td>{rule.port ?? "Any"}</td><td>{rule.protocol}</td>
                      <td><span className={`decision ${rule.action.toLowerCase()}`}>{rule.action}</span></td>
                      <td><button className="delete-btn" onClick={() => deleteRule(rule.id)}>Delete</button></td>
                    </tr>
                  ))}
                  {rules.length === 0 && <tr><td colSpan="8" className="empty-cell">No rules configured. Add a rule above.</td></tr>}
                </tbody>
              </table>
            </div>
          </section>
        )}

        {tab === "traffic" && (
          <section className="content-grid traffic-layout">
            <div className="panel">
              <div className="panel-heading"><div><h3>Craft a simulated packet</h3><p>Events stay inside this local simulation.</p></div></div>
              <form className="traffic-form" onSubmit={(e) => { e.preventDefault(); simulateTraffic(); }}>
                <label>Source IP<input value={packet.source_ip} onChange={(e) => setPacket({...packet, source_ip: e.target.value})} required /></label>
                <label>Destination IP<input value={packet.destination_ip} onChange={(e) => setPacket({...packet, destination_ip: e.target.value})} required /></label>
                <label>Destination port<input type="number" min="1" max="65535" value={packet.port} onChange={(e) => setPacket({...packet, port: e.target.value})} required /></label>
                <label>Protocol<select value={packet.protocol} onChange={(e) => setPacket({...packet, protocol: e.target.value})}><option>TCP</option><option>UDP</option><option>ICMP</option></select></label>
                <label>Event type<select value={packet.event_type} onChange={(e) => setPacket({...packet, event_type: e.target.value})}><option value="normal">Normal traffic</option><option value="failed_ssh_login">Failed SSH login</option><option value="port_scan">Simulated port scan</option></select></label>
                <button className="primary-btn" disabled={loading}>▶ Process packet</button>
              </form>
              <div className="preset-buttons">
                <button className="secondary-btn" disabled={loading} onClick={() => simulateTraffic("normal")}>HTTP request</button>
                <button className="secondary-btn" disabled={loading} onClick={() => simulateTraffic("failed_ssh_login")}>Failed SSH login</button>
                <button className="secondary-btn" disabled={loading} onClick={() => simulateTraffic("port_scan")}>Port scan event</button>
                <button className="danger-btn" disabled={loading} onClick={simulateBurst}>Simulate 10 SSH failures</button>
              </div>
            </div>

            <div className="panel">
              <div className="panel-heading"><div><h3>Traffic results</h3><p>Latest local event measurements</p></div></div>
              <div className="result-list">
                <div className="result-row"><span>Recent events</span><strong>{traffic.length}</strong></div>
                <div className="result-row"><span>Firewall decision</span><strong>See result notice above</strong></div>
                <div className="result-row"><span>Detection engine</span><strong>Rule + statistical demo</strong></div>
              </div>
              <div className="info-box">The firewall decision and IDS alerts are calculated by FastAPI, not by the frontend.</div>
            </div>
          </section>
        )}

        {tab === "alerts" && (
          <section className="panel">
            <div className="panel-heading"><div><h3>Intrusion detection feed</h3><p>Alerts refresh automatically every three seconds.</p></div><span className="small-tag">{alerts.length} ALERTS</span></div>
            <AlertList alerts={alerts} />
            {alerts.length > 0 && <button className="secondary-btn" onClick={async () => { await axios.delete(`${API}/ids/alerts`); await loadData(); }}>Clear alerts</button>}
          </section>
        )}

        {tab === "threats" && (
          <section className="encyclopedia-grid">
            <ThreatCard title="File-infector virus" type="VIRUS" description="A virus attaches its code to a host file or program. When that host executes, the malicious code may run too." defense="Use reputable endpoint protection, keep software updated, and avoid untrusted attachments or downloads." />
            <ThreatCard title="Boot-sector virus" type="VIRUS" description="A virus targets boot-related storage areas and may run during the startup process on affected systems." defense="Keep recovery media, apply security updates, and use modern protections such as Secure Boot where supported." />
            <ThreatCard title="Email worm" type="WORM" description="A worm can spread copies of itself between systems, for example through malicious email attachments or links." defense="Filter suspicious mail, verify unexpected attachments, use multi-factor authentication, and keep systems patched." />
            <ThreatCard title="Network worm" type="WORM" description="A network worm spreads between systems by exploiting reachable services or security weaknesses." defense="Patch exposed services, segment networks, minimize open ports, and monitor unusual connection patterns." />
            <div className="panel concept-note"><h3>Virus vs worm</h3><p>A virus typically relies on a host file or program. A worm can self-propagate between systems. Both can cause harm, and both require layered preventive controls.</p></div>
            <div className="panel concept-note"><h3>Bastion host concept</h3><p>A bastion host is a hardened system designed to provide controlled access across a network boundary. In real deployments, restrict its services, enforce strong authentication, patch it frequently, and monitor access.</p></div>
          </section>
        )}

        <footer> SENTINEL • EDUCATIONAL SECURITY SIMULATOR • NO REAL NETWORK TRAFFIC </footer>
      </main>
    </div>
  );
}

function AlertList({ alerts }) {
  if (!alerts.length) {
    return <div className="empty-alerts"><span>✓</span><p>No alerts recorded yet</p><small>Generate suspicious traffic to test the IDS.</small></div>;
  }

  return (
    <div className="alert-list">
      {alerts.map((alert) => (
        <div className="alert-row" key={alert.id}>
          <span className={`severity ${alert.severity.toLowerCase()}`}>{alert.severity}</span>
          <div><strong>{alert.category.replaceAll("_", " ")}</strong><p>{alert.message}</p><small>{alert.source_ip} · {new Date(alert.created_at).toLocaleTimeString()}</small></div>
        </div>
      ))}
    </div>
  );
}

function ThreatCard({ title, type, description, defense }) {
  return (
    <article className="panel threat-card">
      <span className="small-tag">{type}</span>
      <h3>{title}</h3>
      <p>{description}</p>
      <div className="defense-box"><strong>Countermeasures</strong><p>{defense}</p></div>
    </article>
  );
}

export default App;
