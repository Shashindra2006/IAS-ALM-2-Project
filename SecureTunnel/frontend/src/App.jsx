
import { useState } from "react";
import axios from "axios";
import "./App.css";
import Ipsec from "./Ipsec";

const API = "http://127.0.0.1:8000";

const protocols = {
  TLS: [
    {
      name: "Client Hello",
      sender: "CLIENT",
      description:
        "The browser announces the cipher suites it supports.",
    },
    {
      name: "Server Hello + Certificate",
      sender: "SERVER",
      description:
        "The server selects a cipher suite and shares its RSA public key.",
    },
    {
      name: "Client Key Exchange",
      sender: "CLIENT",
      description:
        "The client encrypts a random pre-master secret with the server's public key.",
    },
    {
      name: "Session Key Generation",
      sender: "BOTH",
      description:
        "The client and server independently derive matching session keys.",
    },
    {
      name: "Finished",
      sender: "BOTH",
      description:
        "Both sides verify handshake confirmation messages.",
    },
  ],

  SSH: [
    {
      name: "Protocol Version Exchange",
      sender: "BOTH",
      description:
        "The client and server announce their SSH protocol versions.",
    },
    {
      name: "Diffie-Hellman Key Exchange",
      sender: "BOTH",
      description:
        "Both sides exchange public values and independently derive a shared secret.",
    },
    {
      name: "Server Authentication",
      sender: "SERVER",
      description:
        "The client verifies the server's identity signature and public-key fingerprint.",
    },
    {
      name: "User Authentication",
      sender: "CLIENT",
      description:
        "The server checks the simulated user's credentials.",
    },
    {
      name: "Secure Channel Established",
      sender: "BOTH",
      description:
        "Both sides derive matching session keys.",
    },
  ],
};

const protocolInfo = {
  TLS: {
    title: "TLS Handshake",
    subtitle: "RSA + Session Keys",
    description:
      "Explore how a client and server establish a secure connection using asymmetric and symmetric cryptography.",
  },
  SSH: {
    title: "SSH Connection",
    subtitle: "Diffie–Hellman",
    description:
      "Explore protocol negotiation, key exchange, server identity verification, and simulated user authentication.",
  },
  IPsec: {
    title: "IPsec Packets",
    subtitle: "ESP Encapsulation",
    description:
      "Explore how IPsec ESP protects IP traffic using Transport Mode and Tunnel Mode.",
  },
};

export default function App() {
  const [protocol, setProtocol] = useState("TLS");

  const [sessions, setSessions] = useState({
    TLS: "",
    SSH: "",
  });

  const [progress, setProgress] = useState({
    TLS: 0,
    SSH: 0,
  });

  const [logs, setLogs] = useState({
    TLS: [],
    SSH: [],
  });

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const [complete, setComplete] = useState({
    TLS: false,
    SSH: false,
  });

  const isIpsec = protocol === "IPsec";
  const steps = protocols[protocol] || [];
  const currentStep = progress[protocol] ?? 0;
  const activeStep =
    currentStep > 0 ? steps[currentStep - 1] : null;
  const sessionId = sessions[protocol] || "";
  const currentLogs = logs[protocol] || [];
  const isComplete = complete[protocol] ?? false;
  const info = protocolInfo[protocol];

  async function startHandshake() {
    if (isIpsec) return;

    setLoading(true);
    setError("");

    try {
      const response = await axios.post(
        `${API}/${protocol.toLowerCase()}/start`
      );

      setSessions((old) => ({
        ...old,
        [protocol]: response.data.session_id,
      }));

      setProgress((old) => ({
        ...old,
        [protocol]: 0,
      }));

      setLogs((old) => ({
        ...old,
        [protocol]: [],
      }));

      setComplete((old) => ({
        ...old,
        [protocol]: false,
      }));
    } catch (err) {
      setError(
        err.response?.data?.detail ||
          "Cannot connect to the backend. Make sure FastAPI is running."
      );
    } finally {
      setLoading(false);
    }
  }

  async function nextStep() {
    if (isIpsec || !sessionId || currentStep >= 5) {
      return;
    }

    setLoading(true);
    setError("");

    try {
      const next = currentStep + 1;

      const response = await axios.post(
        `${API}/${protocol.toLowerCase()}/${sessionId}/step/${next}`
      );

      const result = response.data.result;

      setProgress((old) => ({
        ...old,
        [protocol]: next,
      }));

      setLogs((old) => ({
        ...old,
        [protocol]: [
          ...old[protocol],
          {
            ...result,
            timestamp: new Date().toLocaleTimeString(),
          },
        ],
      }));

      if (next === 5) {
        setComplete((old) => ({
          ...old,
          [protocol]:
            result.secure_channel_established === true,
        }));
      }
    } catch (err) {
      setError(
        err.response?.data?.detail ||
          "The handshake step failed. Check the backend."
      );
    } finally {
      setLoading(false);
    }
  }

  async function resetHandshake() {
    if (isIpsec) return;

    setLoading(true);
    setError("");

    try {
      if (sessionId) {
        await axios.post(
          `${API}/${protocol.toLowerCase()}/${sessionId}/reset`
        );
      }

      setSessions((old) => ({
        ...old,
        [protocol]: "",
      }));

      setProgress((old) => ({
        ...old,
        [protocol]: 0,
      }));

      setLogs((old) => ({
        ...old,
        [protocol]: [],
      }));

      setComplete((old) => ({
        ...old,
        [protocol]: false,
      }));
    } catch (err) {
      setError(
        err.response?.data?.detail ||
          "Could not reset the session."
      );
    } finally {
      setLoading(false);
    }
  }

  function changeProtocol(item) {
    setProtocol(item);
    setError("");
  }

  return (
    <div className="app-shell">
      <header className="topbar">
        <a className="brand" href="#home">
          <span className="brand-icon">S</span>

          <span>
            <strong>SecureTunnel</strong>
            <small>PROTOCOL LEARNING LAB</small>
          </span>
        </a>

        <div className="topbar-right">
          <span className="status-dot" />
          EDUCATIONAL SIMULATOR
        </div>
      </header>

      <main className="main-content" id="home">
        <section className="hero">
          <div className="eyebrow">
            NETWORK SECURITY / PROTOCOL LAB
          </div>

          <h1>Build a secure connection.</h1>

          <p>{info.description}</p>
        </section>

        {/* Protocol navigation */}
        <div className="protocol-tabs">
          {["TLS", "SSH", "IPsec"].map((item) => (
            <button
              key={item}
              className={`protocol-tab ${
                protocol === item ? "selected" : ""
              }`}
              onClick={() => changeProtocol(item)}
            >
              {protocolInfo[item].title}

              <span>{protocolInfo[item].subtitle}</span>
            </button>
          ))}
        </div>

        {isIpsec ? (
          /* IPsec is a frontend-only conceptual visualization */
          <Ipsec />
        ) : (
          <>
            {/* TLS and SSH dashboard */}
            <section className="stats-grid">
              <div className="stat-card">
                <span>ACTIVE PROTOCOL</span>
                <strong>{protocol}</strong>
              </div>

              <div className="stat-card">
                <span>HANDSHAKE STEPS</span>
                <strong>
                  {String(currentStep).padStart(2, "0")} / 05
                </strong>
              </div>

              <div className="stat-card">
                <span>CONNECTION</span>
                <strong
                  className={isComplete ? "success-text" : ""}
                >
                  {isComplete
                    ? "Established"
                    : "In progress"}
                </strong>
              </div>
            </section>

            <section className="workspace">
              <div className="section-heading">
                <div>
                  <div className="eyebrow">
                    LIVE VISUALIZATION
                  </div>

                  <h2>{info.title}</h2>
                </div>

                <span className="step-counter">
                  STEP {currentStep} OF 5
                </span>
              </div>

              <div className="connection-stage">
                <div
                  className={`endpoint ${
                    activeStep?.sender === "CLIENT" ||
                    activeStep?.sender === "BOTH"
                      ? "endpoint-active"
                      : ""
                  }`}
                >
                  <div className="endpoint-icon">⌘</div>

                  <h3>Client</h3>

                  <p>
                    {protocol === "TLS"
                      ? "Browser"
                      : "SSH Client"}
                  </p>

                  <span className="endpoint-tag">
                    CLIENT SIDE
                  </span>
                </div>

                <div className="message-lane">
                  <div className="connection-line">
                    <span className="line-dot" />
                    <span className="line-dot second-dot" />
                  </div>

                  <div className="message-card">
                    <span className="message-label">
                      {activeStep
                        ? activeStep.sender
                        : "AWAITING HANDSHAKE"}
                    </span>

                    <strong>
                      {activeStep
                        ? activeStep.name
                        : "No messages yet"}
                    </strong>

                    <p>
                      {activeStep
                        ? activeStep.description
                        : "Start the simulation to begin exchanging messages."}
                    </p>
                  </div>

                  <div className="lane-caption">
                    {protocol} COMMUNICATION SIMULATION
                  </div>
                </div>

                <div
                  className={`endpoint ${
                    activeStep?.sender === "SERVER" ||
                    activeStep?.sender === "BOTH"
                      ? "endpoint-active"
                      : ""
                  }`}
                >
                  <div className="endpoint-icon server-icon">
                    ▣
                  </div>

                  <h3>Server</h3>
                  <p>SecureTunnel</p>

                  <span className="endpoint-tag">
                    SERVER SIDE
                  </span>
                </div>
              </div>

              <div className="progress-track">
                {steps.map((step, index) => (
                  <div
                    key={step.name}
                    className={`progress-item ${
                      index < currentStep
                        ? "progress-done"
                        : ""
                    } ${
                      index === currentStep && currentStep < 5
                        ? "progress-current"
                        : ""
                    }`}
                  >
                    <div className="progress-number">
                      {index < currentStep
                        ? "✓"
                        : index + 1}
                    </div>

                    <span>{step.name}</span>
                  </div>
                ))}
              </div>

              <div className="controls">
                <button
                  className="button button-secondary"
                  onClick={resetHandshake}
                  disabled={loading}
                >
                  Reset
                </button>

                {!sessionId ? (
                  <button
                    className="button button-primary"
                    onClick={startHandshake}
                    disabled={loading}
                  >
                    {loading
                      ? "Starting..."
                      : "Start handshake →"}
                  </button>
                ) : (
                  <button
                    className="button button-primary"
                    onClick={nextStep}
                    disabled={loading || currentStep >= 5}
                  >
                    {loading
                      ? "Processing..."
                      : currentStep >= 5
                        ? "Handshake completed ✓"
                        : `Next step (${currentStep + 1}/5) →`}
                  </button>
                )}
              </div>

              {error && (
                <div className="error-banner">
                  {error}
                </div>
              )}

              {isComplete && (
                <div className="success-banner">
                  ✓ {protocol} simulation completed successfully!
                </div>
              )}
            </section>

            <section className="log-section">
              <div className="section-heading">
                <div>
                  <div className="eyebrow">
                    EVENT HISTORY
                  </div>

                  <h2>{protocol} handshake log</h2>
                </div>

                <span className="step-counter">
                  {currentLogs.length} EVENTS
                </span>
              </div>

              {currentLogs.length === 0 ? (
                <div className="empty-log">
                  Handshake events will appear here as you
                  advance through the steps.
                </div>
              ) : (
                <div className="log-list">
                  {currentLogs.map((log, index) => (
                    <article
                      className="log-entry"
                      key={`${log.step}-${index}`}
                    >
                      <div className="log-number">
                        {String(log.step).padStart(2, "0")}
                      </div>

                      <div className="log-content">
                        <div className="log-title-row">
                          <strong>{log.name}</strong>
                          <time>{log.timestamp}</time>
                        </div>

                        <p>{log.explanation}</p>

                        {log.public_key && (
                          <details>
                            <summary>View public key</summary>
                            <pre>{log.public_key}</pre>
                          </details>
                        )}

                        {log.encrypted_premaster_secret && (
                          <details>
                            <summary>
                              View encrypted pre-master secret
                            </summary>
                            <pre>
                              {log.encrypted_premaster_secret}
                            </pre>
                          </details>
                        )}

                        {log.client_public_key !== undefined && (
                          <details>
                            <summary>
                              View Diffie–Hellman public values
                            </summary>
                            <p>
                              Client public value:{" "}
                              {String(log.client_public_key)}
                            </p>
                            <p>
                              Server public value:{" "}
                              {String(log.server_public_key)}
                            </p>
                          </details>
                        )}

                        {log.server_fingerprint && (
                          <details>
                            <summary>
                              View server fingerprint
                            </summary>
                            <pre>{log.server_fingerprint}</pre>
                          </details>
                        )}

                        {log.signature_valid !== undefined && (
                          <div className="verification">
                            Server signature valid:{" "}
                            {String(log.signature_valid)}
                          </div>
                        )}

                        {log.shared_secret_match !== undefined && (
                          <div className="verification">
                            Shared secret match:{" "}
                            {String(log.shared_secret_match)}
                          </div>
                        )}

                        {log.session_keys_match !== undefined && (
                          <div className="verification">
                            Session keys match:{" "}
                            {String(log.session_keys_match)}
                          </div>
                        )}

                        {log.authenticated !== undefined && (
                          <div className="verification">
                            User authenticated:{" "}
                            {String(log.authenticated)}
                          </div>
                        )}

                        {log.client_master_secret_match !==
                          undefined && (
                          <div className="verification">
                            Master secrets match:{" "}
                            {String(
                              log.client_master_secret_match
                            )}
                          </div>
                        )}
                      </div>
                    </article>
                  ))}
                </div>
              )}
            </section>
          </>
        )}

        <footer>
          <span>
            SecureTunnel · Network Security Learning Lab
          </span>

          <span>
            Educational simulations — not production protocols
          </span>
        </footer>
      </main>
    </div>
  );
}
