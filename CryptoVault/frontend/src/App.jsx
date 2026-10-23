
import { useState } from "react";
import axios from "axios";
import "./App.css";

const API = "http://127.0.0.1:8000";

export default function App() {
  const [tab, setTab] = useState("RSA");
  const [message, setMessage] = useState("Hello CryptoVault!");
  const [publicKey, setPublicKey] = useState("");
  const [privateKey, setPrivateKey] = useState("");
  const [ciphertext, setCiphertext] = useState("");
  const [signature, setSignature] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [userId, setUserId] = useState("");
  const [elgamal, setElgamal] = useState(null);
  const [dh, setDh] = useState(null);

  async function run(action) {
    setLoading(true);
    setResult(null);

    try {
      const data = await action();
      setResult(data);
    } catch (error) {
      setResult({
        error:
          error.response?.data?.detail ||
          error.message ||
          "Request failed",
      });
    } finally {
      setLoading(false);
    }
  }

  async function generateRSA() {
    const { data } = await axios.post(`${API}/rsa/generate-keys`);
    setPublicKey(data.public_key);
    setPrivateKey(data.private_key);
    return { message: "RSA key pair generated successfully" };
  }

  async function encrypt() {
    const { data } = await axios.post(`${API}/rsa/encrypt`, {
      message,
      public_key: publicKey,
    });
    setCiphertext(data.ciphertext);
    return data;
  }

  async function decrypt() {
    const { data } = await axios.post(`${API}/rsa/decrypt`, {
      ciphertext,
      private_key: privateKey,
    });
    return data;
  }

  async function sign() {
    const { data } = await axios.post(`${API}/rsa/sign`, {
      message,
      private_key: privateKey,
    });
    setSignature(data.signature);
    return data;
  }

  async function verify() {
    const { data } = await axios.post(`${API}/rsa/verify`, {
      message,
      signature,
      public_key: publicKey,
    });
    return data;
  }

  async function exchangeDH() {
    const { data } = await axios.post(`${API}/dh/exchange`);
    setDh(data);
    return data;
  }

  async function generateElgamal() {
    const { data } = await axios.post(
      `${API}/elgamal/generate-keys`
    );
    setElgamal(data);
    return {
      p: data.p,
      g: data.g,
      public_key: data.public_key,
      message: "ElGamal keys generated",
    };
  }

  async function signElgamal() {
    if (!elgamal) throw new Error("Generate ElGamal keys first");

    const { data } = await axios.post(`${API}/elgamal/sign`, {
      message,
      p: elgamal.p,
      g: elgamal.g,
      private_key: elgamal.private_key,
    });
    setSignature(JSON.stringify(data));
    return data;
  }

  async function verifyElgamal() {
    if (!elgamal) throw new Error("Generate ElGamal keys first");

    const sig = JSON.parse(signature);
    const { data } = await axios.post(`${API}/elgamal/verify`, {
      message,
      p: elgamal.p,
      g: elgamal.g,
      public_key: elgamal.public_key,
      r: sig.r,
      s: sig.s,
    });
    return data;
  }

  async function register() {
    const { data } = await axios.post(`${API}/auth/register`, {
      username,
      email,
      password,
    });
    setUserId(String(data.user_id));
    setPublicKey(data.public_key);
    return {
      message: data.message,
      user_id: data.user_id,
      public_key: data.public_key,
    };
  }

  async function login() {
    const { data } = await axios.post(`${API}/auth/login`, {
      username,
      password,
    });
    setUserId(String(data.user_id));
    setPublicKey(data.public_key);
    return data;
  }

  async function downloadCertificate() {
    if (!userId) throw new Error("Register or log in first");

    const { data } = await axios.get(
      `${API}/certificates/${userId}/download`,
      { responseType: "blob" }
    );

    const url = URL.createObjectURL(data);
    const link = document.createElement("a");
    link.href = url;
    link.download = `${username || "user"}.crt.pem`;
    link.click();
    URL.revokeObjectURL(url);

    return { message: "Certificate download requested" };
  }

  const tabs = ["RSA", "Diffie–Hellman", "ElGamal", "Account"];

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-icon">C</div>
          <div>
            <h2>CryptoVault</h2>
            <p>Cryptography toolkit</p>
          </div>
        </div>

        <p className="nav-label">WORKSPACE</p>

        {tabs.map((item) => (
          <button
            key={item}
            className={`nav-item ${tab === item ? "active" : ""}`}
            onClick={() => {
              setTab(item);
              setResult(null);
            }}
          >
            <span>{{
              RSA: "◇",
              "Diffie–Hellman": "⇄",
              ElGamal: "✳",
              Account: "♙",
            }[item]}</span>
            {item}
          </button>
        ))}

        <div className="sidebar-bottom">
          <span className="status-dot" />
          Local API · 127.0.0.1:8000
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <span>WORKSPACE / {tab.toUpperCase()}</span>
          <span className="secure-label">● Educational environment</span>
        </header>

        <section className="page-heading">
          <div className="eyebrow">CRYPTOVAULT SECURITY LAB</div>
          <h1>{{
            RSA: "RSA Cryptography",
            "Diffie–Hellman": "Key Exchange",
            ElGamal: "ElGamal Signatures",
            Account: "Account & Certificates",
          }[tab]}</h1>
          <p>
            {tab === "RSA"
              ? "Generate keys, encrypt messages and verify digital signatures."
              : tab === "Diffie–Hellman"
              ? "Explore how Alice and Bob establish a shared secret."
              : tab === "ElGamal"
              ? "Hash messages with SHA-512 and sign them using ElGamal."
              : "Register, log in and download your X.509 certificate."}
          </p>
        </section>

        {tab === "RSA" && (
          <>
            <section className="card">
              <div className="card-title">
                <div>
                  <span className="step-tag">01 / RSA</span>
                  <h2>Message workspace</h2>
                </div>
                <button className="secondary-btn" onClick={() => run(generateRSA)}>
                  Generate RSA keys
                </button>
              </div>

              <label>Message</label>
              <textarea
                value={message}
                onChange={(e) => setMessage(e.target.value)}
                rows={3}
              />

              <div className="two-columns">
                <div>
                  <label>Public key · PEM</label>
                  <textarea
                    value={publicKey}
                    onChange={(e) => setPublicKey(e.target.value)}
                    rows={5}
                    placeholder="Generate or paste a public key"
                  />
                </div>
                <div>
                  <label>Private key · PEM</label>
                  <textarea
                    value={privateKey}
                    onChange={(e) => setPrivateKey(e.target.value)}
                    rows={5}
                    placeholder="Generate or paste a private key"
                  />
                </div>
              </div>

              <div className="actions">
                <button onClick={() => run(encrypt)}>Encrypt</button>
                <button onClick={() => run(decrypt)}>Decrypt</button>
                <button onClick={() => run(sign)}>Sign</button>
                <button onClick={() => run(verify)}>Verify</button>
              </div>

              <label>Ciphertext · Base64</label>
              <textarea
                value={ciphertext}
                onChange={(e) => setCiphertext(e.target.value)}
                rows={3}
                placeholder="Encrypted output appears here"
              />

              <label>Signature · Base64</label>
              <textarea
                value={signature}
                onChange={(e) => setSignature(e.target.value)}
                rows={3}
                placeholder="Generated signature appears here"
              />
            </section>
          </>
        )}

        {tab === "Diffie–Hellman" && (
          <section className="card">
            <span className="step-tag">02 / KEY EXCHANGE</span>
            <h2>Alice ↔ Bob</h2>
            <p className="muted">
              Generate a demonstration exchange and inspect the intermediate values.
            </p>
            <button onClick={() => run(exchangeDH)}>Run key exchange</button>

            {dh && (
              <div className="two-columns result-grid">
                <div className="mini-card">
                  <h3>Alice</h3>
                  <p>Private key: {dh.alice_private}</p>
                  <p>Public key: {dh.alice_public}</p>
                  <p>Shared secret: {dh.alice_shared_secret}</p>
                </div>
                <div className="mini-card">
                  <h3>Bob</h3>
                  <p>Private key: {dh.bob_private}</p>
                  <p>Public key: {dh.bob_public}</p>
                  <p>Shared secret: {dh.bob_shared_secret}</p>
                </div>
                <div className="result-banner">
                  p = {dh.p} · g = {dh.g} · Shared secrets match: {String(dh.match)}
                </div>
              </div>
            )}
          </section>
        )}

        {tab === "ElGamal" && (
          <section className="card">
            <span className="step-tag">03 / DIGITAL SIGNATURE</span>
            <h2>ElGamal + SHA-512</h2>
            <label>Message to sign</label>
            <textarea
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              rows={3}
            />
            <div className="actions">
              <button onClick={() => run(generateElgamal)}>Generate ElGamal keys</button>
              <button onClick={() => run(signElgamal)}>Hash & sign</button>
              <button onClick={() => run(verifyElgamal)}>Verify signature</button>
            </div>
            {elgamal && (
              <p className="muted">
                ElGamal keys generated. Private key is held in this page's memory.
              </p>
            )}
          </section>
        )}

        {tab === "Account" && (
          <section className="card">
            <span className="step-tag">04 / IDENTITY</span>
            <h2>Account access</h2>
            <label>Username</label>
            <input value={username} onChange={(e) => setUsername(e.target.value)} />
            <label>Email · for registration</label>
            <input value={email} onChange={(e) => setEmail(e.target.value)} />
            <label>Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
            <div className="actions">
              <button onClick={() => run(register)}>Register</button>
              <button onClick={() => run(login)}>Log in</button>
              <button className="secondary-btn" onClick={() => run(downloadCertificate)}>
                Download X.509 certificate
              </button>
            </div>
            {userId && <p className="muted">Current user ID: {userId}</p>}
          </section>
        )}

        {loading && <div className="notice">Processing request…</div>}

        {result && (
          <section className="card response-card">
            <div className="card-title">
              <h2>API response</h2>
              <button className="secondary-btn" onClick={() => setResult(null)}>
                Clear
              </button>
            </div>
            <pre>{JSON.stringify(result, null, 2)}</pre>
          </section>
        )}

        <footer>CryptoVault · ALM Project 2 · Learning cryptography responsibly</footer>
      </main>
    </div>
  );
}
