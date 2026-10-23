
import { useState } from "react";
import "./Ipsec.css";

export default function Ipsec() {
  const [mode, setMode] = useState("transport");

  const transport = mode === "transport";

  const parts = transport
    ? [
        {
          label: "Original IP Header",
          detail: "Routing information remains visible",
          type: "header",
        },
        {
          label: "ESP Header",
          detail: "SPI + sequence number",
          type: "esp",
        },
        {
          label: "Encrypted Payload",
          detail: "Original transport-layer payload",
          type: "encrypted",
        },
        {
          label: "ESP Trailer",
          detail: "Padding + pad length + next header",
          type: "esp",
        },
        {
          label: "Integrity Data",
          detail: "Authentication data, when configured",
          type: "integrity",
        },
      ]
    : [
        {
          label: "New IP Header",
          detail: "Outer source and destination addresses",
          type: "header",
        },
        {
          label: "ESP Header",
          detail: "SPI + sequence number",
          type: "esp",
        },
        {
          label: "Encrypted Original Packet",
          detail: "Original IP header + payload + ESP trailer",
          type: "encrypted",
        },
        {
          label: "Integrity Data",
          detail: "Authentication data, when configured",
          type: "integrity",
        },
      ];

  return (
    <section className="ipsec-page">
      <div className="ipsec-intro">
        <div className="eyebrow">NETWORK SECURITY / IPSEC</div>
        <h2>IP packet encapsulation</h2>
        <p>
          Explore how Encapsulating Security Payload (ESP) protects IP
          traffic in Transport Mode and Tunnel Mode.
        </p>
      </div>

      <div className="ipsec-mode-switch">
        <button
          className={transport ? "mode-button selected" : "mode-button"}
          onClick={() => setMode("transport")}
        >
          Transport Mode
          <span>Protect the payload</span>
        </button>

        <button
          className={!transport ? "mode-button selected" : "mode-button"}
          onClick={() => setMode("tunnel")}
        >
          Tunnel Mode
          <span>Encapsulate the original packet</span>
        </button>
      </div>

      <div className="ipsec-card">
        <div className="ipsec-card-heading">
          <div>
            <span className="eyebrow">PACKET STRUCTURE</span>
            <h3>{transport ? "Transport Mode" : "Tunnel Mode"}</h3>
          </div>
          <span className="ipsec-tag">ESP</span>
        </div>

        <div className="packet-flow">
          {parts.map((part, index) => (
            <div className="packet-part-wrap" key={part.label}>
              {index > 0 && <div className="packet-connector">→</div>}
              <div className={`packet-part ${part.type}`}>
                <strong>{part.label}</strong>
                <span>{part.detail}</span>
              </div>
            </div>
          ))}
        </div>

        <div className="packet-legend">
          <span><i className="legend-header" /> Visible IP header</span>
          <span><i className="legend-encrypted" /> Encrypted content</span>
          <span><i className="legend-esp" /> ESP fields</span>
          <span><i className="legend-integrity" /> Integrity/authentication</span>
        </div>
      </div>

      <div className="ipsec-explanation-grid">
        <article className="ipsec-info-card">
          <span className="info-number">01</span>
          <h3>What stays visible?</h3>
          <p>
            {transport
              ? "The original IP header remains visible so routers can forward the packet. The transport payload is protected."
              : "The new outer IP header remains visible for routing. The original IP header is inside the protected packet."}
          </p>
        </article>

        <article className="ipsec-info-card">
          <span className="info-number">02</span>
          <h3>What does ESP protect?</h3>
          <p>
            ESP encrypts the protected payload when encryption is configured.
            Integrity and data-origin authentication are provided when
            supported algorithms and keys are configured.
          </p>
        </article>

        <article className="ipsec-info-card">
          <span className="info-number">03</span>
          <h3>When is it used?</h3>
          <p>
            Transport Mode is commonly associated with host-to-host protection.
            Tunnel Mode is widely used in VPNs, where an entire original IP
            packet is encapsulated inside another packet.
          </p>
        </article>
      </div>

      <div className="ipsec-note">
        <strong>Educational visualization:</strong> This diagram illustrates
        packet structure only. It does not encrypt packets or create an
        actual IPsec connection. ESP integrity data is shown conceptually;
        exact fields depend on the ESP algorithms and configuration.
      </div>
    </section>
  );
}
