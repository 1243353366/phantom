import { useState } from "react";
import GraphView from "./components/GraphView";
import NegativeSpaceView from "./components/NegativeSpaceView";
import CounterIntelView from "./components/CounterIntelView";
import ExposureView from "./components/ExposureView";
import ConsentView from "./components/ConsentView";
import SelfAuditView from "./components/SelfAuditView";
import IngestView from "./components/IngestView";

const TABS = [
  ["graph", "Phantom graph"],
  ["negative", "Negative space"],
  ["counter", "Counter-observation"],
  ["exposure", "Exposure"],
  ["consent", "Contact permissions"],
  ["audit", "Who watches the watchers"],
  ["ingest", "Add a message"],
] as const;

type Tab = (typeof TABS)[number][0];

export default function App() {
  const [tab, setTab] = useState<Tab>("graph");

  return (
    <div className="shell">
      <header className="masthead">
        <div>
          <h1>PHANTOM</h1>
          <p className="tagline">See the ecosystem that sees you.</p>
        </div>
        <p className="local-badge" title="There is no PHANTOM server. This is your machine.">
          local only
        </p>
      </header>

      <nav className="tabs">
        {TABS.map(([key, label]) => (
          <button
            key={key}
            className={tab === key ? "tab active" : "tab"}
            onClick={() => setTab(key)}
          >
            {label}
          </button>
        ))}
      </nav>

      <main>
        {tab === "graph" && <GraphView />}
        {tab === "negative" && <NegativeSpaceView />}
        {tab === "counter" && <CounterIntelView />}
        {tab === "exposure" && <ExposureView />}
        {tab === "consent" && <ConsentView />}
        {tab === "audit" && <SelfAuditView />}
        {tab === "ingest" && <IngestView />}
      </main>

      <footer className="footer">
        Every edge carries its evidence. Hypothesised edges are capped at 0.65 confidence
        and can never be promoted by volume alone. The counter-observation graph maps
        infrastructure, never people.
      </footer>
    </div>
  );
}
