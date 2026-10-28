import { useCallback, useEffect, useRef, useState } from "react";

import evalResults from "../../evals/results.json";
import { api } from "./api";
import { EvalPanel } from "./components/EvalPanel";
import { HealthBar } from "./components/HealthBar";
import { History, type HistoryEntry } from "./components/History";
import { type ScanResult, Scanner } from "./components/Scanner";
import { StatsPanel } from "./components/StatsPanel";
import type { EvalResults, HealthResponse, StatsResponse } from "./types";

const EVAL = evalResults as unknown as EvalResults;
const POLL_MS = 5000;
const MAX_HISTORY = 50;

export default function App() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [healthError, setHealthError] = useState<string | null>(null);
  const [stats, setStats] = useState<StatsResponse | null>(null);
  const [statsError, setStatsError] = useState<string | null>(null);
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const nextId = useRef(0);

  const refresh = useCallback(async () => {
    const [h, s] = await Promise.allSettled([api.health(), api.stats()]);
    if (h.status === "fulfilled") {
      setHealth(h.value);
      setHealthError(null);
    } else {
      setHealthError(String(h.reason));
    }
    if (s.status === "fulfilled") {
      setStats(s.value);
      setStatsError(null);
    } else {
      setStatsError(s.reason instanceof Error ? s.reason.message : String(s.reason));
    }
  }, []);

  useEffect(() => {
    void refresh();
    const id = window.setInterval(() => {
      // Don't poll from a background tab.
      if (document.visibilityState === "visible") void refresh();
    }, POLL_MS);
    return () => window.clearInterval(id);
  }, [refresh]);

  const onResult = useCallback(
    (scan: ScanResult) => {
      setHistory((prev) => [{ id: nextId.current++, scan }, ...prev].slice(0, MAX_HISTORY));
      void refresh();
    },
    [refresh],
  );

  return (
    <main className="app">
      <header className="header">
        <div>
          <h1>Prompt-Security Gateway</h1>
          <p>Stop secrets, personal data and confidential documents from reaching an LLM.</p>
        </div>
        <HealthBar health={health} error={healthError} />
      </header>

      <div className="grid">
        <div className="stack">
          <Scanner onResult={onResult} />
          <History entries={history} />
        </div>
        <div className="stack">
          <StatsPanel stats={stats} error={statsError} />
          <EvalPanel data={EVAL} />
        </div>
      </div>
    </main>
  );
}
