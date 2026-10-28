import { categoryLabel, ms } from "../format";
import type { ScanResult } from "./Scanner";
import { VerdictBadge } from "./VerdictView";

export interface HistoryEntry {
  id: number;
  scan: ScanResult;
}

export function History({ entries }: { entries: HistoryEntry[] }) {
  return (
    <div className="card">
      <h2>This session</h2>
      <p className="sub">Every prompt you screened here, newest first.</p>
      {entries.length === 0 ? (
        <p className="empty">Nothing screened yet.</p>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Prompt</th>
                <th>Verdict</th>
                <th className="num">Latency</th>
              </tr>
            </thead>
            <tbody>
              {entries.map(({ id, scan }) => (
                <tr key={id}>
                  <td className="query">
                    {scan.text.length > 90 ? `${scan.text.slice(0, 90)}…` : scan.text}
                    {scan.check.categories.length > 0 && (
                      <div className="kv">{scan.check.categories.map(categoryLabel).join(", ")}</div>
                    )}
                  </td>
                  <td>
                    <VerdictBadge verdict={scan.check.verdict} />
                  </td>
                  <td className="num">{ms(scan.check.latency_ms)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
