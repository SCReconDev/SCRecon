import { useMemo } from "react";
import type { Scan } from "../types/scans";
import { parseSubdomains } from "../utils/subdomains";

type Props = {
  subdomainl1: Scan["subdomainl1"] | undefined;
};

export function SubdomainL1Panel({ subdomainl1 }: Props) {
  const raw = (subdomainl1 as any)?.["subdomains:"] as string | undefined;

  const rows = useMemo(() => parseSubdomains(raw ?? null), [raw]);

  return (
    <div className="detailBox">
      <div className="label">Subdomains / paths</div>

      {rows.length === 0 ? (
        <div className="muted" style={{ marginTop: 6, fontSize: 14 }}>n/a</div>
      ) : (
        <div className="tableWrap" style={{ marginTop: 8 }}>
          <table className="table">
            <thead className="thead">
              <tr>
                <th className="th">Path</th>
                <th className="th">Status</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r, idx) => (
                <tr className="tr" key={`${r.path}-${r.status}-${idx}`}>
                  <td className="td mono">{r.path}</td>
                  <td className="td">{r.status}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
