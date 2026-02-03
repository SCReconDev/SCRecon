import { useMemo } from "react";
import type { Scan } from "../types/scans";
import { parseSmbShares } from "../utils/smbshares";

type Props = {
  smbshares: Scan["smbshares"] | undefined;
};

export function SmbSharesPanel({ smbshares }: Props) {
  const raw: string | null =
    smbshares && typeof smbshares === "object"
      ? (smbshares as any).scan_result ?? null
      : typeof smbshares === "string"
        ? smbshares
        : null;

  const rows = useMemo(() => parseSmbShares(raw), [raw]);

  return (
    <div className="detailBox">
      <div className="label">SMB Shares</div>

      {rows.length === 0 ? (
        <div className="muted" style={{ marginTop: 6, fontSize: 14 }}>
          n/a
        </div>
      ) : (
        <div className="tableWrap" style={{ marginTop: 8 }}>
          <table className="table">
            <thead className="thead">
              <tr>
                <th className="th">Name</th>
                <th className="th">Type</th>
                <th className="th">Comment</th>
                <th className="th">Path</th>
                <th className="th">Anonymous access</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r, idx) => (
                <tr className="tr" key={`${r.name}-${idx}`}>
                  <td className="td mono">{r.name}</td>
                  <td className="td">{r.stype}</td>
                  <td className="td">{r.comment}</td>
                  <td className="td mono">{r.path}</td>
                  <td className="td">{r.anonymousAccess}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
