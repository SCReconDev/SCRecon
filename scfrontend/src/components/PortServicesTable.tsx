import { useMemo } from "react";
import { parsePortServices } from "../utils/portServices";

type Props = {
  title?: string;
  scanResult?: string | null;
};

export function PortServicesTable({ title = "Ports & Services", scanResult }: Props) {
  const rows = useMemo(() => {
    const parsed = parsePortServices(scanResult);
    return parsed.sort((a, b) => (a.port ?? 1e9) - (b.port ?? 1e9));
  }, [scanResult]);

  if (rows.length === 0) {
    return <div className="muted" style={{ fontSize: 14 }}>n/a</div>;
  }

  return (
    <div>
      <div className="label">{title}</div>

      <div className="tableWrap" style={{ marginTop: 8 }}>
        <table className="table">
          <thead className="thead">
            <tr>
              <th className="th">Port</th>
              <th className="th">Service</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row, idx) => (
              <tr key={`${row.port}-${row.service}-${idx}`} className="tr">
                <td className="td mono">
                  {row.port ?? <span className="na">?</span>}
                </td>
                <td className="td">
                  {row.service || <span className="na">n/a</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
