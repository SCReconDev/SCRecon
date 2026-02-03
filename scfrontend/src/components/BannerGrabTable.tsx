import { useMemo } from "react";
import { parseBannerGrab } from "../utils/bannerGrab";

type Props = {
  title?: string;
  scanResult?: string | null;
};

function cell(v: string) {
  return v && v.length > 0 ? v : null;
}

export function BannerGrabTable({ title = "Bannergrab", scanResult }: Props) {
  const rows = useMemo(() => parseBannerGrab(scanResult), [scanResult]);

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
              <th className="th">Product</th>
              <th className="th">Version</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r, idx) => (
              <tr key={`${r.port}-${r.service}-${r.product}-${r.version}-${idx}`} className="tr">
                <td className="td mono">{r.port ?? <span className="na">?</span>}</td>
                <td className="td">{cell(r.service) ?? <span className="na">n/a</span>}</td>
                <td className="td">{cell(r.product) ?? <span className="na">n/a</span>}</td>
                <td className="td mono">{cell(r.version) ?? <span className="na">n/a</span>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
