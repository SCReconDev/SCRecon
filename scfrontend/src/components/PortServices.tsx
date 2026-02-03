import { useMemo } from "react";
import { parsePortServices } from "../utils/portServices";

type Props = {
  title?: string;
  scanResult?: string | null;
};

export function PortServices({ title = "Open ports", scanResult }: Props) {
const items = useMemo(() => {
  const parsed = parsePortServices(scanResult);
  return parsed.sort((a, b) => (a.port ?? 1e9) - (b.port ?? 1e9));
}, [scanResult]);

  if (items.length === 0) {
    return <div className="muted" style={{ fontSize: 14 }}>n/a</div>;
  }

  return (
    <div>
      <div className="label">{title}</div>

      <div className="portsGrid">
        {items.map((it, idx) => (
          <div key={`${it.port}-${it.service}-${idx}`} className="portChip">
            <span className="portChipPort">{it.port ?? "?"}</span>
            <span className="portChipService">{it.service}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
