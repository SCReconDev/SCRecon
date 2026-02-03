type Props = { severity: string | null };

function classFor(sev: string | null) {
  const s = (sev ?? "").toUpperCase();
  if (s === "CRITICAL") return "badge badgeRed";
  if (s === "HIGH") return "badge badgeOrange";
  if (s === "MEDIUM") return "badge badgeYellow";
  if (s === "LOW") return "badge badgeGreen";
  return "badge badgeGray";
}

export function SeverityBadge({ severity }: Props) {
  return (
    <span className={classFor(severity)} title={severity ?? "Unknown"}>
      {severity ?? "UNKNOWN"}
    </span>
  );
}
