export type SmbShareRow = {
  name: string;
  stype: string;
  comment: string;
  path: string;
  anonymousAccess: string;
};

function cell(v: string | undefined): string {
  const s = (v ?? "").trim();
  return s.length ? s : "n/a";
}

export function parseSmbShares(input?: string | null): SmbShareRow[] {
  if (!input) return [];

  const parts = input.split(",").map((s) => s.trim());

  const out: SmbShareRow[] = [];

  for (let i = 0; i < parts.length; i += 5) {
    const chunk = parts.slice(i, i + 5);

    if (chunk.length === 0 || chunk.every((x) => !x)) continue;

    out.push({
      name: cell(chunk[0]),
      stype: cell(chunk[1]),
      comment: cell(chunk[2]),
      path: cell(chunk[3]),
      anonymousAccess: cell(chunk[4]),
    });
  }

  if (
    out.length === 1 &&
    Object.values(out[0]).every((v) => v === "n/a")
  ) {
    return [];
  }

  return out;
}
