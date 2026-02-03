export type BannerRow = {
  port: number | null;
  service: string;
  product: string;
  version: string;
};

//make undefined an empty string
function toCell(value: string | undefined): string {
  return (value ?? "").trim();
}

export function parseBannerGrab(input?: string | null): BannerRow[] {
  if (input == null) return [];

  const parts = input.split(",").map((s) => s.trim());

  const out: BannerRow[] = [];

  for (let i = 0; i < parts.length; i += 4) {
    const portRaw = toCell(parts[i]);
    const service = toCell(parts[i + 1]);
    const product = toCell(parts[i + 2]);
    const version = toCell(parts[i + 3]);

    if (!portRaw && !service && !product && !version) continue;

    const portNum = Number(portRaw);

    out.push({
      port: Number.isFinite(portNum) ? portNum : null,
      service,
      product,
      version,
    });
  }

  out.sort((a, b) => (a.port ?? 1e9) - (b.port ?? 1e9));

  return out;
}
