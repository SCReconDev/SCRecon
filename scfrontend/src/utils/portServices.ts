export type PortService = {
  port: number | null;
  service: string;
};

export function parsePortServices(input?: string | null): PortService[] {
  if (input == null) return [];

  const parts = input.split(",").map((s) => s.trim());
  const out: PortService[] = [];

  for (let i = 0; i < parts.length; i += 2) {
    const portRaw = (parts[i] ?? "").trim();
    const service = (parts[i + 1] ?? "").trim();

    if (!portRaw && !service) continue;

    const portNum = Number(portRaw);
    out.push({
      port: Number.isFinite(portNum) ? portNum : null,
      service: service || "n/a",
    });
  }

  return out.sort((a, b) => (a.port ?? 1e9) - (b.port ?? 1e9));
}

