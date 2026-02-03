export type SubdomainRow = {
  path: string;
  status: string;
};

export function parseSubdomains(input?: string | null): SubdomainRow[] {
  if (!input) return [];

  const parts = input.split(",").map((s) => s.trim());

  const out: SubdomainRow[] = [];
  for (let i = 0; i < parts.length; i += 2) {
    const path = (parts[i] ?? "").trim();
    const status = (parts[i + 1] ?? "").trim();

    if (!path && !status) continue;

    out.push({
      path: path || "n/a",
      status: status || "n/a",
    });
  }

  return out;
}
