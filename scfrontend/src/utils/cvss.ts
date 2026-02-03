import type { CveDetails } from "../types/scans";

export type CvssNormalized = {
  score: number | null;
  version: "3.1" | "3.0" | "2.0" | null;
  severity: string | null;
  vector: string | null;
};
//prefer newer cvss versions
export function normalizeCvss(cve: CveDetails): CvssNormalized {
  const cvss = cve.cvss;

  if (cvss?.cvssV3_1?.baseScore != null) {
    return {
      score: cvss.cvssV3_1.baseScore,
      version: "3.1",
      severity: cvss.cvssV3_1.baseSeverity ?? null,
      vector: cvss.cvssV3_1.vectorString ?? null,
    };
  }

  if (cvss?.cvssV3_0?.baseScore != null) {
    return {
      score: cvss.cvssV3_0.baseScore,
      version: "3.0",
      severity: cvss.cvssV3_0.baseSeverity ?? null,
      vector: cvss.cvssV3_0.vectorString ?? null,
    };
  }

  if (cvss?.cvssV2_0?.baseScore != null) {
    return {
      score: cvss.cvssV2_0.baseScore,
      version: "2.0",
      severity: cvss.cvssV2_0.baseSeverity ?? null,
      vector: cvss.cvssV2_0.vectorString ?? null,
    };
  }

  return { score: null, version: null, severity: null, vector: null };
}

export function sortCvesByCvssDesc(entries: Array<[string, CveDetails]>) {
  return [...entries].sort((a, b) => {
    const ca = normalizeCvss(a[1]).score;
    const cb = normalizeCvss(b[1]).score;

    if (ca == null && cb == null) return a[0].localeCompare(b[0]);
    if (ca == null) return 1;
    if (cb == null) return -1;

    if (cb !== ca) return cb - ca;
    return a[0].localeCompare(b[0]);
  });
}
