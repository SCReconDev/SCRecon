import { useEffect, useMemo, useState } from "react";
import type { Scan } from "../types/scans";
import { fetchScans } from "../api/scans";

export function useScans() {
  const [data, setData] = useState<Scan[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const reload = async (): Promise<Scan[]> => {
    setLoading(true);
    setError(null);

    const ctrl = new AbortController();

    try {
      const scans = await fetchScans(ctrl.signal);
      scans.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
      setData(scans);
      return scans;
    } catch (e: any) {
      if (e?.name !== "AbortError") setError(String(e?.message ?? e));
      setData([]);
      return [];
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void reload();
  }, []);

  const scans = useMemo(() => data ?? [], [data]);

  return { scans, loading, error, reload };
}
