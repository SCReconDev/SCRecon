import { useState } from "react";
import type { Scan, MetamoduleResult } from "../types/scans";
import { normalizeCvss, sortCvesByCvssDesc } from "../utils/cvss";
import { SeverityBadge } from "./SeverityBadge";

type Props = { scan: Scan };

function formatField(v: any) {
  if (v == null || v === "") return "n/a";
  return String(v);
}

function moduleKey(cveId: string, m: MetamoduleResult, idx: number) {
  return `${cveId}:${m.module_refname ?? m.module_name ?? "mod"}:${idx}`;
}

export function CveTable({ scan }: Props) {
  const cvesObject = scan.cves?.cves ?? {};
  const cvesEntries = Object.entries(cvesObject);
  const cvesSorted = sortCvesByCvssDesc(cvesEntries);

  const modulesByCve = scan.metamodules?.results ?? {};
  const [open, setOpen] = useState<Record<string, boolean>>({});

  const toggle = (key: string) => {
    setOpen((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  if (cvesSorted.length === 0) {
    return <div className="muted" style={{ fontSize: 14 }}>No CVEs in this scan.</div>;
  }

  return (
    <div className="tableWrap">
      <table className="table">
        <thead className="thead">
          <tr>
            <th className="th">CVE</th>
            <th className="th">CVSS</th>
            <th className="th">Severity</th>
            <th className="th">Vector</th>
            <th className="th">Description</th>
            <th className="th">Metasploit Modules</th>
          </tr>
        </thead>

        <tbody>
          {cvesSorted.map(([cveId, cve]) => {
            const cvss = normalizeCvss(cve);
            const modules = (modulesByCve as Record<string, MetamoduleResult[]>)[cveId] ?? [];

            return (
              <tr key={cveId} className="tr">
                <td className="td mono">{cveId}</td>

                <td className="td">
                  {cvss.score != null ? (
                    <span style={{ fontWeight: 800 }}>
                      {cvss.score.toFixed(1)}{" "}
                      <span className="muted" style={{ fontWeight: 600 }}>
                        v{cvss.version}
                      </span>
                    </span>
                  ) : (
                    <span className="na">n/a</span>
                  )}
                </td>

                <td className="td">
                  <SeverityBadge severity={cvss.severity} />
                </td>

                <td className="td vector">
                  {cvss.vector ?? <span className="na">n/a</span>}
                </td>

                <td className="td">
                  {cve.description_en ?? <span className="na">n/a</span>}
                </td>

                <td className="td">
                  {modules.length === 0 ? (
                    <span className="na">n/a</span>
                  ) : (
                    <div>
                      <div className="moduleList">
                        {modules.map((m, idx) => {
                          const key = moduleKey(cveId, m, idx);
                          const isOpen = !!open[key];

                          return (
                            <button
                              key={key}
                              type="button"
                              className="moduleButton"
                              onClick={() => toggle(key)}
                              title={m.module_refname}
                            >
                              {m.module_name || m.module_refname || "Module"} {isOpen ? "▾" : "▸"}
                            </button>
                          );
                        })}
                      </div>

                      {modules.map((m, idx) => {
                        const key = moduleKey(cveId, m, idx);
                        if (!open[key]) return null;

                        return (
                          <div className="moduleDetails" key={`${key}-details`}>
                            <div className="moduleDetailsTitle">
                              <div className="moduleDetailsTitleName">
                                {formatField(m.module_name)}
                              </div>
                              <div className="moduleDetailsTitleRef">
                                {formatField(m.module_refname)}
                              </div>
                            </div>

                            <div className="moduleDetailsGrid">
                              <div>
                                <span className="moduleFieldLabel">Type:</span>
                                {formatField(m.module_type)}
                              </div>
                              <div>
                                <span className="moduleFieldLabel">Rank:</span>
                                {formatField(m.rank)}
                              </div>
                              <div>
                                <span className="moduleFieldLabel">Disclosure:</span>
                                {formatField(m.disclosure_date)}
                              </div>
                              <div>
                                <span className="moduleFieldLabel">Loaded fullname:</span>
                                <span className="mono">{formatField(m.loaded_fullname)}</span>
                              </div>
                              <div>
                                <span className="moduleFieldLabel">Search fullname:</span>
                                <span className="mono">{formatField(m.search_fullname)}</span>
                              </div>
                              <div>
                                <span className="moduleFieldLabel">Search refname:</span>
                                <span className="mono">{formatField(m.search_refname)}</span>
                              </div>
                            </div>

                            <div className="moduleDesc">
                              <span className="moduleFieldLabel">Description:</span>
                              {formatField(m.description)}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
