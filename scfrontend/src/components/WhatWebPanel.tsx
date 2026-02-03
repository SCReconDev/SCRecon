import { useMemo, useState } from "react";
import type { Scan } from "../types/scans";

type Props = {
  whatweb: Scan["whatweb"] | undefined;
};

function isEmptyObject(obj: any) {
  return obj && typeof obj === "object" && !Array.isArray(obj) && Object.keys(obj).length === 0;
}

function formatValue(v: any): string {
  if (v == null) return "";
  if (typeof v === "string") return v;
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  try {
    return JSON.stringify(v, null, 2);
  } catch {
    return String(v);
  }
}

function safeEntries(obj: any): Array<[string, any]> {
  if (!obj || typeof obj !== "object") return [];
  return Object.entries(obj);
}

export function WhatWebPanel({ whatweb }: Props) {
  const [openPlugins, setOpenPlugins] = useState<Record<string, boolean>>({});

  const hasAny =
    !!whatweb &&
    !(
      !whatweb.report_for &&
      !whatweb.status &&
      !whatweb.title &&
      !whatweb.ip &&
      !whatweb.country &&
      (whatweb.summary_plugins?.length ?? 0) === 0 &&
      isEmptyObject(whatweb.detected_plugins) &&
      isEmptyObject(whatweb.http_headers)
    );

  const summaryRows = useMemo(() => whatweb?.summary_plugins ?? [], [whatweb]);
  const detected = useMemo(() => safeEntries(whatweb?.detected_plugins), [whatweb]);
  const headers = useMemo(() => safeEntries(whatweb?.http_headers), [whatweb]);

  if (!hasAny) {
    return (
      <div className="detailBox">
        <div className="label">WhatWeb</div>
        <div className="muted" style={{ marginTop: 6, fontSize: 14 }}>
          n/a
        </div>
      </div>
    );
  }

  return (
    <div className="detailBox">
      <div className="label">WhatWeb</div>

      <div className="whatwebBasic">
        <div className="whatwebRow">
          <span className="muted">Title:</span>{" "}
          <span>{whatweb?.title ?? "n/a"}</span>
        </div>
        <div className="whatwebRow">
          <span className="muted">Status:</span>{" "}
          <span>{whatweb?.status ?? "n/a"}</span>
        </div>
        <div className="whatwebRow">
          <span className="muted">Report for:</span>{" "}
          <span className="mono">{whatweb?.report_for ?? "n/a"}</span>
        </div>
        <div className="whatwebRow">
          <span className="muted">IP:</span>{" "}
          <span className="mono">{whatweb?.ip ?? "n/a"}</span>
        </div>
        <div className="whatwebRow">
          <span className="muted">Country:</span>{" "}
          <span>{whatweb?.country ?? "n/a"}</span>
        </div>
      </div>

      <div style={{ marginTop: 12 }}>
        <div className="sectionTitle" style={{ margin: "0 0 8px 0" }}>
          Summary plugins
        </div>

        {summaryRows.length === 0 ? (
          <div className="muted" style={{ fontSize: 14 }}>
            n/a
          </div>
        ) : (
          <div className="tableWrap">
            <table className="table">
              <thead className="thead">
                <tr>
                  <th className="th">Plugin</th>
                  <th className="th">Values</th>
                </tr>
              </thead>
              <tbody>
                {summaryRows.map((p, idx) => (
                  <tr className="tr" key={`${p.name}-${idx}`}>
                    <td className="td">{p.name}</td>
                    <td className="td mono">
                      {(p.summary_values ?? []).join(", ") || "n/a"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div style={{ marginTop: 12 }}>
        <div className="sectionTitle" style={{ margin: "0 0 8px 0" }}>
          Detected plugins
        </div>

        {detected.length === 0 ? (
          <div className="muted" style={{ fontSize: 14 }}>
            n/a
          </div>
        ) : (
          <div className="whatwebPlugins">
            {detected.map(([pluginName, pluginObj]) => {
              const isOpen = !!openPlugins[pluginName];
              const pluginEntries = safeEntries(pluginObj);

              return (
                <div className="whatwebPluginCard" key={pluginName}>
                  <button
                    className="whatwebPluginHeader"
                    onClick={() =>
                      setOpenPlugins((prev) => ({
                        ...prev,
                        [pluginName]: !prev[pluginName],
                      }))
                    }
                    type="button"
                  >
                    <span className="whatwebPluginTitle">{pluginName}</span>
                    <span className="whatwebPluginChevron">
                      {isOpen ? "▾" : "▸"}
                    </span>
                  </button>

                  {isOpen && (
                    <div className="whatwebPluginBody">
                      {pluginEntries.length === 0 ? (
                        <div className="muted" style={{ fontSize: 14 }}>
                          No fields
                        </div>
                      ) : (
                        <div className="tableWrap">
                          <table className="table">
                            <thead className="thead">
                              <tr>
                                <th className="th">Key</th>
                                <th className="th">Value</th>
                              </tr>
                            </thead>
                            <tbody>
                              {pluginEntries.map(([k, v]) => (
                                <tr className="tr" key={`${pluginName}-${k}`}>
                                  <td className="td">{k}</td>
                                  <td className="td">
                                    {typeof v === "string" ? (
                                      <span className="mono">{v || "n/a"}</span>
                                    ) : (
                                      <pre className="whatwebPre">
                                        {formatValue(v) || "n/a"}
                                      </pre>
                                    )}
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>

      <div style={{ marginTop: 12 }}>
        <div className="sectionTitle" style={{ margin: "0 0 8px 0" }}>
          HTTP headers
        </div>

        {headers.length === 0 ? (
          <div className="muted" style={{ fontSize: 14 }}>
            n/a
          </div>
        ) : (
          <div className="tableWrap">
            <table className="table">
              <thead className="thead">
                <tr>
                  <th className="th">Header</th>
                  <th className="th">Value</th>
                </tr>
              </thead>
              <tbody>
                {headers.map(([k, v]) => (
                  <tr className="tr" key={`hdr-${k}`}>
                    <td className="td mono">{k}</td>
                    <td className="td mono">{formatValue(v) || "n/a"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
