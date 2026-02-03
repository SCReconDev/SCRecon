import { useMemo, useState } from "react";
import type { Scan } from "./types/scans";
import { useScans } from "./hooks/useScans";
import { deleteScan } from "./api/scans";

import { CveTable } from "./components/CveTable";
import { BannerGrabTable } from "./components/BannerGrabTable";
import { WhatWebPanel } from "./components/WhatWebPanel";
import { SubdomainL1Panel } from "./components/SubdomainL1Panel";
import { SmbSharesPanel } from "./components/SmbSharesPanel";
import { NewScanModal } from "./components/NewScanModal";
//import logo from "./assets/logo.png";


type ScanTab = "cves" | "bannergrab" | "whatweb" | "subdomains" | "smbshares";

function ScanRow({
  scan,
  selected,
  onSelect,
}: {
  scan: Scan;
  selected: boolean;
  onSelect: () => void;
}) {
  return (
    <button
      onClick={onSelect}
      className={`scanRow ${selected ? "scanRowSelected" : ""}`}
      type="button"
    >
      <div className="scanRowTop">
        <div className="scanIp">{scan.ip}</div>
        <div className="scanDate">{new Date(scan.created_at).toLocaleString()}</div>
      </div>

      <div className="scanMeta">
        <span>
          scan_id: <span className="mono">{scan.scan_id}</span>
        </span>
        <span>CVEs: {Object.keys(scan.cves?.cves ?? {}).length}</span>
      </div>
    </button>
  );
}

function TabButton({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      className={`tabButton ${active ? "tabButtonActive" : ""}`}
      onClick={onClick}
    >
      {children}
    </button>
  );
}

export default function App() {
  const { scans, loading, error, reload } = useScans();

  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [activeTab, setActiveTab] = useState<ScanTab>("cves");

  const [deleteError, setDeleteError] = useState<string | null>(null);
  const [deleting, setDeleting] = useState(false);

  const [newScanOpen, setNewScanOpen] = useState(false);

  const selected = useMemo(() => {
    if (!scans.length) return null;
    const found = scans.find((s) => s.scan_id === selectedId);
    return found ?? scans[0];
  }, [scans, selectedId]);

  const onDeleteSelected = async () => {
    if (!selected) return;

    const ok = window.confirm(
      `Delete scan ${selected.scan_id} for ${selected.ip}?\n\nThis will remove it from the backend completely.`
    );
    if (!ok) return;

    setDeleteError(null);
    setDeleting(true);

    try {
      await deleteScan(selected.scan_id);

      const fresh = await reload();

      if (fresh.length === 0) {
        setSelectedId(null);
        return;
      }

      setSelectedId(fresh[0].scan_id);
    } catch (e: any) {
      setDeleteError(String(e?.message ?? e));
    } finally {
      setDeleting(false);
    }
  };

  return (
    <div className="page">
      <header className="header">
        <div className="container headerInner">
         {/*<div className="headerLogo">
          <img
          src={logo}
          alt="Vulnerability Scanner"
          style={{ height: 60}}
          />
          </div>*/}
          <div className="headerTitle">SCRecon</div>

          <div style={{ display: "flex", gap: 10 }}>
            <button onClick={reload} className="button" type="button">
              Reload
            </button>
            <button
              onClick={() => setNewScanOpen(true)}
              className="button"
              type="button"
            >
              New scan
            </button>
          </div>
        </div>
      </header>

      <main className="container mainGrid">
        <aside className="panel">
          <div className="panelHeader">Scans</div>

          {loading && <div className="panelBody muted">Loading…</div>}
          {error && <div className="panelBody error">{error}</div>}

          {!loading && !error && scans.length === 0 && (
            <div className="panelBody muted">No scans found.</div>
          )}

          {!loading && !error && scans.length > 0 && (
            <div className="scanList">
              {scans.map((scan) => (
                <ScanRow
                  key={scan.scan_id}
                  scan={scan}
                  selected={selected?.scan_id === scan.scan_id}
                  onSelect={() => setSelectedId(scan.scan_id)}
                />
              ))}
            </div>
          )}
        </aside>

        <section className="stack">
          {!selected ? (
            <div className="card muted">Select a scan.</div>
          ) : (
            <>
              <div className="card">
                <div className="cardTop">
                  <div>
                    <div className="label">Target</div>
                    <div className="big">{selected.ip}</div>
                    <div className="smallLine">
                      scan_id <span className="mono">{selected.scan_id}</span> · created{" "}
                      {new Date(selected.created_at).toLocaleString()}
                    </div>
                  </div>

                  <div className="count">
                    CVEs: <strong>{Object.keys(selected.cves?.cves ?? {}).length}</strong>
                  </div>
                </div>
              </div>

              <div>
                <div className="tabBarRow">
                  <div className="tabBar">
                    <TabButton
                      active={activeTab === "cves"}
                      onClick={() => setActiveTab("cves")}
                    >
                      CVEs
                    </TabButton>

                    <TabButton
                      active={activeTab === "bannergrab"}
                      onClick={() => setActiveTab("bannergrab")}
                    >
                      Bannergrab
                    </TabButton>

                    <TabButton
                      active={activeTab === "whatweb"}
                      onClick={() => setActiveTab("whatweb")}
                    >
                      WhatWeb
                    </TabButton>

                    <TabButton
                      active={activeTab === "subdomains"}
                      onClick={() => setActiveTab("subdomains")}
                    >
                      Subdomains
                    </TabButton>

                    <TabButton
                      active={activeTab === "smbshares"}
                      onClick={() => setActiveTab("smbshares")}
                    >
                      SMB Shares
                    </TabButton>
                  </div>

                  <button
                    type="button"
                    className="dangerButton"
                    onClick={onDeleteSelected}
                    disabled={deleting}
                    title="Delete this scan"
                  >
                    {deleting ? "Deleting…" : "Delete scan"}
                  </button>
                </div>

                {deleteError && (
                  <div className="error" style={{ marginTop: 8 }}>
                    {deleteError}
                  </div>
                )}

                <div className="tabPanel">
                  {activeTab === "cves" && <CveTable scan={selected} />}

                  {activeTab === "bannergrab" && (
                    <div className="detailBox">
                      <BannerGrabTable
                        title="Bannergrab"
                        scanResult={selected.bannergrab?.scan_result ?? null}
                      />
                    </div>
                  )}

                  {activeTab === "whatweb" && <WhatWebPanel whatweb={selected.whatweb} />}

                  {activeTab === "subdomains" && (
                    <SubdomainL1Panel subdomainl1={selected.subdomainl1} />
                  )}

                  {activeTab === "smbshares" && (
                    <SmbSharesPanel smbshares={selected.smbshares} />
                  )}
                </div>
              </div>
            </>
          )}
        </section>
      </main>

      <NewScanModal
        open={newScanOpen}
        onClose={() => setNewScanOpen(false)}
        onCreated={async (scanId) => {
          const fresh = await reload();
          const found = fresh.find((s) => s.scan_id === scanId);
          setSelectedId(found ? found.scan_id : scanId);
          setActiveTab("cves");
        }}
      />
    </div>
  );
}
