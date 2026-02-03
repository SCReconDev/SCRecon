import { useEffect, useMemo, useState } from "react";
import {
  createScanSession,
  lookupCves,
  lookupMetamodules,
  runBannergrab,
  runPortscan,
  runSmbShares,
  runSubenum,
  runVulnscan,
  runWhatweb,
} from "../api/scans";

type ScanChoice =
  | "portscan"
  | "bannergrab"
  | "vulnscan"
  | "cves"
  | "metamodules"
  | "subenum"
  | "smbshares"
  | "whatweb";

type Props = {
  open: boolean;
  onClose: () => void;
  onCreated: (scanId: number) => void;
};

const DEFAULT_TIMING = 5;

const LABELS: Record<ScanChoice, string> = {
  portscan: "Port scan",
  bannergrab: "Banner grab",
  vulnscan: "Vulnerability scan",
  cves: "Lookup CVEs",
  metamodules: "Lookup Metasploit modules",
  subenum: "Subdomain enumeration",
  smbshares: "SMB shares",
  whatweb: "WhatWeb",
};

function isValidIp(ip: string) {
  return ip.trim().length > 0;
}


function normalizeChoices(set: Set<ScanChoice>): Set<ScanChoice> {
  const out = new Set(set);

  if (out.has("bannergrab") || out.has("vulnscan")) {
    out.add("portscan");
  }

  if (out.has("cves") || out.has("metamodules")) {
    out.add("vulnscan");
    out.add("portscan");
  }

  return out;
}

export function NewScanModal({ open, onClose, onCreated }: Props) {
  const [ip, setIp] = useState("");

  const [choices, setChoices] = useState<Set<ScanChoice>>(
    () => new Set<ScanChoice>(["portscan", "vulnscan", "cves", "metamodules"])
  );

  const normalized = useMemo(() => normalizeChoices(choices), [choices]);

  const [running, setRunning] = useState(false);
  const [log, setLog] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);

  const [totalSteps, setTotalSteps] = useState(0);
  const [doneSteps, setDoneSteps] = useState(0);
  const [currentStep, setCurrentStep] = useState<string>("");

  const progressCount = totalSteps > 0 ? Math.round((doneSteps / totalSteps) * 100) : 0;

  const addLog = (line: string) => setLog((prev) => [...prev, line]);

  const startProgress = (total: number) => {
    setTotalSteps(total);
    setDoneSteps(0);
    setCurrentStep("");
  };

  const stepStart = (label: string) => setCurrentStep(label);

  const stepDone = () => setDoneSteps((d) => d + 1);

  useEffect(() => {
    if (!open) {
      setError(null);
      setLog([]);
      setRunning(false);
      setTotalSteps(0);
      setDoneSteps(0);
      setCurrentStep("");
    }
  }, [open]);

  const toggle = (key: ScanChoice) => {
    setChoices((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return normalizeChoices(next);
    });
  };

  const canStart = open && !running && isValidIp(ip) && normalized.size > 0;

  const start = async () => {
    setError(null);
    setLog([]);
    setRunning(true);

    const chosenModules: string[] = [];
    chosenModules.push("Create scan session");

    if (normalized.has("portscan")) chosenModules.push("Port scan");
    if (normalized.has("bannergrab")) chosenModules.push("Banner grab");
    if (normalized.has("vulnscan")) chosenModules.push("Vulnerability scan");
    if (normalized.has("cves")) chosenModules.push("CVE lookup");
    if (normalized.has("metamodules")) chosenModules.push("Metasploit module lookup");
    if (normalized.has("subenum")) chosenModules.push("Subdomain enumeration");
    if (normalized.has("smbshares")) chosenModules.push("SMB shares");
    if (normalized.has("whatweb")) chosenModules.push("WhatWeb");

    startProgress(chosenModules.length);

    const ctrl = new AbortController();

    try {
      stepStart("Create scan session");
      addLog(`Creating scan session…`);
      const scanId = await createScanSession(ip.trim(), DEFAULT_TIMING, ctrl.signal);
      addLog(`Created scan_id ${scanId}`);
      stepDone();

      let vulnFound = true;

      if (normalized.has("portscan")) {
        stepStart("Port scan");
        addLog("Running port scan…");
        await runPortscan(scanId, ctrl.signal);
        addLog("Port scan done.");
        stepDone();
      }

      if (normalized.has("bannergrab")) {
        stepStart("Banner grab");
        addLog("Running banner grab…");
        await runBannergrab(scanId, ctrl.signal);
        addLog("Banner grab done.");
        stepDone();
      }

      if (normalized.has("vulnscan")) {
        stepStart("Vulnerability scan");
        addLog("Running vulnerability scan… (this can take 5 - 15 minutes)");
        const vulnRes = await runVulnscan(scanId, ctrl.signal);
        addLog("Vulnerability scan done.");
        stepDone();

        const vulns =
          (vulnRes?.vulnerabilities as string | undefined) ??
          (vulnRes?.vulnerabilityscan?.vulnerabilities as string | undefined) ??
          "";

        vulnFound = typeof vulns === "string" && vulns.trim().length > 0;
        if (!vulnFound) addLog("No vulnerabilities found.");
      }

      if (normalized.has("cves")) {
        stepStart("CVE lookup");
        if (!vulnFound) {
          addLog("Skipping CVE lookup (no vulnerabilities).");
          stepDone();
        } else {
          addLog("Looking up CVEs…");
          await lookupCves(scanId, ctrl.signal);
          addLog("CVE lookup done.");
          stepDone();
        }
      }

      if (normalized.has("metamodules")) {
        stepStart("Metasploit module lookup");
        if (!vulnFound) {
          addLog("Skipping Metasploit module lookup (no vulnerabilities).");
          stepDone();
        } else {
          addLog("Looking up Metasploit modules…");
          await lookupMetamodules(scanId, ctrl.signal);
          addLog("Metasploit module lookup done.");
          stepDone();
        }
      }

      if (normalized.has("subenum")) {
        stepStart("Subdomain enumeration");
        addLog("Running subdomain enumeration…");
        await runSubenum(scanId, ctrl.signal);
        addLog("Subdomain enumeration done.");
        stepDone();
      }

      if (normalized.has("smbshares")) {
        stepStart("SMB shares");
        addLog("Checking SMB shares…");
        await runSmbShares(scanId, ctrl.signal);
        addLog("SMB shares done.");
        stepDone();
      }

      if (normalized.has("whatweb")) {
        stepStart("WhatWeb");
        addLog("Running WhatWeb…");
        await runWhatweb(scanId, ctrl.signal);
        addLog("WhatWeb done.");
        stepDone();
      }

      stepStart("Done");
      addLog("All selected scans completed.");
      onCreated(scanId);
      onClose();
    } catch (e: any) {
      const msg = String(e?.message ?? e);
      setError(msg);
      addLog(`ERROR: ${msg}`);
    } finally {
      setRunning(false);
    }
  };

  useEffect(() => {
    if (!open) return;
    const onKey = (ev: KeyboardEvent) => {
      if (ev.key === "Escape" && !running) onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose, running]);

  if (!open) return null;

  const lockedPortscan =
    normalized.has("bannergrab") ||
    normalized.has("vulnscan") ||
    normalized.has("cves") ||
    normalized.has("metamodules");

  const lockedVulnscan = normalized.has("cves") || normalized.has("metamodules");
  
  return (
    <div className="modalOverlay" role="dialog" aria-modal="true">
      <div className="modalCard">
        <div className="modalHeader">
          <div className="modalTitle">Create new scan</div>
          <button className="button" type="button" onClick={onClose} disabled={running}>
            Close
          </button>
        </div>

        <div className="modalBody">
          <div className="modalField">
            <div className="label">Target IP</div>
            <input
              className="textInput"
              value={ip}
              onChange={(e) => setIp(e.target.value)}
              placeholder="e.g. 192.168.1.10"
              disabled={running}
              autoFocus
            />
            <div className="muted" style={{ fontSize: 12, marginTop: 4 }}>
              
            </div>
          </div>

          <div className="modalField" style={{ marginTop: 12 }}>
            <div className="label">Select scans</div>

            <div className="checkGrid">
              {(
                [
                  "portscan",
                  "bannergrab",
                  "vulnscan",
                  "cves",
                  "metamodules",
                  "whatweb",
                  "subenum",
                  "smbshares",
                ] as ScanChoice[]
              ).map((key) => {
                const checked = normalized.has(key);

                const locked =
                  (key === "portscan" && lockedPortscan) || (key === "vulnscan" && lockedVulnscan);

                return (
                  <label key={key} className={`checkItem ${locked ? "checkItemLocked" : ""}`}>
                    <input
                      type="checkbox"
                      checked={checked}
                      disabled={running || locked}
                      onChange={() => toggle(key)}
                    />
                    <span>{LABELS[key]}</span>
                    {locked && <span className="checkHint">(required)</span>}
                  </label>
                );
              })}
            </div>

            <div className="muted" style={{ fontSize: 12, marginTop: 6 }}>
              Dependent scans add prerequisites automatically.
            </div>
          </div>

          <div className="modalActions">
            <button className="button" type="button" onClick={onClose} disabled={running}>
              Cancel
            </button>
            <button className="primaryButton" type="button" onClick={start} disabled={!canStart}>
              {running ? "Running…" : "Start scan"}
            </button>
          </div>

          {error && (
            <div className="error" style={{ marginTop: 10 }}>
              {error}
            </div>
          )}

          <div className="progressWrap">
            <div className="progressTop">
              <div className="progressLabel">Progress</div>
              <div className="progressPct">{progressCount}%</div>
            </div>

            <div className="progressBarOuter" aria-hidden="true">
              <div className="progressBarInner" style={{ width: `${progressCount}%` }} />
            </div>

            <div className="progressSub">
              {running ? (
                <>
                  {currentStep ? `Current: ${currentStep}` : "Preparing…"}{" "}
                  {totalSteps > 0 && <span className="mono">({doneSteps}/{totalSteps})</span>}
                </>
              ) : (
                <>
                  {totalSteps > 0 ? "Ready." : "No actions yet."}{" "}
                  {totalSteps > 0 && <span className="mono">({doneSteps}/{totalSteps})</span>}
                </>
              )}
            </div>
          </div>

          <div className="logBox">
            <div className="label">Log</div>
            {log.length === 0 ? (
              <div className="muted" style={{ fontSize: 13, marginTop: 6 }}>
                No actions yet.
              </div>
            ) : (
              <ul className="logList">
                {log.map((line, i) => (
                  <li key={i} className="mono">
                    {line}
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
