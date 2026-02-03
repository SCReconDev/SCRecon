import type { Scan } from "../types/scans";

const API_BASE = "/api";

async function errorIfResNotOk(res: Response, action: string) {
  if (res.ok) return;
  const text = await res.text().catch(() => "");
  throw new Error(`${action} failed (${res.status}): ${text || res.statusText}`);
}

export async function fetchScans(signal?: AbortSignal): Promise<Scan[]> {
  const res = await fetch(`${API_BASE}/scans`, { signal });
  await errorIfResNotOk(res, "Fetch scans");
  return (await res.json()) as Scan[];
}

export async function deleteScan(scanId: number, signal?: AbortSignal): Promise<void> {
  const res = await fetch(`${API_BASE}/deletescan/${scanId}`, {
    method: "DELETE",
    signal,
  });
  await errorIfResNotOk(res, "Delete scan");
}

export async function createScanSession(ip: string, timing = 5, signal?: AbortSignal): Promise<number> {
  const res = await fetch(`${API_BASE}/createscansession/${timing}/${encodeURIComponent(ip)}`, {
    method: "GET",
    signal,
  });
  await errorIfResNotOk(res, "Create scan session");
  const data = (await res.json()) as { scan_id?: number; error?: string };
  if (!data.scan_id) throw new Error(data.error || "Missing scan_id from backend.");
  return data.scan_id;
}

export async function runPortscan(scanId: number, signal?: AbortSignal) {
  const res = await fetch(`${API_BASE}/scan/port/${scanId}`, { signal });
  await errorIfResNotOk(res, "Portscan");
  return res.json();
}

export async function runBannergrab(scanId: number, signal?: AbortSignal) {
  const res = await fetch(`${API_BASE}/scan/banner/${scanId}`, { signal });
  await errorIfResNotOk(res, "Bannergrab");
  return res.json();
}

export async function runVulnscan(scanId: number, signal?: AbortSignal) {
  const res = await fetch(`${API_BASE}/scan/vuln/${scanId}`, { signal });
  await errorIfResNotOk(res, "Vulnscan");
  return res.json();
}

export async function runSubenum(scanId: number, signal?: AbortSignal) {
  const res = await fetch(`${API_BASE}/scan/subenum/${scanId}`, { signal });
  await errorIfResNotOk(res, "Subdomain enumeration");
  return res.json();
}

export async function runSmbShares(scanId: number, signal?: AbortSignal) {
  const res = await fetch(`${API_BASE}/scan/smbshares/${scanId}`, { signal });
  await errorIfResNotOk(res, "SMB shares");
  return res.json();
}

export async function runWhatweb(scanId: number, signal?: AbortSignal) {
  const res = await fetch(`${API_BASE}/scan/whatweb/${scanId}`, { signal });
  await errorIfResNotOk(res, "WhatWeb");
  return res.json();
}

export async function lookupCves(scanId: number, signal?: AbortSignal) {
  const res = await fetch(`${API_BASE}/lookup/cves/${scanId}`, { signal });
  await errorIfResNotOk(res, "CVE lookup");
  return res.json();
}

export async function lookupMetamodules(scanId: number, signal?: AbortSignal) {
  const res = await fetch(`${API_BASE}/lookup/metamodules/${scanId}`, { signal });
  await errorIfResNotOk(res, "Metasploit module lookup");
  return res.json();
}
