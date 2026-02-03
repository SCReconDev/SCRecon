import os
import re
import asyncio
from typing import Any, Dict, List, Optional, Tuple

import httpx
from fastapi import FastAPI

app = FastAPI()

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
CIRCL_URL = "https://cve.circl.lu/api/cve/{cve_id}"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def get_english_description(cve: Dict[str, Any]):
    # first check CNA container
    for description in cve.get("containers", {}).get("cna", {}).get("descriptions", []) or []:
        if description.get("lang") == "en" and description.get("value"):
            return description["value"]

    # adp if cna is missing
    for adp in cve.get("containers", {}).get("adp", []) or []:
        for description in adp.get("descriptions", []) or []:
            if description.get("lang") == "en" and description.get("value"):
                return description["value"]

    return None

# extract CVSS metrics
# returning dict: {"cvssV3_1": {...}, "cvssV3_0": {...}}
def collect_cvss_metrics(cve: Dict[str, Any]):
    out: Dict[str, Any] = {}

    def scan_metrics_list(metrics_list: List[Dict[str, Any]]):
        for cvss_metric in metrics_list or []:
            for field, value in (cvss_metric or {}).items():
                if isinstance(field, str) and field.lower().startswith("cvss") and isinstance(value, dict):
                    out.setdefault(field, value)

    cna_metrics = cve.get("containers", {}).get("cna", {}).get("metrics", []) or []
    scan_metrics_list(cna_metrics)

    for adp in cve.get("containers", {}).get("adp", []) or []:
        scan_metrics_list(adp.get("metrics", []) or [])

    return out


def simplify_cve(cveid_queried: str, cve: Dict[str, Any], cvss_nvd: Optional[Dict[str, Any]] = None):
    metdata = cve.get("cveMetadata", {}) or {}
    cveid = metdata.get("cveId") or cveid_queried

    affected_json = cve.get("containers", {}).get("cna", {}).get("affected", []) or []
    simplified_affected: List[Dict[str, Any]] = []

    for affected in affected_json:
        vendor = affected.get("vendor")
        product = affected.get("product")
        default_status = affected.get("defaultStatus")
        versions = affected.get("versions", []) or []

        simplified_affected.append(
            {
                "defaultStatus": default_status,
                "vendor": vendor,
                "product": product,
                "versions": versions,
            }
        )

    cvss = cvss_nvd if isinstance(cvss_nvd, dict) else collect_cvss_metrics(cve)

    return {
        "cveId": cveid,
        "affected": simplified_affected,
        "description_en": get_english_description(cve),
        "cvss": cvss,
    }

def _nvd_headers():
    key = os.getenv("NVD_API_KEY")
    return {"apiKey": key} if key else {}

# extract cvss dict from nvd response
def extract_nvd_cvss(cve_item: Dict[str, Any]):
    metrics = cve_item.get("metrics") or {}
    if not isinstance(metrics, dict):
        return {}

    candidates: List[Tuple[str, str, str]] = [
        ("cvssMetricV31", "cvssV3_1", "3.1"),
        ("cvssMetricV30", "cvssV3_0", "3.0"),
        ("cvssMetricV2", "cvssV2_0", "2.0"),
    ]

    for field_name, output_name, version in candidates:
        cvss_array = metrics.get(field_name)
        if not (isinstance(cvss_array, list) and cvss_array):
            continue

        entry = cvss_array[0] or {}
        cvss_data = entry.get("cvssData") or {}
        if not isinstance(cvss_data, dict):
            continue

        base_score = cvss_data.get("baseScore")
        base_severity = cvss_data.get("baseSeverity") or entry.get("baseSeverity")
        cvss_metric_vector = cvss_data.get("vectorString")

        if isinstance(base_score, (int, float)):
            return {
                output_name: {
                    "baseScore": float(base_score),
                    "baseSeverity": base_severity if isinstance(base_severity, str) else None,
                    "vectorString": cvss_metric_vector if isinstance(cvss_metric_vector, str) else None,
                    "version": version,
                }
            }

    return {}

# requests CVE from NVD
async def fetch_nvd_cvss(client: httpx.AsyncClient, cve_id: str):

    try:
        response = await client.get(NVD_URL, params={"cveId": cve_id}, headers=_nvd_headers())
    except httpx.HTTPError:
        return {}

    if response.status_code != 200:
        return {}

    try:
        data = response.json()
    except ValueError:
        return {}

    vulnerabilities = data.get("vulnerabilities")
    if not (isinstance(vulnerabilities, list) and vulnerabilities):
        return {}

    cve = vulnerabilities[0].get("cve")
    if not isinstance(cve, dict):
        return {}

    return extract_nvd_cvss(cve)


@app.get("/scan/cvesearch/{vuln}")
async def scan_cvesearch(vuln: str):
    # CVE search API is used first
    # If there is no cvss in CVE search, NVD is used as fallback
    cveids = [id.strip() for id in vuln.split(",") if id.strip()]
    for cveid in cveids:
        if not CVE_RE.match(cveid):
            return {"error": f"Invalid CVE ID: {cveid}"}

    CIRCL_CONCURRENCY = 1
    NVD_CONCURRENCY = 1
    CIRCL_DELAY_S = 0.25
    NVD_DELAY_S = 0.5   

    circl_sem = asyncio.Semaphore(CIRCL_CONCURRENCY)
    nvd_sem = asyncio.Semaphore(NVD_CONCURRENCY)

    timeout = httpx.Timeout(connect=10.0, read=20.0, write=10.0, pool=10.0)

    async with httpx.AsyncClient(timeout=timeout) as client:

        async def fetch_circl(cveid: str) -> httpx.Response:
            async with circl_sem:
                await asyncio.sleep(CIRCL_DELAY_S)
                return await client.get(CIRCL_URL.format(cve_id=cveid))

        async def fetch_nvd(cveid: str) -> Dict[str, Any]:
            async with nvd_sem:
                await asyncio.sleep(NVD_DELAY_S)
                return await fetch_nvd_cvss(client, cveid)

        async def get_cve_info(cveid: str) -> Tuple[str, Dict[str, Any]]:
            try:
                response = await fetch_circl(cveid)
            except httpx.HTTPError:
                return cveid, {"error": "CVE lookup failed"}

            if response.status_code != 200:
                return cveid, {"error": "CVE not found"}

            try:
                raw_response = response.json()
            except ValueError:
                return cveid, {"error": "Invalid response from CVE source"}

            cvss = collect_cvss_metrics(raw_response)

            if not cvss:
                # fallback to NVD
                try:
                    cvss = await fetch_nvd(cveid)
                except httpx.HTTPError:
                    cvss = {}

            return cveid, simplify_cve(cveid, raw_response, cvss_nvd=cvss)

        results = await asyncio.gather(*(get_cve_info(c) for c in cveids))
        out: Dict[str, Any] = {cveid: payload for (cveid, payload) in results}

    return {"cves": out}

