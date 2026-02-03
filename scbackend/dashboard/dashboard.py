import asyncio
import json
import os
import random
from pathlib import Path
from urllib.parse import quote

import httpx
import ipaddress
from fastapi import FastAPI, HTTPException

from .targetInformation import TargetInformation

PORTSCANNER_URL = os.getenv("PORTSCANNER_URL", "http://portscanner:8001")
BANNER_URL      = os.getenv("BANNER_URL",      "http://bannergrabbing:8002")
VULN_URL        = os.getenv("VULN_URL",        "http://vulnerability:8003")
SUBENUM_URL     = os.getenv("SUBENUM_URL",     "http://subenum:8004")
SMBSHARES_URL   = os.getenv("SMBSHARES_URL",   "http://smbshares:8005")
WHATWEB_URL     = os.getenv("WHATWEB_URL",     "http://whatweb:8006")
CVE_URL         = os.getenv("CVE_URL",         "http://cvelookup:8007")
METASPLOIT_URL  = os.getenv("METASPLOIT_URL",  "http://metasploit:8008")

scanresults: dict[int, TargetInformation] = {}
scan_ids: list[int] = []

STATE_FILE = Path(os.getenv("STATE_FILE", "/app/state/scan_state.json"))

state_lock = asyncio.Lock()


async def save_state():
    data = {
        "scan_ids": scan_ids,
        "scanresults": {str(k): v.to_dict() for k, v in scanresults.items()},
    }

    tmp = STATE_FILE.with_suffix(".tmp")
    async with state_lock:
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        tmp.replace(STATE_FILE)


async def load_state():
    if not STATE_FILE.exists():
        return

    async with state_lock:
        data = json.loads(STATE_FILE.read_text(encoding="utf-8"))

    scan_ids.clear()
    scanresults.clear()

    scan_ids.extend(data.get("scan_ids", []))

    raw = data.get("scanresults", {})
    for _, v in raw.items():
        t = TargetInformation.from_dict(v)
        scanresults[t.scan_id] = t


app = FastAPI()


@app.on_event("startup")
async def on_startup():
    await load_state()


def validate_ip(ip: str):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def generate_scan_id():
    new_id = random.randint(1, 2**52)
    while new_id in scan_ids:
        new_id = random.randint(1, 2**52)
    scan_ids.append(new_id)
    return new_id


def require_scan(scan_id: int):
    if scan_id not in scanresults:
        raise HTTPException(status_code=400, detail="Invalid scan_id.")
    return scanresults[scan_id]


def retrieve_ip(scan_id: int):
    info = require_scan(scan_id)
    if not validate_ip(info.ip):
        raise HTTPException(status_code=400, detail="Invalid IP address stored.")
    return info.ip


def retrieve_timing(scan_id: int):
    info = require_scan(scan_id)
    return info.timing


def retrieve_ports(scan_id: int):
    info = require_scan(scan_id)

    portscan_data = info.portscan
    if not isinstance(portscan_data, dict):
        raise HTTPException(status_code=400, detail="No portscan data found.")

    scan_result = portscan_data.get("scan_result")
    if not scan_result:
        raise HTTPException(status_code=400, detail="No scan_result found in portscan.")

    portscan_parts = scan_result.split(",")

    portstring = ",".join(portscan_parts[0::2]).rstrip(",")
    return portstring


def retrieve_vulnerabilityscan(scan_id: int):
    info = require_scan(scan_id)

    vuln_data = info.vulnerabilityscan
    if not isinstance(vuln_data, dict):
        raise HTTPException(status_code=400, detail="No vulnerabilityscan data found.")

    vulnerabilities = vuln_data.get("vulnerabilities")
    if not vulnerabilities:
        raise HTTPException(status_code=400, detail="No vulnerabilities field found.")

    return vulnerabilities


@app.get("/createscansession/{timing}/{ip}")
async def create_scan_session(timing: int, ip: str):
    if not validate_ip(ip):
        return {"error": "Invalid IP address."}
    if not 0 <= timing <= 5:
        return {"error": "Invalid timing."}

    scan_id = generate_scan_id()
    scanresults[scan_id] = TargetInformation(scan_id=scan_id, ip=ip, timing=timing)

    await save_state()
    return {"scan_id": scan_id}


@app.get("/scan/port/{scan_id}")
async def call_nmap_service(scan_id: int):
    info = require_scan(scan_id)
    ip = retrieve_ip(scan_id)
    timing = retrieve_timing(scan_id)

    timeout = httpx.Timeout(connect=5.0, read=3600.0, write=100.0, pool=5.0)
    async with httpx.AsyncClient(timeout=timeout) as client:
        response = await client.get(f"{PORTSCANNER_URL}/scan/{timing}/{ip}")
        data = response.json()

    info.set_portscan(data)
    await save_state()

    data["scan_id"] = scan_id
    return data


@app.get("/scan/banner/{scan_id}")
async def call_banner_service(scan_id: int):
    info = require_scan(scan_id)
    ports = retrieve_ports(scan_id)
    ip = retrieve_ip(scan_id)
    timing = retrieve_timing(scan_id)

    timeout = httpx.Timeout(connect=5.0, read=3600.0, write=100.0, pool=5.0)
    async with httpx.AsyncClient(timeout=timeout) as client:
        response = await client.get(f"{BANNER_URL}/scan/banner/{timing}/{ip}/{ports}")
        data = response.json()

    info.set_bannergrab(data)
    await save_state()

    data["scan_id"] = scan_id
    return data


@app.get("/scan/vuln/{scan_id}")
async def call_vuln_service(scan_id: int):
    info = require_scan(scan_id)
    ports = retrieve_ports(scan_id)
    ip = retrieve_ip(scan_id)
    timing = retrieve_timing(scan_id)

    timeout = httpx.Timeout(connect=5.0, read=7200.0, write=100.0, pool=5.0)
    async with httpx.AsyncClient(timeout=timeout) as client:
        response = await client.get(f"{VULN_URL}/scan/nmapvuln/{timing}/{ip}/{ports}")
        data = response.json()

    info.set_vulnerabilityscan(data)
    await save_state()

    data["scan_id"] = scan_id
    return data


@app.get("/scan/subenum/{scan_id}")
async def call_subenum_service(scan_id: int):
    info = require_scan(scan_id)
    ip = retrieve_ip(scan_id)

    timeout = httpx.Timeout(connect=5.0, read=3600.0, write=100.0, pool=5.0)
    async with httpx.AsyncClient(timeout=timeout) as client:
        response = await client.get(f"{SUBENUM_URL}/scan/subenum/{ip}")
        data = response.json()

    info.set_subdomainl1(data)
    await save_state()

    data["scan_id"] = scan_id
    return data


@app.get("/scan/smbshares/{scan_id}")
async def call_smbshares_service(scan_id: int):
    info = require_scan(scan_id)
    ip = retrieve_ip(scan_id)

    timeout = httpx.Timeout(connect=5.0, read=3600.0, write=100.0, pool=5.0)
    async with httpx.AsyncClient(timeout=timeout) as client:
        response = await client.get(f"{SMBSHARES_URL}/scan/smbshares/{ip}")
        data = response.json()

    info.set_smbshares(data)
    await save_state()

    data["scan_id"] = scan_id
    return data


@app.get("/scan/whatweb/{scan_id}")
async def call_whatweb_service(scan_id: int):
    info = require_scan(scan_id)
    ip = retrieve_ip(scan_id)

    timeout = httpx.Timeout(connect=5.0, read=3600.0, write=100.0, pool=5.0)
    async with httpx.AsyncClient(timeout=timeout) as client:
        response = await client.get(f"{WHATWEB_URL}/scan/whatweb/{ip}")
        data = response.json()

    info.set_whatweb(data)
    await save_state()

    data["scan_id"] = scan_id
    return data


@app.get("/lookup/cves/{scan_id}")
async def call_cveservice(scan_id: int):
    info = require_scan(scan_id)

    vuln = retrieve_vulnerabilityscan(scan_id)
    vuln_encoded = quote(vuln, safe="")

    timeout = httpx.Timeout(connect=5.0, read=3600.0, write=100.0, pool=5.0)
    async with httpx.AsyncClient(timeout=timeout) as client:
        response = await client.get(f"{CVE_URL}/scan/cvesearch/{vuln_encoded}")
        data = response.json()

    info.set_cves(data)
    await save_state()

    data["scan_id"] = scan_id
    return data


@app.get("/lookup/metamodules/{scan_id}")
async def call_metasploitservice(scan_id: int):
    info = require_scan(scan_id)

    vuln = retrieve_vulnerabilityscan(scan_id)
    vuln_encoded = quote(vuln, safe="")

    timeout = httpx.Timeout(connect=10.0, read=3600.0, write=100.0, pool=30.0)
    async with httpx.AsyncClient(timeout=timeout) as client:
        response = await client.get(f"{METASPLOIT_URL}/lookup/metamodules/{vuln_encoded}")
        data = response.json()

    info.set_metamodules(data)
    await save_state()

    data["scan_id"] = scan_id
    return data


@app.get("/scans")
async def get_all_scans():
    all_scans = []
    for scan_id in scan_ids:
        if scan_id not in scanresults:
            continue

        scan_info = scanresults[scan_id]
        all_scans.append(scan_info.to_dict())

    return all_scans

@app.delete("/deletescan/{scan_id}")
async def delete_scan(scan_id: int):
    if scan_id in scanresults:
        del scanresults[scan_id]
    if scan_id in scan_ids:
        scan_ids.remove(scan_id)

    await save_state()
    return {"message": f"Scan {scan_id} deleted."}
