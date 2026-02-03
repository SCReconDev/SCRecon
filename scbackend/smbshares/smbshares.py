import random
import sys

from fastapi import FastAPI
import httpx
import ipaddress
import asyncio
import re
import xml.etree.ElementTree as ET
from collections import defaultdict

app = FastAPI()

@app.get("/scan/smbshares/{ip}")
async def scan_smbshares(ip: str):
    if not validate_ip(ip):
        return {"error": "Invalid IP address"}
    process = await asyncio.create_subprocess_exec(
        "nmap", "-p", "445", "--script", "smb-enum-shares", "-Pn", "-oX", "-", ip,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await process.communicate()
    print(stdout.decode())
    #print("fehler")
    print(stderr.decode())
    root = ET.fromstring(stdout.decode())
    output = ""
    for share_tbl in root.findall(".//hostscript/script[@id='smb-enum-shares']/table"):
        unc = (share_tbl.get("key") or "").strip()
        name = unc.rsplit("\\", 1)[-1] if "\\" in unc else unc

        typ = (share_tbl.findtext("elem[@key='Type']", default="") or "").strip()
        comment = (share_tbl.findtext("elem[@key='Comment']", default="") or "").strip()
        path = (share_tbl.findtext("elem[@key='Path']", default="") or "").strip()
        anon = (share_tbl.findtext("elem[@key='Anonymous access']", default="") or "").strip()

        print(f"Name: {name}")
        print(f"Type: {typ}")
        print(f"Comment: {comment}")
        print(f"Path: {path}")
        print(f"Anonymous: {anon}")
        print("-" * 40)
        output += f"{name},{typ},{comment},{path},{anon},"
    output = output.rstrip(",")
    return {
        "scan_result": output
    }

def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False