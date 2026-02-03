from fastapi import FastAPI
import httpx
import ipaddress
import asyncio
import re
import xml.etree.ElementTree as ET
from collections import defaultdict

app = FastAPI()

@app.get("/scan/banner/{timing}/{ip}/{ports}")
async def nmap_banner_grabbing(timing: int, ip: str, ports: str):
    if not validate_ip(ip):
        return {"error": "Invalid IP address."}
    if 0 <= timing <= 5:
        process = await asyncio.create_subprocess_exec(
            "nmap", "-T", str(timing), "-p", ports, "-sV", "-oX", "-", ip,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        print(stdout.decode())
        print("fehler")
        print(stderr.decode())

        nmapout = ET.fromstring(stdout.decode())

        ports = nmapout.findall(".//port")

        port_services = {}
        port_products = {}
        port_versions = {}
        for port in ports:
            port_id = port.get('portid')
            service = port.find('service')


            if service is not None:
                service_name = service.get('name')
                port_services[port_id] = service_name
                service_product = service.get('product') or ""
                service_version = service.get('version') or ""
                port_products[port_id] = service_product
                port_versions[port_id] = service_version

        output = ""
        for port_id, service_name, in port_services.items():
            print(f"Port ID: {port_id}, Service: {service_name}, Product: {port_products.get(port_id)}, Version: {port_versions.get(port_id)}")
            output += port_id + "," + service_name + "," + port_products.get(port_id) + "," + port_versions.get(port_id) + ","
        output = output.rstrip(",")

        return {
            "scan_result": output
        }
    else:
        return {"error": "Invalid timing."}


def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False