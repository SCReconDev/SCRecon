from fastapi import FastAPI
import ipaddress
import asyncio
import xml.etree.ElementTree as ET

app = FastAPI()

@app.get("/")
async def read_root():
    return {"message": "Port Scan Service is running."}

@app.get("/scan/{timing}/{ip}")
async def scan_ports(timing: int, ip: str):
    if not validate_ip(ip):
        return {"error": "Invalid IP address."}
    if 0 <= timing <= 5:
        process = await asyncio.create_subprocess_exec(
            "nmap",
            "-T", str(timing),
            "-sS",
            "-sU",
            "--top-ports", "3500",
            "-Pn",
            "--max-retries", "1",
            "-oX", "-",
            ip,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        


        stdout, stderr = await process.communicate()
        print(stdout.decode())
        #print("fehler")
        print(stderr.decode())

        nmapout = ET.fromstring(stdout.decode())

        ports = nmapout.findall(".//port")

        port_services = {}
        for port in ports:
            port_id = port.get('portid')
            service = port.find('service')
            if service is not None:
                service_name = service.get('name')
                port_services[port_id] = service_name

        output = ""
        for port_id, service_name in port_services.items():
            print(f"Port ID: {port_id}, Service: {service_name}")
            output += port_id + "," + service_name + ","
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