from pathlib import Path
from time import sleep

from fastapi import FastAPI
import ipaddress
import asyncio

app = FastAPI()

@app.get("/scan/subenum/{ip}")
async def scan_subenum(ip: str):
    if not validate_ip(ip):
        return {"error": "Invalid IP address."}
    try:
        process = await asyncio.create_subprocess_exec(
            "gobuster", "dir", "-u", ip, "-w",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "-o", "tempout.txt",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        print(stdout)
        print(stderr)
        sleep(2)
        output = ""
        with open("tempout.txt", "r") as f:
            for line in f.readlines():
                print("line:")
                print(line)
                parts = line.split()
                output += parts[0] + "," + parts[2].rstrip(")") + ","
        sleep(1)
    finally:
        if Path("tempout.txt").exists():
            Path("tempout.txt").unlink()

    try:
        process = await asyncio.create_subprocess_exec(
            "gobuster", "dir", "-u", ip, "-w",
            "/usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt",
            "-o", "tempout2.txt",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        print(stdout)
        print(stderr)
        sleep(2)


        with open("tempout2.txt", "r") as f:
            for line in f.readlines():
                print("line:")
                print(line)
                parts = line.split()
                output += parts[0] + "," + parts[2].rstrip(")") + ","
        sleep(1)
    finally:
        if Path("tempout2.txt").exists():
            Path("tempout2.txt").unlink()

    output_without_duplicates = ""
    isDomain = True
    isNew = False
    for out in output.split(","):
        if not isDomain:
            isDomain = True
            if isNew:
                output_without_duplicates += out + ","
        else:
            isDomain = False
            if not out in output_without_duplicates:
                output_without_duplicates += out + ","
                isNew = True
            else:
                isNew = False



    return {"subdomains:": output_without_duplicates.rstrip(",")}



def validate_ip(ip):
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False