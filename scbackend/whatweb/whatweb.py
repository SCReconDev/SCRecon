import os
import re
import asyncio
import ipaddress
import textwrap

from fastapi import FastAPI
from fastapi.responses import JSONResponse

ANSI_REGEX = re.compile(r"\x1b\[[0-9;]*m")
PLUGIN_HEADER_REGEX = re.compile(r"^\[\s*(.+?)\s*\]\s*$")
FIELDS_REGEX = re.compile(r"^\s*([A-Za-z][A-Za-z0-9 \-]+?)\s*:\s*(.+?)\s*$")

app = FastAPI()


@app.get("/scan/whatweb/{ip}")
async def whatweb_scan(ip: str):
    if not validate_ip(ip):
        return {"error": "Invalid IP address."}

    output_whatweb = await run_whatweb(ip)
    data = parse_whatweb(output_whatweb)
    return data


def validate_ip(ip: str):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def strip_ansi(str_to_strip: str):
    return ANSI_REGEX.sub("", str_to_strip)


async def run_whatweb(ip: str):
    process = await asyncio.create_subprocess_exec(
        "whatweb", "-v", "-a", "3", ip,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await process.communicate()
    return strip_ansi(stdout.decode(errors="replace"))


def split_outside_brackets(str_to_split: str):
    parts = []
    buffer = []
    depth = 0
    for character in str_to_split:
        if character == "[":
            depth += 1
        elif character == "]" and depth > 0:
            depth -= 1

        if character == "," and depth == 0:
            parts.append("".join(buffer).strip())
            buffer = []
        else:
            buffer.append(character)
    tail = "".join(buffer).strip()
    if tail:
        parts.append(tail)
    return parts


def parse_summary(summary_text: str):
    plugins = []
    for part in split_outside_brackets(summary_text):
        if not part:
            continue
        matched_part = re.match(r"^(?P<name>[^\[]+)(?P<rest>(\[[^\]]*\])*)$", part.strip())
        if not matched_part:
            continue
        name = matched_part.group("name").strip()
        values = re.findall(r"\[([^\]]*)\]", matched_part.group("rest"))
        plugins.append({"name": name, "summary_values": values})
    return plugins


def parse_whatweb(text: str):
    lines = text.splitlines()

    out = {
        "report_for": None,
        "status": None,
        "title": None,
        "ip": None,
        "country": None,
        "summary_plugins": [],
        "detected_plugins": {},
        "http_headers": {},
    }

    i = 0
    while i < len(lines):
        line = lines[i].strip()

        if line.startswith("WhatWeb report for "):
            out["report_for"] = line.replace("WhatWeb report for ", "").strip()

        matched_line = re.match(r"^(Status|Title|IP|Country)\s*:\s*(.+)$", line)
        if matched_line:
            out[matched_line.group(1).lower()] = matched_line.group(2).strip()

        if line.startswith("Summary"):
            out["summary_plugins"] = parse_summary(line.split(":", 1)[1].strip())

        if line == "Detected Plugins:":
            i += 1
            break
        i += 1

    current = None
    description_buffer = []

    def flush_description():
        nonlocal description_buffer
        if current is not None:
            raw_description = "\n".join(description_buffer).replace("\t", "    ")
            description = textwrap.dedent(raw_description).strip()
            if description:
                out["detected_plugins"][current]["description"] = description
        description_buffer = []

    while i < len(lines):
        line = lines[i].rstrip("\n")

        if line.strip() == "HTTP Headers:":
            flush_description()
            i += 1
            break

        header = PLUGIN_HEADER_REGEX.match(line.strip())
        if header:
            flush_description()
            current = header.group(1).strip()
            out["detected_plugins"][current] = {}
            i += 1
            continue

        if current:
            matched_field = FIELDS_REGEX.match(line)
            if matched_field:
                field = matched_field.group(1).strip()
                value = matched_field.group(2).strip()

                if field.lower() in {"http", "https"}:
                    description_buffer.append(line)
                    i += 1
                    continue

                detected_plugin = out["detected_plugins"][current]
                if field in detected_plugin:
                    detected_plugin[field] = detected_plugin[field] + [value] if isinstance(detected_plugin[field], list) else [detected_plugin[field], value]
                else:
                    detected_plugin[field] = value
            else:
                description_buffer.append(line)
        i += 1

    if i < len(lines):
        first = lines[i].strip()
        if first and ":" not in first:
            out["http_headers"]["_status_line"] = first
            i += 1

    while i < len(lines):
        header_line = lines[i].strip()
        if not header_line:
            i += 1
            continue
        if ":" in header_line:
            field, value = header_line.split(":", 1)
            out["http_headers"][field.strip()] = value.strip()
        i += 1

    return out