import asyncio
from typing import Any, Dict, List, Optional, Tuple, Set
import os

from fastapi import FastAPI
from pymetasploit3.msfrpc import MsfRpcClient

app = FastAPI()

MSF_HOST = os.getenv("MSF_RPC_HOST", "msfrpcd")
MSF_PORT = int(os.getenv("MSF_RPC_PORT", "55553"))
MSF_PASSWORD = os.getenv("MSF_RPC_PASS", "msfpassword")
MSF_USERNAME = os.getenv("MSF_RPC_USER", "msfuser")
MSF_SSL = os.getenv("MSF_RPC_SSL", "false").lower() in ("1", "true", "yes")

def _search_sync(client: MsfRpcClient, query: str):
    return client.modules.search(query)


def _use_sync(client: MsfRpcClient, module_type: str, refname: str):
    return client.modules.use(module_type, refname)

#returns Tuple[Optional[str], Optional[str], str] which is (module_type, module_refname, display_name)
def _normalize_module_ref(m: Dict[str, Any]):
    display_name = (
        m.get("name")
        or m.get("title")
        or m.get("fullname")
        or m.get("refname")
        or "Unknown module"
    )

    module_type = m.get("type") if isinstance(m.get("type"), str) else None

    raw_ref = m.get("refname") or m.get("fullname") or m.get("path")
    refname: Optional[str] = None

    if isinstance(raw_ref, str) and raw_ref:
        parts = raw_ref.split("/")
        if parts and parts[0] in {"exploit", "auxiliary", "post", "payload", "encoder", "nop"}:
            if module_type is None:
                module_type = parts[0]
            refname = "/".join(parts[1:]) if len(parts) > 1 else None
        else:
            refname = raw_ref

    return module_type, refname, display_name


async def _load_description(client: MsfRpcClient, module_type: str, refname: str):
    msf_module = await asyncio.to_thread(_use_sync, client, module_type, refname)

    if msf_module is False:
        raise RuntimeError("modules.use() returned False (module could not be loaded)")

    desc = getattr(msf_module, "description", None) or "No description available"
    rank = getattr(msf_module, "rank", None)
    fullname = getattr(msf_module, "fullname", None)

    return {
        "description": desc,
        "rank": rank,
        "loaded_fullname": fullname,
    }

@app.get("/debug_one")
async def debug_one():
    client = MsfRpcClient(password=MSF_PASSWORD, username=MSF_USERNAME,
                          server=MSF_HOST, port=MSF_PORT, ssl=MSF_SSL)
    cve = "CVE-2017-0144"
    numeric = cve[4:]
    queries = [f"cve:{numeric}", f'"{cve}"', f'"{numeric}"']
    out = {}
    for q in queries:
        found = await asyncio.to_thread(_search_sync, client, q) or []
        out[q] = len(found)
    return out


@app.get("/lookup/metamodules/{cve_ids}")
async def lookup_metasploit_modules(cve_ids: str):
    cve_list = [c.strip() for c in cve_ids.split(",") if c.strip()]

    try:
        client = MsfRpcClient(
            password=MSF_PASSWORD,
            username=MSF_USERNAME,
            server=MSF_HOST,
            port=MSF_PORT,
            ssl=MSF_SSL,
)

    except Exception as e:
        return {"error": f"Failed to connect to Metasploit RPC server: {e}"}

    results: Dict[str, List[Dict[str, Any]]] = {}

    module_types_to_search = ["exploit", "auxiliary", "post"]

    for cve in cve_list:
        results[cve] = []

        queries = [f"cve:{cve}"] + [f"type:{t} cve:{cve}" for t in module_types_to_search]

        numeric = cve.replace("CVE-", "")
        if numeric != cve:
            queries.append(f"cve:{numeric}")
            queries.extend([f"type:{t} cve:{numeric}" for t in module_types_to_search])

        seen: Set[Tuple[str, str]] = set()

        for q in queries:
            try:
                found = await asyncio.to_thread(_search_sync, client, q)
            except Exception as e:
                print(f"Search failed for query='{q}': {e}")
                continue

            print(f"Query='{q}' hits={len(found) if found else 0}")

            if not found:
                continue

            for m in found:
                module_type, refname, display_name = _normalize_module_ref(m)

                if not module_type or not refname:
                    results[cve].append({
                        "module_name": display_name,
                        "module_type": module_type,
                        "module_refname": refname,
                        "description": m.get("description") or "No description available",
                        "rank": m.get("rank"),
                        "note": "Search entry missing usable module_type/refname; cannot load full details.",
                        "search_fullname": m.get("fullname"),
                        "search_refname": m.get("refname"),
                        "search_path": m.get("path"),
                    })
                    continue

                key = (module_type, refname)
                if key in seen:
                    continue
                seen.add(key)

                entry: Dict[str, Any] = {
                    "module_name": display_name,
                    "module_type": module_type,
                    "module_refname": refname,
                    "rank": m.get("rank"),
                    "disclosure_date": m.get("disclosure_date"),
                    "search_fullname": m.get("fullname"),
                    "search_refname": m.get("refname"),
                    "search_path": m.get("path"),
                }

                try:
                    details = await _load_description(client, module_type, refname)
                    entry["description"] = details["description"]
                    entry["rank"] = details.get("rank") or entry.get("rank")
                    if details.get("loaded_fullname"):
                        entry["loaded_fullname"] = details["loaded_fullname"]
                except Exception as e:
                    entry["description"] = "No description available"
                    entry["error"] = f"Failed to load module details: {e}"

                results[cve].append(entry)

    return {"results": results}
