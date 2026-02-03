from __future__ import annotations
from datetime import datetime, timezone



class TargetInformation:
    def __init__(self, scan_id: int, ip: str, timing: int, created_at: str | None = None):
        self.scan_id = scan_id
        self.ip = ip
        self.timing = timing

        self.created_at = created_at or datetime.now(timezone.utc).isoformat()

        self.portscan = None
        self.bannergrab = None
        self.vulnerabilityscan = None
        self.subdomainl1 = None
        self.smbshares = None
        self.cves = None
        self.metamodules = None
        self.whatweb = None


    def set_portscan(self, portscan):
        self.portscan = portscan

    def set_bannergrab(self, bannergrab):
        self.bannergrab = bannergrab

    def set_vulnerabilityscan(self, vulnerabilityscan):
        self.vulnerabilityscan = vulnerabilityscan

    def set_subdomainl1(self, subdomainl1):
        self.subdomainl1 = subdomainl1

    def set_smbshares(self, smbshares):
        self.smbshares = smbshares

    def set_cves(self, cves):
        self.cves = cves

    def set_metamodules(self, metamodules):
        self.metamodules = metamodules

    def set_whatweb(self, whatweb):
        self.whatweb = whatweb

    def to_dict(self):
        return {
            "scan_id": self.scan_id,
            "ip": self.ip,
            "timing": self.timing,
            "created_at": self.created_at,
            "portscan": self.portscan,
            "bannergrab": self.bannergrab,
            "vulnerabilityscan": self.vulnerabilityscan,
            "subdomainl1": self.subdomainl1,
            "smbshares": self.smbshares,
            "cves": self.cves,
            "metamodules": self.metamodules,
            "whatweb": self.whatweb,
        }

    @classmethod
    def from_dict(cls, d: dict):
        t = cls(
            scan_id=d["scan_id"],
            ip=d["ip"],
            timing=d["timing"],
            created_at=d.get("created_at")
        )
        t.portscan = d.get("portscan")
        t.bannergrab = d.get("bannergrab")
        t.vulnerabilityscan = d.get("vulnerabilityscan")
        t.subdomainl1 = d.get("subdomainl1")
        t.smbshares = d.get("smbshares")
        t.cves = d.get("cves")
        t.metamodules = d.get("metamodules")
        t.whatweb = d.get("whatweb")
        return t

