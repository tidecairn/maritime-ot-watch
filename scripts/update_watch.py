#!/usr/bin/env python3
"""Build Maritime OT Watch from curated records + CISA ICS RSS + CISA KEV + FIRST EPSS.

Trust properties:
- Source failures preserve the prior records for that source.
- checkedAt and lastSuccess are distinct; a failed fetch never advances lastSuccess.
- KEV relevance is restricted to selected OT products or CVEs already present in selected CISA ICS records.
- Every generated signal retains a primary-source URL and origin.
"""
from __future__ import annotations
import datetime as dt
import hashlib
import html
from html.parser import HTMLParser
import json
import pathlib
import re
import sys
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

ROOT = pathlib.Path(__file__).resolve().parents[1]
DATA = ROOT / "data" / "watch.json"
CURATED = ROOT / "data" / "curated.json"
SHA = ROOT / "data" / "watch.sha256"
ICS_RSS = "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
UA = "TIDECAIRN-Maritime-OT-Watch/1.2 (+public-source intelligence updater)"
MAX_BYTES = 12 * 1024 * 1024

OT_VENDORS = {
    "abb", "advantech", "aveva", "beckhoff", "belden", "bosch rexroth", "codesys",
    "emerson", "ge vernova", "hms industrial networks", "honeywell", "hitachi energy",
    "mitsubishi electric", "moxa", "omron", "phoenix contact", "prosoft technology",
    "rockwell automation", "schneider electric", "siemens", "wago", "weidmuller",
    "westermo", "yokogawa"
}
OT_TERMS = (
    "plc", "programmable logic", "scada", "hmi", "dcs", "rtu", "industrial", "automation",
    "simatic", "contrologix", "compactlogix", "modicon", "sysmac", "ac500", "experion",
    "foxboro", "opc ua", "controller", "remote connect", "industrial ethernet", "iot gateway",
    "edge gateway", "safety system", "safety controller", "drive", "pac", "process control"
)
ALLOWED_SOURCE_HOST_SUFFIXES = (
    "cisa.gov", "first.org", "uscg.mil", "siemens.com", "rockwellautomation.com", "se.com", "abb.com"
)

class TextExtractor(HTMLParser):
    def __init__(self): super().__init__(); self.parts=[]
    def handle_data(self, data): self.parts.append(data)
    def text(self): return " ".join(" ".join(self.parts).split())

def utcnow(): return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

def fetch_bytes(url: str, timeout: int = 30) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json, application/rss+xml, application/xml, text/xml;q=0.9, */*;q=0.1"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = r.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES: raise ValueError("upstream response exceeds size cap")
        return data

def fetch_json(url: str): return json.loads(fetch_bytes(url).decode("utf-8"))

def source_allowed(url: str) -> bool:
    try:
        p=urllib.parse.urlparse(url)
        host=(p.hostname or "").lower()
        return p.scheme == "https" and any(host == s or host.endswith("."+s) for s in ALLOWED_SOURCE_HOST_SUFFIXES)
    except Exception: return False

def parse_description(markup: str) -> dict:
    p=TextExtractor(); p.feed(html.unescape(markup or "")); text=p.text()
    def field(name):
        m=re.search(rf"\b{name}:\s*(.+?)(?=\s+[A-Z][A-Z /-]{{2,}}:|$)", text, re.I)
        return m.group(1).strip() if m else ""
    cvss_match=re.search(r"CVSS\s+v(?:3(?:\.\d)?|4)\s*([0-9]+(?:\.[0-9]+)?)", text, re.I)
    cves=sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", text, re.I)))
    return {"text": text, "vendor": field("Vendor"), "equipment": field("Equipment"), "cvss": float(cvss_match.group(1)) if cvss_match else None, "cves": [x.upper() for x in cves]}

def is_ot_relevant(vendor: str, product: str) -> bool:
    v=(vendor or "").lower().strip(); p=(product or "").lower()
    return (v in OT_VENDORS and any(t in p for t in OT_TERMS)) or any(t in p for t in OT_TERMS)

def parse_ics_rss(blob: bytes) -> list[dict]:
    root=ET.fromstring(blob)
    out=[]
    for item in root.findall("./channel/item"):
        title=(item.findtext("title") or "").strip(); link=(item.findtext("link") or "").strip(); desc=item.findtext("description") or ""
        pub=(item.findtext("pubDate") or "").strip(); info=parse_description(desc)
        vendor=info["vendor"]; product=info["equipment"] or title
        if not link.startswith("https://www.cisa.gov/") or not is_ot_relevant(vendor, product): continue
        id_match=re.search(r"/(ics[am]-\d{2}-\d{3}-\d{2})/?$", link, re.I)
        sid=(id_match.group(1).upper() if id_match else "CISA-ICS-"+hashlib.sha256(link.encode()).hexdigest()[:12].upper())
        date=""
        m=re.search(r"\b(20\d{2})[-/](\d{2})[-/](\d{2})\b", pub)
        if m: date="-".join(m.groups())
        if not date:
            try:
                from email.utils import parsedate_to_datetime
                date=parsedate_to_datetime(pub).date().isoformat()
            except Exception: date=""
        summary=info["text"][:520]
        out.append({
            "id":sid,"origin":"CISA-ICS","kind":"CISA ICS advisory","date":date,"title":title,
            "summary":summary,"source":link,"sourceName":"CISA ICS Advisory","tags":["CISA ICS"],
            "products":[{"vendor":vendor or "Unspecified", "product":product}],"cves":info["cves"],"cvss":info["cvss"],
            "relevance":"Selected by OT product/vendor criteria; maritime deployment not asserted"
        })
    return out

def fetch_epss(cves: list[str]) -> tuple[dict, bool, str]:
    out={}
    if not cves: return out, True, ""
    try:
        for i in range(0, len(cves), 80):
            q=urllib.parse.urlencode({"cve": ",".join(cves[i:i+80])})
            for x in fetch_json(EPSS_URL+"?"+q).get("data", []):
                out[x["cve"].upper()]={"epss":float(x["epss"]),"epssPercentile":float(x["percentile"])}
        return out, True, ""
    except Exception as e: return out, False, str(e)

def prior_by_origin(old, origin): return [x for x in old.get("signals",[]) if x.get("origin")==origin]

def source_state(old, key, checked, success, count, error=""):
    prev=(old.get("meta",{}).get("sources",{}) or {}).get(key,{})
    return {"status":"healthy" if success else "degraded","checkedAt":checked,"lastSuccess":checked if success else prev.get("lastSuccess"),"recordCount":count,"error":error[:180] if error else ""}

def main():
    checked=utcnow(); old=json.loads(DATA.read_text()) if DATA.exists() else {"meta":{},"signals":[]}
    curated=json.loads(CURATED.read_text()).get("signals",[])
    for s in curated:
        if not source_allowed(s["source"]): raise ValueError(f"curated source host not allowlisted: {s['source']}")

    sources={"curated":{"status":"healthy","checkedAt":checked,"lastSuccess":checked,"recordCount":len(curated),"error":""}}; ics=[]; kev=[]
    try:
        ics=parse_ics_rss(fetch_bytes(ICS_RSS)); sources["cisaIcs"]=source_state(old,"cisaIcs",checked,True,len(ics))
    except Exception as e:
        ics=prior_by_origin(old,"CISA-ICS"); sources["cisaIcs"]=source_state(old,"cisaIcs",checked,False,len(ics),str(e)); print("WARN CISA ICS:",e,file=sys.stderr)

    selected_cves={c for s in ics for c in s.get("cves",[])}
    try:
        catalog=fetch_json(KEV_URL); rows=catalog.get("vulnerabilities",[])
        for v in rows:
            c=(v.get("cveID") or "").upper(); vendor=v.get("vendorProject") or ""; product=v.get("product") or ""
            if not c or not (c in selected_cves or is_ot_relevant(vendor,product)): continue
            kev.append({
                "id":"KEV-"+c,"origin":"CISA-KEV","kind":"Known exploited vulnerability","date":v.get("dateAdded") or "",
                "title":f"{c} — {vendor} {product} is in CISA KEV","summary":v.get("shortDescription") or "",
                "source":"https://www.cisa.gov/known-exploited-vulnerabilities-catalog","sourceName":"CISA Known Exploited Vulnerabilities",
                "tags":["KEV"],"products":[{"vendor":vendor,"product":product}],"cves":[c],"kev":True,"dueDate":v.get("dueDate"),
                "relevance":"Known exploitation plus selected OT product/CVE criteria; maritime deployment not asserted"
            })
        sources["cisaKev"]=source_state(old,"cisaKev",checked,True,len(kev))
    except Exception as e:
        kev=prior_by_origin(old,"CISA-KEV"); sources["cisaKev"]=source_state(old,"cisaKev",checked,False,len(kev),str(e)); print("WARN CISA KEV:",e,file=sys.stderr)

    all_cves=sorted({c for s in ics+kev+curated for c in s.get("cves",[])})
    epss_map, epss_ok, epss_err=fetch_epss(all_cves)
    if not epss_ok:
        for s in old.get("signals",[]):
            for c in s.get("cves",[]):
                if s.get("epss") is not None: epss_map.setdefault(c,{"epss":s.get("epss"),"epssPercentile":s.get("epssPercentile")})
    sources["firstEpss"]=source_state(old,"firstEpss",checked,epss_ok,len(epss_map),epss_err)

    signals={s["id"]:dict(s) for s in curated+ics+kev}
    for s in signals.values():
        vals=[epss_map[c] for c in s.get("cves",[]) if c in epss_map]
        if vals:
            top=max(vals,key=lambda x:x["epss"]); s.update(top)
        if not source_allowed(s["source"]): raise ValueError(f"generated source host not allowlisted: {s['source']}")
    rows=sorted(signals.values(), key=lambda x:(x.get("date") or "", x["id"]), reverse=True)
    statuses=[x["status"] for x in sources.values()]
    health="HEALTHY" if statuses and all(x=="healthy" for x in statuses) else ("DEGRADED" if statuses and all(x=="degraded" for x in statuses) else "PARTIAL")
    critical_success=[sources[k].get("lastSuccess") for k in ("cisaIcs","cisaKev") if sources.get(k,{}).get("lastSuccess")]
    data_as_of=min(critical_success) if len(critical_success)==2 else None
    doc={
        "meta":{
            "schema":"maritime-ot-watch/v2","generatedAt":checked,"dataAsOf":data_as_of,
            "health":health,"sources":sources,
            "uscgDeadline":"2027-07-16",
            "uscgSource":"https://www.news.uscg.mil/maritime-commons/Article/4247529/final-rule-cybersecurity-in-the-marine-transportation-system-implementation-tim/",
            "commercialEmail":old.get("meta",{}).get("commercialEmail","")
        },
        "signals":rows
    }
    tmp=DATA.with_suffix(".json.tmp"); tmp.write_text(json.dumps(doc,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    json.loads(tmp.read_text(encoding="utf-8")); tmp.replace(DATA)
    digest=hashlib.sha256(DATA.read_bytes()).hexdigest(); SHA.write_text(digest+"  watch.json\n",encoding="utf-8")
    print(f"PASS: {len(rows)} signals; health={health}; sha256={digest}")

if __name__ == "__main__": main()
