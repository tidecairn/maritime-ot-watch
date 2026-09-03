#!/usr/bin/env python3
"""Build Maritime OT Watch from curated records + CISA ICS + CISA KEV + FIRST EPSS.

Trust properties:
- Source failures preserve the prior records for that source.
- checkedAt and lastSuccess are distinct; a failed fetch never advances lastSuccess.
- CISA ICS acquisition uses an official listing-page fallback when the legacy RSS surface is blocked.
- Source plausibility gates quarantine empty/implausibly collapsed successful responses.
- KEV relevance uses token-aware typed rules; generic IT substrings cannot impersonate OT terms.
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
from email.utils import parsedate_to_datetime

ROOT = pathlib.Path(__file__).resolve().parents[1]
DATA = ROOT / "data" / "watch.json"
CURATED = ROOT / "data" / "curated.json"
SHA = ROOT / "data" / "watch.sha256"
ICS_RSS = "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml"
ICS_LIST = "https://www.cisa.gov/news-events/cybersecurity-advisories?f%5B0%5D=advisory_type%3A95&items_per_page=100&sort_by=field_release_date"
CISA_CSAF_OT_FEED = "https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/cisa-csaf-ot-feed-tlp-white.json"
CISA_CSAF_OT_PREFIX = "https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
UA = "TIDECAIRN-Maritime-OT-Watch/1.2-rc2 (+public-source intelligence updater; https://tidecairn.com)"
MAX_BYTES = 12 * 1024 * 1024
MAX_ICS_ITEMS = 50
MIN_ICS_RECORDS = 5
MAX_COLLAPSE_RATIO = 0.50  # do not silently replace a known-good live corpus with <50% of its prior size

OT_VENDORS = {
    "abb", "advantech", "aveva", "beckhoff", "belden", "bosch rexroth", "codesys",
    "emerson", "ge vernova", "hms industrial networks", "honeywell", "hitachi energy",
    "mitsubishi electric", "moxa", "omron", "phoenix contact", "prosoft technology",
    "rockwell automation", "schneider electric", "siemens", "trihedral", "unitronics",
    "wago", "weidmuller", "westermo", "yokogawa", "openplc", "contec", "solarview"
}

# Strong industrial-control identifiers may stand on their own. Patterns are deliberately
# token-aware where ordinary English/IT words would otherwise create false positives.
STRONG_OT_PATTERNS = (
    re.compile(r"plc", re.I),
    re.compile(r"scada", re.I),
    re.compile(r"\bhmi\b", re.I),
    re.compile(r"programmable\s+logic", re.I),
    re.compile(r"\bsimatic\b", re.I), re.compile(r"\bcontrologix\b", re.I),
    re.compile(r"\bcompactlogix\b", re.I), re.compile(r"\bmodicon\b", re.I),
    re.compile(r"\bsysmac\b", re.I), re.compile(r"\bac500\b", re.I),
    re.compile(r"\bexperion\b", re.I), re.compile(r"\bfoxboro\b", re.I),
    re.compile(r"\bopc\s*ua\b", re.I), re.compile(r"\bprocess\s+control\b", re.I),
    re.compile(r"\bindustrial\s+control\b", re.I), re.compile(r"\bremote\s+terminal\s+unit\b", re.I),
    re.compile(r"\brtu\b", re.I), re.compile(r"\bsafety\s+(?:system|controller)\b", re.I),
)

# These words/acronyms are meaningful only when paired with a recognized OT vendor.
# This prevents driver->drive, Virtual->RTU, Apache/Compact/Workspace->PAC, and D-Link DCS camera matches.
VENDOR_GATED_PATTERNS = (
    re.compile(r"\bdcs\b", re.I), re.compile(r"\bpac\b", re.I),
    re.compile(r"\bindustrial\b", re.I), re.compile(r"\bautomation\b", re.I),
    re.compile(r"\bcontroller\b", re.I), re.compile(r"\bdrives?\b", re.I),
    re.compile(r"\bindustrial\s+ethernet\b", re.I), re.compile(r"\biot\s+gateway\b", re.I),
    re.compile(r"\bedge\s+gateway\b", re.I),
)

# Explicit industrial products whose terse KEV product name cannot establish OT relevance by text alone.
EXPLICIT_OT_PRODUCTS = {
    ("solarview", "compact"),
    ("contec", "solarview compact"),
}

ALLOWED_SOURCE_HOST_SUFFIXES = (
    "cisa.gov", "first.org", "uscg.mil", "siemens.com", "rockwellautomation.com", "se.com", "abb.com"
)

class TextExtractor(HTMLParser):
    def __init__(self):
        super().__init__(); self.parts=[]
    def handle_data(self, data): self.parts.append(data)
    def text(self): return " ".join(" ".join(self.parts).split())

class CisaListingParser(HTMLParser):
    """Collect CISA ICS links and nearby text without depending on fragile CSS classes."""
    def __init__(self):
        super().__init__(); self.tokens=[]; self._href=None; self._anchor=[]
    def handle_starttag(self, tag, attrs):
        if tag.lower()=="a":
            self._href=dict(attrs).get("href"); self._anchor=[]
    def handle_data(self, data):
        text=" ".join((data or "").split())
        if not text: return
        self.tokens.append(("text", text))
        if self._href is not None: self._anchor.append(text)
    def handle_endtag(self, tag):
        if tag.lower()=="a" and self._href is not None:
            label=" ".join(self._anchor).strip(); self.tokens.append(("link", self._href, label)); self._href=None; self._anchor=[]


def utcnow(): return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

def fetch_bytes(url: str, timeout: int = 30) -> bytes:
    req = urllib.request.Request(url, headers={
        "User-Agent": UA,
        "Accept": "application/json, application/rss+xml, application/xml, text/html, text/xml;q=0.9, */*;q=0.1",
        "Accept-Language": "en-US,en;q=0.8",
        "Cache-Control": "no-cache",
    })
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = r.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES: raise ValueError("upstream response exceeds size cap")
        return data

def fetch_json(url: str): return json.loads(fetch_bytes(url).decode("utf-8"))

def source_allowed(url: str) -> bool:
    try:
        p=urllib.parse.urlparse(url); host=(p.hostname or "").lower()
        return p.scheme == "https" and any(host == s or host.endswith("."+s) for s in ALLOWED_SOURCE_HOST_SUFFIXES)
    except Exception: return False

def strip_html(markup: str) -> str:
    p=TextExtractor(); p.feed(html.unescape(markup or "")); return p.text()

def parse_description(markup: str) -> dict:
    text=strip_html(markup)
    def field(name):
        m=re.search(rf"\b{name}:\s*(.+?)(?=\s+[A-Z][A-Z /-]{{2,}}:|$)", text, re.I)
        return m.group(1).strip() if m else ""
    cvss_match=re.search(r"CVSS\s+v(?:3(?:\.\d)?|4)\s*([0-9]+(?:\.[0-9]+)?)", text, re.I)
    cves=sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", text, re.I)))
    return {"text": text, "vendor": field("Vendor"), "equipment": field("Equipment"), "cvss": float(cvss_match.group(1)) if cvss_match else None, "cves": [x.upper() for x in cves]}

def normalize_text(s: str) -> str: return " ".join((s or "").lower().split())

def is_ot_relevant(vendor: str, product: str) -> bool:
    v=normalize_text(vendor); p=normalize_text(product)
    if (v,p) in EXPLICIT_OT_PRODUCTS: return True
    if any(rx.search(p) for rx in STRONG_OT_PATTERNS): return True
    return v in OT_VENDORS and any(rx.search(p) for rx in VENDOR_GATED_PATTERNS)

def advisory_id_from_text(text: str) -> str:
    m=re.search(r"\b(ICSMA|ICSA)-\d{2}-\d{3}-\d{2}\b", text or "", re.I)
    return m.group(0).upper() if m else ""

def parse_date_text(text: str) -> str:
    for fmt in ("%b %d, %Y", "%B %d, %Y"):
        try: return dt.datetime.strptime(text.strip(), fmt).date().isoformat()
        except Exception: pass
    try: return parsedate_to_datetime(text).date().isoformat()
    except Exception: return ""

def parse_ics_rss(blob: bytes) -> list[dict]:
    root=ET.fromstring(blob); out=[]
    for item in root.findall("./channel/item"):
        title=(item.findtext("title") or "").strip(); link=(item.findtext("link") or "").strip(); desc=item.findtext("description") or ""; pub=(item.findtext("pubDate") or "").strip(); info=parse_description(desc)
        if not link.startswith("https://www.cisa.gov/"): continue
        sid=advisory_id_from_text(" ".join((title,link,info["text"]))) or "CISA-ICS-"+hashlib.sha256(link.encode()).hexdigest()[:12].upper()
        product=info["equipment"] or title
        out.append({
            "id":sid,"origin":"CISA-ICS","kind":"CISA ICS advisory","date":parse_date_text(pub),"title":title,
            "summary":info["text"][:520],"source":link,"sourceName":"CISA ICS Advisory","tags":["CISA ICS"],
            "products":[{"vendor":info["vendor"] or "Unspecified", "product":product}],"cves":info["cves"],"cvss":info["cvss"],
            "relevance":"Official CISA ICS advisory; maritime deployment not asserted"
        })
    return out

def parse_ics_listing(blob: bytes) -> list[dict]:
    parser=CisaListingParser(); parser.feed(blob.decode("utf-8", errors="replace")); tokens=parser.tokens; out=[]; seen=set()
    for i,tok in enumerate(tokens):
        if tok[0] != "link": continue
        href,label=tok[1],tok[2]
        absurl=urllib.parse.urljoin("https://www.cisa.gov", href)
        if not absurl.startswith("https://www.cisa.gov/news-events/ics-advisories/") or absurl in seen: continue
        context=" ".join(x[1] for x in tokens[max(0,i-18):i] if x[0]=="text")
        sid=advisory_id_from_text(context+" "+label)
        date=""
        dates=re.findall(r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{1,2},\s+20\d{2}\b", context, re.I)
        if dates: date=parse_date_text(dates[-1])
        if not sid:
            # CISA advisory detail URLs may not contain the advisory number; require the listing to expose it.
            continue
        title=label.strip()
        if not title or title.lower() in {"read more", "view more"}: continue
        out.append({"id":sid,"date":date,"title":title,"source":absurl}); seen.add(absurl)
        if len(out)>=MAX_ICS_ITEMS: break
    return out

def parse_csaf_feed(blob: bytes) -> tuple[list[dict], str, str]:
    """Parse CISA's standards-based TLP:WHITE OT ROLIE feed.

    Returns newest ICSA entries plus feed updated timestamp and a snapshot hash of the exact feed bytes.
    ICS Medical advisories are intentionally excluded from Maritime OT Watch.
    """
    doc=json.loads(blob.decode("utf-8")); feed=doc.get("feed") or {}; entries=feed.get("entry") or []
    out=[]; seen=set()
    for entry in entries:
        sid=(entry.get("id") or "").strip().upper()
        if not re.fullmatch(r"ICSA-\d{2}-\d{3}-\d{2}", sid) or sid in seen: continue
        src=((entry.get("content") or {}).get("src") or "").strip()
        if not src:
            for link in entry.get("link") or []:
                href=(link or {}).get("href") or ""
                if (link or {}).get("rel") == "self" and href.endswith(".json"):
                    src=href; break
        if not src.startswith(CISA_CSAF_OT_PREFIX) or not src.lower().endswith(".json"): continue
        out.append({
            "id":sid,
            "title":str(entry.get("title") or sid).strip(),
            "published":str(entry.get("published") or "").strip(),
            "updated":str(entry.get("updated") or entry.get("published") or "").strip(),
            "src":src,
        }); seen.add(sid)
    out.sort(key=lambda x:(x.get("updated") or x.get("published") or "",x["id"]), reverse=True)
    return out[:MAX_ICS_ITEMS], str(feed.get("updated") or "").strip(), hashlib.sha256(blob).hexdigest()


def _csaf_note(notes: list[dict]) -> str:
    for wanted in ("summary","description"):
        for note in notes or []:
            if str((note or {}).get("category") or "").lower()==wanted and (note or {}).get("text"):
                return " ".join(str(note["text"]).split())
    for note in notes or []:
        if (note or {}).get("text"): return " ".join(str(note["text"]).split())
    return ""


def _csaf_products(tree: dict) -> list[dict]:
    out=[]; seen=set()
    def walk(branches, vendor=""):
        for b in branches or []:
            cat=str((b or {}).get("category") or ""); name=str((b or {}).get("name") or "").strip(); current=vendor
            if cat=="vendor" and name: current=name
            if cat=="product_name" and name:
                key=(current or "Unspecified",name)
                if key not in seen: out.append({"vendor":key[0],"product":key[1]}); seen.add(key)
            walk((b or {}).get("branches") or [], current)
    walk((tree or {}).get("branches") or [])
    return out[:8]


def parse_csaf_advisory(doc: dict, expected_id: str="") -> dict:
    meta=doc.get("document") or {}; tracking=meta.get("tracking") or {}; sid=str(tracking.get("id") or "").upper()
    if not re.fullmatch(r"ICSA-\d{2}-\d{3}-\d{2}",sid): raise ValueError("CSAF document is not an ICSA advisory")
    if expected_id and sid != expected_id.upper(): raise ValueError(f"CSAF id mismatch: expected {expected_id}, got {sid}")
    if meta.get("category") != "csaf_security_advisory": raise ValueError("unexpected CSAF category")
    if str(tracking.get("status") or "").lower() != "final": raise ValueError("CSAF advisory is not final")
    tlp=((meta.get("distribution") or {}).get("tlp") or {}).get("label")
    if str(tlp or "").upper() != "WHITE": raise ValueError("CSAF advisory is not TLP:WHITE")
    source=""
    for ref in meta.get("references") or []:
        u=str((ref or {}).get("url") or "")
        if u.startswith("https://www.cisa.gov/news-events/ics-advisories/"):
            source=u; break
    if not source: raise ValueError("CSAF advisory lacks CISA web self-reference")
    vulns=doc.get("vulnerabilities") or []; cves=sorted({str(v.get("cve") or "").upper() for v in vulns if re.fullmatch(r"CVE-\d{4}-\d{4,7}",str(v.get("cve") or ""),re.I)})
    scores=[]
    for v in vulns:
        for score in v.get("scores") or []:
            for key in ("cvss_v4","cvss_v3"):
                try: scores.append(float(((score or {}).get(key) or {}).get("baseScore")))
                except Exception: pass
    summary=_csaf_note(meta.get("notes") or [])
    if not summary:
        summary=" ".join(filter(None,(_csaf_note(v.get("notes") or []) for v in vulns)))
    title=str(meta.get("title") or sid).strip(); products=_csaf_products(doc.get("product_tree") or {})
    if not products: products=[{"vendor":"Unspecified","product":title}]
    released=str(tracking.get("initial_release_date") or "")[:10]; updated=str(tracking.get("current_release_date") or "")[:10]
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}",released): raise ValueError("CSAF advisory lacks valid initial release date")
    out={
        "id":sid,"origin":"CISA-ICS","kind":"CISA ICS advisory","date":released,"title":title,
        "summary":summary[:520] if summary else f"CISA ICS Advisory {sid}. Open the primary source for affected products, versions, mitigations, and revisions.",
        "source":source,"sourceName":"CISA ICS Advisory","tags":["CISA ICS","CSAF"],"products":products,"cves":cves,
        "relevance":"Official CISA ICS advisory; maritime deployment not asserted"
    }
    if scores: out["cvss"]=max(scores)
    if updated and updated != released: out["updated"]=updated
    return out


def acquire_ics_csaf(old) -> tuple[list[dict], dict]:
    checked=utcnow(); blob=fetch_bytes(CISA_CSAF_OT_FEED); candidates,feed_updated,snapshot=parse_csaf_feed(blob)
    ok,why=plausible_count(len(candidates),live_prior_count(old,"CISA-ICS"),MIN_ICS_RECORDS)
    if not ok: raise ValueError(why)
    rows=[]
    for entry in candidates:
        raw=fetch_json(entry["src"]); rows.append(parse_csaf_advisory(raw,entry["id"]))
    ok,why=plausible_count(len(rows),live_prior_count(old,"CISA-ICS"),MIN_ICS_RECORDS)
    if not ok: raise ValueError(why)
    note="CISA official OT TLP:WHITE CSAF ROLIE feed (cisagov/CSAF)"
    state=source_state(old,"cisaIcs",checked,True,len(rows),mode="live-acquisition",note=note)
    state["feedUpdated"]=feed_updated; state["snapshotSha256"]=snapshot
    return rows,state


def enrich_ics_listing(rows: list[dict]) -> tuple[list[dict], int]:
    out=[]; failures=0
    for row in rows:
        info={"text":"","vendor":"","equipment":"","cvss":None,"cves":[]}
        try: info=parse_description(fetch_bytes(row["source"]).decode("utf-8", errors="replace"))
        except Exception: failures += 1
        product=info["equipment"] or row["title"]
        summary=info["text"][:520] if info["text"] else f"CISA ICS Advisory {row['id']}. Open the primary source for affected products, versions, mitigations, and revisions."
        out.append({
            "id":row["id"],"origin":"CISA-ICS","kind":"CISA ICS advisory","date":row["date"],"title":row["title"],
            "summary":summary,"source":row["source"],"sourceName":"CISA ICS Advisory","tags":["CISA ICS"],
            "products":[{"vendor":info["vendor"] or "Unspecified", "product":product}],"cves":info["cves"],"cvss":info["cvss"],
            "relevance":"Official CISA ICS advisory; maritime deployment not asserted"
        })
    return out,failures

def prior_by_origin(old, origin): return [x for x in old.get("signals",[]) if x.get("origin")==origin]

def live_prior_count(old, origin): return len(prior_by_origin(old, origin))

def plausible_count(new_count: int, prior_count: int, minimum: int = 1) -> tuple[bool,str]:
    if new_count < minimum: return False, f"plausibility gate: {new_count} records below minimum {minimum}"
    if prior_count >= max(minimum*2, 10) and new_count < int(prior_count * MAX_COLLAPSE_RATIO):
        return False, f"plausibility gate: corpus collapsed from {prior_count} to {new_count}"
    return True, ""

def source_state(old, key, checked, success, count, error="", mode="live-acquisition", note=""):
    prev=(old.get("meta",{}).get("sources",{}) or {}).get(key,{})
    return {"status":"healthy" if success else "degraded","mode":mode,"checkedAt":checked,"lastSuccess":checked if success else prev.get("lastSuccess"),"recordCount":count,"error":error[:220] if error else "","note":note[:220] if note else ""}

def acquire_ics(old) -> tuple[list[dict], dict]:
    checked=utcnow(); errors=[]
    # Preferred machine-readable path: CISA's official TLP:WHITE OT CSAF ROLIE feed.
    try:
        return acquire_ics_csaf(old)
    except Exception as e: errors.append("CSAF "+str(e))
    # Direct CISA RSS remains a fail-closed fallback when the CSAF mirror is unavailable.
    try:
        rows=parse_ics_rss(fetch_bytes(ICS_RSS)); ok,why=plausible_count(len(rows), live_prior_count(old,"CISA-ICS"), MIN_ICS_RECORDS)
        if ok: return rows, source_state(old,"cisaIcs",checked,True,len(rows),mode="live-acquisition",note="CISA ICS RSS fallback")
        errors.append("RSS "+why)
    except Exception as e: errors.append("RSS "+str(e))
    # Official CISA advisory listing is the final direct-site fallback; CISA type 95 is ICS Advisory.
    try:
        listing=parse_ics_listing(fetch_bytes(ICS_LIST)); ok,why=plausible_count(len(listing), live_prior_count(old,"CISA-ICS"), MIN_ICS_RECORDS)
        if not ok: raise ValueError(why)
        rows,detail_failures=enrich_ics_listing(listing)
        if detail_failures: raise ValueError(f"{detail_failures} detail page fetch failure(s)")
        return rows, source_state(old,"cisaIcs",checked,True,len(rows),mode="live-acquisition",note="CISA official ICS advisory listing fallback")
    except Exception as e: errors.append("listing "+str(e))
    prior=prior_by_origin(old,"CISA-ICS")
    return prior, source_state(old,"cisaIcs",checked,False,len(prior),"; ".join(errors),mode="live-acquisition")

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

def main():
    checked=utcnow(); old=json.loads(DATA.read_text(encoding='utf-8')) if DATA.exists() else {"meta":{},"signals":[]}
    curated=json.loads(CURATED.read_text(encoding='utf-8')).get("signals",[])
    for s in curated:
        if not source_allowed(s["source"]): raise ValueError(f"curated source host not allowlisted: {s['source']}")

    sources={"curated":source_state(old,"curated",checked,True,len(curated),mode="local-registry",note="Local curated registry loaded; individual records retain their own source dates")}
    ics,ics_state=acquire_ics(old); sources["cisaIcs"]=ics_state

    selected_cves={c for s in ics for c in s.get("cves",[])}; kev=[]
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
                "relevance":"Known exploitation plus explicit OT product/CVE criteria; maritime deployment not asserted"
            })
        ok,why=plausible_count(len(kev), live_prior_count(old,"CISA-KEV"), 1)
        # For KEV a large reduction is expected in RC2 because the selector is intentionally stricter;
        # only enforce anti-collapse after a prior corpus was itself generated under RC2 semantics.
        prior_selector=(old.get("meta",{}).get("selectorVersion") or "")
        if prior_selector == "ot-relevance/v2" and not ok: raise ValueError(why)
        sources["cisaKev"]=source_state(old,"cisaKev",checked,True,len(kev),mode="live-acquisition",note="Token-aware OT selector v2")
    except Exception as e:
        kev=prior_by_origin(old,"CISA-KEV"); sources["cisaKev"]=source_state(old,"cisaKev",checked,False,len(kev),str(e),mode="live-acquisition"); print("WARN CISA KEV:",e,file=sys.stderr)

    all_cves=sorted({c for s in ics+kev+curated for c in s.get("cves",[])})
    epss_map,epss_ok,epss_err=fetch_epss(all_cves)
    if not epss_ok:
        for s in old.get("signals",[]):
            for c in s.get("cves",[]):
                if s.get("epss") is not None: epss_map.setdefault(c,{"epss":s.get("epss"),"epssPercentile":s.get("epssPercentile")})
    sources["firstEpss"]=source_state(old,"firstEpss",checked,epss_ok,len(epss_map),epss_err,mode="enrichment")

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
            "schema":"maritime-ot-watch/v2","selectorVersion":"ot-relevance/v2","acquisitionVersion":"cisa-ics-csaf/v1","generatedAt":checked,"dataAsOf":data_as_of,
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
