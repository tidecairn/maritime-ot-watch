import hashlib,json,pathlib,re,unittest,sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from scripts.update_watch import (
    parse_description,is_ot_relevant,source_allowed,parse_ics_rss,parse_ics_listing,
    source_state,plausible_count
)
R=pathlib.Path(__file__).resolve().parents[1]

class WatchTests(unittest.TestCase):
 def setUp(self): self.d=json.loads((R/'data/watch.json').read_text(encoding='utf-8'))
 def test_schema(self): self.assertEqual(self.d['meta']['schema'],'maritime-ot-watch/v2'); self.assertTrue(self.d['signals'])
 def test_unique_ids(self): ids=[x['id'] for x in self.d['signals']]; self.assertEqual(len(ids),len(set(ids)))
 def test_required_fields(self): self.assertTrue(all(x.get('id') and x.get('kind') and x.get('date') and x.get('title') and x.get('source') and x.get('origin') for x in self.d['signals']))
 def test_https_sources(self): self.assertTrue(all(x['source'].startswith('https://') for x in self.d['signals']))
 def test_allowed_sources(self): self.assertTrue(all(source_allowed(x['source']) for x in self.d['signals']))
 def test_integrity_sidecar(self): self.assertEqual((R/'data/watch.sha256').read_text(encoding='utf-8').split()[0],hashlib.sha256((R/'data/watch.json').read_bytes()).hexdigest())
 def test_no_remote_inventory_form(self): s=(R/'index.html').read_text(encoding='utf-8'); self.assertNotIn('type="file"',s); self.assertNotRegex(s,r'<form[^>]+action=')
 def test_privacy_copy(self): self.assertIn('not transmitted',(R/'index.html').read_text(encoding='utf-8'))
 def test_no_external_script_css(self): s=(R/'index.html').read_text(encoding='utf-8'); self.assertNotRegex(s,r'<(?:script|link)[^>]+https://')
 def test_no_duplicate_class_attributes(self):
  for tag in re.findall(r'<[^>]+>',(R/'index.html').read_text(encoding='utf-8')): self.assertLessEqual(len(re.findall(r'\bclass=',tag)),1,tag)
 def test_contact_not_exposed_when_unconfigured(self): self.assertEqual(self.d['meta'].get('commercialEmail'),''); self.assertNotIn('contact-link',(R/'index.html').read_text(encoding='utf-8'))
 def test_description_parser(self):
  x=parse_description('<b>CVSS v3 9.8</b><p>Vendor: Siemens</p><p>Equipment: SIMATIC S7-1500 PLC</p><p>CVE-2026-12345</p>'); self.assertEqual(x['cvss'],9.8); self.assertIn('CVE-2026-12345',x['cves'])
 def test_ot_relevance_positive(self):
  positives=[
   ('Siemens','SIMATIC S7-1500 PLC'),('OpenPLC','ScadaBR'),('Unitronics','Vision PLC and HMI'),
   ('Trihedral','VTScada (formerly VTS)'),('SolarView','Compact')
  ]
  for vendor,product in positives: self.assertTrue(is_ot_relevant(vendor,product),(vendor,product))
 def test_ot_relevance_rejects_substring_false_positives(self):
  negatives=[
   ('Microsoft','Windows Ancillary Function Driver for WinSock'),('Omnissa','Workspace One UEM'),
   ('Dell','RecoverPoint for Virtual Machines (RP4VMs)'),('Arm','Mali GPU Kernel Driver'),
   ('Apache','Apache'),('D-Link','DCS-2530L and DCS-2670L Devices'),
   ('Cisco','Catalyst SD-WAN Controller and Manager'),('Oracle','VirtualBox'),
   ('Citrix','Application Delivery Controller (ADC) and Gateway')
  ]
  for vendor,product in negatives: self.assertFalse(is_ot_relevant(vendor,product),(vendor,product))
 def test_source_allowlist(self): self.assertTrue(source_allowed('https://www.cisa.gov/x')); self.assertFalse(source_allowed('https://cisa.gov.evil.example/x'))
 def test_failed_source_does_not_advance_last_success(self):
  old={'meta':{'sources':{'cisaIcs':{'lastSuccess':'2026-08-01T00:00:00Z'}}}}; s=source_state(old,'cisaIcs','2026-09-02T00:00:00Z',False,12,'timeout'); self.assertEqual(s['lastSuccess'],'2026-08-01T00:00:00Z'); self.assertEqual(s['checkedAt'],'2026-09-02T00:00:00Z')
 def test_curated_source_mode_is_explicit(self):
  s=source_state({},'curated','2026-09-03T00:00:00Z',True,6,mode='local-registry',note='registry load'); self.assertEqual(s['mode'],'local-registry'); self.assertEqual(s['note'],'registry load')
 def test_ics_rss_accepts_official_ics_without_extra_ot_filter(self):
  rss=b'''<rss><channel><item><title>Specialized Control Product</title><link>https://www.cisa.gov/news-events/ics-advisories/icsa-26-001-01</link><pubDate>Thu, 20 Aug 2026 12:00:00 GMT</pubDate><description>Vendor: Example Equipment: Specialized Product CVSS v3 9.8 CVE-2026-12345</description></item></channel></rss>'''; rows=parse_ics_rss(rss); self.assertEqual(len(rows),1); self.assertEqual(rows[0]['id'],'ICSA-26-001-01')
 def test_ics_listing_parser(self):
  doc=b'''<html><body><div>Sep 03, 2026</div><span>ICS Advisory | ICSA-26-246-01</span><h3><a href="/news-events/ics-advisories/example-industrial-product">Example Industrial Product</a></h3><div>Sep 02, 2026</div><span>Alert</span><h3><a href="/news-events/alerts/example">Not ICS</a></h3></body></html>'''
  rows=parse_ics_listing(doc); self.assertEqual(len(rows),1); self.assertEqual(rows[0]['id'],'ICSA-26-246-01'); self.assertEqual(rows[0]['date'],'2026-09-03')
 def test_plausibility_gate_rejects_empty_and_collapse(self):
  self.assertFalse(plausible_count(0,0,5)[0]); self.assertFalse(plausible_count(4,40,5)[0]); self.assertTrue(plausible_count(25,40,5)[0])

if __name__=='__main__': unittest.main()
