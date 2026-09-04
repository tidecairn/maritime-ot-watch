import hashlib,json,pathlib,re,unittest,sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from scripts.update_watch import (
    parse_description,is_ot_relevant,source_allowed,parse_ics_rss,parse_ics_listing,
    parse_csaf_feed,parse_csaf_advisory,source_state,plausible_count,clip_summary,build_kev_signal
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
 def test_contact_surface_is_configured(self):
  self.assertEqual(self.d['meta'].get('commercialEmail'),'contact@tidecairn.com')
  html=(R/'index.html').read_text(encoding='utf-8'); js=(R/'assets/watch.js').read_text(encoding='utf-8')
  self.assertIn('contact-link',html); self.assertIn('configureContact(m.commercialEmail)',js); self.assertIn('mailto:',js)
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
 def test_csaf_rolie_feed_filters_to_public_icsa(self):
  feed={"feed":{"updated":"2026-09-03T08:00:00Z","entry":[
   {"id":"ICSA-26-246-01","title":"Example PLC","published":"2026-09-03T06:00:00Z","updated":"2026-09-03T06:00:00Z","content":{"src":"https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/2026/icsa-26-246-01.json"}},
   {"id":"ICSMA-26-246-02","title":"Medical","content":{"src":"https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/2026/icsma-26-246-02.json"}},
   {"id":"ICSA-26-246-03","title":"Wrong path","content":{"src":"https://example.com/icsa-26-246-03.json"}}
  ]}}
  blob=json.dumps(feed).encode(); rows,updated,snapshot=parse_csaf_feed(blob); self.assertEqual([x['id'] for x in rows],['ICSA-26-246-01']); self.assertEqual(updated,'2026-09-03T08:00:00Z'); self.assertEqual(len(snapshot),64)
 def test_csaf_advisory_parser_preserves_cisa_provenance(self):
  doc={"document":{"category":"csaf_security_advisory","distribution":{"tlp":{"label":"WHITE"}},"notes":[{"category":"summary","text":"Successful exploitation could disrupt process visibility."}],"references":[{"category":"self","summary":"Web Version","url":"https://www.cisa.gov/news-events/ics-advisories/icsa-26-246-01"}],"title":"Example Control Platform","tracking":{"id":"ICSA-26-246-01","initial_release_date":"2026-09-03T06:00:00Z","current_release_date":"2026-09-04T07:00:00Z","status":"final"}},"product_tree":{"branches":[{"category":"vendor","name":"Example Controls","branches":[{"category":"product_name","name":"Marine PLC","branches":[]}]}]},"vulnerabilities":[{"cve":"CVE-2026-12345","scores":[{"cvss_v3":{"baseScore":9.8}}]}]}
  x=parse_csaf_advisory(doc,'ICSA-26-246-01'); self.assertEqual(x['source'],'https://www.cisa.gov/news-events/ics-advisories/icsa-26-246-01'); self.assertEqual(x['products'][0],{'vendor':'Example Controls','product':'Marine PLC'}); self.assertEqual(x['cves'],['CVE-2026-12345']); self.assertEqual(x['cvss'],9.8); self.assertEqual(x['updated'],'2026-09-04')
 def test_csaf_advisory_rejects_nonfinal_or_nonwhite(self):
  base={"document":{"category":"csaf_security_advisory","distribution":{"tlp":{"label":"WHITE"}},"references":[{"url":"https://www.cisa.gov/news-events/ics-advisories/icsa-26-246-01"}],"tracking":{"id":"ICSA-26-246-01","initial_release_date":"2026-09-03T06:00:00Z","status":"draft"}}}
  with self.assertRaises(ValueError): parse_csaf_advisory(base,'ICSA-26-246-01')


 def test_csaf_prefers_advisory_summary_over_geography(self):
  doc={"document":{"category":"csaf_security_advisory","distribution":{"tlp":{"label":"WHITE"}},"notes":[
   {"category":"other","title":"Countries/areas deployed","text":"Worldwide"},
   {"category":"other","title":"Critical infrastructure sectors","text":"Critical Manufacturing"},
   {"category":"other","title":"Advisory Summary","text":"Successful exploitation could force a nonrecoverable fault requiring controller recovery."}
  ],"references":[{"url":"https://www.cisa.gov/news-events/ics-advisories/icsa-26-244-05"}],"title":"Rockwell Automation ControlLogix","tracking":{"id":"ICSA-26-244-05","initial_release_date":"2026-09-01T06:00:00Z","status":"final"}},"product_tree":{"branches":[]},"vulnerabilities":[]}
  x=parse_csaf_advisory(doc,'ICSA-26-244-05'); self.assertTrue(x['summary'].startswith('Successful exploitation')); self.assertNotEqual(x['summary'],'Worldwide')
 def test_csaf_contextualizes_generic_series_labels(self):
  doc={"document":{"category":"csaf_security_advisory","distribution":{"tlp":{"label":"WHITE"}},"references":[{"url":"https://www.cisa.gov/news-events/ics-advisories/icsa-26-244-06"}],"title":"Rockwell Automation Historian ME","tracking":{"id":"ICSA-26-244-06","initial_release_date":"2026-09-01T06:00:00Z","status":"final"}},"product_tree":{"branches":[{"category":"vendor","name":"Rockwell Automation","branches":[{"category":"product_name","name":"Series B","branches":[]},{"category":"product_name","name":"Series C","branches":[]}]}]},"vulnerabilities":[{"cve":"CVE-2026-12661","notes":[{"category":"summary","text":"A denial-of-service issue affects the product."}]}]}
  x=parse_csaf_advisory(doc,'ICSA-26-244-06'); self.assertEqual(x['products'][0]['product'],'Historian ME — Series B'); self.assertEqual(x['products'][1]['product'],'Historian ME — Series C')
 def test_summary_clipping_avoids_mid_sentence(self):
  text=("First sentence explains the operational effect clearly. "*8)+"A final sentence that should not be cut in half because the display limit is reached."
  clipped=clip_summary(text,220); self.assertLessEqual(len(clipped),220); self.assertTrue(clipped.endswith('.'))
 def test_kev_ics_linkage_is_explicit(self):
  v={"cveID":"CVE-2019-11043","vendorProject":"PHP","product":"FastCGI Process Manager (FPM)","dateAdded":"2022-03-25","dueDate":"2022-04-15","shortDescription":"RCE"}
  x=build_kev_signal(v,{"CVE-2019-11043":["ICSA-26-239-02"]}); self.assertEqual(x['relatedIcs'],['ICSA-26-239-02']); self.assertIn('CISA ICS-linked',x['tags']); self.assertIn('appears in the current CISA ICS advisory corpus',x['relevance'])
  self.assertIsNone(build_kev_signal(v,{}))

 def test_plausibility_gate_rejects_empty_and_collapse(self):
  self.assertFalse(plausible_count(0,0,5)[0]); self.assertFalse(plausible_count(4,40,5)[0]); self.assertTrue(plausible_count(25,40,5)[0])

if __name__=='__main__': unittest.main()
