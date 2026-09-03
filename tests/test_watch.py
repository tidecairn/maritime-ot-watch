import hashlib,json,pathlib,re,unittest,sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from urllib.parse import urlparse
from scripts.update_watch import parse_description,is_ot_relevant,source_allowed,parse_ics_rss,source_state
R=pathlib.Path(__file__).resolve().parents[1]
class WatchTests(unittest.TestCase):
 def setUp(self): self.d=json.loads((R/'data/watch.json').read_text())
 def test_schema(self): self.assertEqual(self.d['meta']['schema'],'maritime-ot-watch/v2'); self.assertTrue(self.d['signals'])
 def test_unique_ids(self): ids=[x['id'] for x in self.d['signals']]; self.assertEqual(len(ids),len(set(ids)))
 def test_required_fields(self): self.assertTrue(all(x.get('id') and x.get('kind') and x.get('date') and x.get('title') and x.get('source') and x.get('origin') for x in self.d['signals']))
 def test_https_sources(self): self.assertTrue(all(x['source'].startswith('https://') for x in self.d['signals']))
 def test_allowed_sources(self): self.assertTrue(all(source_allowed(x['source']) for x in self.d['signals']))
 def test_integrity_sidecar(self): self.assertEqual((R/'data/watch.sha256').read_text().split()[0],hashlib.sha256((R/'data/watch.json').read_bytes()).hexdigest())
 def test_no_remote_inventory_form(self): s=(R/'index.html').read_text(); self.assertNotIn('type="file"',s); self.assertNotRegex(s,r'<form[^>]+action=')
 def test_privacy_copy(self): self.assertIn('not transmitted',(R/'index.html').read_text())
 def test_no_external_script_css(self): s=(R/'index.html').read_text(); self.assertNotRegex(s,r'<(?:script|link)[^>]+https://')
 def test_no_duplicate_class_attributes(self):
  for tag in re.findall(r'<[^>]+>',(R/'index.html').read_text()): self.assertLessEqual(len(re.findall(r'\bclass=',tag)),1,tag)
 def test_contact_not_exposed_when_unconfigured(self): self.assertEqual(self.d['meta'].get('commercialEmail'),''); self.assertNotIn('contact-link',(R/'index.html').read_text())
 def test_description_parser(self):
  x=parse_description('<b>CVSS v3 9.8</b><p>Vendor: Siemens</p><p>Equipment: SIMATIC S7-1500 PLC</p><p>CVE-2026-12345</p>'); self.assertEqual(x['cvss'],9.8); self.assertIn('CVE-2026-12345',x['cves'])
 def test_ot_relevance(self): self.assertTrue(is_ot_relevant('Siemens','SIMATIC S7-1500 PLC')); self.assertFalse(is_ot_relevant('Cisco','Webex'))
 def test_source_allowlist(self): self.assertTrue(source_allowed('https://www.cisa.gov/x')); self.assertFalse(source_allowed('https://cisa.gov.evil.example/x'))
 def test_failed_source_does_not_advance_last_success(self):
  old={'meta':{'sources':{'cisaIcs':{'lastSuccess':'2026-08-01T00:00:00Z'}}}}; s=source_state(old,'cisaIcs','2026-09-02T00:00:00Z',False,12,'timeout'); self.assertEqual(s['lastSuccess'],'2026-08-01T00:00:00Z'); self.assertEqual(s['checkedAt'],'2026-09-02T00:00:00Z')
 def test_ics_filter(self):
  rss=b'''<rss><channel><item><title>SIMATIC PLC</title><link>https://www.cisa.gov/news-events/ics-advisories/icsa-26-001-01</link><pubDate>Thu, 20 Aug 2026 12:00:00 GMT</pubDate><description>Vendor: Siemens Equipment: SIMATIC S7-1500 PLC CVSS v3 9.8 CVE-2026-12345</description></item><item><title>Generic desktop</title><link>https://www.cisa.gov/news-events/ics-advisories/icsa-26-001-02</link><description>Vendor: Example Equipment: Desktop editor</description></item></channel></rss>'''; rows=parse_ics_rss(rss); self.assertEqual(len(rows),1); self.assertEqual(rows[0]['id'],'ICSA-26-001-01')
if __name__=='__main__': unittest.main()
