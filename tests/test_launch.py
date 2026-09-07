from pathlib import Path
import json
import unittest

ROOT = Path(__file__).resolve().parents[1]

class LaunchConfigurationTests(unittest.TestCase):
    def test_production_watch_markers(self):
        data = json.loads((ROOT / "data" / "watch.json").read_text(encoding="utf-8"))
        meta = data["meta"]
        self.assertEqual(meta.get("health"), "HEALTHY")
        self.assertEqual(meta.get("presentationVersion"), "watch-ui/v1.1")
        self.assertEqual(meta.get("commercialEmail"), "contact@tidecairn.com")

    def test_refresh_is_scheduled_and_self_deploying(self):
        text = (ROOT / ".github" / "workflows" / "refresh.yml").read_text(encoding="utf-8")
        self.assertIn('cron: "17 1,7,13,19 * * *"', text)
        self.assertIn("workflow_dispatch:", text)
        self.assertIn("actions/deploy-pages@", text)
        self.assertIn("git push", text)
        self.assertIn("tidecairn-watch-production", text)

    def test_pages_publishes_main_pushes(self):
        text = (ROOT / ".github" / "workflows" / "pages.yml").read_text(encoding="utf-8")
        self.assertIn("push:", text)
        self.assertIn("- main", text)
        self.assertIn("workflow_dispatch:", text)
        self.assertIn("actions/deploy-pages@", text)
        self.assertIn("tidecairn-watch-production", text)

    def test_public_readme_is_production_not_prelaunch(self):
        text = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("public production service", text)
        self.assertIn("https://watch.tidecairn.com", text)
        self.assertNotIn("manual-only", text.lower())
        self.assertNotIn("launch candidate", text.lower())

if __name__ == "__main__":
    unittest.main()
