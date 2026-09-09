import unittest

from src.gpo_review import review_gpos, severity_counts


class GPOReviewTests(unittest.TestCase):
    def test_broad_local_admin_is_critical(self):
        doc = {"gpos": [{"name": "x", "scope": ["Lab"], "settings": {"local_admin_group": "Domain Users"}}]}
        findings = review_gpos(doc)
        self.assertEqual(findings[0].control_id, "GPO-PRIV-001")
        self.assertEqual(findings[0].severity, "CRITICAL")

    def test_secure_rdp_not_flagged(self):
        doc = {"gpos": [{"name": "x", "scope": ["Admin"], "settings": {"allow_rdp": True, "rdp_nla_required": True}}]}
        ids = {f.control_id for f in review_gpos(doc)}
        self.assertNotIn("GPO-RM-001", ids)

    def test_disabled_auditing_detected(self):
        doc = {"gpos": [{"name": "x", "scope": ["Servers"], "settings": {"process_creation_auditing": False}}]}
        self.assertIn("GPO-AUDIT-001", {f.control_id for f in review_gpos(doc)})

    def test_unsigned_powershell_detected(self):
        doc = {"gpos": [{"name": "x", "scope": ["Servers"], "settings": {"powershell_execution": "unsigned_allowed"}}]}
        self.assertIn("GPO-SCRIPT-001", {f.control_id for f in review_gpos(doc)})

    def test_severity_counts(self):
        doc = {"gpos": [{"name": "x", "scope": ["All Workstations"], "settings": {"allow_rdp": True, "rdp_nla_required": False}}]}
        counts = severity_counts(review_gpos(doc))
        self.assertGreaterEqual(counts["HIGH"], 1)


if __name__ == "__main__":
    unittest.main()
