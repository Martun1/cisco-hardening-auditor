import sys, unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import auditor as a


class TestAuditor(unittest.TestCase):
    def load(self, name):
        return a.IOSConfig.parse((ROOT / "samples" / name).read_text())

    def test_type7_decode(self):
        self.assertEqual(a.decode_type7("0802455D0A165445414A"), "Cisco123!")

    def test_insecure_scores_low(self):
        pct, grade = a.score(a.audit(self.load("branch-sw01-insecure.cfg")))
        self.assertLess(pct, 40)
        self.assertEqual(grade, "F")

    def test_hardened_scores_high(self):
        pct, _ = a.score(a.audit(self.load("core-r1-hardened.cfg")))
        self.assertGreaterEqual(pct, 90)

    def test_telnet_detected(self):
        f = {x.id: x for x in a.audit(self.load("branch-sw01-insecure.cfg"))}
        self.assertFalse(f["MGMT-01"].passed)
        self.assertFalse(f["SNMP-01"].passed)
        self.assertFalse(f["PWD-02"].passed)

    def test_hostname(self):
        self.assertEqual(self.load("core-r1-hardened.cfg").hostname, "CORE-R1")


if __name__ == "__main__":
    unittest.main()
