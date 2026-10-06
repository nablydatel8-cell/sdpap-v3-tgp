import os
import unittest
import sqlite3
import json
import uuid
import tempfile
from sdpap_v3_production import (
    SDPAPKernelProduction,
    MerkleTree,
    PhysicalInvariantSolver,
    canonical_serialize,
    canonical_hash
)

class TestSDPAPv3KeylessFullSuite(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp_dir.name, "test_sdpap_keyless.db")
        self.kernel = SDPAPKernelProduction(db_path=self.db_path)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def _make_valid_request(self, target_node="node_photonic_01", version=1, nonce=None):
        if nonce is None:
            nonce = str(uuid.uuid4())
        payload = {
            "target_node": target_node,
            "required_permission": "execute_core",
            "metric_value": 42.0,
            "photonic_energy_joules": 1e-6,
            "photonic_power_loss": 1e-12,
            "frequency_hz": 1.93e14,
            "mass_kg": 2.5,
            "distance_km": 15.0,
            "test_hypothesis_falsified": False
        }
        env_hash = canonical_hash({"version": version, "nonce": nonce, "payload": payload})
        return {
            "version": version,
            "nonce": nonce,
            "payload": payload,
            "envelope_hash": env_hash
        }

    def test_01_valid_hash_chain_request_passes(self):
        req = self._make_valid_request(version=1)
        res = self.kernel.process_request(req)
        self.assertEqual(res, "PASS")
        self.assertEqual(self.kernel.current_state.version, 2)

    def test_02_tampered_envelope_hash_rejected(self):
        req = self._make_valid_request(version=1)
        req["envelope_hash"] = "0" * 64
        res = self.kernel.process_request(req)
        self.assertEqual(res, "REJECT")
        self.assertEqual(self.kernel.current_state.version, 1)

    def test_03_replay_attack_rejected(self):
        req1 = self._make_valid_request(version=1, nonce="nonce_replay_test")
        self.assertEqual(self.kernel.process_request(req1), "PASS")

        req2 = self._make_valid_request(version=2, nonce="nonce_replay_test")
        self.assertEqual(self.kernel.process_request(req2), "REJECT")

    def test_04_numeric_tampering_nan_inf_bool_rejected(self):
        req_nan = self._make_valid_request(version=1)
        req_nan["payload"]["metric_value"] = float("nan")
        req_nan["envelope_hash"] = canonical_hash({"version": 1, "nonce": req_nan["nonce"], "payload": req_nan["payload"]})
        self.assertEqual(self.kernel.process_request(req_nan), "REJECT")

        req_bool = self._make_valid_request(version=1)
        req_bool["payload"]["metric_value"] = True
        req_bool["envelope_hash"] = canonical_hash({"version": 1, "nonce": req_bool["nonce"], "payload": req_bool["payload"]})
        self.assertEqual(self.kernel.process_request(req_bool), "REJECT")

    def test_05_physical_q_factor_violation_rejected(self):
        req = self._make_valid_request(version=1)
        req["payload"]["photonic_power_loss"] = 1e11  # High power loss drops Q < 10^4
        req["envelope_hash"] = canonical_hash({"version": 1, "nonce": req["nonce"], "payload": req["payload"]})
        self.assertEqual(self.kernel.process_request(req), "REJECT")

    def test_06_popperean_hypothesis_falsification_rejected(self):
        req = self._make_valid_request(version=1)
        req["payload"]["test_hypothesis_falsified"] = True
        req["envelope_hash"] = canonical_hash({"version": 1, "nonce": req["nonce"], "payload": req["payload"]})
        self.assertEqual(self.kernel.process_request(req), "REJECT")

    def test_07_permission_violation_rejected(self):
        req = self._make_valid_request(version=1)
        req["payload"]["required_permission"] = "super_admin_unauthorized"
        req["envelope_hash"] = canonical_hash({"version": 1, "nonce": req["nonce"], "payload": req["payload"]})
        self.assertEqual(self.kernel.process_request(req), "REJECT")

    def test_08_database_append_only_triggers_enforced(self):
        req = self._make_valid_request(version=1)
        self.assertEqual(self.kernel.process_request(req), "PASS")

        conn = sqlite3.connect(self.db_path)
        with self.assertRaises(sqlite3.IntegrityError):
            conn.execute("UPDATE audit_log SET evaluation_result = 'MODIFIED' WHERE sequence = 1;")
        with self.assertRaises(sqlite3.IntegrityError):
            conn.execute("DELETE FROM audit_log WHERE sequence = 1;")
        conn.close()

    def test_09_merkle_proof_verification(self):
        req1 = self._make_valid_request(version=1)
        self.assertEqual(self.kernel.process_request(req1), "PASS")

        proof_data = self.kernel.generate_merkle_proof(sequence=1)
        self.assertTrue(proof_data["verified"])
        self.assertEqual(proof_data["merkle_root"], self.kernel.current_state.merkle_root)

    def test_10_public_green_anchor_export(self):
        req1 = self._make_valid_request(version=1)
        self.assertEqual(self.kernel.process_request(req1), "PASS")

        anchor = self.kernel.export_public_anchor()
        self.assertEqual(anchor["protocol"], "SDPAP_v3_TGP")
        self.assertEqual(anchor["state_version"], 2)
        self.assertEqual(anchor["merkle_root"], self.kernel.current_state.merkle_root)

        is_valid, msg = self.kernel.verify_full_integrity()
        self.assertTrue(is_valid)

if __name__ == "__main__":
    unittest.main()
