import base64
import hashlib
import tempfile
import unittest
from datetime import date, timedelta
from pathlib import Path

from app import BusinessError, PreservationStore


class PreservationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = PreservationStore(Path(self.tmp.name) / "test.db")
        self.store.seed()
        self.archive = self.store.create_archive("owner", "城市测绘档案", (date.today() + timedelta(days=3650)).isoformat())
        self.raw = b"<record><id>1</id></record>"
        self.version = self.store.ingest_version("owner", self.archive["id"], [
            {"path": "records/one.xml", "content_b64": base64.b64encode(self.raw).decode()},
            {"path": "README.txt", "content_b64": base64.b64encode(b"archive readme").decode()},
        ])
        self.copy1 = self.store.add_copy("owner", self.version["id"], "offline-disk-a")["id"]
        self.copy2 = self.store.add_copy("owner", self.version["id"], "offline-disk-b")["id"]

    def tearDown(self):
        self.tmp.cleanup()

    def test_integrity_repair_and_format_migration(self):
        self.store.simulate_corruption("owner", self.copy1, "records/one.xml")
        result = self.store.verify_copy("owner", self.copy1)
        self.assertEqual(result["state"], "healthy")
        self.assertTrue(result["repaired"])
        self.assertEqual(result["corrupt_paths"], ["records/one.xml"])
        migrated = self.store.migrate(
            "owner", self.version["id"], "records/one.xml", "records/one.html", "html",
            base64.b64encode(b"<html><body><p>1</p></body></html>").decode(),
        )
        detail = self.store.get_version("owner", migrated["id"])
        self.assertEqual(detail["version"]["version"], 2)
        self.assertTrue(any(f["path"] == "records/one.html" for f in detail["files"]))
        status = self.store.archive_status("owner", self.archive["id"])
        self.assertGreater(status["days_remaining"], 3000)

    def test_restricted_access_and_invalid_manifest_are_rejected(self):
        with self.assertRaises(BusinessError) as ctx:
            self.store.get_version("outsider", self.version["id"])
        self.assertEqual(ctx.exception.status, 403)
        with self.assertRaises(BusinessError) as ctx:
            self.store.ingest_version("owner", self.archive["id"], [{"path": "../escape.txt", "content_b64": "eA=="}])
        self.assertEqual(ctx.exception.code, "unsafe_path")
        with self.assertRaises(BusinessError) as ctx:
            self.store.add_copy("owner", self.version["id"], "offline-disk-a")
        self.assertEqual(ctx.exception.code, "copy_exists")

    def _register(self, copy_id, serial, site):
        return self.store.register_media("owner", copy_id, serial, site)

    def test_decommission_requires_registered_diverse_healthy_copy(self):
        # 未登记介质编号/存放点：拦下
        blocked = self.store.submit_decommission("owner", [self.copy1])
        self.assertEqual(blocked["state"], "blocked")
        reasons = blocked["items"][0]["reasons"]
        self.assertIn("media_unregistered", [r["code"] for r in reasons])

        # 只登记同库两盘：存放点不构成冗余，逐文件核对后列缺口
        self._register(self.copy1, "TAPE-1", "档案楼B库")
        self._register(self.copy2, "TAPE-2", "档案楼B库")
        blocked2 = self.store.submit_decommission("owner", [self.copy1])
        gap = [r for r in blocked2["items"][0]["reasons"] if r["code"] == "no_diverse_healthy_copy"]
        self.assertEqual(len(gap), 1)
        self.assertEqual({g["path"] for g in gap[0]["gaps"]}, {"records/one.xml", "README.txt"})

        # 第二份放到不同存放点后，批准停用；档案里位置和审计仍保留
        self.store.register_media("owner", self.copy2, "TAPE-2", "异地灾备库")
        approved = self.store.submit_decommission("owner", [self.copy1], note="第三批下线")
        self.assertEqual(approved["state"], "approved")
        detail = self.store.get_version("owner", self.version["id"])
        retired = next(c for c in detail["copies"] if c["id"] == self.copy1)
        self.assertFalse(retired["active"])
        self.assertEqual(retired["media_serial"], "TAPE-1")
        self.assertEqual(retired["location"], "offline-disk-a")
        self.assertIsNotNone(retired["deactivated_at"])
        status = self.store.archive_status("owner", self.archive["id"])
        self.assertTrue(any(a["action"] == "media.decommission" for a in status["audit"]))

    def test_verifying_copy_cannot_be_approved(self):
        self._register(self.copy1, "TAPE-1", "档案楼B库")
        self._register(self.copy2, "TAPE-2", "异地灾备库")
        self.store.start_verification("owner", self.copy1)
        batch = self.store.submit_decommission("owner", [self.copy1])
        self.assertEqual(batch["state"], "blocked")
        self.assertIn("verifying_in_progress", [r["code"] for r in batch["items"][0]["reasons"]])
        # 校验完成后放行
        self.store.verify_copy("owner", self.copy1)
        approved = self.store.submit_decommission("owner", [self.copy1])
        self.assertEqual(approved["state"], "approved")

    def test_corrupt_copy_leaves_damage_list_and_blocks(self):
        self._register(self.copy1, "TAPE-1", "档案楼B库")
        self._register(self.copy2, "TAPE-2", "异地灾备库")
        self.store.simulate_corruption("owner", self.copy1, "README.txt")
        # 损坏被健康的异地副本自动修复，损坏清单留痕后修复、随后可正常退役
        result = self.store.verify_copy("owner", self.copy1)
        self.assertTrue(result["repaired"])
        self.assertEqual(self.store.get_copy("owner", self.copy1)["state"], "healthy")
        self.assertEqual(self.store.get_copy("owner", self.copy1)["damage_list"], [])

        # 没有健康供体时：损坏清单保留且退役被拦
        self.store.simulate_corruption("owner", self.copy1, "records/one.xml")
        self.store.simulate_corruption("owner", self.copy2, "records/one.xml")
        res = self.store.verify_copy("owner", self.copy2)
        self.assertEqual(res["state"], "degraded")
        batch = self.store.submit_decommission("owner", [self.copy2])
        corrupt = [r for r in batch["items"][0]["reasons"] if r["code"] == "copy_corrupt"]
        self.assertEqual(len(corrupt), 1)
        self.assertEqual([d["path"] for d in corrupt[0]["damage_list"]], ["records/one.xml"])
        view = self.store.get_copy("owner", self.copy2)
        self.assertEqual([d["path"] for d in view["damage_list"]], ["records/one.xml"])

    def test_batch_does_not_treat_other_retiring_copy_as_redundancy(self):
        self._register(self.copy1, "TAPE-1", "档案楼B库")
        self._register(self.copy2, "TAPE-2", "异地灾备库")
        # 两盘同时撤走：彼此不能互为异地冗余，双双拦下
        batch = self.store.submit_decommission("owner", [self.copy1, self.copy2])
        self.assertEqual(batch["state"], "blocked")
        self.assertEqual(batch["blocked_count"], 2)
        for item in batch["items"]:
            self.assertIn("no_diverse_healthy_copy", [r["code"] for r in item["reasons"]])
        # 批次记录可回看
        again = self.store.get_decommission("owner", batch["id"])
        self.assertEqual(len(again["items"]), 2)

    def test_blocked_batch_keeps_copy_active_and_auditor_can_read(self):
        self.store.grant("owner", self.archive["id"], "archivist", "write")
        self.store.grant("owner", self.archive["id"], "auditor", "read")
        self._register(self.copy1, "TAPE-1", "档案楼B库")
        self._register(self.copy2, "TAPE-2", "档案楼B库")
        batch = self.store.submit_decommission("archivist", [self.copy1])
        self.assertEqual(batch["state"], "blocked")
        self.assertTrue(self.store.get_copy("auditor", self.copy1)["active"])
        self.assertEqual(self.store.get_decommission("auditor", batch["id"])["state"], "blocked")
        with self.assertRaises(BusinessError) as ctx:
            self.store.submit_decommission("outsider", [self.copy1])
        self.assertEqual(ctx.exception.status, 403)



if __name__ == "__main__":
    unittest.main()
