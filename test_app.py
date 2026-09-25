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


"""介质退役流程测试。"""
import base64
import sqlite3
import tempfile
import unittest
from datetime import date, timedelta
from pathlib import Path

from app import BusinessError, PreservationStore


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


class RetirementTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "test.db"
        self.store = PreservationStore(self.db)
        self.store.seed()
        self.archive = self.store.create_archive("owner", "声像档案批次", (date.today() + timedelta(days=3650)).isoformat())
        self.version = self.store.ingest_version("owner", self.archive["id"], [
            {"path": "records/a.wav", "content_b64": b64(b"audio-a")},
            {"path": "records/b.wav", "content_b64": b64(b"audio-b")},
        ])["id"]
        self.copy_a = self.store.add_copy("owner", self.version, "一号库房", media_id="MEDIA-A-01")["id"]
        self.copy_b = self.store.add_copy("owner", self.version, "二号库房", media_id="MEDIA-B-02")["id"]

    def tearDown(self):
        self.tmp.cleanup()

    def _audit_actions(self) -> list[str]:
        conn = sqlite3.connect(self.db)
        try:
            return [r[0] for r in conn.execute("SELECT action FROM audit_log ORDER BY id")]
        finally:
            conn.close()

    def test_media_id_must_be_registered_before_retirement(self):
        unregistered = self.store.add_copy("owner", self.version, "三号库房")["id"]
        with self.assertRaises(BusinessError) as ctx:
            self.store.submit_retirement("owner", unregistered)
        self.assertEqual(ctx.exception.code, "retirement_blocked")
        self.assertIn("media_not_registered", ctx.exception.payload["reasons"])
        # 拦截记录已持久化，可查看阻塞原因
        records = self.store.list_retirements("owner", unregistered)["retirements"]
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["state"], "blocked")
        # 补登介质编号后可再次提交
        self.store.register_copy("owner", unregistered, media_id="MEDIA-C-03")
        result = self.store.submit_retirement("owner", unregistered)
        self.assertEqual(result["state"], "retired")

    def test_verifying_media_cannot_be_approved(self):
        self.store.start_verification("owner", self.copy_a)
        with self.assertRaises(BusinessError) as ctx:
            self.store.submit_retirement("owner", self.copy_a)
        self.assertEqual(ctx.exception.code, "retirement_blocked")
        self.assertEqual(ctx.exception.payload["reasons"], ["copy_verifying"])
        self.assertEqual(ctx.exception.payload["gaps"][0]["type"], "copy_verifying")
        # 校验完成且有异点健康副本后可退役
        self.store.complete_verification("owner", self.copy_a)
        result = self.store.submit_retirement("owner", self.copy_a)
        self.assertEqual(result["state"], "retired")

    def test_last_healthy_copy_is_blocked_with_gap_listing(self):
        self.store.submit_retirement("owner", self.copy_b)  # copy_a 仍在异点
        with self.assertRaises(BusinessError) as ctx:
            self.store.submit_retirement("owner", self.copy_a)
        self.assertEqual(ctx.exception.code, "retirement_blocked")
        self.assertIn("no_other_healthy_copy", ctx.exception.payload["reasons"])
        gap_paths = {g["path"] for g in ctx.exception.payload["gaps"] if g["type"] == "no_other_healthy_copy"}
        self.assertEqual(gap_paths, {"records/a.wav", "records/b.wav"})
        blocked = self.store.list_retirements("owner", self.copy_a)["retirements"]
        self.assertEqual(blocked[-1]["state"], "blocked")
        self.assertIn("no_other_healthy_copy", blocked[-1]["reasons"])

    def test_per_file_gap_when_peer_missing_one_file(self):
        # 直接删副本文件模拟介质局部缺损
        conn = sqlite3.connect(self.db)
        conn.execute("DELETE FROM copy_files WHERE copy_id=? AND path=?", (self.copy_b, "records/a.wav"))
        conn.commit()
        conn.close()
        with self.assertRaises(BusinessError) as ctx:
            self.store.submit_retirement("owner", self.copy_a)
        gaps = [g for g in ctx.exception.payload["gaps"] if g["type"] == "no_other_healthy_copy"]
        self.assertEqual([g["path"] for g in gaps], ["records/a.wav"])
        self.assertIn("records/b.wav", [g["path"] for g in ctx.exception.payload["gaps"] if g["type"] == "redundancy_ok"])

    def test_corrupt_copy_needs_damage_report_then_can_repair_and_retire(self):
        self.store.simulate_corruption("owner", self.copy_b, "records/a.wav")
        # 未校验、没有损坏清单 -> 拦下
        with self.assertRaises(BusinessError) as ctx:
            self.store.submit_retirement("owner", self.copy_b)
        reasons = ctx.exception.payload["reasons"]
        self.assertIn("damage_report_missing", reasons)
        self.assertIn("copy_not_healthy", reasons)
        # 校验产生损坏清单并从异点健康副本修复
        result = self.store.verify_copy("owner", self.copy_b)
        self.assertTrue(result["repaired"])
        self.assertIsNotNone(result["damage_report_id"])
        reports = self.store.damage_reports("owner", self.copy_b)["reports"]
        self.assertEqual(reports[0]["corrupt_paths"], ["records/a.wav"])
        self.assertTrue(reports[0]["repaired"])
        # 退役停用，但原位置/介质编号与审计仍在
        retired = self.store.submit_retirement("owner", self.copy_b)
        self.assertEqual(retired["state"], "retired")
        detail = self.store.get_version("owner", self.version)
        row = next(c for c in detail["copies"] if c["id"] == self.copy_b)
        self.assertEqual(row["state"], "retired")
        self.assertEqual(row["location"], "二号库房")
        self.assertEqual(row["media_id"], "MEDIA-B-02")
        self.assertIsNotNone(row["latest_damage_report"])
        actions = self._audit_actions()
        self.assertIn("media.retired", actions)
        self.assertIn("copy.verify", actions)

    def test_unrepaired_corruption_blocks_retirement_even_with_report(self):
        self.store.simulate_corruption("owner", self.copy_a, "records/a.wav")
        self.store.simulate_corruption("owner", self.copy_b, "records/a.wav")
        self.store.verify_copy("owner", self.copy_a)  # 双方皆损，无法修复
        self.store.verify_copy("owner", self.copy_b)
        with self.assertRaises(BusinessError) as ctx:
            self.store.submit_retirement("owner", self.copy_a)
        # 已有损坏清单 -> 不再报缺失；但副本不健康且无冗余，仍然拦截
        self.assertNotIn("damage_report_missing", ctx.exception.payload["reasons"])
        self.assertIn("copy_not_healthy", ctx.exception.payload["reasons"])
        self.assertIn("no_other_healthy_copy", ctx.exception.payload["reasons"])

    def test_duplicate_media_id_and_retired_copy_guard(self):
        with self.assertRaises(BusinessError) as ctx:
            self.store.register_copy("owner", self.copy_b, media_id="MEDIA-A-01")
        self.assertEqual(ctx.exception.code, "media_id_exists")
        self.store.submit_retirement("owner", self.copy_a)
        with self.assertRaises(BusinessError) as ctx:
            self.store.register_copy("owner", self.copy_a, media_id="NEW")
        self.assertEqual(ctx.exception.code, "copy_retired")
        with self.assertRaises(BusinessError) as ctx:
            self.store.submit_retirement("owner", self.copy_a)
        self.assertEqual(ctx.exception.code, "copy_retired")


if __name__ == "__main__":
    unittest.main()
