"""数字档案长期保存服务：SQLite 多副本、哈希校验、修复与迁移。"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import sqlite3
import threading
from datetime import date, datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DB = BASE_DIR / "preservation.db"
MAX_FILE_SIZE = 10 * 1024 * 1024


class BusinessError(Exception):
    def __init__(self, message: str, status: int = 400, code: str = "bad_request"):
        super().__init__(message)
        self.message, self.status, self.code = message, status, code


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def verify_manifest(files: object) -> list[dict]:
    if not isinstance(files, list) or not files:
        raise BusinessError("files 必须是非空数组", 422, "invalid_manifest")
    result, seen = [], set()
    for item in files:
        if not isinstance(item, dict):
            raise BusinessError("文件条目必须是对象", 422, "invalid_manifest")
        raw_path = str(item.get("path", "")).strip().replace("\\", "/")
        pure = PurePosixPath(raw_path)
        if not raw_path or pure.is_absolute() or ".." in pure.parts or pure.name in {"", ".", ".."}:
            raise BusinessError(f"档案路径不安全: {raw_path}", 422, "unsafe_path")
        if raw_path in seen:
            raise BusinessError(f"档案路径重复: {raw_path}", 409, "duplicate_path")
        seen.add(raw_path)
        encoded = item.get("content_b64")
        if not isinstance(encoded, str):
            raise BusinessError(f"{raw_path} 缺少 content_b64", 422, "content_required")
        try:
            content = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError):
            raise BusinessError(f"{raw_path} 不是合法 Base64", 422, "invalid_base64")
        if len(content) > MAX_FILE_SIZE:
            raise BusinessError(f"{raw_path} 超过单文件大小限制", 413, "file_too_large")
        result.append(
            {"path": raw_path, "content": content, "sha256": hashlib.sha256(content).hexdigest(), "size": len(content)}
        )
    return result


class PreservationStore:
    def __init__(self, db_path: str | Path = DEFAULT_DB):
        self.db_path = str(db_path)
        self._lock = threading.Lock()

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=10000")
        return conn

    def init_schema(self) -> None:
        with self._lock, self.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS users(
                    id TEXT PRIMARY KEY, name TEXT NOT NULL,
                    role TEXT NOT NULL CHECK(role IN ('owner','archivist','auditor'))
                );
                CREATE TABLE IF NOT EXISTS archives(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    owner_id TEXT NOT NULL REFERENCES users(id),
                    retention_until TEXT NOT NULL,
                    restricted INTEGER NOT NULL DEFAULT 1 CHECK(restricted IN (0,1)),
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS archive_members(
                    archive_id INTEGER NOT NULL REFERENCES archives(id),
                    user_id TEXT NOT NULL REFERENCES users(id),
                    permission TEXT NOT NULL CHECK(permission IN ('read','write')),
                    PRIMARY KEY(archive_id,user_id)
                );
                CREATE TABLE IF NOT EXISTS archive_versions(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    archive_id INTEGER NOT NULL REFERENCES archives(id),
                    version INTEGER NOT NULL,
                    state TEXT NOT NULL DEFAULT 'verified' CHECK(state IN ('verified','degraded')),
                    created_by TEXT NOT NULL REFERENCES users(id),
                    created_at TEXT NOT NULL,
                    UNIQUE(archive_id,version)
                );
                CREATE TABLE IF NOT EXISTS archive_files(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    version_id INTEGER NOT NULL REFERENCES archive_versions(id),
                    path TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    content BLOB NOT NULL,
                    UNIQUE(version_id,path)
                );
                CREATE TABLE IF NOT EXISTS copies(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    version_id INTEGER NOT NULL REFERENCES archive_versions(id),
                    location TEXT NOT NULL,
                    state TEXT NOT NULL DEFAULT 'healthy' CHECK(state IN ('healthy','corrupt','degraded')),
                    created_at TEXT NOT NULL,
                    last_verified_at TEXT,
                    media_serial TEXT NOT NULL DEFAULT '',
                    storage_site TEXT NOT NULL DEFAULT '',
                    verifying INTEGER NOT NULL DEFAULT 0 CHECK(verifying IN (0,1)),
                    deactivated_at TEXT,
                    deactivated_by TEXT,
                    UNIQUE(version_id,location)
                );
                CREATE TABLE IF NOT EXISTS copy_files(
                    copy_id INTEGER NOT NULL REFERENCES copies(id),
                    path TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    content BLOB NOT NULL,
                    PRIMARY KEY(copy_id,path)
                );
                CREATE TABLE IF NOT EXISTS copy_damages(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    copy_id INTEGER NOT NULL REFERENCES copies(id),
                    path TEXT NOT NULL,
                    expected_sha256 TEXT NOT NULL,
                    found_sha256 TEXT,
                    size INTEGER,
                    detected_at TEXT NOT NULL,
                    repaired_at TEXT,
                    UNIQUE(copy_id,path)
                );
                CREATE TABLE IF NOT EXISTS decommission_batches(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_by TEXT NOT NULL REFERENCES users(id),
                    note TEXT NOT NULL DEFAULT '',
                    state TEXT NOT NULL CHECK(state IN ('blocked','approved')),
                    created_at TEXT NOT NULL,
                    decided_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS decommission_items(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    batch_id INTEGER NOT NULL REFERENCES decommission_batches(id),
                    copy_id INTEGER NOT NULL REFERENCES copies(id),
                    version_id INTEGER NOT NULL REFERENCES archive_versions(id),
                    outcome TEXT NOT NULL CHECK(outcome IN ('approved','blocked')),
                    reasons TEXT NOT NULL DEFAULT '[]',
                    UNIQUE(batch_id,copy_id)
                );
                CREATE TABLE IF NOT EXISTS migrations(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_version_id INTEGER NOT NULL REFERENCES archive_versions(id),
                    target_version_id INTEGER NOT NULL UNIQUE REFERENCES archive_versions(id),
                    source_path TEXT NOT NULL,
                    target_path TEXT NOT NULL,
                    target_format TEXT NOT NULL,
                    actor_id TEXT NOT NULL REFERENCES users(id),
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit_log(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    archive_id INTEGER NOT NULL REFERENCES archives(id),
                    actor_id TEXT NOT NULL REFERENCES users(id),
                    action TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                """
            )
            self._migrate(conn)

    def _migrate(self, conn: sqlite3.Connection) -> None:
        """为早于介质退役流程的旧库补齐列与表（幂等）。"""
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(copies)")}
        if "media_serial" not in cols:
            conn.execute("ALTER TABLE copies ADD COLUMN media_serial TEXT NOT NULL DEFAULT ''")
        if "storage_site" not in cols:
            conn.execute("ALTER TABLE copies ADD COLUMN storage_site TEXT NOT NULL DEFAULT ''")
        if "verifying" not in cols:
            conn.execute("ALTER TABLE copies ADD COLUMN verifying INTEGER NOT NULL DEFAULT 0")
        if "deactivated_at" not in cols:
            conn.execute("ALTER TABLE copies ADD COLUMN deactivated_at TEXT")
        if "deactivated_by" not in cols:
            conn.execute("ALTER TABLE copies ADD COLUMN deactivated_by TEXT REFERENCES users(id)")

    def seed(self) -> None:
        self.init_schema()
        with self.connect() as conn:
            conn.executemany(
                "INSERT OR IGNORE INTO users(id,name,role) VALUES(?,?,?)",
                [
                    ("owner", "机构档案负责人", "owner"),
                    ("archivist", "档案管理员", "archivist"),
                    ("auditor", "独立审计员", "auditor"),
                    ("outsider", "未授权访客", "auditor"),
                ],
            )

    def _user(self, conn, user_id: str | None, roles: set[str] | None = None) -> sqlite3.Row:
        if not user_id:
            raise BusinessError("缺少 X-User-Id", 401, "authentication_required")
        user = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if not user:
            raise BusinessError("用户不存在", 401, "unknown_user")
        if roles and user["role"] not in roles:
            raise BusinessError("当前角色无权执行此操作", 403, "forbidden")
        return user

    def _access(self, conn, archive_id: int, user: sqlite3.Row, require_write: bool = False) -> None:
        archive = conn.execute("SELECT * FROM archives WHERE id=?", (archive_id,)).fetchone()
        if not archive:
            raise BusinessError("档案不存在", 404, "not_found")
        if archive["owner_id"] == user["id"]:
            return
        row = conn.execute(
            "SELECT permission FROM archive_members WHERE archive_id=? AND user_id=?", (archive_id, user["id"])
        ).fetchone()
        if not row or (require_write and row["permission"] != "write"):
            raise BusinessError("没有该受限档案的访问权限", 403, "forbidden")

    def _audit(self, conn, archive_id: int, actor: str, action: str, detail: dict) -> None:
        conn.execute(
            "INSERT INTO audit_log(archive_id,actor_id,action,detail,created_at) VALUES(?,?,?,?,?)",
            (archive_id, actor, action, json.dumps(detail, ensure_ascii=False, sort_keys=True), now()),
        )

    def _active_copy(self, conn, copy_id: int) -> sqlite3.Row:
        copy = conn.execute("SELECT * FROM copies WHERE id=?", (copy_id,)).fetchone()
        if not copy:
            raise BusinessError("副本不存在", 404, "not_found")
        return copy

    def _corrupt_findings(self, conn, copy_id: int) -> list[dict]:
        """逐文件比对副本内容与版本权威清单，返回损坏或缺失的文件。"""
        copy = conn.execute("SELECT version_id FROM copies WHERE id=?", (copy_id,)).fetchone()
        canonical = {
            r["path"]: r
            for r in conn.execute(
                "SELECT path,sha256,size FROM archive_files WHERE version_id=?", (copy["version_id"],)
            ).fetchall()
        }
        stored = {
            r["path"]: r
            for r in conn.execute("SELECT path,sha256,size,content FROM copy_files WHERE copy_id=?", (copy_id,)).fetchall()
        }
        findings: list[dict] = []
        for path, ref in canonical.items():
            row = stored.get(path)
            found_hash = hashlib.sha256(row["content"]).hexdigest() if row is not None else None
            if row is None or found_hash != ref["sha256"] or len(row["content"]) != ref["size"]:
                findings.append(
                    {"path": path, "expected_sha256": ref["sha256"], "found_sha256": found_hash,
                     "size": len(row["content"]) if row is not None else 0}
                )
        return findings

    def _record_damages(self, conn, copy_id: int, findings: list[dict]) -> None:
        for f in findings:
            conn.execute(
                """INSERT INTO copy_damages(copy_id,path,expected_sha256,found_sha256,size,detected_at,repaired_at)
                   VALUES(?,?,?,?,?,?,NULL)
                   ON CONFLICT(copy_id,path) DO UPDATE SET
                       expected_sha256=excluded.expected_sha256,
                       found_sha256=excluded.found_sha256,
                       size=excluded.size,
                       detected_at=excluded.detected_at,
                       repaired_at=NULL""",
                (copy_id, f["path"], f["expected_sha256"], f["found_sha256"], f["size"], now()),
            )

    def _open_damages(self, conn, copy_id: int) -> list[dict]:
        return [
            {"path": r["path"], "expected_sha256": r["expected_sha256"], "found_sha256": r["found_sha256"],
             "size": r["size"], "detected_at": r["detected_at"]}
            for r in conn.execute(
                "SELECT path,expected_sha256,found_sha256,size,detected_at FROM copy_damages "
                "WHERE copy_id=? AND repaired_at IS NULL ORDER BY path",
                (copy_id,),
            ).fetchall()
        ]

    def _copy_payload(self, conn, copy: sqlite3.Row) -> dict:
        payload = dict(copy)
        payload["verifying"] = bool(copy["verifying"])
        payload["active"] = copy["deactivated_at"] is None
        payload["damage_count"] = conn.execute(
            "SELECT COUNT(*) FROM copy_damages WHERE copy_id=? AND repaired_at IS NULL", (copy["id"],)
        ).fetchone()[0]
        return payload

    def create_archive(self, user_id: str, name: str, retention_until: str, restricted: bool = True) -> dict:
        name = name.strip()
        if len(name) < 2:
            raise BusinessError("档案名称至少 2 字", 422, "invalid_name")
        try:
            deadline = date.fromisoformat(retention_until)
        except ValueError:
            raise BusinessError("retention_until 必须是 YYYY-MM-DD", 422, "invalid_retention")
        if deadline < date.today():
            raise BusinessError("保留期限不能早于今天", 422, "retention_in_past")
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist"})
            try:
                cur = conn.execute(
                    "INSERT INTO archives(name,owner_id,retention_until,restricted,created_at) VALUES(?,?,?,?,?)",
                    (name, user_id, retention_until, int(bool(restricted)), now()),
                )
            except sqlite3.IntegrityError:
                raise BusinessError("档案名称已存在", 409, "archive_exists")
            archive_id = cur.lastrowid
            conn.execute(
                "INSERT INTO archive_members(archive_id,user_id,permission) VALUES(?,?,'write')", (archive_id, user_id)
            )
            self._audit(conn, archive_id, user_id, "archive.create", {"retention_until": retention_until, "restricted": restricted})
            return {"id": archive_id, "name": name, "retention_until": retention_until, "restricted": restricted}

    def grant(self, actor_id: str, archive_id: int, user_id: str, permission: str) -> dict:
        if permission not in {"read", "write"}:
            raise BusinessError("permission 必须是 read 或 write", 422, "invalid_permission")
        with self.connect() as conn:
            actor = self._user(conn, actor_id)
            archive = conn.execute("SELECT * FROM archives WHERE id=?", (archive_id,)).fetchone()
            if not archive:
                raise BusinessError("档案不存在", 404, "not_found")
            if archive["owner_id"] != actor_id:
                raise BusinessError("只有档案所有者可以授权", 403, "forbidden")
            self._user(conn, user_id)
            conn.execute(
                """INSERT INTO archive_members(archive_id,user_id,permission) VALUES(?,?,?)
                   ON CONFLICT(archive_id,user_id) DO UPDATE SET permission=excluded.permission""",
                (archive_id, user_id, permission),
            )
            self._audit(conn, archive_id, actor_id, "access.grant", {"user_id": user_id, "permission": permission})
            return {"archive_id": archive_id, "user_id": user_id, "permission": permission}

    def ingest_version(self, actor_id: str, archive_id: int, files: object) -> dict:
        manifest = verify_manifest(files)
        with self.connect() as conn:
            actor = self._user(conn, actor_id, {"owner", "archivist"})
            self._access(conn, archive_id, actor, require_write=True)
            try:
                conn.execute("BEGIN IMMEDIATE")
                version_no = conn.execute(
                    "SELECT COALESCE(MAX(version),0)+1 FROM archive_versions WHERE archive_id=?", (archive_id,)
                ).fetchone()[0]
                cur = conn.execute(
                    "INSERT INTO archive_versions(archive_id,version,created_by,created_at) VALUES(?,?,?,?)",
                    (archive_id, version_no, actor_id, now()),
                )
                version_id = cur.lastrowid
                for item in manifest:
                    conn.execute(
                        "INSERT INTO archive_files(version_id,path,sha256,size,content) VALUES(?,?,?,?,?)",
                        (version_id, item["path"], item["sha256"], item["size"], item["content"]),
                    )
                self._audit(
                    conn, archive_id, actor_id, "version.ingest",
                    {"version_id": version_id, "version": version_no, "files": len(manifest),
                     "manifest": [{"path": x["path"], "sha256": x["sha256"], "size": x["size"]} for x in manifest]},
                )
                return {"id": version_id, "archive_id": archive_id, "version": version_no, "file_count": len(manifest)}
            except Exception:
                conn.rollback()
                raise

    def add_copy(self, actor_id: str, version_id: int, location: str) -> dict:
        location = location.strip()
        if len(location) < 2:
            raise BusinessError("副本位置不能为空", 422, "invalid_location")
        with self.connect() as conn:
            actor = self._user(conn, actor_id, {"owner", "archivist"})
            version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (version_id,)).fetchone()
            if not version:
                raise BusinessError("档案版本不存在", 404, "not_found")
            self._access(conn, version["archive_id"], actor, require_write=True)
            try:
                conn.execute("BEGIN IMMEDIATE")
                cur = conn.execute(
                    "INSERT INTO copies(version_id,location,created_at,last_verified_at) VALUES(?,?,?,?)",
                    (version_id, location, now(), now()),
                )
                copy_id = cur.lastrowid
                conn.execute(
                    """INSERT INTO copy_files(copy_id,path,sha256,size,content)
                       SELECT ?,path,sha256,size,content FROM archive_files WHERE version_id=?""",
                    (copy_id, version_id),
                )
                self._audit(conn, version["archive_id"], actor_id, "copy.create", {"copy_id": copy_id, "version_id": version_id, "location": location})
                return {"id": copy_id, "version_id": version_id, "location": location, "state": "healthy"}
            except sqlite3.IntegrityError:
                conn.rollback()
                raise BusinessError("该版本的副本位置已存在", 409, "copy_exists")
            except Exception:
                conn.rollback()
                raise

    def get_version(self, user_id: str, version_id: int) -> dict:
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist", "auditor"})
            version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (version_id,)).fetchone()
            if not version:
                raise BusinessError("档案版本不存在", 404, "not_found")
            self._access(conn, version["archive_id"], user)
            files = conn.execute(
                "SELECT path,sha256,size FROM archive_files WHERE version_id=? ORDER BY path", (version_id,)
            ).fetchall()
            copies = conn.execute(
                "SELECT * FROM copies WHERE version_id=? ORDER BY id", (version_id,)
            ).fetchall()
            archive = conn.execute("SELECT * FROM archives WHERE id=?", (version["archive_id"],)).fetchone()
            return {"version": dict(version), "archive": dict(archive), "files": [dict(x) for x in files],
                    "copies": [self._copy_payload(conn, c) for c in copies]}

    def start_verification(self, user_id: str, copy_id: int) -> dict:
        """标记介质正在校验，校验结束前不得批准退役。"""
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist", "auditor"})
            try:
                conn.execute("BEGIN IMMEDIATE")
                copy = self._active_copy(conn, copy_id)
                version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (copy["version_id"],)).fetchone()
                self._access(conn, version["archive_id"], user)
                if copy["deactivated_at"] is not None:
                    raise BusinessError("副本已停用，不能再校验", 409, "copy_deactivated")
                conn.execute("UPDATE copies SET verifying=1 WHERE id=?", (copy_id,))
                self._audit(conn, version["archive_id"], user_id, "copy.verify_start", {"copy_id": copy_id})
                return {"copy_id": copy_id, "verifying": True}
            except Exception:
                conn.rollback()
                raise

    def verify_copy(self, user_id: str, copy_id: int) -> dict:
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist", "auditor"})
            try:
                conn.execute("BEGIN IMMEDIATE")
                copy = self._active_copy(conn, copy_id)
                version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (copy["version_id"],)).fetchone()
                self._access(conn, version["archive_id"], user)
                if copy["deactivated_at"] is not None:
                    raise BusinessError("副本已停用，不能再校验", 409, "copy_deactivated")
                findings = self._corrupt_findings(conn, copy_id)
                corrupt_paths = [f["path"] for f in findings]
                repaired = False
                if not findings:
                    conn.execute(
                        "UPDATE copies SET state='healthy',last_verified_at=?,verifying=0 WHERE id=?", (now(), copy_id)
                    )
                    conn.execute("UPDATE copy_damages SET repaired_at=? WHERE copy_id=? AND repaired_at IS NULL", (now(), copy_id))
                    result_state = "healthy"
                else:
                    # 损坏副本先留下损坏清单，再尝试从其他健康副本修复
                    self._record_damages(conn, copy_id, findings)
                    conn.execute("UPDATE copies SET state='corrupt',last_verified_at=? WHERE id=?", (now(), copy_id))
                    healthy = conn.execute(
                        """SELECT id FROM copies WHERE version_id=? AND id<>? AND state='healthy'
                               AND deactivated_at IS NULL ORDER BY last_verified_at DESC LIMIT 1""",
                        (copy["version_id"], copy_id),
                    ).fetchone()
                    result_state = "degraded"
                    if healthy:
                        donor = conn.execute(
                            "SELECT path,sha256,size,content FROM copy_files WHERE copy_id=? ORDER BY path",
                            (healthy["id"],),
                        ).fetchall()
                        donor_by_path = {r["path"]: r for r in donor}
                        expected = {r["path"]: r for r in conn.execute(
                            "SELECT path,sha256,size FROM archive_files WHERE version_id=?", (copy["version_id"],)
                        ).fetchall()}
                        if set(donor_by_path) == set(expected) and all(
                            hashlib.sha256(donor_by_path[p]["content"]).hexdigest() == expected[p]["sha256"] for p in expected
                        ):
                            conn.execute("DELETE FROM copy_files WHERE copy_id=?", (copy_id,))
                            conn.execute(
                                """INSERT INTO copy_files(copy_id,path,sha256,size,content)
                                   SELECT ?,path,sha256,size,content FROM copy_files WHERE copy_id=?""",
                                (copy_id, healthy["id"]),
                            )
                            conn.execute(
                                "UPDATE copies SET state='healthy',last_verified_at=?,verifying=0 WHERE id=?",
                                (now(), copy_id),
                            )
                            conn.execute(
                                "UPDATE copy_damages SET repaired_at=? WHERE copy_id=? AND repaired_at IS NULL",
                                (now(), copy_id),
                            )
                            repaired, result_state = True, "healthy"
                    if result_state == "degraded":
                        conn.execute("UPDATE copies SET verifying=0 WHERE id=?", (copy_id,))
                        conn.execute("UPDATE archive_versions SET state='degraded' WHERE id=?", (copy["version_id"],))
                self._audit(
                    conn, version["archive_id"], user_id, "copy.verify",
                    {"copy_id": copy_id, "state": result_state, "corrupt_paths": corrupt_paths, "repaired": repaired},
                )
                return {"copy_id": copy_id, "state": result_state, "corrupt_paths": corrupt_paths,
                        "repaired": repaired,
                        "damage_list": self._open_damages(conn, copy_id) if result_state != "healthy" else []}
            except Exception:
                conn.rollback()
                raise

    def register_media(self, actor_id: str, copy_id: int, media_serial: str, storage_site: str) -> dict:
        """给副本登记物理介质编号和存放点。"""
        media_serial = (media_serial or "").strip()
        storage_site = (storage_site or "").strip()
        if not media_serial:
            raise BusinessError("介质编号不能为空", 422, "invalid_media_serial")
        if not storage_site:
            raise BusinessError("存放点不能为空", 422, "invalid_storage_site")
        with self.connect() as conn:
            actor = self._user(conn, actor_id, {"owner", "archivist"})
            copy = self._active_copy(conn, copy_id)
            version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (copy["version_id"],)).fetchone()
            self._access(conn, version["archive_id"], actor, require_write=True)
            if copy["deactivated_at"] is not None:
                raise BusinessError("副本已停用，不能再登记介质", 409, "copy_deactivated")
            conflict = conn.execute(
                "SELECT id FROM copies WHERE version_id=? AND media_serial=? AND id<>? AND deactivated_at IS NULL",
                (copy["version_id"], media_serial, copy_id),
            ).fetchone()
            if conflict:
                raise BusinessError("该版本下介质编号已被其他副本登记", 409, "media_serial_exists")
            conn.execute(
                "UPDATE copies SET media_serial=?,storage_site=? WHERE id=?", (media_serial, storage_site, copy_id)
            )
            self._audit(
                conn, version["archive_id"], actor_id, "media.register",
                {"copy_id": copy_id, "media_serial": media_serial, "storage_site": storage_site},
            )
            return self._copy_payload(conn, self._active_copy(conn, copy_id))

    def get_copy(self, user_id: str, copy_id: int) -> dict:
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist", "auditor"})
            copy = self._active_copy(conn, copy_id)
            version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (copy["version_id"],)).fetchone()
            self._access(conn, version["archive_id"], user)
            payload = self._copy_payload(conn, copy)
            payload["damage_list"] = self._open_damages(conn, copy_id)
            return payload


    def simulate_corruption(self, user_id: str, copy_id: int, path: str) -> dict:
        """仅用于演示和测试，在受控环境中模拟底层介质损坏。"""
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist"})
            copy = conn.execute("SELECT * FROM copies WHERE id=?", (copy_id,)).fetchone()
            if not copy:
                raise BusinessError("副本不存在", 404, "not_found")
            version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (copy["version_id"],)).fetchone()
            self._access(conn, version["archive_id"], user, require_write=True)
            if copy["deactivated_at"] is not None:
                raise BusinessError("副本已停用，不能再模拟损坏", 409, "copy_deactivated")
            row = conn.execute("SELECT content FROM copy_files WHERE copy_id=? AND path=?", (copy_id, path)).fetchone()
            if not row:
                raise BusinessError("副本文件不存在", 404, "not_found")
            damaged = bytes([row["content"][0] ^ 0xFF]) + row["content"][1:] if row["content"] else b"corrupt"
            conn.execute("UPDATE copy_files SET content=? WHERE copy_id=? AND path=?", (damaged, copy_id, path))
            conn.execute("UPDATE copies SET state='corrupt' WHERE id=?", (copy_id,))
            self._audit(conn, version["archive_id"], user_id, "copy.simulate_corruption", {"copy_id": copy_id, "path": path})
            return {"copy_id": copy_id, "path": path, "state": "corrupt"}

    def migrate(self, actor_id: str, version_id: int, source_path: str, target_path: str, target_format: str, content_b64: str) -> dict:
        with self.connect() as conn:
            actor = self._user(conn, actor_id, {"owner", "archivist"})
            source_version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (version_id,)).fetchone()
            if not source_version:
                raise BusinessError("源档案版本不存在", 404, "not_found")
            self._access(conn, source_version["archive_id"], actor, require_write=True)
            source = conn.execute(
                "SELECT * FROM archive_files WHERE version_id=? AND path=?", (version_id, source_path)
            ).fetchone()
            if not source:
                raise BusinessError("源文件不存在", 404, "source_not_found")
            converted = verify_manifest([{"path": target_path, "content_b64": content_b64}])[0]
            try:
                conn.execute("BEGIN IMMEDIATE")
                version_no = conn.execute(
                    "SELECT COALESCE(MAX(version),0)+1 FROM archive_versions WHERE archive_id=?", (source_version["archive_id"],)
                ).fetchone()[0]
                cur = conn.execute(
                    "INSERT INTO archive_versions(archive_id,version,created_by,created_at) VALUES(?,?,?,?)",
                    (source_version["archive_id"], version_no, actor_id, now()),
                )
                target_version_id = cur.lastrowid
                conn.execute(
                    """INSERT INTO archive_files(version_id,path,sha256,size,content)
                       SELECT ?,path,sha256,size,content FROM archive_files
                       WHERE version_id=? AND path<>?""",
                    (target_version_id, version_id, source_path),
                )
                conn.execute(
                    "INSERT INTO archive_files(version_id,path,sha256,size,content) VALUES(?,?,?,?,?)",
                    (target_version_id, converted["path"], converted["sha256"], converted["size"], converted["content"]),
                )
                conn.execute(
                    "INSERT INTO migrations(source_version_id,target_version_id,source_path,target_path,target_format,actor_id,created_at) VALUES(?,?,?,?,?,?,?)",
                    (version_id, target_version_id, source_path, converted["path"], target_format.strip(), actor_id, now()),
                )
                self._audit(
                    conn, source_version["archive_id"], actor_id, "format.migrate",
                    {"source_version_id": version_id, "target_version_id": target_version_id,
                     "source_path": source_path, "target_path": converted["path"], "target_format": target_format.strip()},
                )
                return {"id": target_version_id, "version": version_no, "source_version_id": version_id, "target_path": converted["path"]}
            except Exception:
                conn.rollback()
                raise

    def _evaluate_decommission(self, conn, copy: sqlite3.Row, retiring_ids: set[int]) -> list[dict]:
        """核对单份副本能否撤走；返回阻塞原因列表，空列表即通过。"""
        reasons: list[dict] = []
        if copy["verifying"]:
            reasons.append({"code": "verifying_in_progress", "message": "介质正在校验，不能批准退役"})
        if not copy["media_serial"] or not copy["storage_site"]:
            reasons.append({"code": "media_unregistered", "message": "副本尚未登记介质编号或存放点"})
        findings = self._corrupt_findings(conn, copy["id"])
        if findings:
            # 已损坏副本：先留下损坏清单
            self._record_damages(conn, copy["id"], findings)
            conn.execute("UPDATE copies SET state='corrupt' WHERE id=?", (copy["id"],))
            conn.execute("UPDATE archive_versions SET state='degraded' WHERE id=?", (copy["version_id"],))
            reasons.append({
                "code": "copy_corrupt",
                "message": "副本存在损坏或缺失文件，损坏清单已留存",
                "damage_list": [
                    {"path": f["path"], "expected_sha256": f["expected_sha256"],
                     "found_sha256": f["found_sha256"], "size": f["size"]}
                    for f in findings
                ],
            })
        if copy["media_serial"] and copy["storage_site"]:
            # 按版本逐份核对：每个文件都需要另一个健康且存放点不同的副本
            canonical = conn.execute(
                "SELECT path,sha256,size FROM archive_files WHERE version_id=? ORDER BY path",
                (copy["version_id"],),
            ).fetchall()
            candidates = conn.execute(
                """SELECT id,location,media_serial,storage_site FROM copies
                   WHERE version_id=? AND id<>? AND state='healthy' AND deactivated_at IS NULL
                       AND media_serial<>'' AND storage_site<>'' AND storage_site<>?""",
                (copy["version_id"], copy["id"], copy["storage_site"]),
            ).fetchall()
            candidates = [c for c in candidates if c["id"] not in retiring_ids]
            missing_files = []
            for f in canonical:
                donor = None
                for c in candidates:
                    row = conn.execute(
                        "SELECT content FROM copy_files WHERE copy_id=? AND path=?", (c["id"], f["path"])
                    ).fetchone()
                    if row is not None and hashlib.sha256(row["content"]).hexdigest() == f["sha256"]:
                        donor = c
                        break
                if donor is None:
                    missing_files.append({
                        "path": f["path"],
                        "sha256": f["sha256"],
                        "size": f["size"],
                        "reason": "没有另一个健康且不同存放点的副本",
                    })
            if missing_files:
                reasons.append({
                    "code": "no_diverse_healthy_copy",
                    "message": "部分文件缺少另一个健康且不同存放点的副本",
                    "gaps": missing_files,
                })
        return reasons

    def submit_decommission(self, actor_id: str, copy_ids: object, note: str = "") -> dict:
        if not isinstance(copy_ids, list) or not copy_ids:
            raise BusinessError("copy_ids 必须是非空数组", 422, "invalid_copy_ids")
        try:
            ids = [int(x) for x in copy_ids]
        except (TypeError, ValueError):
            raise BusinessError("copy_ids 必须是整数数组", 422, "invalid_copy_ids")
        if len(set(ids)) != len(ids):
            raise BusinessError("同一批次中副本不能重复", 422, "duplicate_copy")
        with self.connect() as conn:
            actor = self._user(conn, actor_id, {"owner", "archivist"})
            copies = []
            for cid in ids:
                copy = self._active_copy(conn, cid)
                if copy["deactivated_at"] is not None:
                    raise BusinessError(f"副本 {cid} 已停用，不能再次退役", 409, "copy_deactivated")
                version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (copy["version_id"],)).fetchone()
                self._access(conn, version["archive_id"], actor, require_write=True)
                copies.append(copy)
            try:
                conn.execute("BEGIN IMMEDIATE")
                ts = now()
                results = []
                for copy in copies:
                    reasons = self._evaluate_decommission(conn, copy, set(ids))
                    results.append({"copy": copy, "reasons": reasons})
                blocked = any(r["reasons"] for r in results)
                state = "blocked" if blocked else "approved"
                batch_id = conn.execute(
                    "INSERT INTO decommission_batches(created_by,note,state,created_at,decided_at) VALUES(?,?,?,?,?)",
                    (actor_id, (note or "").strip(), state, ts, ts),
                ).lastrowid
                for r in results:
                    copy = r["copy"]
                    outcome = "blocked" if r["reasons"] else "approved"
                    conn.execute(
                        "INSERT INTO decommission_items(batch_id,copy_id,version_id,outcome,reasons) VALUES(?,?,?,?,?)",
                        (batch_id, copy["id"], copy["version_id"], outcome,
                         json.dumps(r["reasons"], ensure_ascii=False, sort_keys=True)),
                    )
                    version = conn.execute(
                        "SELECT archive_id FROM archive_versions WHERE id=?", (copy["version_id"],)
                    ).fetchone()
                    if outcome == "approved":
                        # 校验通过后在档案里停用，原位置、介质信息和审计记录仍保留
                        conn.execute(
                            "UPDATE copies SET deactivated_at=?,deactivated_by=? WHERE id=?",
                            (ts, actor_id, copy["id"]),
                        )
                        self._audit(
                            conn, version["archive_id"], actor_id, "media.decommission",
                            {"batch_id": batch_id, "copy_id": copy["id"], "version_id": copy["version_id"],
                             "media_serial": copy["media_serial"], "storage_site": copy["storage_site"],
                             "location": copy["location"], "outcome": "approved"},
                        )
                    else:
                        self._audit(
                            conn, version["archive_id"], actor_id, "media.decommission_blocked",
                            {"batch_id": batch_id, "copy_id": copy["id"], "version_id": copy["version_id"],
                             "reasons": r["reasons"]},
                        )
                return self._decommission_payload(conn, batch_id)
            except Exception:
                conn.rollback()
                raise

    def _decommission_payload(self, conn, batch_id: int) -> dict:
        batch = conn.execute("SELECT * FROM decommission_batches WHERE id=?", (batch_id,)).fetchone()
        if not batch:
            raise BusinessError("退役批次不存在", 404, "not_found")
        items = []
        for it in conn.execute(
            "SELECT * FROM decommission_items WHERE batch_id=? ORDER BY id", (batch_id,)
        ).fetchall():
            copy = conn.execute("SELECT * FROM copies WHERE id=?", (it["copy_id"],)).fetchone()
            items.append({
                "item_id": it["id"],
                "copy_id": it["copy_id"],
                "version_id": it["version_id"],
                "outcome": it["outcome"],
                "reasons": json.loads(it["reasons"]),
                "copy": self._copy_payload(conn, copy) if copy else None,
            })
        return {
            "id": batch["id"],
            "created_by": batch["created_by"],
            "note": batch["note"],
            "state": batch["state"],
            "created_at": batch["created_at"],
            "decided_at": batch["decided_at"],
            "items": items,
            "approved_count": sum(1 for i in items if i["outcome"] == "approved"),
            "blocked_count": sum(1 for i in items if i["outcome"] == "blocked"),
        }

    def get_decommission(self, user_id: str, batch_id: int) -> dict:
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist", "auditor"})
            payload = self._decommission_payload(conn, batch_id)
            for item in payload["items"]:
                version = conn.execute(
                    "SELECT archive_id FROM archive_versions WHERE id=?", (item["version_id"],)
                ).fetchone()
                self._access(conn, version["archive_id"], user)
            return payload

    def list_decommissions(self, user_id: str) -> dict:
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist", "auditor"})
            visible = []
            for b in conn.execute("SELECT * FROM decommission_batches ORDER BY id DESC").fetchall():
                rows = conn.execute(
                    """SELECT v.archive_id FROM decommission_items i
                       JOIN archive_versions v ON v.id=i.version_id
                       WHERE i.batch_id=?""",
                    (b["id"],),
                ).fetchall()
                try:
                    for r in rows:
                        self._access(conn, r["archive_id"], user)
                except BusinessError:
                    continue
                items = conn.execute("SELECT copy_id,version_id,outcome,reasons FROM decommission_items WHERE batch_id=? ORDER BY id", (b["id"],)).fetchall()
                visible.append({
                    "id": b["id"], "created_by": b["created_by"], "note": b["note"], "state": b["state"],
                    "created_at": b["created_at"], "decided_at": b["decided_at"],
                    "items": [{"copy_id": i["copy_id"], "version_id": i["version_id"], "outcome": i["outcome"],
                               "reasons": json.loads(i["reasons"])} for i in items],
                })
            return {"batches": visible}

    def archive_status(self, user_id: str, archive_id: int) -> dict:
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist", "auditor"})
            self._access(conn, archive_id, user)
            archive = conn.execute("SELECT * FROM archives WHERE id=?", (archive_id,)).fetchone()
            versions = conn.execute("SELECT id,version,state,created_at FROM archive_versions WHERE archive_id=? ORDER BY version", (archive_id,)).fetchall()
            deadline = date.fromisoformat(archive["retention_until"])
            return {
                "archive": dict(archive),
                "days_remaining": (deadline - date.today()).days,
                "versions": [dict(v) | {"file_count": conn.execute("SELECT COUNT(*) FROM archive_files WHERE version_id=?", (v["id"],)).fetchone()[0],
                                         "copy_count": conn.execute("SELECT COUNT(*) FROM copies WHERE version_id=?", (v["id"],)).fetchone()[0]}
                             for v in versions],
                "audit": [dict(r) | {"detail": json.loads(r["detail"])} for r in conn.execute("SELECT * FROM audit_log WHERE archive_id=? ORDER BY id", (archive_id,)).fetchall()],
            }


class Handler(BaseHTTPRequestHandler):
    server_version = "Preservation/1.0"

    def _store(self):
        return self.server.store  # type: ignore[attr-defined]

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        try:
            data = json.loads(self.rfile.read(length) or b"{}")
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise BusinessError("请求体必须是合法 JSON", 400, "invalid_json")
        if not isinstance(data, dict):
            raise BusinessError("JSON 顶层必须是对象", 422, "invalid_json")
        return data

    def _send(self, status: int, payload) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _dispatch(self, method: str) -> None:
        path = urlparse(self.path).path.rstrip("/") or "/"
        parts = [p for p in path.split("/") if p]
        user = self.headers.get("X-User-Id", "")
        if method == "GET" and path == "/":
            body = (BASE_DIR / "web" / "index.html").read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if method == "GET" and path == "/health":
            return self._send(200, {"ok": True})
        store = self._store()
        if parts == ["api", "archives"] and method == "POST":
            d = self._body()
            return self._send(201, store.create_archive(user, d.get("name", ""), d.get("retention_until", ""), bool(d.get("restricted", True))))
        if len(parts) == 4 and parts[:2] == ["api", "archives"] and method == "POST":
            archive_id = int(parts[2])
            if parts[3] == "versions":
                d = self._body()
                return self._send(201, store.ingest_version(user, archive_id, d.get("files")))
            if parts[3] == "members":
                d = self._body()
                return self._send(201, store.grant(user, archive_id, d.get("user_id", ""), d.get("permission", "")))
        if len(parts) == 4 and parts[:2] == ["api", "archives"] and parts[3] == "status" and method == "GET":
            return self._send(200, store.archive_status(user, int(parts[2])))
        if len(parts) == 3 and parts[:2] == ["api", "versions"] and method == "GET":
            return self._send(200, store.get_version(user, int(parts[2])))
        if len(parts) == 3 and parts[:2] == ["api", "copies"] and method == "GET":
            return self._send(200, store.get_copy(user, int(parts[2])))
        if len(parts) == 4 and parts[:2] == ["api", "versions"] and parts[3] == "copies" and method == "POST":
            d = self._body()
            return self._send(201, store.add_copy(user, int(parts[2]), d.get("location", "")))
        if len(parts) == 4 and parts[:2] == ["api", "versions"] and parts[3] == "migrate" and method == "POST":
            d = self._body()
            return self._send(201, store.migrate(user, int(parts[2]), d.get("source_path", ""), d.get("target_path", ""), d.get("target_format", ""), d.get("content_b64", "")))
        if len(parts) == 4 and parts[:2] == ["api", "copies"] and parts[3] == "verify" and method == "POST":
            return self._send(200, store.verify_copy(user, int(parts[2])))
        if len(parts) == 4 and parts[:2] == ["api", "copies"] and parts[3] == "start-verification" and method == "POST":
            return self._send(200, store.start_verification(user, int(parts[2])))
        if len(parts) == 4 and parts[:2] == ["api", "copies"] and parts[3] == "media" and method == "POST":
            d = self._body()
            return self._send(200, store.register_media(user, int(parts[2]), d.get("media_serial", ""), d.get("storage_site", "")))
        if len(parts) == 4 and parts[:2] == ["api", "copies"] and parts[3] == "simulate-corruption" and method == "POST":
            d = self._body()
            return self._send(200, store.simulate_corruption(user, int(parts[2]), d.get("path", "")))
        if parts == ["api", "decommissions"] and method == "GET":
            return self._send(200, store.list_decommissions(user))
        if parts == ["api", "decommissions"] and method == "POST":
            d = self._body()
            return self._send(201, store.submit_decommission(user, d.get("copy_ids"), d.get("note", "")))
        if len(parts) == 3 and parts[:2] == ["api", "decommissions"] and method == "GET":
            return self._send(200, store.get_decommission(user, int(parts[2])))
        raise BusinessError("接口不存在", 404, "not_found")

    def _handle(self, method: str) -> None:
        try:
            self._dispatch(method)
        except BusinessError as exc:
            self._send(exc.status, {"error": {"code": exc.code, "message": exc.message}})
        except (ValueError, TypeError):
            self._send(400, {"error": {"code": "invalid_path", "message": "路径参数格式错误"}})
        except Exception as exc:
            self._send(500, {"error": {"code": "internal_error", "message": str(exc)}})

    def do_GET(self): self._handle("GET")
    def do_POST(self): self._handle("POST")
    def do_DELETE(self): self._handle("DELETE")
    def log_message(self, fmt, *args): print(f"{self.address_string()} - {fmt % args}")


class PreservationServer(ThreadingHTTPServer):
    daemon_threads = True
    def __init__(self, address, store):
        self.store = store
        super().__init__(address, Handler)


def main() -> None:
    parser = argparse.ArgumentParser(description="数字档案长期保存服务")
    parser.add_argument("--db", default=str(DEFAULT_DB))
    parser.add_argument("--port", type=int, default=8102)
    parser.add_argument("--init", action="store_true")
    parser.add_argument("--seed", action="store_true")
    args = parser.parse_args()
    store = PreservationStore(args.db)
    store.init_schema()
    if args.seed:
        store.seed()
    if args.init or args.seed:
        print(f"数据库已初始化: {args.db}")
        return
    print(f"数字档案服务运行于 http://127.0.0.1:{args.port}")
    server = PreservationServer(("127.0.0.1", args.port), store)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
