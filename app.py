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
    def __init__(self, message: str, status: int = 400, code: str = "bad_request", payload: dict | None = None):
        super().__init__(message)
        self.message, self.status, self.code, self.payload = message, status, code, payload


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def digest(content: bytes | str) -> str:
    if isinstance(content, str):
        content = content.encode()
    return hashlib.sha256(content).hexdigest()


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
            {"path": raw_path, "content": content, "sha256": digest(content), "size": len(content)}
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
        with self._lock:
            with self.connect() as conn:
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
                    """
                )
                self._migrate_copies(conn)
                conn.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS copy_files(
                        copy_id INTEGER NOT NULL REFERENCES copies(id),
                        path TEXT NOT NULL,
                        sha256 TEXT NOT NULL,
                        size INTEGER NOT NULL,
                        content BLOB NOT NULL,
                        PRIMARY KEY(copy_id,path)
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
                    CREATE TABLE IF NOT EXISTS copy_damage_reports(
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        copy_id INTEGER NOT NULL REFERENCES copies(id),
                        version_id INTEGER NOT NULL REFERENCES archive_versions(id),
                        corrupt_paths TEXT NOT NULL,
                        found_at TEXT NOT NULL,
                        repaired INTEGER NOT NULL CHECK(repaired IN (0,1)),
                        actor_id TEXT NOT NULL REFERENCES users(id)
                    );
                    CREATE TABLE IF NOT EXISTS retirements(
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        copy_id INTEGER NOT NULL REFERENCES copies(id),
                        version_id INTEGER NOT NULL REFERENCES archive_versions(id),
                        state TEXT NOT NULL CHECK(state IN ('blocked','retired')),
                        reasons TEXT NOT NULL,
                        gaps TEXT NOT NULL,
                        submitted_by TEXT NOT NULL REFERENCES users(id),
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
                    CREATE INDEX IF NOT EXISTS idx_damage_copy ON copy_damage_reports(copy_id);
                    CREATE INDEX IF NOT EXISTS idx_retirements_copy ON retirements(copy_id);
                    """
                )

    def _migrate_copies(self, conn: sqlite3.Connection) -> None:
        """补齐介质编号、校验中/已退役状态；旧库通过重建 copies 表放宽 CHECK。"""
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(copies)").fetchall()}
        if not cols:
            conn.execute(
                """
                CREATE TABLE copies(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    version_id INTEGER NOT NULL REFERENCES archive_versions(id),
                    location TEXT NOT NULL,
                    media_id TEXT,
                    state TEXT NOT NULL DEFAULT 'healthy'
                        CHECK(state IN ('healthy','corrupt','degraded','verifying','retired')),
                    created_at TEXT NOT NULL,
                    last_verified_at TEXT,
                    verify_started_at TEXT,
                    UNIQUE(version_id,location)
                )
                """
            )
            conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_copies_media ON copies(media_id) WHERE media_id IS NOT NULL")
            return
        ddl = conn.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='copies'").fetchone()[0]
        if "media_id" not in cols or "'retired'" not in ddl:
            conn.executescript(
                """
                ALTER TABLE copies RENAME TO copies_old;
                CREATE TABLE copies(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    version_id INTEGER NOT NULL REFERENCES archive_versions(id),
                    location TEXT NOT NULL,
                    media_id TEXT,
                    state TEXT NOT NULL DEFAULT 'healthy'
                        CHECK(state IN ('healthy','corrupt','degraded','verifying','retired')),
                    created_at TEXT NOT NULL,
                    last_verified_at TEXT,
                    verify_started_at TEXT,
                    UNIQUE(version_id,location)
                );
                INSERT INTO copies(id,version_id,location,media_id,state,created_at,last_verified_at,verify_started_at)
                    SELECT id,version_id,location,NULL,state,created_at,last_verified_at,NULL FROM copies_old;
                DROP TABLE copies_old;
                CREATE UNIQUE INDEX IF NOT EXISTS idx_copies_media ON copies(media_id) WHERE media_id IS NOT NULL;
                """
            )

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

    def add_copy(self, actor_id: str, version_id: int, location: str, media_id: str | None = None) -> dict:
        location = location.strip()
        if len(location) < 2:
            raise BusinessError("副本存放点不能为空", 422, "invalid_location")
        media_id = self._clean_media_id(media_id)
        with self.connect() as conn:
            actor = self._user(conn, actor_id, {"owner", "archivist"})
            version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (version_id,)).fetchone()
            if not version:
                raise BusinessError("档案版本不存在", 404, "not_found")
            self._access(conn, version["archive_id"], actor, require_write=True)
            try:
                conn.execute("BEGIN IMMEDIATE")
                cur = conn.execute(
                    "INSERT INTO copies(version_id,location,media_id,created_at,last_verified_at) VALUES(?,?,?,?,?)",
                    (version_id, location, media_id, now(), now()),
                )
                copy_id = cur.lastrowid
                conn.execute(
                    """INSERT INTO copy_files(copy_id,path,sha256,size,content)
                       SELECT ?,path,sha256,size,content FROM archive_files WHERE version_id=?""",
                    (copy_id, version_id),
                )
                self._audit(conn, version["archive_id"], actor_id, "copy.create",
                            {"copy_id": copy_id, "version_id": version_id, "location": location, "media_id": media_id})
                return {"id": copy_id, "version_id": version_id, "location": location,
                        "storage_site": location, "media_id": media_id, "state": "healthy"}
            except sqlite3.IntegrityError as exc:
                conn.rollback()
                raise self._copy_conflict(exc)
            except Exception:
                conn.rollback()
                raise

    @staticmethod
    def _clean_media_id(media_id: object) -> str | None:
        if media_id is None:
            return None
        media_id = str(media_id).strip()
        if not media_id:
            return None
        if len(media_id) < 2 or len(media_id) > 64:
            raise BusinessError("介质编号长度需在 2-64 之间", 422, "invalid_media_id")
        return media_id

    @staticmethod
    def _copy_conflict(exc: sqlite3.IntegrityError) -> BusinessError:
        message = str(exc)
        if "idx_copies_media" in message or "media_id" in message:
            return BusinessError("介质编号已被其他副本登记", 409, "media_id_exists")
        return BusinessError("该版本的副本存放点已存在", 409, "copy_exists")

    def register_copy(self, actor_id: str, copy_id: int, media_id: str | None = None,
                      location: str | None = None) -> dict:
        """给已存在的副本补登介质编号，或更正存放点（已退役副本封存不可改）。"""
        media_id = self._clean_media_id(media_id)
        updates, params = [], []
        if location is not None:
            location = location.strip()
            if len(location) < 2:
                raise BusinessError("副本存放点不能为空", 422, "invalid_location")
            updates.append("location=?")
            params.append(location)
        with self.connect() as conn:
            actor = self._user(conn, actor_id, {"owner", "archivist"})
            copy = conn.execute("SELECT * FROM copies WHERE id=?", (copy_id,)).fetchone()
            if not copy:
                raise BusinessError("副本不存在", 404, "not_found")
            version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (copy["version_id"],)).fetchone()
            self._access(conn, version["archive_id"], actor, require_write=True)
            if copy["state"] == "retired":
                raise BusinessError("副本已退役封存，登记信息不可修改", 409, "copy_retired")
            if copy["state"] == "verifying":
                raise BusinessError("介质正在校验，完成前不可变更登记信息", 409, "copy_verifying")
            if media_id is not None:
                updates.append("media_id=?")
                params.append(media_id)
            if not updates:
                raise BusinessError("未提供需要登记的 media_id 或 storage_site", 422, "nothing_to_register")
            params.append(copy_id)
            try:
                conn.execute(f"UPDATE copies SET {','.join(updates)} WHERE id=?", params)
            except sqlite3.IntegrityError as exc:
                raise self._copy_conflict(exc)
            detail = {"copy_id": copy_id, "media_id": media_id, "location": location}
            self._audit(conn, version["archive_id"], actor_id, "copy.register", detail)
            row = conn.execute("SELECT * FROM copies WHERE id=?", (copy_id,)).fetchone()
            return {"id": copy_id, "version_id": copy["version_id"], "location": row["location"],
                    "storage_site": row["location"], "media_id": row["media_id"], "state": row["state"]}

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
            copies = []
            for c in conn.execute(
                "SELECT id,location,media_id,state,created_at,last_verified_at,verify_started_at FROM copies WHERE version_id=? ORDER BY id",
                (version_id,),
            ).fetchall():
                damage = conn.execute(
                    "SELECT id,corrupt_paths,found_at,repaired FROM copy_damage_reports WHERE copy_id=? ORDER BY id DESC LIMIT 1",
                    (c["id"],),
                ).fetchone()
                retirement = conn.execute(
                    "SELECT id,state,reasons,gaps,created_at FROM retirements WHERE copy_id=? ORDER BY id DESC LIMIT 1",
                    (c["id"],),
                ).fetchone()
                copies.append(
                    dict(c)
                    | {"storage_site": c["location"]}
                    | ({"latest_damage_report": {"id": damage["id"],
                                                 "corrupt_paths": json.loads(damage["corrupt_paths"]),
                                                 "found_at": damage["found_at"], "repaired": bool(damage["repaired"])}}
                       if damage else {"latest_damage_report": None})
                    | ({"latest_retirement": {"id": retirement["id"], "state": retirement["state"],
                                              "reasons": json.loads(retirement["reasons"]),
                                              "gaps": json.loads(retirement["gaps"]),
                                              "created_at": retirement["created_at"]}}
                       if retirement else {"latest_retirement": None})
                )
            archive = conn.execute("SELECT * FROM archives WHERE id=?", (version["archive_id"],)).fetchone()
            return {"version": dict(version), "archive": dict(archive),
                    "files": [dict(x) for x in files], "copies": copies}

    def start_verification(self, user_id: str, copy_id: int) -> dict:
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist", "auditor"})
            try:
                conn.execute("BEGIN IMMEDIATE")
                copy = conn.execute("SELECT * FROM copies WHERE id=?", (copy_id,)).fetchone()
                if not copy:
                    raise BusinessError("副本不存在", 404, "not_found")
                version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (copy["version_id"],)).fetchone()
                self._access(conn, version["archive_id"], user)
                if copy["state"] == "retired":
                    raise BusinessError("副本已退役封存，无需校验", 409, "copy_retired")
                if copy["state"] == "verifying":
                    raise BusinessError("介质正在校验中", 409, "copy_verifying")
                started = now()
                conn.execute("UPDATE copies SET state='verifying',verify_started_at=? WHERE id=?", (started, copy_id))
                self._audit(conn, version["archive_id"], user_id, "copy.verify_start",
                            {"copy_id": copy_id, "started_at": started})
                return {"copy_id": copy_id, "state": "verifying", "started_at": started}
            except Exception:
                conn.rollback()
                raise

    def _run_verification(self, conn: sqlite3.Connection, user: sqlite3.Row, copy: sqlite3.Row) -> dict:
        """逐文件比对哈希与大小；发现损坏先留损坏清单，再尝试从异点健康副本修复。"""
        copy_id = copy["id"]
        version_id = copy["version_id"]
        version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (version_id,)).fetchone()
        stored = conn.execute(
            "SELECT path,sha256,size,content FROM copy_files WHERE copy_id=? ORDER BY path", (copy_id,)
        ).fetchall()
        corrupt_paths = [
            r["path"] for r in stored
            if digest(r["content"]) != r["sha256"] or len(r["content"]) != r["size"]
        ]
        report_id = None
        repaired = False
        if not corrupt_paths:
            conn.execute(
                "UPDATE copies SET state='healthy',last_verified_at=?,verify_started_at=NULL WHERE id=?",
                (now(), copy_id),
            )
            result_state = "healthy"
        else:
            conn.execute("UPDATE copies SET state='corrupt',last_verified_at=? WHERE id=?", (now(), copy_id))
            healthy = conn.execute(
                "SELECT id,location FROM copies WHERE version_id=? AND id<>? AND state='healthy' ORDER BY last_verified_at DESC LIMIT 1",
                (version_id, copy_id),
            ).fetchone()
            result_state = "degraded"
            if healthy:
                donor = conn.execute(
                    "SELECT path,sha256,size,content FROM copy_files WHERE copy_id=? ORDER BY path", (healthy["id"],)
                ).fetchall()
                donor_by_path = {r["path"]: r for r in donor}
                expected = {r["path"]: r for r in conn.execute(
                    "SELECT path,sha256,size FROM archive_files WHERE version_id=?", (version_id,)
                ).fetchall()}
                if set(donor_by_path) == set(expected) and all(
                    digest(donor_by_path[p]["content"]) == expected[p]["sha256"] for p in expected
                ):
                    conn.execute("DELETE FROM copy_files WHERE copy_id=?", (copy_id,))
                    conn.execute(
                        """INSERT INTO copy_files(copy_id,path,sha256,size,content)
                           SELECT ?,path,sha256,size,content FROM copy_files WHERE copy_id=?""",
                        (copy_id, healthy["id"]),
                    )
                    conn.execute(
                        "UPDATE copies SET state='healthy',last_verified_at=?,verify_started_at=NULL WHERE id=?",
                        (now(), copy_id),
                    )
                    repaired, result_state = True, "healthy"
            # 先留下损坏清单，再决定修复结果；清单永久保留
            cur = conn.execute(
                """INSERT INTO copy_damage_reports(copy_id,version_id,corrupt_paths,found_at,repaired,actor_id)
                   VALUES(?,?,?,?,?,?)""",
                (copy_id, version_id, json.dumps(corrupt_paths, ensure_ascii=False), now(), int(repaired), user["id"]),
            )
            report_id = cur.lastrowid
            if result_state == "degraded":
                conn.execute(
                    "UPDATE archive_versions SET state='degraded' WHERE id=?", (version_id,))
            conn.execute("UPDATE copies SET verify_started_at=NULL WHERE id=?", (copy_id,))
        self._audit(
            conn, version["archive_id"], user["id"], "copy.verify",
            {"copy_id": copy_id, "state": result_state, "corrupt_paths": corrupt_paths,
             "repaired": repaired, "damage_report_id": report_id},
        )
        return {"copy_id": copy_id, "state": result_state, "corrupt_paths": corrupt_paths,
                "repaired": repaired, "damage_report_id": report_id}

    def complete_verification(self, user_id: str, copy_id: int) -> dict:
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist", "auditor"})
            try:
                conn.execute("BEGIN IMMEDIATE")
                copy = conn.execute("SELECT * FROM copies WHERE id=?", (copy_id,)).fetchone()
                if not copy:
                    raise BusinessError("副本不存在", 404, "not_found")
                if copy["state"] == "retired":
                    raise BusinessError("副本已退役封存，无法完成校验", 409, "copy_retired")
                if copy["state"] != "verifying":
                    raise BusinessError("该副本不在校验中，需先开始校验", 409, "not_verifying")
                result = self._run_verification(conn, user, copy)
                return result
            except Exception:
                conn.rollback()
                raise

    def verify_copy(self, user_id: str, copy_id: int) -> dict:
        """原子校验入口：开始校验后立即完成，供批处理/兼容既有流程使用。"""
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist", "auditor"})
            try:
                conn.execute("BEGIN IMMEDIATE")
                copy = conn.execute("SELECT * FROM copies WHERE id=?", (copy_id,)).fetchone()
                if not copy:
                    raise BusinessError("副本不存在", 404, "not_found")
                version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (copy["version_id"],)).fetchone()
                self._access(conn, version["archive_id"], user)
                if copy["state"] == "retired":
                    raise BusinessError("副本已退役封存，无法校验", 409, "copy_retired")
                if copy["state"] == "verifying":
                    raise BusinessError("介质正在校验中，请先完成本次校验", 409, "copy_verifying")
                conn.execute("UPDATE copies SET state='verifying',verify_started_at=? WHERE id=?", (now(), copy_id))
                copy = conn.execute("SELECT * FROM copies WHERE id=?", (copy_id,)).fetchone()
                return self._run_verification(conn, user, copy)
            except Exception:
                conn.rollback()
                raise

    def simulate_corruption(self, user_id: str, copy_id: int, path: str) -> dict:
        """仅用于演示和测试，在受控环境中模拟底层介质损坏。"""
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist"})
            copy = conn.execute("SELECT * FROM copies WHERE id=?", (copy_id,)).fetchone()
            if not copy:
                raise BusinessError("副本不存在", 404, "not_found")
            version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (copy["version_id"],)).fetchone()
            self._access(conn, version["archive_id"], user, require_write=True)
            if copy["state"] == "retired":
                raise BusinessError("副本已退役封存", 409, "copy_retired")
            if copy["state"] == "verifying":
                raise BusinessError("介质正在校验中", 409, "copy_verifying")
            row = conn.execute("SELECT content FROM copy_files WHERE copy_id=? AND path=?", (copy_id, path)).fetchone()
            if not row:
                raise BusinessError("副本文件不存在", 404, "not_found")
            damaged = bytes([row["content"][0] ^ 0xFF]) + row["content"][1:] if row["content"] else b"corrupt"
            conn.execute("UPDATE copy_files SET content=? WHERE copy_id=? AND path=?", (damaged, copy_id, path))
            conn.execute("UPDATE copies SET state='corrupt' WHERE id=?", (copy_id,))
            self._audit(conn, version["archive_id"], user_id, "copy.simulate_corruption", {"copy_id": copy_id, "path": path})
            return {"copy_id": copy_id, "path": path, "state": "corrupt"}

    def damage_reports(self, user_id: str, copy_id: int) -> dict:
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist", "auditor"})
            copy = conn.execute("SELECT * FROM copies WHERE id=?", (copy_id,)).fetchone()
            if not copy:
                raise BusinessError("副本不存在", 404, "not_found")
            version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (copy["version_id"],)).fetchone()
            self._access(conn, version["archive_id"], user)
            rows = conn.execute(
                "SELECT id,copy_id,corrupt_paths,found_at,repaired,actor_id FROM copy_damage_reports WHERE copy_id=? ORDER BY id",
                (copy_id,),
            ).fetchall()
            return {"copy_id": copy_id,
                    "reports": [dict(r) | {"corrupt_paths": json.loads(r["corrupt_paths"]), "repaired": bool(r["repaired"])}
                                for r in rows]}

    def submit_retirement(self, user_id: str, copy_id: int) -> dict:
        """提交介质退役：登记校验 → 健康校验 → 逐文件确认异点健康副本，缺口列出并拦截。"""
        with self.connect() as conn:
            actor = self._user(conn, user_id, {"owner", "archivist"})
            copy = conn.execute("SELECT * FROM copies WHERE id=?", (copy_id,)).fetchone()
            if not copy:
                raise BusinessError("副本不存在", 404, "not_found")
            version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (copy["version_id"],)).fetchone()
            self._access(conn, version["archive_id"], actor, require_write=True)
            reasons: list[str] = []
            gaps: list[dict] = []
            committed = False

            def record(state: str) -> dict:
                nonlocal committed
                unique_reasons = list(dict.fromkeys(reasons))
                cur = conn.execute(
                    "INSERT INTO retirements(copy_id,version_id,state,reasons,gaps,submitted_by,created_at) VALUES(?,?,?,?,?,?,?)",
                    (copy_id, version["id"], state,
                     json.dumps(unique_reasons, ensure_ascii=False), json.dumps(gaps, ensure_ascii=False),
                     user_id, now()),
                )
                conn.commit()
                committed = True
                return {"id": cur.lastrowid, "copy_id": copy_id, "version_id": version["id"], "state": state,
                        "reasons": unique_reasons, "gaps": gaps}

            if copy["state"] == "retired":
                raise BusinessError("副本已退役封存", 409, "copy_retired")
            # 介质正在校验时不能批准
            if copy["state"] == "verifying":
                reasons.append("copy_verifying")
                gaps.append({"type": "copy_verifying", "copy_id": copy_id,
                             "message": "介质正在校验中，校验完成前不得批准退役",
                             "verify_started_at": copy["verify_started_at"]})
                result = record("blocked")
                self._audit(conn, version["archive_id"], user_id, "media.retire_blocked",
                            {"copy_id": copy_id, "reasons": reasons, "retirement_id": result["id"]})
                conn.commit()
                raise BusinessError("介质正在校验，退役请求已拦截", 409, "retirement_blocked", result)
            # 介质编号与存放点登记
            if not copy["media_id"]:
                reasons.append("media_not_registered")
                gaps.append({"type": "media_not_registered", "copy_id": copy_id,
                             "message": "该副本尚未登记介质编号，无法追溯下线介质"})
            if not copy["location"]:
                reasons.append("storage_site_missing")
                gaps.append({"type": "storage_site_missing", "copy_id": copy_id,
                             "message": "该副本缺少存放点"})
            # 损坏副本必须先留下损坏清单；仍未恢复健康同样拦截
            own_paths = {r["path"]: r for r in conn.execute(
                "SELECT path,sha256,size,content FROM copy_files WHERE copy_id=?", (copy_id,)).fetchall()}
            expected = {r["path"]: r for r in conn.execute(
                "SELECT path,sha256,size FROM archive_files WHERE version_id=?", (version["id"],)).fetchall()}
            own_bad = [
                p for p in expected
                if p not in own_paths
                or digest(own_paths[p]["content"]) != expected[p]["sha256"]
                or len(own_paths[p]["content"]) != expected[p]["size"]
            ]
            if own_bad:
                report = conn.execute(
                    "SELECT id FROM copy_damage_reports WHERE copy_id=? ORDER BY id DESC LIMIT 1", (copy_id,)
                ).fetchone()
                if not report:
                    reasons.append("damage_report_missing")
                    gaps.append({"type": "damage_report_missing", "copy_id": copy_id, "paths": own_bad,
                                 "message": "副本已损坏且没有损坏清单，需先完成校验登记损坏文件"})
                reasons.append("copy_not_healthy")
                gaps.append({"type": "copy_not_healthy", "copy_id": copy_id, "paths": own_bad,
                             "message": "损坏副本须先修复并通过校验，才能停用撤走"})
            elif copy["state"] in {"corrupt", "degraded"}:
                reasons.append("copy_not_healthy")
                gaps.append({"type": "copy_not_healthy", "copy_id": copy_id,
                             "message": f"副本状态为 {copy['state']}，须先通过校验"})
            # 逐份核对：每个文件都要有另一个健康且不同存放点的副本
            peers = conn.execute(
                "SELECT id,location,media_id,state,last_verified_at FROM copies WHERE version_id=? AND id<>? ORDER BY id",
                (version["id"], copy_id),
            ).fetchall()
            peer_files = {p["id"]: {r["path"]: r for r in conn.execute(
                "SELECT path,sha256,size,content FROM copy_files WHERE copy_id=?", (p["id"],)).fetchall()}
                for p in peers}
            for path in sorted(expected):
                candidates = []
                for p in peers:
                    if p["state"] != "healthy" or p["location"] == copy["location"]:
                        continue
                    row = peer_files[p["id"]].get(path)
                    if row and digest(row["content"]) == expected[path]["sha256"] \
                            and len(row["content"]) == expected[path]["size"]:
                        candidates.append({"copy_id": p["id"], "location": p["location"],
                                           "storage_site": p["location"], "media_id": p["media_id"],
                                           "last_verified_at": p["last_verified_at"]})
                if not candidates:
                    reasons.append("no_other_healthy_copy")
                    if not peers:
                        detail = "该版本没有任何其他副本"
                    elif not any(p["location"] != copy["location"] for p in peers):
                        detail = "其他副本与待退役介质在同一存放点"
                    elif not any(p["state"] == "healthy" for p in peers):
                        detail = "其他副本均不处于健康状态"
                    else:
                        detail = "异点健康副本缺少该文件或哈希不一致"
                    gaps.append({"type": "no_other_healthy_copy", "path": path,
                                 "sha256": expected[path]["sha256"], "size": expected[path]["size"],
                                 "current_site": copy["location"], "detail": detail,
                                 "available_copies": [{"copy_id": p["id"], "location": p["location"],
                                                       "state": p["state"]} for p in peers]})
                else:
                    gaps.append({"type": "redundancy_ok", "path": path, "replicas": candidates})
            if reasons:
                result = record("blocked")
                self._audit(conn, version["archive_id"], user_id, "media.retire_blocked",
                            {"copy_id": copy_id, "reasons": reasons, "gap_count": sum(1 for g in gaps if g["type"] == "no_other_healthy_copy"),
                             "retirement_id": result["id"]})
                conn.commit()
                raise BusinessError("退役核对未通过，存在副本缺口", 409, "retirement_blocked", result)
            result = record("retired")
            conn.execute("UPDATE copies SET state='retired' WHERE id=?", (copy_id,))
            self._audit(conn, version["archive_id"], user_id, "media.retired",
                        {"copy_id": copy_id, "media_id": copy["media_id"], "location": copy["location"],
                         "file_count": len(expected), "retirement_id": result["id"]})
            conn.commit()
            return result

    def list_retirements(self, user_id: str, copy_id: int | None = None) -> dict:
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist", "auditor"})
            if copy_id is not None:
                copy = conn.execute("SELECT * FROM copies WHERE id=?", (copy_id,)).fetchone()
                if not copy:
                    raise BusinessError("副本不存在", 404, "not_found")
                version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (copy["version_id"],)).fetchone()
                self._access(conn, version["archive_id"], user)
                rows = conn.execute("SELECT * FROM retirements WHERE copy_id=? ORDER BY id", (copy_id,)).fetchall()
            else:
                self._user(conn, user_id, {"owner", "archivist", "auditor"})
                rows = conn.execute("SELECT * FROM retirements ORDER BY id DESC LIMIT 100").fetchall()
            items = []
            for r in rows:
                d = dict(r)
                d["reasons"] = json.loads(d["reasons"])
                d["gaps"] = json.loads(d["gaps"])
                items.append(d)
            return {"retirements": items}

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
        if len(parts) == 4 and parts[:2] == ["api", "versions"] and parts[3] == "copies" and method == "POST":
            d = self._body()
            return self._send(201, store.add_copy(user, int(parts[2]), d.get("location", d.get("storage_site", "")), d.get("media_id")))
        if len(parts) == 4 and parts[:2] == ["api", "versions"] and parts[3] == "migrate" and method == "POST":
            d = self._body()
            return self._send(201, store.migrate(user, int(parts[2]), d.get("source_path", ""), d.get("target_path", ""), d.get("target_format", ""), d.get("content_b64", "")))
        if len(parts) == 5 and parts[:2] == ["api", "copies"] and parts[3] == "register" and method == "POST":
            d = self._body()
            return self._send(200, store.register_copy(user, int(parts[2]), d.get("media_id"), d.get("storage_site", d.get("location"))))
        if len(parts) == 4 and parts[:2] == ["api", "copies"] and parts[3] == "verify" and method == "POST":
            return self._send(200, store.verify_copy(user, int(parts[2])))
        if len(parts) == 5 and parts[:2] == ["api", "copies"] and parts[3] == "verification" and method == "POST":
            action = parts[4]
            if action == "start":
                return self._send(202, store.start_verification(user, int(parts[2])))
            if action == "complete":
                return self._send(200, store.complete_verification(user, int(parts[2])))
        if len(parts) == 4 and parts[:2] == ["api", "copies"] and parts[3] == "damage-reports" and method == "GET":
            return self._send(200, store.damage_reports(user, int(parts[2])))
        if len(parts) == 4 and parts[:2] == ["api", "copies"] and parts[3] == "retire" and method == "POST":
            return self._send(200, store.submit_retirement(user, int(parts[2])))
        if len(parts) == 4 and parts[:2] == ["api", "copies"] and parts[3] == "retirements" and method == "GET":
            return self._send(200, store.list_retirements(user, int(parts[2])))
        if parts == ["api", "retirements"] and method == "GET":
            return self._send(200, store.list_retirements(user))
        if len(parts) == 4 and parts[:2] == ["api", "copies"] and parts[3] == "simulate-corruption" and method == "POST":
            d = self._body()
            return self._send(200, store.simulate_corruption(user, int(parts[2]), d.get("path", "")))
        raise BusinessError("接口不存在", 404, "not_found")

    def _handle(self, method: str) -> None:
        try:
            self._dispatch(method)
        except BusinessError as exc:
            payload = {"error": {"code": exc.code, "message": exc.message}}
            if exc.payload:
                payload["error"]["details"] = exc.payload
            self._send(exc.status, payload)
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
