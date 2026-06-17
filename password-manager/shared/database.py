# -*- coding: utf-8 -*-
"""
密码管理器 - 数据库模块 (Web版 v2)
==================================
新增: 密码分类、密码历史、安全审计、导入导出、自动迁移
"""

import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent / "passwords.db"

# 预定义的密码分类
CATEGORIES = ['社交', '邮箱', '金融', '购物', '工作', '学习', '娱乐', '其他']

# 当前数据库 schema 版本
SCHEMA_VERSION = 2


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


# ============================================================
# 数据库初始化 + 自动迁移
# ============================================================

def init_db():
    """初始化数据库并运行迁移。"""
    conn = get_connection()
    cursor = conn.cursor()

    # v1 基础表
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS entries (
            id                 INTEGER PRIMARY KEY AUTOINCREMENT,
            website            TEXT    NOT NULL,
            username           TEXT    NOT NULL,
            encrypted_password TEXT    NOT NULL,
            notes              TEXT    DEFAULT '',
            category           TEXT    DEFAULT '其他',
            strength_score     INTEGER DEFAULT 0,
            created_at         TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at         TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

    # 自动迁移
    migrate()


def migrate():
    """自动检测并执行 schema 迁移。"""
    version_str = get_setting('db_schema_version')
    current = int(version_str) if version_str else 1

    if current < 2:
        _migrate_v2()
        set_setting('db_schema_version', str(SCHEMA_VERSION))


def _migrate_v2():
    """v2 迁移：添加分类、强度评分、密码历史表、索引。"""
    conn = get_connection()
    cursor = conn.cursor()

    # 添加 category 列
    for col, dtype in [('category', "TEXT DEFAULT '其他'"),
                       ('strength_score', 'INTEGER DEFAULT 0')]:
        try:
            cursor.execute(f"ALTER TABLE entries ADD COLUMN {col} {dtype}")
        except sqlite3.OperationalError:
            pass  # 列已存在

    # 密码历史表
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS password_history (
            id                 INTEGER PRIMARY KEY AUTOINCREMENT,
            entry_id           INTEGER NOT NULL,
            encrypted_password TEXT    NOT NULL,
            changed_at         TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (entry_id) REFERENCES entries(id) ON DELETE CASCADE
        )
    """)

    # 索引
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_entries_category ON entries(category)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_history_entry ON password_history(entry_id)")

    conn.commit()
    conn.close()


# ============================================================
# 设置操作
# ============================================================

def get_setting(key: str) -> str | None:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT value FROM settings WHERE key = ?", (key,))
    row = cursor.fetchone()
    conn.close()
    return row["value"] if row else None


def set_setting(key: str, value: str):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))
    conn.commit()
    conn.close()


def is_first_run() -> bool:
    return get_setting("salt") is None


# ============================================================
# 密码条目 CRUD（增强版）
# ============================================================

def add_entry(website: str, username: str, encrypted_password: str,
              notes: str = "", category: str = "其他",
              strength_score: int = 0) -> int:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """INSERT INTO entries (website, username, encrypted_password, notes, category, strength_score)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (website, username, encrypted_password, notes, category, strength_score),
    )
    conn.commit()
    entry_id = cursor.lastrowid
    conn.close()
    return entry_id


def get_all_entries(category: str | None = None) -> list[dict]:
    conn = get_connection()
    cursor = conn.cursor()
    if category and category != '全部':
        cursor.execute(
            """SELECT id, website, username, notes, category, strength_score, created_at, updated_at
               FROM entries WHERE category = ? ORDER BY website""", (category,))
    else:
        cursor.execute(
            """SELECT id, website, username, notes, category, strength_score, created_at, updated_at
               FROM entries ORDER BY website""")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def search_entries(query: str, category: str | None = None) -> list[dict]:
    conn = get_connection()
    cursor = conn.cursor()
    like = f"%{query}%"
    if category and category != '全部':
        cursor.execute(
            """SELECT id, website, username, notes, category, strength_score, created_at, updated_at
               FROM entries
               WHERE (website LIKE ? OR username LIKE ? OR notes LIKE ?)
                 AND category = ?
               ORDER BY website""",
            (like, like, like, category))
    else:
        cursor.execute(
            """SELECT id, website, username, notes, category, strength_score, created_at, updated_at
               FROM entries
               WHERE website LIKE ? OR username LIKE ? OR notes LIKE ?
               ORDER BY website""",
            (like, like, like))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_entry(entry_id: int) -> dict | None:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM entries WHERE id = ?", (entry_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def get_encrypted_password(entry_id: int) -> str | None:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT encrypted_password FROM entries WHERE id = ?", (entry_id,))
    row = cursor.fetchone()
    conn.close()
    return row["encrypted_password"] if row else None


def update_entry(entry_id: int, website: str, username: str,
                 encrypted_password: str, notes: str,
                 category: str = "其他", strength_score: int = 0):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """UPDATE entries
           SET website = ?, username = ?, encrypted_password = ?,
               notes = ?, category = ?, strength_score = ?, updated_at = CURRENT_TIMESTAMP
           WHERE id = ?""",
        (website, username, encrypted_password, notes, category, strength_score, entry_id),
    )
    conn.commit()
    conn.close()


def delete_entry(entry_id: int):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM entries WHERE id = ?", (entry_id,))
    conn.commit()
    conn.close()


# ============================================================
# 密码历史
# ============================================================

def add_password_history(entry_id: int, encrypted_password: str):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO password_history (entry_id, encrypted_password) VALUES (?, ?)",
        (entry_id, encrypted_password))
    conn.commit()
    conn.close()


def get_password_history(entry_id: int) -> list[dict]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """SELECT id, encrypted_password, changed_at
           FROM password_history
           WHERE entry_id = ?
           ORDER BY changed_at DESC
           LIMIT 10""", (entry_id,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


# ============================================================
# 分类统计
# ============================================================

def get_category_stats() -> list[dict]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT category, COUNT(*) as count FROM entries GROUP BY category ORDER BY count DESC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


# ============================================================
# 安全审计（需配合解密层）
# ============================================================

def get_all_encrypted_passwords_with_meta() -> list[dict]:
    """返回包含加密密码和元数据的完整列表，供审计使用。"""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, website, username, encrypted_password, strength_score, updated_at FROM entries")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


# ============================================================
# 导入导出
# ============================================================

def export_all_entries() -> list[dict]:
    """导出所有条目（含加密密码）用于备份。"""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM entries ORDER BY website")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_stats() -> dict:
    """获取整体统计信息。"""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM entries")
    total = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(DISTINCT category) FROM entries")
    cat_count = cursor.fetchone()[0]
    conn.close()
    return {'total_entries': total, 'total_categories': cat_count}
