#!/usr/bin/env python3
import hashlib
import os
import sqlite3
import sys

# Фиксируем путь к БД в папке скрипта
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, "sip_users.db")
DEFAULT_REALM = "sip.local"


def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            ha1 TEXT NOT NULL,
            realm TEXT NOT NULL,
            type TEXT DEFAULT 'normal',
            audio_file TEXT
        )
        """
    )
    # Автоматическая миграция схемы, если таблица уже создавалась ранее
    for col, col_type in [("type", "TEXT DEFAULT 'normal'"), ("audio_file", "TEXT")]:
        try:
            conn.execute(f"ALTER TABLE users ADD COLUMN {col} {col_type}")
        except sqlite3.OperationalError:
            pass
    return conn


def calculate_ha1(username: str, realm: str, password: str) -> str:
    raw = f"{username}:{realm}:{password}"
    return hashlib.md5(raw.encode("utf-8")).hexdigest()


def add_user(username: str, password: str, acc_type: str = "normal", audio_file: str = "welcome.wav"):
    acc_type = acc_type.lower()
    if acc_type not in ("normal", "prerecorded"):
        print("[-] Ошибка: тип аккаунта должен быть 'normal' или 'prerecorded'")
        return

    ha1 = calculate_ha1(username, DEFAULT_REALM, password)
    conn = get_db()
    with conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO users (username, ha1, realm, type, audio_file)
            VALUES (?, ?, ?, ?, ?)
            """,
            (username, ha1, DEFAULT_REALM, acc_type, audio_file if acc_type == "prerecorded" else None),
        )
    print(f"[+] Пользователь '{username}' сохранен.")
    print(f"    Тип: {acc_type}")
    if acc_type == "prerecorded":
        print(f"    Аудиофайл: {audio_file}")


def list_users():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT username, type, audio_file FROM users")
    rows = cursor.fetchall()
    conn.close()

    if not rows:
        print("В базе нет пользователей.")
        return

    print(f"\n{'Номер (Ext)':<15} {'Тип аккаунта':<15} {'Файл автоответчика':<25}")
    print("=" * 55)
    for u, t, f in rows:
        print(f"{u:<15} {t:<15} {str(f or '-'):<25}")
    print()


def delete_user(username: str):
    conn = get_db()
    with conn:
        cursor = conn.execute("DELETE FROM users WHERE username = ?", (username,))
        if cursor.rowcount > 0:
            print(f"[+] Пользователь '{username}' удален.")
        else:
            print(f"[-] Пользователь '{username}' не найден.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Использование:")
        print("  Обычный софтфон:")
        print("    python manage_users.py add <номер> <пароль> normal")
        print("  Автоответчик с аудиофайлом:")
        print("    python manage_users.py add <номер> <пароль> prerecorded [аудиофайл.wav]")
        print("  Список абонентов:")
        print("    python manage_users.py list")
        print("  Удаление абонента:")
        print("    python manage_users.py del <номер>")
        sys.exit(1)

    cmd = sys.argv[1].lower()

    if cmd == "add" and len(sys.argv) >= 4:
        ext = sys.argv[2]
        pwd = sys.argv[3]
        acc_type = sys.argv[4] if len(sys.argv) > 4 else "normal"
        audio = sys.argv[5] if len(sys.argv) > 5 else "welcome.wav"
        add_user(ext, pwd, acc_type, audio)
    elif cmd == "list":
        list_users()
    elif cmd == "del" and len(sys.argv) >= 3:
        delete_user(sys.argv[2])
    else:
        print("Неверные параметры. Запустите без аргументов для справки.")