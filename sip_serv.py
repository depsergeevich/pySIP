import hashlib
import json
import math
import os
import re
import secrets
import socket
import socketserver
import sqlite3
import struct
import subprocess
import threading
import time
import wave
from werkzeug.utils import secure_filename
from flask import Flask, jsonify, request, send_from_directory, render_template_string

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, "sip_users.db")
REALM = "sip.local"

# Публичный IP вашего VPS сервера
PUBLIC_IP = "2.26.61.185"

# Порт веб-панели управления
WEB_PORT = 8080

# Дефолтный сервисный номер IVR
IVR_NUMBER = "7777"

# Номер дежурного оператора при невыборе пункта в IVR
IVR_DEFAULT_EXT = "1001"

# ---------------------------------------------------------------------
# НАСТРОЙКИ ВРЕМЕНИ ОЖИДАНИЯ
# ---------------------------------------------------------------------
# 1. Время паузы в IVR (сколько секунд ждать нажатия кнопки перед автопереводом)
IVR_TIMEOUT_SEC = 5.0

# 2. Время дозвона до оператора под музыку (сколько секунд звонить софтфону оператора)
OPERATOR_RING_TIMEOUT = 25.0
# ---------------------------------------------------------------------

REGISTRY = {}   # {"1001": ("ip", port, last_seen_time)}
CALLS = {}      # {call_id: dict_info}


# =====================================================================
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ СЕТИ И ЗВУКА
# =====================================================================

def is_private_ip(ip: str) -> bool:
    if not ip or ip.startswith(("10.", "192.168.", "127.")):
        return True
    if ip.startswith("172."):
        parts = ip.split(".")
        if len(parts) >= 2 and 16 <= int(parts[1]) <= 31:
            return True
    if ip.startswith("100."):
        parts = ip.split(".")
        if len(parts) >= 2 and 64 <= int(parts[1]) <= 127:
            return True
    return False


def get_local_ip(target_ip=None):
    if not target_ip or target_ip == "127.0.0.1":
        return "127.0.0.1"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((target_ip, 5060))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def extract_clean_uri(header_val: str) -> str:
    if not header_val:
        return ""
    match = re.search(r"(sip:[^>;\s]+)", header_val)
    return match.group(1) if match else ""


def linear_to_ulaw(pcm_val: int) -> int:
    BIAS = 0x84
    CLIP = 32635
    sign = 0x80 if pcm_val < 0 else 0
    if pcm_val < 0:
        pcm_val = -pcm_val
    if pcm_val > CLIP:
        pcm_val = CLIP
    pcm_val += BIAS
    exp = 7
    for e in range(7, -1, -1):
        if pcm_val & (1 << (e + 7)):
            exp = e
            break
    mantissa = (pcm_val >> (exp + 3)) & 0x0F
    return ~(sign | (exp << 4) | mantissa) & 0xFF


def linear_to_alaw(pcm_val: int) -> int:
    sign = 0x80 if pcm_val >= 0 else 0
    if pcm_val < 0:
        pcm_val = -pcm_val
    if pcm_val > 32767:
        pcm_val = 32767
    if pcm_val >= 256:
        exp = 7
        for e in range(7, 0, -1):
            if pcm_val & (1 << (e + 7)):
                exp = e
                break
        mantissa = (pcm_val >> (exp + 3)) & 0x0F
        alaw = (exp << 4) | mantissa
    else:
        alaw = pcm_val >> 4
    return (alaw ^ 0xD5) if sign else ((alaw | 0x80) ^ 0xD5)


def convert_audio_to_pcm(audio_path: str, codec_type: str = "PCMU") -> str:
    ext = ".pcmu" if codec_type == "PCMU" else ".pcma"
    pcm_path = audio_path + ext

    if os.path.exists(pcm_path) and os.path.getmtime(pcm_path) >= os.path.getmtime(audio_path):
        return pcm_path

    try:
        raw_temp = pcm_path + ".raw"
        res = subprocess.run(
            ["ffmpeg", "-y", "-i", audio_path, "-ar", "8000", "-ac", "1", "-f", "s16le", raw_temp],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        if res.returncode == 0 and os.path.exists(raw_temp):
            with open(raw_temp, "rb") as rf:
                raw_16 = rf.read()
            os.remove(raw_temp)

            encoded = bytearray()
            samples = struct.unpack(f"<{len(raw_16)//2}h", raw_16)
            for s in samples:
                encoded.append(linear_to_ulaw(s) if codec_type == "PCMU" else linear_to_alaw(s))

            with open(pcm_path, "wb") as f:
                f.write(encoded)
            return pcm_path
    except FileNotFoundError:
        pass

    with wave.open(audio_path, "rb") as wf:
        n_channels = wf.getnchannels()
        sampwidth = wf.getsampwidth()
        framerate = wf.getframerate()
        raw_frames = wf.readframes(wf.getnframes())

    total_frames = len(raw_frames) // (sampwidth * n_channels)
    samples = []
    if sampwidth == 2:
        for i in range(total_frames):
            offset = i * n_channels * 2
            samples.append(struct.unpack_from("<h", raw_frames, offset)[0])
    elif sampwidth == 1:
        for i in range(total_frames):
            offset = i * n_channels
            b = raw_frames[offset]
            samples.append((b - 128) * 256)
    else:
        samples = [0] * total_frames

    if framerate != 8000 and total_frames > 0:
        ratio = 8000.0 / framerate
        new_len = int(total_frames * ratio)
        resampled = []
        for i in range(new_len):
            orig_idx = int(i / ratio)
            if orig_idx < len(samples):
                resampled.append(samples[orig_idx])
        samples = resampled

    encoded = bytearray()
    for s in samples:
        encoded.append(linear_to_ulaw(s) if codec_type == "PCMU" else linear_to_alaw(s))

    with open(pcm_path, "wb") as f:
        f.write(encoded)

    return pcm_path


def generate_synth_wav(filepath: str, melody_type: str = "ivr"):
    if os.path.exists(filepath):
        return
    sample_rate = 8000
    raw_samples = bytearray()
    if melody_type == "ivr":
        notes = [523.25, 659.25, 783.99, 1046.50]
        for note in notes:
            for i in range(int(sample_rate * 0.3)):
                s = int(8000 * math.sin(2 * math.pi * note * (i / sample_rate)))
                raw_samples.extend(struct.pack("<h", s))
    else:
        chords = [440.0, 554.37, 659.25, 880.0]
        for c in chords:
            for i in range(int(sample_rate * 0.4)):
                s = int(6000 * math.sin(2 * math.pi * c * (i / sample_rate)))
                raw_samples.extend(struct.pack("<h", s))

    with wave.open(filepath, "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(sample_rate)
        wf.writeframes(raw_samples)


# =====================================================================
# РАБОТА С БАЗОЙ ДАННЫХ SQLITE
# =====================================================================

def init_db():
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
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS ivr_routes (
            digit INTEGER PRIMARY KEY,
            target_ext TEXT NOT NULL,
            description TEXT
        )
        """
    )
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM ivr_routes")
    if cur.fetchone()[0] == 0:
        conn.execute("INSERT INTO ivr_routes (digit, target_ext, description) VALUES (1, '1001', 'Администрация')")
        conn.execute("INSERT INTO ivr_routes (digit, target_ext, description) VALUES (2, '1002', 'Техподдержка')")

    conn.commit()
    conn.close()


def get_user_record(username: str):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT ha1, type, audio_file FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return {"ha1": row[0], "type": row[1] or "normal", "audio_file": row[2] or "welcome.wav"}
    return None


def get_all_users():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT username, type, audio_file FROM users ORDER BY username ASC")
    rows = cursor.fetchall()
    conn.close()
    result = []
    for u, t, f in rows:
        is_online = u in REGISTRY
        addr = f"{REGISTRY[u][0]}:{REGISTRY[u][1]}" if is_online else "-"
        result.append({"username": u, "type": t, "audio_file": f or "-", "online": is_online, "address": addr})
    return result


def add_or_update_user(username, password, acc_type="normal", audio_file="welcome.wav"):
    raw = f"{username}:{REALM}:{password}"
    ha1 = hashlib.md5(raw.encode("utf-8")).hexdigest()
    conn = sqlite3.connect(DB_FILE)
    with conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO users (username, ha1, realm, type, audio_file)
            VALUES (?, ?, ?, ?, ?)
            """,
            (username, ha1, REALM, acc_type, audio_file if acc_type == "prerecorded" else None)
        )
    conn.close()


def delete_user_from_db(username):
    conn = sqlite3.connect(DB_FILE)
    with conn:
        conn.execute("DELETE FROM users WHERE username = ?", (username,))
    conn.close()
    REGISTRY.pop(username, None)


def get_ivr_routes_from_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT digit, target_ext, description FROM ivr_routes ORDER BY digit ASC")
    rows = cursor.fetchall()
    conn.close()
    return {row[0]: {"target": row[1], "desc": row[2] or ""} for row in rows}


def set_ivr_route_db(digit, target_ext, description=""):
    conn = sqlite3.connect(DB_FILE)
    with conn:
        conn.execute(
            "INSERT OR REPLACE INTO ivr_routes (digit, target_ext, description) VALUES (?, ?, ?)",
            (digit, target_ext, description)
        )
    conn.close()


def delete_ivr_route_db(digit):
    conn = sqlite3.connect(DB_FILE)
    with conn:
        conn.execute("DELETE FROM ivr_routes WHERE digit = ?", (digit,))
    conn.close()


# =====================================================================
# СИГНАЛЬНЫЙ ПАРСИНГ SIP
# =====================================================================

def parse_sdp(sdp_text: str):
    rtp_ip = None
    rtp_port = None
    preferred_codec = 0
    for line in sdp_text.splitlines():
        line = line.strip()
        if line.startswith("c=IN IP4"):
            parts = line.split()
            if len(parts) >= 3:
                rtp_ip = parts[2]
        elif line.startswith("m=audio"):
            parts = line.split()
            if len(parts) >= 2:
                try:
                    rtp_port = int(parts[1])
                except ValueError:
                    pass
            if len(parts) >= 4:
                codecs = parts[3:]
                if "8" in codecs and (codecs.index("8") < codecs.index("0") if "0" in codecs else True):
                    preferred_codec = 8
                elif "0" in codecs:
                    preferred_codec = 0
    return rtp_ip, rtp_port, preferred_codec


def parse_sip_message(raw_data: str):
    parts = raw_data.split("\r\n\r\n", 1)
    header_section = parts[0]
    body = parts[1] if len(parts) > 1 else ""
    lines = header_section.split("\r\n")
    start_line = lines[0]
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().title()] = v.strip()
    return start_line, headers, body


def parse_auth_header(auth_header: str):
    if not auth_header.startswith("Digest "):
        return {}
    content = auth_header[7:]
    pattern = r'(\w+)=(?:"([^"]*)"|([^,\s]*))'
    return {k: (v1 or v2) for k, v1, v2 in re.findall(pattern, content)}


def verify_digest(method: str, auth_params: dict) -> bool:
    username = auth_params.get("username")
    user = get_user_record(username)
    if not user:
        return False
    ha1 = user["ha1"]
    uri = auth_params.get("uri", "")
    nonce = auth_params.get("nonce", "")
    nc = auth_params.get("nc")
    cnonce = auth_params.get("cnonce")
    qop = auth_params.get("qop")
    client_response = auth_params.get("response", "")

    ha2 = hashlib.md5(f"{method}:{uri}".encode("utf-8")).hexdigest()
    if qop and qop.lower() == "auth":
        expected = hashlib.md5(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}".encode("utf-8")).hexdigest()
    else:
        expected = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode("utf-8")).hexdigest()
    return secrets.compare_digest(expected.lower(), client_response.lower())


def extract_user(uri_or_header: str):
    match = re.search(r"sip:([^@:;>]+)", uri_or_header)
    return match.group(1) if match else None


# =====================================================================
# ЯДРО SIP СЕРВЕРА (B2BUA + МЕДИА-МОСТ)
# =====================================================================

class SIPHandler(socketserver.BaseRequestHandler):

    def handle(self):
        raw_data = self.request[0].decode("utf-8", errors="ignore")
        sock = self.request[1]
        client_addr = self.client_address

        if not raw_data.strip():
            return

        start_line, headers, body = parse_sip_message(raw_data)
        call_id = headers.get("Call-Id")

        if start_line.startswith("SIP/2.0"):
            self.handle_response(raw_data, start_line, headers, body, call_id, sock, client_addr)
        else:
            self.handle_request(raw_data, start_line, headers, body, call_id, sock, client_addr)

    def handle_request(self, raw_data, start_line, headers, body, call_id, sock, client_addr):
        method = start_line.split()[0].upper()

        if method == "REGISTER":
            self.process_register(method, headers, sock, client_addr)
        elif method == "INVITE":
            self.process_invite(raw_data, start_line, headers, body, call_id, sock, client_addr)
        elif method in ("ACK", "BYE", "CANCEL"):
            self.process_in_dialog(raw_data, method, headers, call_id, sock, client_addr)
        elif method == "SUBSCRIBE":
            resp = (
                f"SIP/2.0 489 Bad Event\r\n"
                f"Via: {headers.get('Via')}\r\n"
                f"From: {headers.get('From')}\r\n"
                f"To: {headers.get('To')};tag={secrets.token_hex(4)}\r\n"
                f"Call-ID: {call_id}\r\n"
                f"CSeq: {headers.get('Cseq')}\r\n"
                "Content-Length: 0\r\n\r\n"
            )
            sock.sendto(resp.encode("utf-8"), client_addr)
        elif method == "OPTIONS":
            resp = (
                f"SIP/2.0 200 OK\r\n"
                f"Via: {headers.get('Via')}\r\n"
                f"From: {headers.get('From')}\r\n"
                f"To: {headers.get('To')}\r\n"
                f"Call-ID: {call_id}\r\n"
                f"CSeq: {headers.get('Cseq')}\r\n"
                "Content-Length: 0\r\n\r\n"
            )
            sock.sendto(resp.encode("utf-8"), client_addr)

    def process_register(self, method, headers, sock, client_addr):
        extension = extract_user(headers.get("To", ""))
        auth_header = headers.get("Authorization")

        if not auth_header:
            self.send_401(headers, sock, client_addr)
            return

        if not verify_digest(method, parse_auth_header(auth_header)):
            self.send_401(headers, sock, client_addr)
            return

        REGISTRY[extension] = (client_addr[0], client_addr[1], time.time())

        raw_via = headers.get("Via", "")
        if ";rport" in raw_via:
            via_header = re.sub(r";rport(?![=\d])", f";received={client_addr[0]};rport={client_addr[1]}", raw_via)
        else:
            via_header = f"{raw_via};received={client_addr[0]}"

        resp = (
            "SIP/2.0 200 OK\r\n"
            f"Via: {via_header}\r\n"
            f"From: {headers.get('From')}\r\n"
            f"To: {headers.get('To')};tag={secrets.token_hex(4)}\r\n"
            f"Call-ID: {headers.get('Call-Id')}\r\n"
            f"CSeq: {headers.get('Cseq')}\r\n"
            f"Contact: {headers.get('Contact', '')}\r\n"
            "Expires: 3600\r\n"
            "Content-Length: 0\r\n\r\n"
        )
        sock.sendto(resp.encode("utf-8"), client_addr)

    def send_401(self, headers, sock, client_addr):
        nonce = secrets.token_hex(16)
        raw_via = headers.get("Via", "")
        if ";rport" in raw_via:
            via_header = re.sub(r";rport(?![=\d])", f";received={client_addr[0]};rport={client_addr[1]}", raw_via)
        else:
            via_header = f"{raw_via};received={client_addr[0]}"

        challenge = (
            "SIP/2.0 401 Unauthorized\r\n"
            f"Via: {via_header}\r\n"
            f"From: {headers.get('From')}\r\n"
            f"To: {headers.get('To')};tag={secrets.token_hex(4)}\r\n"
            f"Call-ID: {headers.get('Call-Id')}\r\n"
            f"CSeq: {headers.get('Cseq')}\r\n"
            f'WWW-Authenticate: Digest realm="{REALM}", nonce="{nonce}", algorithm=MD5, qop="auth"\r\n'
            "Content-Length: 0\r\n\r\n"
        )
        sock.sendto(challenge.encode("utf-8"), client_addr)

    def process_invite(self, raw_data, start_line, headers, body, call_id, sock, client_addr):
        if call_id in CALLS:
            return

        target_user = extract_user(start_line.split()[1])

        # 1. Звонок на голосовое меню IVR
        if target_user == IVR_NUMBER:
            print(f" -> [ВАТС] Вызов поступил на Голосовое Меню IVR ({IVR_NUMBER})")
            trying = (
                f"SIP/2.0 100 Trying\r\n"
                f"Via: {headers.get('Via')}\r\n"
                f"From: {headers.get('From')}\r\n"
                f"To: {headers.get('To')}\r\n"
                f"Call-ID: {call_id}\r\n"
                f"CSeq: {headers.get('Cseq')}\r\n"
                "Content-Length: 0\r\n\r\n"
            )
            sock.sendto(trying.encode("utf-8"), client_addr)

            CALLS[call_id] = {
                "active": True,
                "cancelled": False,
                "type": "ivr",
                "caller": client_addr,
                "headers": headers,
                "leg_b_id": None
            }
            threading.Thread(
                target=self.run_ivr_session,
                args=(headers, body, call_id, sock, client_addr),
                daemon=True
            ).start()
            return

        # 2. Обычный звонок между сотрудниками
        user_rec = get_user_record(target_user)
        if not user_rec:
            not_found = (
                f"SIP/2.0 404 Not Found\r\n"
                f"Via: {headers.get('Via')}\r\n"
                f"From: {headers.get('From')}\r\n"
                f"To: {headers.get('To')};tag={secrets.token_hex(4)}\r\n"
                f"Call-ID: {call_id}\r\n"
                f"CSeq: {headers.get('Cseq')}\r\n"
                "Content-Length: 0\r\n\r\n"
            )
            sock.sendto(not_found.encode("utf-8"), client_addr)
            return

        if target_user not in REGISTRY:
            unavailable = (
                f"SIP/2.0 480 Temporarily Unavailable\r\n"
                f"Via: {headers.get('Via')}\r\n"
                f"From: {headers.get('From')}\r\n"
                f"To: {headers.get('To')};tag={secrets.token_hex(4)}\r\n"
                f"Call-ID: {call_id}\r\n"
                f"CSeq: {headers.get('Cseq')}\r\n"
                "Content-Length: 0\r\n\r\n"
            )
            sock.sendto(unavailable.encode("utf-8"), client_addr)
            return

        target_addr = (REGISTRY[target_user][0], REGISTRY[target_user][1])
        CALLS[call_id] = {"caller": client_addr, "callee": target_addr, "type": "proxy"}

        trying = (
            f"SIP/2.0 100 Trying\r\n"
            f"Via: {headers.get('Via')}\r\n"
            f"From: {headers.get('From')}\r\n"
            f"To: {headers.get('To')}\r\n"
            f"Call-ID: {call_id}\r\n"
            f"CSeq: {headers.get('Cseq')}\r\n"
            "Content-Length: 0\r\n\r\n"
        )
        sock.sendto(trying.encode("utf-8"), client_addr)

        server_ip = PUBLIC_IP if PUBLIC_IP else get_local_ip(target_addr[0])
        record_route = f"Record-Route: <sip:{server_ip}:{sock.getsockname()[1]};lr>\r\n"
        forward_data = raw_data.replace("\r\n\r\n", f"\r\n{record_route}\r\n", 1)
        sock.sendto(forward_data.encode("utf-8"), target_addr)

    # -----------------------------------------------------------------
    # СЕССИЯ IVR + B2BUA ПЕРЕВОД БЕЗ СОЗДАНИЯ ВТОРОГО ЗВОНКА
    # -----------------------------------------------------------------
    def run_ivr_session(self, headers, body, call_id_a, sock, client_addr):
        to_tag_a = secrets.token_hex(4)
        call_state_a = CALLS[call_id_a]

        server_ip = PUBLIC_IP if PUBLIC_IP else get_local_ip(client_addr[0])
        server_port = sock.getsockname()[1]

        raw_via = headers.get("Via", "")
        if ";rport" in raw_via:
            via_header = re.sub(r";rport(?![=\d])", f";received={client_addr[0]};rport={client_addr[1]}", raw_via)
        else:
            via_header = f"{raw_via};received={client_addr[0]}"

        caller_rtp_ip, caller_rtp_port, client_codec = parse_sdp(body)
        if not caller_rtp_ip or is_private_ip(caller_rtp_ip):
            caller_rtp_ip = client_addr[0]
        if not caller_rtp_port:
            caller_rtp_port = 4000

        target_dest_a = (caller_rtp_ip, caller_rtp_port)
        call_state_a["caller_rtp"] = target_dest_a

        rtp_sock_a = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        rtp_sock_a.bind(("0.0.0.0", 0))
        server_rtp_a_port = rtp_sock_a.getsockname()[1]

        codecs_order = "8 0 101" if client_codec == 8 else "0 8 101"

        sdp_lines = [
            "v=0",
            f"o=ivr 1000 1000 IN IP4 {server_ip}",
            "s=Virtual PBX IVR",
            f"c=IN IP4 {server_ip}",
            "t=0 0",
            f"m=audio {server_rtp_a_port} RTP/AVP {codecs_order}",
            "a=rtpmap:0 PCMU/8000",
            "a=rtpmap:8 PCMA/8000",
            "a=rtpmap:101 telephone-event/8000",
            "a=fmtp:101 0-16",
            "a=sendrecv",
            "a=ptime:20",
            ""
        ]
        sdp_resp = "\r\n".join(sdp_lines)
        sdp_bytes = sdp_resp.encode("utf-8")

        ok_resp = (
            f"SIP/2.0 200 OK\r\n"
            f"Via: {via_header}\r\n"
            f"From: {headers.get('From')}\r\n"
            f"To: {headers.get('To')};tag={to_tag_a}\r\n"
            f"Call-ID: {call_id_a}\r\n"
            f"CSeq: {headers.get('Cseq')}\r\n"
            f"Contact: <sip:ivr@{server_ip}:{server_port}>\r\n"
            "Content-Type: application/sdp\r\n"
            f"Content-Length: {len(sdp_bytes)}\r\n\r\n"
            f"{sdp_resp}"
        )
        sock.sendto(ok_resp.encode("utf-8"), client_addr)
        time.sleep(0.05)
        sock.sendto(ok_resp.encode("utf-8"), client_addr)

        ivr_file = os.path.join(BASE_DIR, "ivr_menu.wav")
        if not os.path.exists(ivr_file):
            generate_synth_wav(ivr_file, melody_type="ivr")

        print(f" -> [IVR] Запущено меню. Слушаем нажатия клавиш (пауза {IVR_TIMEOUT_SEC} сек)...")

        # 1. Проигрываем голосовое меню и слушаем нажатия цифр
        pressed_key = self.stream_audio_and_listen_dtmf(
            rtp_sock_a, target_dest_a, ivr_file, call_state_a, client_codec, wait_timeout=IVR_TIMEOUT_SEC
        )

        routes = get_ivr_routes_from_db()
        if pressed_key is not None and pressed_key in routes:
            target_ext = routes[pressed_key]["target"]
            print(f" -> [ВАТС] Абонент нажал [{pressed_key}]. Инициируем вызов оператора {target_ext}...")
        else:
            target_ext = IVR_DEFAULT_EXT
            print(f" -> [IVR Таймаут] Ничего не нажато за {IVR_TIMEOUT_SEC} сек. Перевод на оператора ({target_ext}) с музыкой...")

        # 2. Проверяем регистрацию оператора
        if target_ext not in REGISTRY:
            print(f" -> [B2BUA] Оператор {target_ext} оффлайн. Завершение вызова.")
            self.terminate_leg(call_id_a, headers, to_tag_a, server_ip, server_port, sock, client_addr)
            rtp_sock_a.close()
            return

        # 3. ИНИЦИИРУЕМ ПЛЕЧО B (ВЫЗЫВАЕМ ОПЕРАТОРА С СЕРВЕРА)
        op_ip, op_port = REGISTRY[target_ext][0], REGISTRY[target_ext][1]
        call_id_b = secrets.token_hex(16)
        call_state_a["leg_b_id"] = call_id_b

        rtp_sock_b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        rtp_sock_b.bind(("0.0.0.0", 0))
        server_rtp_b_port = rtp_sock_b.getsockname()[1]

        b_answered = threading.Event()
        b_failed = threading.Event()

        from_tag_b = secrets.token_hex(4)
        from_hdr_b = f'"Caller" <sip:{IVR_NUMBER}@{server_ip}>;tag={from_tag_b}'

        sdp_b = [
            "v=0",
            f"o=pbx 2000 2000 IN IP4 {server_ip}",
            "s=PBX Call",
            f"c=IN IP4 {server_ip}",
            "t=0 0",
            f"m=audio {server_rtp_b_port} RTP/AVP 0 8",
            "a=rtpmap:0 PCMU/8000",
            "a=rtpmap:8 PCMA/8000",
            "a=sendrecv",
            "a=ptime:20",
            ""
        ]
        sdp_b_text = "\r\n".join(sdp_b)

        invite_b = (
            f"INVITE sip:{target_ext}@{op_ip}:{op_port} SIP/2.0\r\n"
            f"Via: SIP/2.0/UDP {server_ip}:{server_port};branch=z9hG4bK{secrets.token_hex(6)}\r\n"
            f"From: {from_hdr_b}\r\n"
            f"To: <sip:{target_ext}@{server_ip}>\r\n"
            f"Call-ID: {call_id_b}\r\n"
            f"CSeq: 1 INVITE\r\n"
            f"Contact: <sip:pbx@{server_ip}:{server_port}>\r\n"
            "Content-Type: application/sdp\r\n"
            f"Content-Length: {len(sdp_b_text.encode('utf-8'))}\r\n\r\n"
            f"{sdp_b_text}"
        )

        CALLS[call_id_b] = {
            "type": "b2bua_leg_b",
            "parent_id": call_id_a,
            "target_ext": target_ext,
            "target_addr": (op_ip, op_port),
            "invite_from": from_hdr_b,
            "event_answered": b_answered,
            "event_failed": b_failed,
            "callee_rtp": None,
            "active": True
        }

        sock.sendto(invite_b.encode("utf-8"), (op_ip, op_port))
        print(f" -> [B2BUA] Вызываем оператора {target_ext}. Звонящему включаем музыку ожидания (таймаут дозвона: {OPERATOR_RING_TIMEOUT} сек)...")

        # 4. ВРЕМЯ ОЖИДАНИЯ ОПЕРАТОРА: ЗВОНЯЩИЙ СЛУШАЕТ МУЗЫКУ (RINGBACK.WAV)
        ringback_file = os.path.join(BASE_DIR, "ringback.wav")
        if not os.path.exists(ringback_file):
            generate_synth_wav(ringback_file, melody_type="ringback")

        pcm_ringback = convert_audio_to_pcm(ringback_file, "PCMA" if client_codec == 8 else "PCMU")

        rtp_sock_a.setblocking(False)
        seq_num = secrets.randbelow(10000)
        timestamp = secrets.randbelow(100000)
        ssrc = secrets.randbelow(10000000)

        start_perf = time.perf_counter()
        idx = 0
        dial_start_time = time.perf_counter()

        # Крутим музыку в цикле, пока оператор не ответит, не сбросит или не выйдет таймаут OPERATOR_RING_TIMEOUT
        while call_state_a["active"] and not b_answered.is_set() and not b_failed.is_set():
            # Проверяем лимит времени дозвона до оператора
            if (time.perf_counter() - dial_start_time) >= OPERATOR_RING_TIMEOUT:
                print(f" -> [B2BUA] Время ожидания ответа оператора ({OPERATOR_RING_TIMEOUT} сек) истекло.")
                b_failed.set()
                break

            with open(pcm_ringback, "rb") as rf:
                while call_state_a["active"] and not b_answered.is_set() and not b_failed.is_set():
                    if (time.perf_counter() - dial_start_time) >= OPERATOR_RING_TIMEOUT:
                        b_failed.set()
                        break

                    chunk = rf.read(160)
                    if not chunk:
                        break

                    header = struct.pack("!BBHII", 0x80, client_codec & 0x7F, seq_num & 0xFFFF, timestamp & 0xFFFFFFFF, ssrc)
                    rtp_sock_a.sendto(header + chunk, call_state_a["caller_rtp"])

                    seq_num += 1
                    timestamp += 160
                    idx += 1

                    target_time = start_perf + (idx * 0.020)
                    time_to_wait = target_time - time.perf_counter()
                    if time_to_wait > 0.002:
                        time.sleep(time_to_wait - 0.001)
                    while time.perf_counter() < target_time:
                        pass

        # 5. ЕСЛИ ОПЕРАТОР НЕ ОТВЕТИЛ ИЛИ ИСТЕК ТАЙМАУТ
        if not b_answered.is_set() or not call_state_a["active"]:
            print(" -> [B2BUA] Вызов отменен: оператор не ответил вовремя.")
            # Отменяем звонок оператору через CANCEL
            b_info = CALLS.get(call_id_b)
            if b_info and b_info.get("active"):
                b_info["active"] = False
                cancel_b = (
                    f"CANCEL sip:{b_info['target_ext']}@{b_info['target_addr'][0]}:{b_info['target_addr'][1]} SIP/2.0\r\n"
                    f"Via: SIP/2.0/UDP {server_ip}:{server_port};branch=z9hG4bK{secrets.token_hex(6)}\r\n"
                    f"From: {b_info['invite_from']}\r\n"
                    f"To: <sip:{b_info['target_ext']}@{server_ip}>\r\n"
                    f"Call-ID: {call_id_b}\r\n"
                    f"CSeq: 1 CANCEL\r\n"
                    "Content-Length: 0\r\n\r\n"
                )
                sock.sendto(cancel_b.encode("utf-8"), b_info["target_addr"])

            self.terminate_leg(call_id_a, headers, to_tag_a, server_ip, server_port, sock, client_addr)
            rtp_sock_a.close()
            rtp_sock_b.close()
            CALLS.pop(call_id_a, None)
            CALLS.pop(call_id_b, None)
            return

        # 6. ОПЕРАТОР СНЯЛ ТРУБКУ: ВЫКЛЮЧАЕМ МУЗЫКУ И ВКЛЮЧАЕМ АУДИОМОСТ
        print(" -> [B2BUA] МУЗЫКА ВЫКЛЮЧЕНА! Оператор снял трубку. Аудиомост активен.")
        callee_rtp = CALLS[call_id_b]["callee_rtp"]
        call_state_a["callee_rtp"] = callee_rtp

        def bridge_caller_to_operator():
            rtp_sock_a.settimeout(0.5)
            while call_state_a["active"] and CALLS.get(call_id_b, {}).get("active"):
                try:
                    data, addr = rtp_sock_a.recvfrom(2048)
                    call_state_a["caller_rtp"] = addr
                    dest = call_state_a.get("callee_rtp")
                    if dest and len(data) >= 12:
                        rtp_sock_b.sendto(data, dest)
                except socket.timeout:
                    continue
                except Exception:
                    break

        def bridge_operator_to_caller():
            rtp_sock_b.settimeout(0.5)
            while call_state_a["active"] and CALLS.get(call_id_b, {}).get("active"):
                try:
                    data, addr = rtp_sock_b.recvfrom(2048)
                    call_state_a["callee_rtp"] = addr
                    dest = call_state_a.get("caller_rtp")
                    if dest and len(data) >= 12:
                        rtp_sock_a.sendto(data, dest)
                except socket.timeout:
                    continue
                except Exception:
                    break

        t1 = threading.Thread(target=bridge_caller_to_operator, daemon=True)
        t2 = threading.Thread(target=bridge_operator_to_caller, daemon=True)
        t1.start()
        t2.start()

        while call_state_a["active"] and CALLS.get(call_id_b, {}).get("active"):
            time.sleep(0.5)

        print(" -> [B2BUA] Разговор завершен. Закрываем аудиомост.")
        rtp_sock_a.close()
        rtp_sock_b.close()
        CALLS.pop(call_id_a, None)
        CALLS.pop(call_id_b, None)

    def terminate_leg(self, call_id, headers, to_tag, server_ip, server_port, sock, client_addr):
        clean_dest = extract_clean_uri(headers.get("Contact")) or extract_clean_uri(headers.get("From"))
        cseq_num = int(headers.get("Cseq", "1").split()[0]) + 1
        bye_req = (
            f"BYE {clean_dest} SIP/2.0\r\n"
            f"Via: SIP/2.0/UDP {server_ip}:{server_port};branch=z9hG4bK{secrets.token_hex(6)}\r\n"
            f"From: {headers.get('To')};tag={to_tag}\r\n"
            f"To: {headers.get('From')}\r\n"
            f"Call-ID: {call_id}\r\n"
            f"CSeq: {cseq_num} BYE\r\n"
            "Max-Forwards: 70\r\n"
            "Content-Length: 0\r\n\r\n"
        )
        sock.sendto(bye_req.encode("utf-8"), client_addr)

    def stream_audio_and_listen_dtmf(self, rtp_sock, dest_addr, audio_path, call_state, codec_pt=0, wait_timeout=3.0):
        codec_name = "PCMA" if codec_pt == 8 else "PCMU"
        try:
            pcm_file = convert_audio_to_pcm(audio_path, codec_name)
        except Exception:
            return None

        rtp_sock.setblocking(False)

        seq_num = secrets.randbelow(10000)
        timestamp = secrets.randbelow(100000)
        ssrc = secrets.randbelow(10000000)

        start_perf = time.perf_counter()
        idx = 0

        with open(pcm_file, "rb") as f:
            while call_state["active"] and not call_state["cancelled"]:
                try:
                    data, incoming_addr = rtp_sock.recvfrom(2048)
                    dest_addr = incoming_addr
                    call_state["caller_rtp"] = incoming_addr
                    if len(data) >= 16 and (data[1] & 0x7F) == 101:
                        event_id = data[12]
                        if 0 <= event_id <= 9:
                            print(f" >>> [DTMF] Получено нажатие клавиши: {event_id} <<<")
                            return event_id
                except (BlockingIOError, socket.error):
                    pass

                chunk = f.read(160)
                if not chunk:
                    timeout_frames = int(wait_timeout / 0.02)
                    for _ in range(timeout_frames):
                        if not call_state["active"] or call_state["cancelled"]:
                            break
                        time.sleep(0.02)
                        try:
                            data, incoming_addr = rtp_sock.recvfrom(2048)
                            dest_addr = incoming_addr
                            call_state["caller_rtp"] = incoming_addr
                            if len(data) >= 16 and (data[1] & 0x7F) == 101:
                                return data[12]
                        except (BlockingIOError, socket.error):
                            pass
                    break

                if len(chunk) < 160:
                    silence = b"\xD5" if codec_pt == 8 else b"\xFF"
                    chunk = chunk + silence * (160 - len(chunk))

                header = struct.pack("!BBHII", 0x80, codec_pt & 0x7F, seq_num & 0xFFFF, timestamp & 0xFFFFFFFF, ssrc)
                rtp_sock.sendto(header + chunk, dest_addr)

                seq_num += 1
                timestamp += 160
                idx += 1

                target_time = start_perf + (idx * 0.020)
                time_to_wait = target_time - time.perf_counter()
                if time_to_wait > 0.002:
                    time.sleep(time_to_wait - 0.001)
                while time.perf_counter() < target_time:
                    pass

        return None

    def process_in_dialog(self, raw_data, method, headers, call_id, sock, client_addr):
        if call_id not in CALLS:
            return
        call = CALLS[call_id]

        if call.get("type") == "ivr":
            if method in ("CANCEL", "BYE"):
                call["cancelled"] = True
                call["active"] = False
                ok_resp = (
                    f"SIP/2.0 200 OK\r\n"
                    f"Via: {headers.get('Via')}\r\n"
                    f"From: {headers.get('From')}\r\n"
                    f"To: {headers.get('To')}\r\n"
                    f"Call-ID: {call_id}\r\n"
                    f"CSeq: {headers.get('Cseq')}\r\n"
                    "Content-Length: 0\r\n\r\n"
                )
                sock.sendto(ok_resp.encode("utf-8"), client_addr)

                leg_b_id = call.get("leg_b_id")
                if leg_b_id and leg_b_id in CALLS:
                    b_info = CALLS[leg_b_id]
                    b_info["active"] = False
                    server_ip = PUBLIC_IP if PUBLIC_IP else get_local_ip(b_info["target_addr"][0])
                    bye_b = (
                        f"BYE sip:{b_info['target_ext']}@{b_info['target_addr'][0]}:{b_info['target_addr'][1]} SIP/2.0\r\n"
                        f"Via: SIP/2.0/UDP {server_ip}:{sock.getsockname()[1]};branch=z9hG4bK{secrets.token_hex(6)}\r\n"
                        f"From: {b_info['invite_from']}\r\n"
                        f"To: <sip:{b_info['target_ext']}@{server_ip}>\r\n"
                        f"Call-ID: {leg_b_id}\r\n"
                        f"CSeq: 2 BYE\r\n"
                        "Content-Length: 0\r\n\r\n"
                    )
                    sock.sendto(bye_b.encode("utf-8"), b_info["target_addr"])
            return

        if call.get("type") == "b2bua_leg_b":
            if method in ("CANCEL", "BYE"):
                call["active"] = False
                ok_resp = (
                    f"SIP/2.0 200 OK\r\n"
                    f"Via: {headers.get('Via')}\r\n"
                    f"From: {headers.get('From')}\r\n"
                    f"To: {headers.get('To')}\r\n"
                    f"Call-ID: {call_id}\r\n"
                    f"CSeq: {headers.get('Cseq')}\r\n"
                    "Content-Length: 0\r\n\r\n"
                )
                sock.sendto(ok_resp.encode("utf-8"), client_addr)

                parent_id = call.get("parent_id")
                if parent_id and parent_id in CALLS:
                    p_info = CALLS[parent_id]
                    p_info["active"] = False
            return

        dest = call["callee"] if client_addr == call["caller"] else call["caller"]
        sock.sendto(raw_data.encode("utf-8"), dest)

    def handle_response(self, raw_data, start_line, headers, body, call_id, sock, client_addr):
        if call_id not in CALLS:
            return
        call = CALLS[call_id]

        if call.get("type") == "b2bua_leg_b":
            server_ip = PUBLIC_IP if PUBLIC_IP else get_local_ip(client_addr[0])
            server_port = sock.getsockname()[1]

            if "180 Ringing" in start_line:
                print(f" -> [B2BUA] Телефон оператора {call['target_ext']} звонит (Ringing)...")
            elif "200 OK" in start_line:
                print(f" -> [B2BUA] Оператор {call['target_ext']} ответил на вызов (200 OK)!")
                rtp_ip, rtp_port, _ = parse_sdp(body)
                if not rtp_ip or is_private_ip(rtp_ip):
                    rtp_ip = client_addr[0]
                call["callee_rtp"] = (rtp_ip, rtp_port or 4000)

                to_hdr = headers.get("To", "")
                ack_req = (
                    f"ACK sip:{call['target_ext']}@{client_addr[0]}:{client_addr[1]} SIP/2.0\r\n"
                    f"Via: SIP/2.0/UDP {server_ip}:{server_port};branch=z9hG4bK{secrets.token_hex(6)}\r\n"
                    f"From: {call['invite_from']}\r\n"
                    f"To: {to_hdr}\r\n"
                    f"Call-ID: {call_id}\r\n"
                    f"CSeq: 1 ACK\r\n"
                    "Max-Forwards: 70\r\n"
                    "Content-Length: 0\r\n\r\n"
                )
                sock.sendto(ack_req.encode("utf-8"), client_addr)
                call["event_answered"].set()
            elif any(err in start_line for err in ("486", "480", "404", "603", "503")):
                print(f" -> [B2BUA] Вызов оператора отклонен ({start_line.strip()})")
                call["event_failed"].set()
            return

        if call.get("type") == "proxy":
            dest = call["caller"] if client_addr == call["callee"] else call["callee"]
            sock.sendto(raw_data.encode("utf-8"), dest)
            cseq = headers.get("Cseq", "").upper()
            if "BYE" in cseq and "200 OK" in start_line:
                CALLS.pop(call_id, None)


# =====================================================================
# ВЕБ-ПАНЕЛЬ УПРАВЛЕНИЯ
# =====================================================================

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024

HTML_DASHBOARD = """
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Панель управления ВАТС</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css">
    <style>
        body { background-color: #0f172a; color: #e2e8f0; font-family: system-ui, -apple-system, sans-serif; }
        .card { background-color: #1e293b; border: 1px solid #334155; border-radius: 12px; }
        .nav-pills .nav-link { color: #94a3b8; border-radius: 8px; margin-right: 8px; }
        .nav-pills .nav-link.active { background-color: #6366f1; color: #fff; }
        .table { color: #e2e8f0; border-color: #334155; }
        .badge-online { background-color: #10b981; }
        .badge-offline { background-color: #64748b; }
        .btn-primary { background-color: #6366f1; border-color: #6366f1; }
        .btn-primary:hover { background-color: #4f46e5; }
        .form-control, .form-select { background-color: #0f172a; border-color: #334155; color: #f8fafc; }
        .form-control:focus, .form-select:focus { background-color: #0f172a; border-color: #6366f1; color: #fff; box-shadow: none; }
    </style>
</head>
<body class="p-4">
    <div class="container-fluid" style="max-width: 1200px;">
        <div class="d-flex justify-content-between align-items-center mb-4">
            <div>
                <h3 class="fw-bold mb-0"><i class="bi bi-telephone-fill text-primary me-2"></i>Панель управления ВАТС</h3>
                <small class="text-secondary">Облачная виртуальная телефония & SIP Сервер (B2BUA)</small>
            </div>
            <div class="text-end">
                <span class="badge bg-secondary p-2"><i class="bi bi-globe me-1"></i> IP: {{ public_ip }}</span>
                <span class="badge bg-primary p-2 ms-2"><i class="bi bi-shield-check me-1"></i> Realm: {{ realm }}</span>
            </div>
        </div>

        <ul class="nav nav-pills mb-4" id="pills-tab">
            <li class="nav-item">
                <button class="nav-link active" data-bs-toggle="pill" data-bs-target="#tab-monitor"><i class="bi bi-speedometer2 me-1"></i> Мониторинг</button>
            </li>
            <li class="nav-item">
                <button class="nav-link" data-bs-toggle="pill" data-bs-target="#tab-users"><i class="bi bi-people me-1"></i> Абоненты (Номера)</button>
            </li>
            <li class="nav-item">
                <button class="nav-link" data-bs-toggle="pill" data-bs-target="#tab-ivr"><i class="bi bi-diagram-3 me-1"></i> Голосовое меню (IVR)</button>
            </li>
            <li class="nav-item">
                <button class="nav-link" data-bs-toggle="pill" data-bs-target="#tab-audio"><i class="bi bi-music-note-beamed me-1"></i> Аудиозаписи</button>
            </li>
        </ul>

        <div class="tab-content">
            <!-- 1. МОНИТОРИНГ -->
            <div class="tab-pane fade show active" id="tab-monitor">
                <div class="row g-3 mb-4">
                    <div class="col-md-3">
                        <div class="card p-3">
                            <div class="text-secondary small">Онлайн абонентов</div>
                            <h2 class="fw-bold text-success mt-1" id="stat-online">0</h2>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card p-3">
                            <div class="text-secondary small">Активных вызовов</div>
                            <h2 class="fw-bold text-primary mt-1" id="stat-calls">0</h2>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card p-3">
                            <div class="text-secondary small">Пауза IVR меню</div>
                            <h2 class="fw-bold text-info mt-1">{{ ivr_timeout }} сек</h2>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card p-3">
                            <div class="text-secondary small">Ожидание оператора</div>
                            <h2 class="fw-bold text-warning mt-1">{{ op_timeout }} сек</h2>
                        </div>
                    </div>
                </div>

                <div class="card p-4">
                    <h5 class="fw-bold mb-3"><i class="bi bi-broadcast me-2"></i>Зарегистрированные софтфоны онлайн</h5>
                    <div class="table-responsive">
                        <table class="table table-hover">
                            <thead>
                                <tr><th>Номер (Ext)</th><th>Внешний адрес (IP:Port)</th><th>Статус</th></tr>
                            </thead>
                            <tbody id="online-users-table">
                                <tr><td colspan="3" class="text-secondary">Нет активных регистраций</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <!-- 2. АБОНЕНТЫ -->
            <div class="tab-pane fade" id="tab-users">
                <div class="card p-4">
                    <div class="d-flex justify-content-between align-items-center mb-3">
                        <h5 class="fw-bold mb-0"><i class="bi bi-person-lines-fill me-2"></i>Внутренние номера сотрудников</h5>
                        <button class="btn btn-primary btn-sm" data-bs-toggle="modal" data-bs-target="#addUserModal"><i class="bi bi-plus-lg me-1"></i>Добавить номер</button>
                    </div>
                    <div class="table-responsive">
                        <table class="table table-hover align-middle">
                            <thead>
                                <tr><th>Номер</th><th>Тип</th><th>Файл ответа</th><th>Статус</th><th>Действия</th></tr>
                            </thead>
                            <tbody id="users-table"></tbody>
                        </table>
                    </div>
                </div>
            </div>

            <!-- 3. ГОЛОСОВОЕ МЕНЮ (IVR) -->
            <div class="tab-pane fade" id="tab-ivr">
                <div class="card p-4">
                    <div class="alert alert-info py-2 mb-3" style="background-color: #1e3a5f; border-color: #2b4c7e; color: #93c5fd;">
                        <i class="bi bi-info-circle-fill me-2"></i> <strong>Логика таймаутов:</strong><br>
                        • <strong>Пауза в меню:</strong> {{ ivr_timeout }} сек (если клиент ничего не нажал — автоперевод на оператора <strong>{{ default_ext }}</strong>).<br>
                        • <strong>Ожидание оператора:</strong> {{ op_timeout }} сек (клиент слушает музыку, пока оператор не возьмет трубку).
                    </div>
                    <div class="d-flex justify-content-between align-items-center mb-3">
                        <div>
                            <h5 class="fw-bold mb-0"><i class="bi bi-diagram-3 me-2"></i>Маршрутизация клавиш IVR (номер {{ ivr_num }})</h5>
                            <small class="text-secondary">Куда переводить звонок при нажатии цифры на телефоне</small>
                        </div>
                        <button class="btn btn-primary btn-sm" data-bs-toggle="modal" data-bs-target="#addIvrModal"><i class="bi bi-plus-lg me-1"></i>Добавить правило</button>
                    </div>
                    <div class="table-responsive">
                        <table class="table table-hover align-middle">
                            <thead>
                                <tr><th>Клавиша (DTMF)</th><th>Куда переводить (Добавочный)</th><th>Описание отдела</th><th>Действие</th></tr>
                            </thead>
                            <tbody id="ivr-table"></tbody>
                        </table>
                    </div>
                </div>
            </div>

            <!-- 4. АУДИОЗАПИСИ -->
            <div class="tab-pane fade" id="tab-audio">
                <div class="card p-4">
                    <h5 class="fw-bold mb-3"><i class="bi bi-upload me-2"></i>Загрузить аудиозапись</h5>
                    <form id="upload-form" class="row g-3 mb-4">
                        <div class="col-md-8">
                            <input class="form-control" type="file" id="audio-file-input" accept=".wav,.mp3" required>
                        </div>
                        <div class="col-md-4">
                            <button class="btn btn-primary w-100" type="submit"><i class="bi bi-cloud-arrow-up me-1"></i>Загрузить на сервер</button>
                        </div>
                    </form>

                    <h5 class="fw-bold mb-3"><i class="bi bi-file-earmark-music me-2"></i>Аудиофайлы на сервере</h5>
                    <div class="table-responsive">
                        <table class="table table-hover align-middle">
                            <thead>
                                <tr><th>Имя файла</th><th>Размер</th><th>Прослушать</th></tr>
                            </thead>
                            <tbody id="audio-table"></tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Модальное окно добавления номера -->
    <div class="modal fade" id="addUserModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content" style="background-color: #1e293b; border: 1px solid #334155;">
                <div class="modal-header border-secondary">
                    <h5 class="modal-title">Добавить абонента</h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <form id="add-user-form">
                        <div class="mb-3">
                            <label class="form-label">Внутренний номер (логин):</label>
                            <input type="text" class="form-control" id="new-username" placeholder="1001" required>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Пароль:</label>
                            <input type="password" class="form-control" id="new-password" placeholder="pass123" required>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Тип аккаунта:</label>
                            <select class="form-select" id="new-type">
                                <option value="normal">Обычный (софтфон / трубка)</option>
                                <option value="prerecorded">Автоответчик (проигрывание трека)</option>
                            </select>
                        </div>
                        <div class="mb-3" id="audio-file-group" style="display: none;">
                            <label class="form-label">Файл автоответчика:</label>
                            <input type="text" class="form-control" id="new-audio-file" value="welcome.wav">
                        </div>
                        <button type="submit" class="btn btn-primary w-100">Сохранить</button>
                    </form>
                </div>
            </div>
        </div>
    </div>

    <!-- Модальное окно добавления правила IVR -->
    <div class="modal fade" id="addIvrModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content" style="background-color: #1e293b; border: 1px solid #334155;">
                <div class="modal-header border-secondary">
                    <h5 class="modal-title">Настроить кнопку IVR</h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <form id="add-ivr-form">
                        <div class="mb-3">
                            <label class="form-label">Цифра на телефоне (0-9):</label>
                            <input type="number" min="0" max="9" class="form-control" id="ivr-digit" placeholder="1" required>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Куда переводить (номер абонента):</label>
                            <input type="text" class="form-control" id="ivr-target" placeholder="1001" required>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Описание отдела:</label>
                            <input type="text" class="form-control" id="ivr-desc" placeholder="Администрация">
                        </div>
                        <button type="submit" class="btn btn-primary w-100">Сохранить правило</button>
                    </form>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        document.getElementById('new-type').addEventListener('change', function() {
            document.getElementById('audio-file-group').style.display = this.value === 'prerecorded' ? 'block' : 'none';
        });

        async function loadData() {
            const resUsers = await fetch('/api/users');
            const users = await resUsers.json();
            
            let onlineCount = 0;
            let usersHtml = '';
            let onlineHtml = '';

            users.forEach(u => {
                if (u.online) {
                    onlineCount++;
                    onlineHtml += `<tr><td><strong>${u.username}</strong></td><td><code>${u.address}</code></td><td><span class="badge badge-online">Онлайн</span></td></tr>`;
                }
                usersHtml += `
                    <tr>
                        <td><strong>${u.username}</strong></td>
                        <td><span class="badge ${u.type === 'normal' ? 'bg-info' : 'bg-warning text-dark'}">${u.type === 'normal' ? 'Софтфон' : 'Автоответчик'}</span></td>
                        <td><small class="text-secondary">${u.audio_file}</small></td>
                        <td><span class="badge ${u.online ? 'badge-online' : 'badge-offline'}">${u.online ? 'Онлайн' : 'Оффлайн'}</span></td>
                        <td>
                            <button class="btn btn-outline-danger btn-sm" onclick="deleteUser('${u.username}')"><i class="bi bi-trash"></i></button>
                        </td>
                    </tr>
                `;
            });

            document.getElementById('stat-online').innerText = onlineCount;
            document.getElementById('users-table').innerHTML = usersHtml || '<tr><td colspan="5" class="text-secondary">Нет абонентов</td></tr>';
            document.getElementById('online-users-table').innerHTML = onlineHtml || '<tr><td colspan="3" class="text-secondary">Нет активных софтфонов</td></tr>';

            const resCalls = await fetch('/api/calls');
            const calls = await resCalls.json();
            document.getElementById('stat-calls').innerText = calls.active_calls;

            const resIvr = await fetch('/api/ivr');
            const ivr = await resIvr.json();
            let ivrHtml = '';
            for (let [digit, data] of Object.entries(ivr)) {
                ivrHtml += `
                    <tr>
                        <td><span class="badge bg-primary fs-6 px-3">${digit}</span></td>
                        <td><strong>${data.target}</strong></td>
                        <td>${data.desc}</td>
                        <td>
                            <button class="btn btn-outline-danger btn-sm" onclick="deleteIvr(${digit})"><i class="bi bi-trash"></i></button>
                        </td>
                    </tr>
                `;
            }
            document.getElementById('ivr-table').innerHTML = ivrHtml || '<tr><td colspan="4" class="text-secondary">Маршруты не настроены</td></tr>';

            const resAudio = await fetch('/api/audio');
            const audioFiles = await resAudio.json();
            let audioHtml = '';
            audioFiles.forEach(f => {
                audioHtml += `
                    <tr>
                        <td><code>${f.name}</code></td>
                        <td><small class="text-secondary">${(f.size / 1024).toFixed(1)} КБ</small></td>
                        <td>
                            <audio controls style="height: 32px;" src="/audio/${f.name}"></audio>
                        </td>
                    </tr>
                `;
            });
            document.getElementById('audio-table').innerHTML = audioHtml || '<tr><td colspan="3" class="text-secondary">Нет аудиофайлов</td></tr>';
        }

        document.getElementById('add-user-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            await fetch('/api/users', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    username: document.getElementById('new-username').value,
                    password: document.getElementById('new-password').value,
                    type: document.getElementById('new-type').value,
                    audio_file: document.getElementById('new-audio-file').value
                })
            });
            bootstrap.Modal.getInstance(document.getElementById('addUserModal')).hide();
            document.getElementById('add-user-form').reset();
            loadData();
        });

        async function deleteUser(username) {
            if (confirm(`Удалить абонента ${username}?`)) {
                await fetch(`/api/users/${username}`, { method: 'DELETE' });
                loadData();
            }
        }

        document.getElementById('add-ivr-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            await fetch('/api/ivr', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    digit: parseInt(document.getElementById('ivr-digit').value),
                    target: document.getElementById('ivr-target').value,
                    desc: document.getElementById('ivr-desc').value
                })
            });
            bootstrap.Modal.getInstance(document.getElementById('addIvrModal')).hide();
            document.getElementById('add-ivr-form').reset();
            loadData();
        });

        async function deleteIvr(digit) {
            if (confirm(`Удалить кнопку ${digit}?`)) {
                await fetch(`/api/ivr/${digit}`, { method: 'DELETE' });
                loadData();
            }
        }

        document.getElementById('upload-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const input = document.getElementById('audio-file-input');
            const formData = new FormData();
            formData.append('file', input.files[0]);

            const res = await fetch('/api/audio/upload', {
                method: 'POST',
                body: formData
            });
            if (res.ok) {
                input.value = '';
                loadData();
            } else {
                alert('Ошибка при загрузке аудиофайла');
            }
        });

        loadData();
        setInterval(loadData, 3000);
    </script>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(
        HTML_DASHBOARD,
        public_ip=PUBLIC_IP,
        realm=REALM,
        ivr_num=IVR_NUMBER,
        default_ext=IVR_DEFAULT_EXT,
        ivr_timeout=IVR_TIMEOUT_SEC,
        op_timeout=OPERATOR_RING_TIMEOUT
    )

@app.route("/api/users", methods=["GET", "POST"])
def api_users():
    if request.method == "POST":
        data = request.json
        add_or_update_user(data["username"], data["password"], data.get("type", "normal"), data.get("audio_file", "welcome.wav"))
        return jsonify({"status": "ok"})
    return jsonify(get_all_users())

@app.route("/api/users/<username>", methods=["DELETE"])
def api_user_delete(username):
    delete_user_from_db(username)
    return jsonify({"status": "ok"})

@app.route("/api/calls")
def api_calls():
    now = time.time()
    active_reg = {k: v for k, v in REGISTRY.items() if now - v[2] < 3600}
    return jsonify({"active_calls": len(CALLS), "active_registrations": len(active_reg)})

@app.route("/api/ivr", methods=["GET", "POST"])
def api_ivr():
    if request.method == "POST":
        data = request.json
        set_ivr_route_db(int(data["digit"]), data["target"], data.get("desc", ""))
        return jsonify({"status": "ok"})
    return jsonify(get_ivr_routes_from_db())

@app.route("/api/ivr/<int:digit>", methods=["DELETE"])
def api_ivr_delete(digit):
    delete_ivr_route_db(digit)
    return jsonify({"status": "ok"})

@app.route("/api/audio")
def api_audio():
    files = []
    for f in os.listdir(BASE_DIR):
        if f.lower().endswith((".wav", ".mp3")):
            full_p = os.path.join(BASE_DIR, f)
            files.append({"name": f, "size": os.path.getsize(full_p)})
    return jsonify(files)

@app.route("/api/audio/upload", methods=["POST"])
def api_audio_upload():
    if 'file' not in request.files:
        return jsonify({"error": "no file"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "empty filename"}), 400
    filename = secure_filename(file.filename)
    dest_path = os.path.join(BASE_DIR, filename)
    file.save(dest_path)
    for ext in (".pcm", ".pcmu", ".pcma"):
        cache_f = dest_path + ext
        if os.path.exists(cache_f):
            os.remove(cache_f)
    return jsonify({"status": "ok", "filename": filename})

@app.route("/audio/<path:filename>")
def serve_audio(filename):
    return send_from_directory(BASE_DIR, filename)


def run_web_panel():
    app.run(host="0.0.0.0", port=WEB_PORT, debug=False, use_reloader=False)


# =====================================================================
# ТОЧКА ВХОДА СЕРВЕРА
# =====================================================================

if __name__ == "__main__":
    init_db()

    generate_synth_wav(os.path.join(BASE_DIR, "ivr_menu.wav"), melody_type="ivr")
    generate_synth_wav(os.path.join(BASE_DIR, "ringback.wav"), melody_type="ringback")
    generate_synth_wav(os.path.join(BASE_DIR, "welcome.wav"), melody_type="ivr")

    web_thread = threading.Thread(target=run_web_panel, daemon=True)
    web_thread.start()

    HOST, PORT = "0.0.0.0", 5060
    print("=" * 65)
    print(f"  ВИРТУАЛЬНАЯ АТС И SIP-СЕРВЕР УСПЕШНО ЗАПУЩЕНЫ")
    print("=" * 65)
    print(f"  SIP Порт (UDP):          {HOST}:{PORT}")
    print(f"  Внешний IP сервера:      {PUBLIC_IP}")
    print(f"  Веб-панель управления:    http://{PUBLIC_IP}:{WEB_PORT}")
    print("=" * 65)
    print(f"  Голосовое меню (IVR):    {IVR_NUMBER}")
    print(f"  Дежурный оператор:       {IVR_DEFAULT_EXT}")
    print(f"  Пауза в меню IVR:        {IVR_TIMEOUT_SEC} сек")
    print(f"  Ожидание оператора:      {OPERATOR_RING_TIMEOUT} сек")
    print("=" * 65)

    try:
        server = socketserver.ThreadingUDPServer((HOST, PORT), SIPHandler)
        server.serve_forever()
    except PermissionError:
        print("Ошибка: Для порта 5060 требуются root-права (запустите через sudo).")
    except KeyboardInterrupt:
        print("\nОстановка сервера.")
