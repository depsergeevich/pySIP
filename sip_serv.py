import hashlib
import math
import os
import re
import secrets
import socket
import socketserver
import sqlite3
import struct
import threading
import time
import wave

try:
    import audioop
except ImportError:
    audioop = None

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, "sip_users.db")
REALM = "sip.local"

REGISTRY = {}   # {"1001": ("ip", port)}
CALLS = {}      # {call_id: dict_info}


def get_local_ip(target_ip=None):
    """Определяет реальный сетевой IP сервера (не 0.0.0.0) для корректного SDP."""
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
    """Извлекает чистый SIP URI без скобок, тегов и параметров (напр. sip:1001@192.168.1.5:5060)."""
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


def generate_default_wav(filepath: str):
    if os.path.exists(filepath):
        return
    print(f"[*] Создаю демо-аудиофайл '{filepath}'...")
    sample_rate = 8000
    frequencies = [523.25, 659.25, 783.99, 1046.50]
    raw_samples = bytearray()
    for freq in frequencies:
        for i in range(int(sample_rate * 0.4)):
            sample = int(8000 * math.sin(2 * math.pi * freq * (i / sample_rate)))
            raw_samples.extend(struct.pack("<h", sample))

    with wave.open(filepath, "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(sample_rate)
        wf.writeframes(raw_samples)


def load_and_prepare_audio(filepath: str) -> list:
    """
    Открывает любой WAV-файл (включая 44.1/48kHz Stereo),
    приводит к моно, ресемплит в 8000Hz и делит на RTP-чанки по 160 байт (20 мс).
    """
    if not os.path.exists(filepath):
        generate_default_wav(filepath)

    with wave.open(filepath, "rb") as wf:
        n_channels = wf.getnchannels()
        sampwidth = wf.getsampwidth()
        framerate = wf.getframerate()
        raw_frames = wf.readframes(wf.getnframes())

    if sampwidth != 2 and audioop:
        raw_frames = audioop.lin2lin(raw_frames, sampwidth, 2)
        sampwidth = 2

    if n_channels > 1 and audioop:
        raw_frames = audioop.tomono(raw_frames, sampwidth, 0.5, 0.5)
        n_channels = 1

    if framerate != 8000 and audioop:
        raw_frames, _ = audioop.ratecv(raw_frames, 2, 1, framerate, 8000, None)
        framerate = 8000

    if audioop:
        ulaw_data = audioop.lin2ulaw(raw_frames, 2)
    else:
        ulaw_data = bytearray()
        samples = struct.unpack(f"<{len(raw_frames)//2}h", raw_frames)
        for s in samples[::n_channels]:
            ulaw_data.append(linear_to_ulaw(s))

    chunk_size = 160
    chunks = []
    for i in range(0, len(ulaw_data), chunk_size):
        chunk = ulaw_data[i:i + chunk_size]
        if len(chunk) < chunk_size:
            chunk = chunk + b"\xFF" * (chunk_size - len(chunk))
        chunks.append(chunk)

    return chunks


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
    for col, col_type in [("type", "TEXT DEFAULT 'normal'"), ("audio_file", "TEXT")]:
        try:
            conn.execute(f"ALTER TABLE users ADD COLUMN {col} {col_type}")
        except sqlite3.OperationalError:
            pass
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


def parse_sdp(sdp_text: str):
    rtp_ip = None
    rtp_port = None
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
    return rtp_ip, rtp_port


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
            self.handle_response(raw_data, start_line, headers, call_id, sock, client_addr)
        else:
            self.handle_request(raw_data, start_line, headers, body, call_id, sock, client_addr)

    def handle_request(self, raw_data, start_line, headers, body, call_id, sock, client_addr):
        method = start_line.split()[0].upper()
        print(f"[REQ] {method} from {client_addr}")

        if method == "REGISTER":
            self.process_register(method, headers, sock, client_addr)
        elif method == "INVITE":
            self.process_invite(raw_data, start_line, headers, body, call_id, sock, client_addr)
        elif method in ("ACK", "BYE", "CANCEL"):
            self.process_in_dialog(raw_data, method, headers, call_id, sock, client_addr)
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
            print(f" -> Ошибка авторизации для '{extension}'")
            self.send_401(headers, sock, client_addr)
            return

        print(f" -> Успешная регистрация '{extension}' на {client_addr}")
        REGISTRY[extension] = client_addr

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
        # Защита от дублей INVITE (retransmission UDP)
        if call_id in CALLS:
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
            return

        target_user = extract_user(start_line.split()[1])
        user_rec = get_user_record(target_user)

        if not user_rec:
            print(f" -> Номер '{target_user}' не найден")
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

        # Если звонят на автоответчик (prerecorded)
        if user_rec["type"] == "prerecorded":
            print(f" -> Принят вызов на автоответчик '{target_user}'")
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

            CALLS[call_id] = {"active": True, "cancelled": False, "type": "bot"}

            threading.Thread(
                target=self.run_prerecorded_call,
                args=(headers, body, call_id, sock, client_addr, user_rec["audio_file"]),
                daemon=True
            ).start()
            return

        # Обычный вызов между двумя софтфонами
        if target_user not in REGISTRY:
            print(f" -> Абонент '{target_user}' оффлайн")
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

        target_addr = REGISTRY[target_user]
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

        server_ip = get_local_ip(target_addr[0])
        record_route = f"Record-Route: <sip:{server_ip}:{sock.getsockname()[1]};lr>\r\n"
        forward_data = raw_data.replace("\r\n\r\n", f"\r\n{record_route}\r\n", 1)
        sock.sendto(forward_data.encode("utf-8"), target_addr)

    def run_prerecorded_call(self, headers, body, call_id, sock, client_addr, audio_path):
        to_tag = secrets.token_hex(4)
        call_state = CALLS[call_id]

        server_ip = get_local_ip(client_addr[0])
        server_port = sock.getsockname()[1]

        raw_via = headers.get("Via", "")
        if ";rport" in raw_via:
            via_header = re.sub(r";rport(?![=\d])", f";received={client_addr[0]};rport={client_addr[1]}", raw_via)
        else:
            via_header = f"{raw_via};received={client_addr[0]}"

        def send_ringing():
            ringing = (
                f"SIP/2.0 180 Ringing\r\n"
                f"Via: {via_header}\r\n"
                f"From: {headers.get('From')}\r\n"
                f"To: {headers.get('To')};tag={to_tag}\r\n"
                f"Call-ID: {call_id}\r\n"
                f"CSeq: {headers.get('Cseq')}\r\n"
                f"Contact: <sip:bot@{server_ip}:{server_port}>\r\n"
                "Content-Length: 0\r\n\r\n"
            )
            sock.sendto(ringing.encode("utf-8"), client_addr)

        def wait_seconds(sec):
            elapsed = 0.0
            while elapsed < sec:
                if not call_state["active"] or call_state["cancelled"]:
                    return False
                time.sleep(0.1)
                elapsed += 0.1
            return True

        # --- 1-й ГУДОК ---
        print(f" -> [{call_id}] Гудок 1 (старт звонка)...")
        send_ringing()
        if not wait_seconds(4.0):
            print(f" -> [{call_id}] Сброшено звонящим на 1 гудке.")
            CALLS.pop(call_id, None)
            return

        # --- 2-й ГУДОК ---
        print(f" -> [{call_id}] Гудок 2 (пауза 4 сек)...")
        send_ringing()
        if not wait_seconds(4.0):
            print(f" -> [{call_id}] Сброшено звонящим на 2 гудке.")
            CALLS.pop(call_id, None)
            return

        # --- 3-й ГУДОК ---
        print(f" -> [{call_id}] Гудок 3 (звучит гудок -> СНИМАЕМ ТРУБКУ)!")
        send_ringing()
        if not wait_seconds(0.6):
            print(f" -> [{call_id}] Сброшено звонящим на 3 гудке.")
            CALLS.pop(call_id, None)
            return

        caller_rtp_ip, caller_rtp_port = parse_sdp(body)
        if not caller_rtp_ip:
            caller_rtp_ip = client_addr[0]
        if not caller_rtp_port:
            caller_rtp_port = 8000

        rtp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        rtp_sock.bind(("0.0.0.0", 0))
        server_rtp_port = rtp_sock.getsockname()[1]

        # Поддержка обоих кодеков PCMU (0) и PCMA (8) для полной совместимости
        sdp_lines = [
            "v=0",
            f"o=bot 1000 1000 IN IP4 {server_ip}",
            "s=SIP Call",
            f"c=IN IP4 {server_ip}",
            "t=0 0",
            f"m=audio {server_rtp_port} RTP/AVP 0 8",
            "a=rtpmap:0 PCMU/8000",
            "a=rtpmap:8 PCMA/8000",
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
            f"To: {headers.get('To')};tag={to_tag}\r\n"
            f"Call-ID: {call_id}\r\n"
            f"CSeq: {headers.get('Cseq')}\r\n"
            f"Contact: <sip:bot@{server_ip}:{server_port}>\r\n"
            "Content-Type: application/sdp\r\n"
            f"Content-Length: {len(sdp_bytes)}\r\n\r\n"
            f"{sdp_resp}"
        )
        sock.sendto(ok_resp.encode("utf-8"), client_addr)
        time.sleep(0.05)
        sock.sendto(ok_resp.encode("utf-8"), client_addr)

        full_audio_path = os.path.join(BASE_DIR, audio_path)
        try:
            self.stream_rtp(rtp_sock, (caller_rtp_ip, caller_rtp_port), full_audio_path, call_state)
        except Exception as e:
            print(f"[-] Ошибка трансляции звука: {e}")
        finally:
            rtp_sock.close()

        if call_state["active"] and not call_state["cancelled"]:
            print(f" -> [{call_id}] Трек завершен. Сервер вешает трубку (BYE).")
            clean_dest_uri = extract_clean_uri(headers.get("Contact")) or extract_clean_uri(headers.get("From"))
            cseq_num = int(headers.get("Cseq", "1").split()[0]) + 1
            bye_req = (
                f"BYE {clean_dest_uri} SIP/2.0\r\n"
                f"Via: SIP/2.0/UDP {server_ip}:{server_port};branch=z9hG4bK{secrets.token_hex(6)}\r\n"
                f"From: {headers.get('To')};tag={to_tag}\r\n"
                f"To: {headers.get('From')}\r\n"
                f"Call-ID: {call_id}\r\n"
                f"CSeq: {cseq_num} BYE\r\n"
                "Max-Forwards: 70\r\n"
                "Content-Length: 0\r\n\r\n"
            )
            sock.sendto(bye_req.encode("utf-8"), client_addr)

        CALLS.pop(call_id, None)

    def stream_rtp(self, rtp_sock, dest_addr, audio_path, call_state):
        print(f" -> Загрузка и подготовка аудио: '{audio_path}'")
        try:
            chunks = load_and_prepare_audio(audio_path)
        except Exception as e:
            print(f"[-] Ошибка загрузки WAV: {e}")
            return

        print(f" -> Старт RTP трансляции ({len(chunks)} пакетов) на {dest_addr}")
        seq_num = secrets.randbelow(10000)
        timestamp = secrets.randbelow(100000)
        ssrc = secrets.randbelow(10000000)

        start_perf = time.perf_counter()

        for idx, chunk in enumerate(chunks):
            if not call_state["active"] or call_state["cancelled"]:
                break

            header = struct.pack("!BBHII", 0x80, 0x00, seq_num & 0xFFFF, timestamp & 0xFFFFFFFF, ssrc)
            rtp_sock.sendto(header + chunk, dest_addr)

            seq_num += 1
            timestamp += 160

            target_time = start_perf + ((idx + 1) * 0.020)
            time_to_wait = target_time - time.perf_counter()

            if time_to_wait > 0.002:
                time.sleep(time_to_wait - 0.001)
            while time.perf_counter() < target_time:
                pass

    def process_in_dialog(self, raw_data, method, headers, call_id, sock, client_addr):
        if call_id not in CALLS:
            return
        call = CALLS[call_id]

        if call.get("type") == "bot":
            if method == "CANCEL":
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
            elif method == "BYE":
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
            return

        dest = call["callee"] if client_addr == call["caller"] else call["caller"]
        sock.sendto(raw_data.encode("utf-8"), dest)

    def handle_response(self, raw_data, start_line, headers, call_id, sock, client_addr):
        if call_id not in CALLS:
            return
        call = CALLS[call_id]
        if call.get("type") == "proxy":
            dest = call["caller"] if client_addr == call["callee"] else call["callee"]
            sock.sendto(raw_data.encode("utf-8"), dest)

            cseq = headers.get("Cseq", "").upper()
            if "BYE" in cseq and "200 OK" in start_line:
                CALLS.pop(call_id, None)


if __name__ == "__main__":
    init_db()
    generate_default_wav(os.path.join(BASE_DIR, "welcome.wav"))

    HOST, PORT = "0.0.0.0", 5060
    print(f"SIP Server запущен на UDP {HOST}:{PORT} (Realm: {REALM})")
    try:
        server = socketserver.ThreadingUDPServer((HOST, PORT), SIPHandler)
        server.serve_forever()
    except PermissionError:
        print("Ошибка: Для порта 5060 требуются права Администратора.")
    except KeyboardInterrupt:
        print("\nОстановка SIP сервера.")