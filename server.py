import http.server
import json
import os
import socket
import hashlib
import secrets
import time
import threading
import re

# ============================================================
# CONFIG
# ============================================================
DATA_FILE = 'data.json'
PORT = 8000
ADMIN_PASSWORD_HASH = None  # set below
SESSION_TIMEOUT = 15 * 60   # 15 minutes
MAX_LOGIN_ATTEMPTS = 5      # per 5 minutes per IP
LOGIN_WINDOW = 5 * 60

# Set the admin password here (it gets hashed on startup)
ADMIN_PASSWORD_PLAIN = "MESSI10!"
ADMIN_PASSWORD_HASH = hashlib.sha256(ADMIN_PASSWORD_PLAIN.encode()).hexdigest()

# ============================================================
# IN-MEMORY STATE (resets when server restarts — that's fine)
# ============================================================
sessions = {}       # {token: {"student_id": int, "expires": timestamp}}
admin_sessions = {} # {token: {"expires": timestamp}}
login_attempts = {} # {ip: [timestamps]}
data_lock = threading.Lock()  # prevents concurrent file writes

# ============================================================
# HELPERS
# ============================================================
def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def read_data():
    with data_lock:
        if not os.path.exists(DATA_FILE):
            empty = {"students": [], "positions": [], "candidates": [], "votes": []}
            with open(DATA_FILE, 'w', encoding='utf-8') as f:
                json.dump(empty, f, indent=2)
            return empty
        with open(DATA_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)

def write_data(data):
    with data_lock:
        # Atomic write: write to temp file, then rename (prevents corruption)
        tmp = DATA_FILE + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, DATA_FILE)

def next_id(arr):
    return max([x['id'] for x in arr], default=0) + 1

def sanitize(text, max_len=100):
    """Basic sanitation: strip HTML tags, limit length."""
    if not isinstance(text, str):
        return ""
    text = re.sub(r'<[^>]+>', '', text)  # strip <script> etc.
    return text.strip()[:max_len]

def check_rate_limit(ip):
    now = time.time()
    attempts = login_attempts.get(ip, [])
    attempts = [t for t in attempts if now - t < LOGIN_WINDOW]
    login_attempts[ip] = attempts
    return len(attempts) < MAX_LOGIN_ATTEMPTS

def record_attempt(ip):
    login_attempts.setdefault(ip, []).append(time.time())

def get_session(token):
    s = sessions.get(token)
    if not s:
        return None
    if time.time() > s['expires']:
        del sessions[token]
        return None
    s['expires'] = time.time() + SESSION_TIMEOUT  # sliding window
    return s

def get_admin_session(token):
    s = admin_sessions.get(token)
    if not s:
        return None
    if time.time() > s['expires']:
        del admin_sessions[token]
        return None
    s['expires'] = time.time() + SESSION_TIMEOUT
    return s

# ============================================================
# REQUEST HANDLER
# ============================================================
class Handler(http.server.SimpleHTTPRequestHandler):

    def log_message(self, format, *args):
        if '/api/' in args[0]:
            print(f"[API] {self.client_address[0]} → {args[0]}")

    # ---------- Response helpers ----------
    def _send_json(self, data, status=200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        # Security headers
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get('Content-Length', 0))
        if length == 0 or length > 2_000_000:  # 2MB cap
            return None
        try:
            return json.loads(self.rfile.read(length).decode('utf-8'))
        except Exception:
            return None

    def _get_token(self):
        return self.headers.get('X-Session-Token', '').strip()

    # ---------- GET ----------
    def do_GET(self):
        if self.path == '/api/ballot':
            self._handle_get_ballot()
        elif self.path == '/api/results':
            self._handle_get_results()
        elif self.path == '/api/admin/students':
            self._handle_admin_list_students()
        elif self.path == '/api/admin/positions':
            self._handle_admin_list_positions()
        elif self.path == '/api/admin/candidates':
            self._handle_admin_list_candidates()
        else:
            super().do_GET()

    # ---------- POST ----------
    def do_POST(self):
        if self.path == '/api/login':
            self._handle_student_login()
        elif self.path == '/api/vote':
            self._handle_vote()
        elif self.path == '/api/logout':
            self._handle_logout()
        elif self.path == '/api/admin/login':
            self._handle_admin_login()
        elif self.path == '/api/admin/logout':
            self._handle_admin_logout()
        elif self.path == '/api/admin/students':
            self._handle_admin_add_student()
        elif self.path == '/api/admin/positions':
            self._handle_admin_add_position()
        elif self.path == '/api/admin/candidates':
            self._handle_admin_add_candidate()
        else:
            self._send_json({"error": "Not found"}, 404)

    # ---------- DELETE ----------
    def do_DELETE(self):
        if self.path.startswith('/api/admin/students/'):
            self._handle_admin_delete_student()
        elif self.path.startswith('/api/admin/positions/'):
            self._handle_admin_delete_position()
        elif self.path.startswith('/api/admin/candidates/'):
            self._handle_admin_delete_candidate()
        else:
            self._send_json({"error": "Not found"}, 404)

    # ========================================================
    # STUDENT AUTH
    # ========================================================
    def _handle_student_login(self):
        ip = self.client_address[0]
        if not check_rate_limit(ip):
            return self._send_json({"error": "Too many attempts. Wait 5 minutes."}, 429)

        body = self._read_body()
        if not body:
            return self._send_json({"error": "Invalid request"}, 400)

        index_num = sanitize(body.get('index_num', ''), 50)
        full_name = sanitize(body.get('full_name', ''), 100)
        if not index_num or not full_name:
            record_attempt(ip)
            return self._send_json({"error": "Missing credentials"}, 400)

        db = read_data()
        student = next(
            (s for s in db['students']
             if s['index_num'] == index_num and s['full_name'] == full_name),
            None
        )
        if not student:
            record_attempt(ip)
            return self._send_json({"error": "Invalid credentials"}, 401)

        # Issue a secure random token
        token = secrets.token_urlsafe(32)
        sessions[token] = {
            "student_id": student['id'],
            "expires": time.time() + SESSION_TIMEOUT
        }
        self._send_json({"success": True, "token": token})

    def _handle_logout(self):
        token = self._get_token()
        sessions.pop(token, None)
        self._send_json({"success": True})

    # ========================================================
    # BALLOT (what the voter sees)
    # ========================================================
    def _handle_get_ballot(self):
        session = get_session(self._get_token())
        if not session:
            return self._send_json({"error": "Unauthorized"}, 401)

        db = read_data()
        student_id = session['student_id']

        # Build ballot for THIS student only.
        # Do NOT include vote counts, other students, or vote records.
        positions_sorted = sorted(db['positions'], key=lambda p: p.get('sort_order', 0))
        ballot = []
        for pos in positions_sorted:
            candidates = [
                {"id": c['id'], "name": c['name'], "image_url": c.get('image_url')}
                for c in db['candidates'] if c['position_id'] == pos['id']
            ]
            already_voted = any(
                v['student_id'] == student_id and v['position_id'] == pos['id']
                for v in db['votes']
            )
            ballot.append({
                "id": pos['id'],
                "title": pos['title'],
                "candidates": candidates,
                "voted": already_voted
            })
        self._send_json({"ballot": ballot})

    # ========================================================
    # VOTE (the most security-critical endpoint)
    # ========================================================
    def _handle_vote(self):
        session = get_session(self._get_token())
        if not session:
            return self._send_json({"error": "Unauthorized"}, 401)

        body = self._read_body()
        if not body:
            return self._send_json({"error": "Invalid request"}, 400)

        try:
            position_id = int(body.get('position_id'))
            candidate_id = int(body.get('candidate_id'))
        except (TypeError, ValueError):
            return self._send_json({"error": "Invalid vote data"}, 400)

        student_id = session['student_id']
        db = read_data()

        # --- Server-side validation (NEVER trust the client) ---
        # 1. Student hasn't voted for this position yet
        if any(v['student_id'] == student_id and v['position_id'] == position_id
               for v in db['votes']):
            return self._send_json({"error": "You already voted for this position"}, 409)

        # 2. Candidate exists AND belongs to the position
        candidate = next(
            (c for c in db['candidates']
             if c['id'] == candidate_id and c['position_id'] == position_id),
            None
        )
        if not candidate:
            return self._send_json({"error": "Invalid candidate"}, 400)

        # 3. Position exists
        if not any(p['id'] == position_id for p in db['positions']):
            return self._send_json({"error": "Invalid position"}, 400)

        # --- Record the vote ---
        db['votes'].append({
            "id": next_id(db['votes']),
            "student_id": student_id,
            "position_id": position_id,
            "candidate_id": candidate_id
        })
        candidate['vote_count'] = candidate.get('vote_count', 0) + 1
        for s in db['students']:
            if s['id'] == student_id:
                s['voted'] = 1
                break

        write_data(db)
        self._send_json({"success": True})

    # ========================================================
    # PUBLIC RESULTS (aggregated only — no student info)
    # ========================================================
    def _handle_get_results(self):
        db = read_data()
        positions_sorted = sorted(db['positions'], key=lambda p: p.get('sort_order', 0))
        results = []
        for pos in positions_sorted:
            candidates = [
                {
                    "id": c['id'],
                    "name": c['name'],
                    "image_url": c.get('image_url'),
                    "vote_count": c.get('vote_count', 0)
                }
                for c in db['candidates'] if c['position_id'] == pos['id']
            ]
            results.append({"id": pos['id'], "title": pos['title'], "candidates": candidates})
        self._send_json({"results": results})

    # ========================================================
    # ADMIN AUTH
    # ========================================================
    def _handle_admin_login(self):
        ip = self.client_address[0]
        if not check_rate_limit(ip):
            return self._send_json({"error": "Too many attempts"}, 429)

        body = self._read_body()
        if not body:
            return self._send_json({"error": "Invalid request"}, 400)

        password = body.get('password', '')
        provided_hash = hashlib.sha256(password.encode()).hexdigest()

        if not secrets.compare_digest(provided_hash, ADMIN_PASSWORD_HASH):
            record_attempt(ip)
            return self._send_json({"error": "Wrong password"}, 401)

        token = secrets.token_urlsafe(32)
        admin_sessions[token] = {"expires": time.time() + SESSION_TIMEOUT}
        self._send_json({"success": True, "token": token})

    def _handle_admin_logout(self):
        admin_sessions.pop(self._get_token(), None)
        self._send_json({"success": True})

    def _admin_required(self):
        return get_admin_session(self._get_token()) is not None

    # ========================================================
    # ADMIN ACTIONS
    # ========================================================
    def _handle_admin_list_students(self):
        if not self._admin_required():
            return self._send_json({"error": "Unauthorized"}, 401)
        db = read_data()
        # Hide nothing (admin needs to see) but format clean
        self._send_json({"students": db['students']})

    def _handle_admin_add_student(self):
        if not self._admin_required():
            return self._send_json({"error": "Unauthorized"}, 401)
        body = self._read_body()
        if not body:
            return self._send_json({"error": "Invalid request"}, 400)

        index_num = sanitize(body.get('index_num', ''), 50)
        full_name = sanitize(body.get('full_name', ''), 100)
        if not index_num or not full_name:
            return self._send_json({"error": "Missing fields"}, 400)

        db = read_data()
        if any(s['index_num'] == index_num for s in db['students']):
            return self._send_json({"error": "Index already exists"}, 409)

        db['students'].append({
            "id": next_id(db['students']),
            "index_num": index_num,
            "full_name": full_name,
            "voted": 0
        })
        write_data(db)
        self._send_json({"success": True})

    def _handle_admin_delete_student(self):
        if not self._admin_required():
            return self._send_json({"error": "Unauthorized"}, 401)
        try:
            student_id = int(self.path.rsplit('/', 1)[-1])
        except ValueError:
            return self._send_json({"error": "Invalid id"}, 400)
        db = read_data()
        db['students'] = [s for s in db['students'] if s['id'] != student_id]
        db['votes'] = [v for v in db['votes'] if v['student_id'] != student_id]
        write_data(db)
        self._send_json({"success": True})

    def _handle_admin_list_positions(self):
        if not self._admin_required():
            return self._send_json({"error": "Unauthorized"}, 401)
        db = read_data()
        self._send_json({"positions": db['positions']})

    def _handle_admin_add_position(self):
        if not self._admin_required():
            return self._send_json({"error": "Unauthorized"}, 401)
        body = self._read_body()
        if not body:
            return self._send_json({"error": "Invalid request"}, 400)
        title = sanitize(body.get('title', ''), 100)
        if not title:
            return self._send_json({"error": "Title required"}, 400)
        try:
            order = int(body.get('sort_order', 0))
        except (TypeError, ValueError):
            order = 0
        db = read_data()
        db['positions'].append({
            "id": next_id(db['positions']),
            "title": title,
            "sort_order": order
        })
        write_data(db)
        self._send_json({"success": True})

    def _handle_admin_delete_position(self):
        if not self._admin_required():
            return self._send_json({"error": "Unauthorized"}, 401)
        try:
            pid = int(self.path.rsplit('/', 1)[-1])
        except ValueError:
            return self._send_json({"error": "Invalid id"}, 400)
        db = read_data()
        db['positions'] = [p for p in db['positions'] if p['id'] != pid]
        db['candidates'] = [c for c in db['candidates'] if c['position_id'] != pid]
        db['votes'] = [v for v in db['votes'] if v['position_id'] != pid]
        write_data(db)
        self._send_json({"success": True})

    def _handle_admin_list_candidates(self):
        if not self._admin_required():
            return self._send_json({"error": "Unauthorized"}, 401)
        db = read_data()
        self._send_json({"candidates": db['candidates']})

    def _handle_admin_add_candidate(self):
        if not self._admin_required():
            return self._send_json({"error": "Unauthorized"}, 401)
        body = self._read_body()
        if not body:
            return self._send_json({"error": "Invalid request"}, 400)
        try:
            position_id = int(body.get('position_id'))
        except (TypeError, ValueError):
            return self._send_json({"error": "Invalid position"}, 400)
        name = sanitize(body.get('name', ''), 100)
        image_url = body.get('image_url', '')
        if not name:
            return self._send_json({"error": "Name required"}, 400)
        # Image URL must be data:image/... (base64) or a relative path
        if image_url and not (
            image_url.startswith('data:image/') or
            image_url.startswith('/images/')
        ):
            return self._send_json({"error": "Invalid image"}, 400)

        db = read_data()
        if not any(p['id'] == position_id for p in db['positions']):
            return self._send_json({"error": "Position not found"}, 400)

        db['candidates'].append({
            "id": next_id(db['candidates']),
            "position_id": position_id,
            "name": name,
            "image_url": image_url,
            "vote_count": 0
        })
        write_data(db)
        self._send_json({"success": True})

    def _handle_admin_delete_candidate(self):
        if not self._admin_required():
            return self._send_json({"error": "Unauthorized"}, 401)
        try:
            cid = int(self.path.rsplit('/', 1)[-1])
        except ValueError:
            return self._send_json({"error": "Invalid id"}, 400)
        db = read_data()
        db['candidates'] = [c for c in db['candidates'] if c['id'] != cid]
        db['votes'] = [v for v in db['votes'] if v['candidate_id'] != cid]
        write_data(db)
        self._send_json({"success": True})


# ============================================================
# START SERVER
# ============================================================
if __name__ == '__main__':
    ip = get_local_ip()
    print("=" * 60)
    print("  ELECTROVOTE SECURE SERVER")
    print("=" * 60)
    print(f"  Local:    http://localhost:{PORT}")
    print(f"  Network:  http://{ip}:{PORT}")
    print(f"  Admin password: {ADMIN_PASSWORD_PLAIN}")
    print("  Press Ctrl+C to stop")
    print("=" * 60)
    server = http.server.ThreadingHTTPServer(('0.0.0.0', PORT), Handler)
    server.serve_forever()