#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import sqlite3
import ssl
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Optional, Tuple

import requests
import yaml
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from fastapi import FastAPI, Request, Response, Form, Depends
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader, select_autoescape
import paho.mqtt.client as mqtt

# =========================================================
# CONFIG + HELPERS
# =========================================================

CONFIG_PATH = "config.yaml"
DB_PATH = os.environ.get("SPC_DB", "solar_pi_control.db")
PBKDF2_ITERS = 310_000

def now_local_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")

def tomorrow_date() -> datetime.date:
    return (datetime.now() + timedelta(days=1)).date()

def parse_hhmm(s: str) -> Tuple[int, int]:
    m = re.match(r"^(\d{1,2}):(\d{2})$", s.strip())
    if not m:
        raise ValueError(f"Invalid time '{s}', expected HH:MM")
    return int(m.group(1)), int(m.group(2))

def load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

cfg = load_config(CONFIG_PATH)

# SolarAssistant response topic (docs)
SA_RESPONSE_TOPIC = "solar_assistant/set/response_message/state"


# =========================================================
# SQLITE
# =========================================================

def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def db_init() -> None:
    conn = db()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      pass_hash TEXT NOT NULL,
      salt TEXT NOT NULL,
      created_ts TEXT NOT NULL
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS kv (
      k TEXT PRIMARY KEY,
      v TEXT NOT NULL
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS audit (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ts TEXT NOT NULL,
      username TEXT,
      action TEXT NOT NULL,
      detail TEXT NOT NULL
    )
    """)
    conn.commit()
    conn.close()

def kv_get(key: str, default: Any = None) -> Any:
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT v FROM kv WHERE k=?", (key,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return default
    try:
        return json.loads(row["v"])
    except Exception:
        return row["v"]

def kv_set(key: str, value: Any) -> None:
    conn = db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO kv(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
        (key, json.dumps(value, ensure_ascii=False)),
    )
    conn.commit()
    conn.close()

def audit_log(username: Optional[str], action: str, detail: str) -> None:
    conn = db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO audit(ts, username, action, detail) VALUES(?,?,?,?)",
        (now_local_iso(), username, action, detail),
    )
    conn.commit()
    conn.close()

def audit_list(limit: int = 300) -> list[dict]:
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT ts, username, action, detail FROM audit ORDER BY id DESC LIMIT ?", (limit,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows

db_init()


# =========================================================
# SINGLE-USER AUTH (PBKDF2) + COOKIE SESSIONS
# =========================================================

def hash_password(password: str) -> tuple[str, str]:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERS, dklen=32)
    return base64.b64encode(dk).decode(), base64.b64encode(salt).decode()

def verify_password(password: str, pass_hash_b64: str, salt_b64: str) -> bool:
    salt = base64.b64decode(salt_b64.encode())
    expected = base64.b64decode(pass_hash_b64.encode())
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERS, dklen=32)
    return secrets.compare_digest(dk, expected)

def user_exists() -> bool:
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM users LIMIT 1")
    row = cur.fetchone()
    conn.close()
    return row is not None

def get_user_by_username(username: str) -> Optional[dict]:
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT username, pass_hash, salt FROM users WHERE username=?", (username,))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None

def create_first_user(username: str, password: str) -> None:
    ph, salt = hash_password(password)
    conn = db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO users(username, pass_hash, salt, created_ts) VALUES(?,?,?,?)",
        (username, ph, salt, now_local_iso()),
    )
    conn.commit()
    conn.close()

# Signed session token: username|ts|signature
def set_session(resp: Response, cfg: dict, username: str) -> None:
    import hmac
    import hashlib as _hashlib
    ts = str(int(time.time()))
    msg = f"{username}|{ts}".encode("utf-8")
    sig = hmac.new(cfg["app"]["secret_key"].encode("utf-8"), msg, _hashlib.sha256).hexdigest()
    token = f"{username}|{ts}|{sig}"
    resp.set_cookie("spc_session", token, httponly=True, samesite="Lax")

def clear_session(resp: Response) -> None:
    resp.delete_cookie("spc_session")

def get_session_user(cfg: dict, req: Request) -> Optional[str]:
    import hmac
    import hashlib as _hashlib
    token = req.cookies.get("spc_session")
    if not token:
        return None
    parts = token.split("|")
    if len(parts) != 3:
        return None
    username, ts, sig = parts
    msg = f"{username}|{ts}".encode("utf-8")
    expected = hmac.new(cfg["app"]["secret_key"].encode("utf-8"), msg, _hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig):
        return None
    try:
        if int(time.time()) - int(ts) > 7 * 24 * 3600:
            return None
    except Exception:
        return None
    return username

class RedirectException(Exception):
    def __init__(self, url: str):
        self.url = url

def require_login(cfg: dict):
    def _dep(req: Request) -> str:
        u = get_session_user(cfg, req)
        if not u:
            raise RedirectException("/login")
        return u
    return _dep


# =========================================================
# ARSO WEATHER (WINTER: overcast counts as bad)
# =========================================================

@dataclass
class WeatherDecision:
    fetched_at: str
    location: str
    source_url: str
    bad_pv_tomorrow: bool
    reason: str
    summary: dict

def fetch_arso_xml(url: str) -> str:
    r = requests.get(url, timeout=15, headers={"User-Agent": "SolarPiControl/1.0"})
    r.raise_for_status()
    return r.text

def decide_bad_pv_from_arso(xml_text: str, cfg: dict) -> WeatherDecision:
    import xml.etree.ElementTree as ET
    root = ET.fromstring(xml_text)

    want = cfg["weather"].get("charge_if", ["rain", "snow", "fog", "overcast"])
    want_set = {w.lower() for w in want}

    sl = cfg["weather"].get("slovene_keywords", {})
    rain_words = set(w.lower() for w in sl.get("rain", ["dež", "plohe", "nevihte"]))
    snow_words = set(w.lower() for w in sl.get("snow", ["sneg", "sneženje", "snež"]))
    fog_words  = set(w.lower() for w in sl.get("fog",  ["megla", "megleno"]))
    over_words = set(w.lower() for w in sl.get("overcast", ["oblačno"]))

    tomorrow = tomorrow_date()

    def parse_valid_date(s: str) -> Optional[datetime.date]:
        s = s.strip()
        m = re.match(r"^(\d{2})\.(\d{2})\.(\d{4})\s", s)
        if not m:
            return None
        dd, mm, yyyy = int(m.group(1)), int(m.group(2)), int(m.group(3))
        return datetime(yyyy, mm, dd).date()

    chosen: list[dict] = []
    signals: list[str] = []

    for md in root.findall(".//metData"):
        valid = (md.findtext("valid") or "").strip()
        d = parse_valid_date(valid)
        if d != tomorrow:
            continue

        valid_day = (md.findtext("valid_day") or "").strip()
        daypart = (md.findtext("valid_daypart") or "").strip()

        nn_icon = (md.findtext("nn_icon") or "").strip().lower()
        nn_short = (md.findtext("nn_shortText") or "").strip().lower()

        wwsyn_icon = (md.findtext("wwsyn_icon") or "").strip().lower()
        wwsyn_short = (md.findtext("wwsyn_shortText") or "").strip().lower()

        fog_icon = (md.findtext("fog_icon") or "").strip().lower()
        fog_short = (md.findtext("fog_shortText") or "").strip().lower()

        rr_icon = (md.findtext("rr_icon") or "").strip().lower()
        rr_decode = (md.findtext("rr_decodeText") or "").strip().lower()

        block_text = " ".join([nn_short, wwsyn_short, fog_short, rr_decode]).strip()

        overcast_hit = ("overcast" in want_set) and (nn_icon == "overcast" or any(w in nn_short for w in over_words))
        fog_hit = ("fog" in want_set) and (fog_icon != "" or any(w in block_text for w in fog_words))

        rain_hit = False
        if "rain" in want_set:
            if ("rain" in wwsyn_icon) or ("shower" in wwsyn_icon) or any(w in block_text for w in rain_words) or rr_icon != "":
                rain_hit = True

        snow_hit = False
        if "snow" in want_set:
            if ("snow" in wwsyn_icon) or any(w in block_text for w in snow_words):
                snow_hit = True

        if overcast_hit:
            signals.append(f"{valid} ({valid_day} {daypart}): overcast/oblačno")
        if fog_hit:
            signals.append(f"{valid} ({valid_day} {daypart}): fog/megla")
        if rain_hit:
            signals.append(f"{valid} ({valid_day} {daypart}): rain/precip")
        if snow_hit:
            signals.append(f"{valid} ({valid_day} {daypart}): snow")

        chosen.append({
            "valid": valid,
            "valid_day": valid_day,
            "valid_daypart": daypart,
            "nn_icon": nn_icon,
            "nn_shortText": nn_short,
            "wwsyn_icon": wwsyn_icon,
            "wwsyn_shortText": wwsyn_short,
            "fog_icon": fog_icon,
            "fog_shortText": fog_short,
            "rr_icon": rr_icon,
            "rr_decodeText": rr_decode,
            "t": (md.findtext("t") or "").strip(),
            "ff_value_kmh": (md.findtext("ff_value_kmh") or "").strip(),
        })

    bad = len(signals) > 0
    reason = "; ".join(signals) if signals else "no overcast/rain/snow/fog detected for tomorrow"

    return WeatherDecision(
        fetched_at=now_local_iso(),
        location=cfg["weather"]["location_label"],
        source_url=cfg["weather"]["arso_url"],
        bad_pv_tomorrow=bad,
        reason=reason,
        summary={"tomorrow_blocks": chosen[:24]},
    )


# =========================================================
# MQTT STATE + CONTROL
# =========================================================

class MqttState:
    def __init__(self) -> None:
        self.last: dict[str, dict[str, Any]] = {}

    def update(self, topic: str, payload: str, retain: bool) -> None:
        self.last[topic] = {"payload": payload, "ts": now_local_iso(), "retain": retain}

    def get(self, topic: str, default: Any = None) -> Any:
        return self.last.get(topic, default)

mqtt_state = MqttState()

class MqttClient:
    def __init__(self, cfg: dict) -> None:
        self.cfg = cfg
        self.client = mqtt.Client(protocol=mqtt.MQTTv311)

        if cfg["mqtt"].get("username"):
            self.client.username_pw_set(cfg["mqtt"]["username"], cfg["mqtt"].get("password"))

        if cfg["mqtt"].get("tls"):
            cafile = cfg["mqtt"].get("cafile")
            certfile = cfg["mqtt"].get("certfile")
            keyfile = cfg["mqtt"].get("keyfile")
            insecure = bool(cfg["mqtt"].get("insecure", False))

            self.client.tls_set(
                ca_certs=cafile if cafile else None,
                certfile=certfile if certfile else None,
                keyfile=keyfile if keyfile else None,
                cert_reqs=ssl.CERT_REQUIRED if not insecure else ssl.CERT_NONE,
                tls_version=ssl.PROTOCOL_TLS_CLIENT,
            )
            if insecure:
                self.client.tls_insecure_set(True)

        self.client.on_connect = self.on_connect
        self.client.on_message = self.on_message

    def start(self) -> None:
        self.client.connect(self.cfg["mqtt"]["host"], int(self.cfg["mqtt"]["port"]), keepalive=60)
        self.client.loop_start()

    def on_connect(self, client, userdata, flags, rc):
        audit_log(None, "mqtt_connect", f"rc={rc}")
        client.subscribe(self.cfg["mqtt"]["subscribe_filter"])

    def on_message(self, client, userdata, msg):
        try:
            payload = msg.payload.decode("utf-8", errors="replace")
        except Exception:
            payload = repr(msg.payload)
        mqtt_state.update(msg.topic, payload, bool(getattr(msg, "retain", False)))

    def publish(self, topic: str, payload: str) -> None:
        self.client.publish(topic, payload, qos=0, retain=False)

def inverter_ids() -> list[str]:
    return ["inverter_1", "inverter_2", "inverter_3"]

def topic_state(cfg: dict, inverter: str, metric: str) -> str:
    return f"{cfg['mqtt']['state_topic_prefix']}/{inverter}/{metric}/state"

def apply_night_mode(cfg: dict, username: Optional[str], amps: int) -> None:
    """
    Night mode:
      - charger_source_priority = Solar and utility simultaneously
      - max_grid_charge_current = amps
    """
    dry_run = bool(cfg["control"].get("dry_run", True))
    topics = cfg["control"]["topics"]
    payloads = cfg["control"]["payloads"]

    t_prio_tpl = topics["charger_source_priority"]
    t_amps_tpl = topics["max_grid_charge_current"]

    p_prio = payloads["charger_solar_utility"]  # exact SA string
    p_amps = str(amps)

    for inv in inverter_ids():
        t_prio = t_prio_tpl.format(inverter=inv)
        t_amps = t_amps_tpl.format(inverter=inv)

        if dry_run:
            audit_log(username, "dry_run_publish", f"{inv}: {t_prio} <- {p_prio}")
            audit_log(username, "dry_run_publish", f"{inv}: {t_amps} <- {p_amps}")
        else:
            mqtt_client.publish(t_prio, p_prio)
            audit_log(username, "publish", f"{inv}: {t_prio} <- {p_prio}")

            mqtt_client.publish(t_amps, p_amps)
            audit_log(username, "publish", f"{inv}: {t_amps} <- {p_amps}")

    kv_set("last_applied", {"ts": now_local_iso(), "mode": "night", "amps": amps, "by": username})

def apply_day_mode(cfg: dict, username: Optional[str], amps: int) -> None:
    """
    Day mode:
      - charger_source_priority = Solar only
      - max_grid_charge_current = amps (usually 0)
    """
    dry_run = bool(cfg["control"].get("dry_run", True))
    topics = cfg["control"]["topics"]
    payloads = cfg["control"]["payloads"]

    t_prio_tpl = topics["charger_source_priority"]
    t_amps_tpl = topics["max_grid_charge_current"]

    p_prio = payloads["charger_solar_only"]  # exact SA string
    p_amps = str(amps)

    for inv in inverter_ids():
        t_prio = t_prio_tpl.format(inverter=inv)
        t_amps = t_amps_tpl.format(inverter=inv)

        if dry_run:
            audit_log(username, "dry_run_publish", f"{inv}: {t_prio} <- {p_prio}")
            audit_log(username, "dry_run_publish", f"{inv}: {t_amps} <- {p_amps}")
        else:
            mqtt_client.publish(t_prio, p_prio)
            audit_log(username, "publish", f"{inv}: {t_prio} <- {p_prio}")

            mqtt_client.publish(t_amps, p_amps)
            audit_log(username, "publish", f"{inv}: {t_amps} <- {p_amps}")

    kv_set("last_applied", {"ts": now_local_iso(), "mode": "day", "amps": amps, "by": username})


# =========================================================
# SCHEDULER JOBS
# =========================================================

def update_weather(cfg: dict) -> WeatherDecision:
    xml = fetch_arso_xml(cfg["weather"]["arso_url"])
    decision = decide_bad_pv_from_arso(xml, cfg)
    kv_set("weather_last", decision.__dict__)
    kv_set(
        "bad_pv_tomorrow",
        {"date": str(tomorrow_date()), "value": decision.bad_pv_tomorrow, "reason": decision.reason},
    )
    audit_log(None, "weather_update", f"bad_pv_tomorrow={decision.bad_pv_tomorrow} reason={decision.reason}")
    return decision

def job_night_start(cfg: dict) -> None:
    auto = kv_get("auto_enabled", True)
    bad = kv_get("bad_pv_tomorrow", {"value": False}).get("value", False)
    if not auto:
        audit_log(None, "auto_skip", "night_start: auto disabled")
        return
    if not bad:
        audit_log(None, "auto_skip", "night_start: not bad PV tomorrow")
        return
    amps = int(cfg["schedule"]["rainy_grid_charge_amps"])
    apply_night_mode(cfg, None, amps=amps)
    audit_log(None, "auto_apply", f"night_start applied amps={amps}")

def job_night_end(cfg: dict) -> None:
    auto = kv_get("auto_enabled", True)
    if not auto:
        audit_log(None, "auto_skip", "night_end: auto disabled")
        return
    amps = int(cfg["schedule"]["normal_grid_charge_amps"])
    apply_day_mode(cfg, None, amps=amps)
    audit_log(None, "auto_apply", f"night_end applied amps={amps}")


# =========================================================
# FASTAPI + TEMPLATES
# =========================================================

app = FastAPI(title=cfg["app"]["name"])
app.mount("/static", StaticFiles(directory="static"), name="static")

env = Environment(
    loader=FileSystemLoader("templates"),
    autoescape=select_autoescape(["html", "xml"]),
)

@app.exception_handler(RedirectException)
def _redir(_, exc: RedirectException):
    return RedirectResponse(exc.url, status_code=302)

def render(template: str, **ctx) -> HTMLResponse:
    t = env.get_template(template)
    return HTMLResponse(t.render(**ctx))


# =========================================================
# STARTUP (MQTT + SCHEDULER)
# =========================================================

mqtt_client = MqttClient(cfg)
scheduler = BackgroundScheduler()

@app.on_event("startup")
def _startup():
    if kv_get("auto_enabled") is None:
        kv_set("auto_enabled", True)

    mqtt_client.start()

    poll_minutes = int(cfg["weather"].get("poll_minutes", 30))
    scheduler.add_job(lambda: update_weather(cfg), "interval", minutes=poll_minutes, id="weather_poll", replace_existing=True)

    sh, sm = parse_hhmm(cfg["schedule"]["cheap_start"])
    eh, em = parse_hhmm(cfg["schedule"]["cheap_end"])
    scheduler.add_job(lambda: job_night_start(cfg), CronTrigger(hour=sh, minute=sm), id="night_start", replace_existing=True)
    scheduler.add_job(lambda: job_night_end(cfg), CronTrigger(hour=eh, minute=em), id="night_end", replace_existing=True)

    scheduler.start()

    try:
        update_weather(cfg)
    except Exception as e:
        audit_log(None, "weather_error", str(e))


# =========================================================
# ROUTES: AUTH (REGISTER FIRST USER)
# =========================================================

@app.get("/", response_class=HTMLResponse)
def root(req: Request):
    if not user_exists():
        return RedirectResponse("/register", status_code=302)
    u = get_session_user(cfg, req)
    return RedirectResponse("/dashboard" if u else "/login", status_code=302)

@app.get("/register", response_class=HTMLResponse)
def register_page(req: Request):
    if user_exists():
        return RedirectResponse("/login", status_code=302)
    return render("register.html", app=cfg["app"]["name"], error=None)

@app.post("/register", response_class=HTMLResponse)
def register(req: Request,
             username: str = Form(...),
             password: str = Form(...),
             password2: str = Form(...)):
    if user_exists():
        return RedirectResponse("/login", status_code=302)

    username = username.strip()
    if len(username) < 3:
        return render("register.html", app=cfg["app"]["name"], error="Username must be at least 3 characters.")
    if len(password) < 10:
        return render("register.html", app=cfg["app"]["name"], error="Password must be at least 10 characters.")
    if password != password2:
        return render("register.html", app=cfg["app"]["name"], error="Passwords do not match.")

    create_first_user(username, password)
    audit_log(username, "register_ok", "first user created")

    resp = RedirectResponse("/dashboard", status_code=302)
    set_session(resp, cfg, username)
    return resp

@app.get("/login", response_class=HTMLResponse)
def login_page(req: Request):
    if not user_exists():
        return RedirectResponse("/register", status_code=302)
    return render("login.html", app=cfg["app"]["name"], error=None)

@app.post("/login", response_class=HTMLResponse)
def login(req: Request, username: str = Form(...), password: str = Form(...)):
    if not user_exists():
        return RedirectResponse("/register", status_code=302)

    username = username.strip()
    user = get_user_by_username(username)
    if not user or not verify_password(password, user["pass_hash"], user["salt"]):
        audit_log(None, "login_failed", f"user={username}")
        return render("login.html", app=cfg["app"]["name"], error="Invalid username or password.")

    resp = RedirectResponse("/dashboard", status_code=302)
    set_session(resp, cfg, username)
    audit_log(username, "login_ok", "logged in")
    return resp

@app.post("/logout")
def logout(req: Request):
    u = get_session_user(cfg, req)
    resp = RedirectResponse("/login", status_code=302)
    clear_session(resp)
    audit_log(u, "logout", "logged out")
    return resp


# =========================================================
# ROUTES: UI
# =========================================================

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(req: Request, username: str = Depends(require_login(cfg))):
    weather_last = kv_get("weather_last", {})
    bad = kv_get("bad_pv_tomorrow", {"value": False, "reason": "—"})
    auto_enabled = kv_get("auto_enabled", True)
    last_applied = kv_get("last_applied", {})
    sa_resp = mqtt_state.get(SA_RESPONSE_TOPIC, {"payload": "—", "ts": "—"})
    return render(
        "dashboard.html",
        app=cfg["app"]["name"],
        username=username,
        weather=weather_last,
        bad=bad,
        auto_enabled=auto_enabled,
        last_applied=last_applied,
        cheap_start=cfg["schedule"]["cheap_start"],
        cheap_end=cfg["schedule"]["cheap_end"],
        dry_run=cfg["control"].get("dry_run", True),
        sa_resp=sa_resp,
    )

@app.get("/weather", response_class=HTMLResponse)
def weather(req: Request, username: str = Depends(require_login(cfg))):
    weather_last = kv_get("weather_last", {})
    bad = kv_get("bad_pv_tomorrow", {"value": False, "reason": "—"})
    return render("weather.html", app=cfg["app"]["name"], username=username, weather=weather_last, bad=bad)

@app.post("/weather/refresh")
def weather_refresh(req: Request, username: str = Depends(require_login(cfg))):
    try:
        d = update_weather(cfg)
        audit_log(username, "weather_manual_refresh", d.reason)
    except Exception as e:
        audit_log(username, "weather_error", str(e))
    return RedirectResponse("/weather", status_code=302)

@app.get("/inverters", response_class=HTMLResponse)
def inverters(req: Request, username: str = Depends(require_login(cfg))):
    def get(inv: str, metric: str) -> dict:
        return mqtt_state.get(topic_state(cfg, inv, metric), {"payload": "—"})

    invs = []
    for inv in inverter_ids():
        invs.append({
            "id": inv,
            "grid_power": get(inv, "grid_power")["payload"],
            "pv_power": get(inv, "pv_power")["payload"],
            "load_power": get(inv, "load_power")["payload"],
            "battery_voltage": get(inv, "battery_voltage")["payload"],
            "battery_current": get(inv, "battery_current")["payload"],
            "charger_source_priority": get(inv, "charger_source_priority")["payload"],
            "max_grid_charge_current": get(inv, "max_grid_charge_current")["payload"],
        })

    total = {
        "grid_power": mqtt_state.get(f"{cfg['mqtt']['state_topic_prefix']}/total/grid_power/state", {"payload": "—"})["payload"],
        "pv_power": mqtt_state.get(f"{cfg['mqtt']['state_topic_prefix']}/total/pv_power/state", {"payload": "—"})["payload"],
        "load_power": mqtt_state.get(f"{cfg['mqtt']['state_topic_prefix']}/total/load_power/state", {"payload": "—"})["payload"],
        "battery_power": mqtt_state.get(f"{cfg['mqtt']['state_topic_prefix']}/total/battery_power/state", {"payload": "—"})["payload"],
        "soc": mqtt_state.get(f"{cfg['mqtt']['state_topic_prefix']}/total/battery_state_of_charge/state", {"payload": "—"})["payload"],
    }

    return render("inverters.html", app=cfg["app"]["name"], username=username, inverters=invs, total=total)

@app.get("/control", response_class=HTMLResponse)
def control(req: Request, username: str = Depends(require_login(cfg))):
    bad = kv_get("bad_pv_tomorrow", {"value": False, "reason": "—"})
    auto_enabled = kv_get("auto_enabled", True)
    sa_resp = mqtt_state.get(SA_RESPONSE_TOPIC, {"payload": "—", "ts": "—"})
    return render(
        "control.html",
        app=cfg["app"]["name"],
        username=username,
        bad=bad,
        auto_enabled=auto_enabled,
        sa_resp=sa_resp,
        dry_run=cfg["control"].get("dry_run", True),
        night_amps=int(cfg["schedule"]["rainy_grid_charge_amps"]),
        day_amps=int(cfg["schedule"]["normal_grid_charge_amps"]),
    )

@app.post("/control/auto/toggle")
def toggle_auto(req: Request, username: str = Depends(require_login(cfg))):
    current = bool(kv_get("auto_enabled", True))
    kv_set("auto_enabled", not current)
    audit_log(username, "auto_toggle", f"auto_enabled={not current}")
    return RedirectResponse("/control", status_code=302)

@app.post("/control/mode/night")
def manual_night(req: Request, username: str = Depends(require_login(cfg))):
    amps = int(cfg["schedule"]["rainy_grid_charge_amps"])
    apply_night_mode(cfg, username, amps=amps)
    audit_log(username, "manual_apply", f"night_mode amps={amps}")
    return RedirectResponse("/control", status_code=302)

@app.post("/control/mode/day")
def manual_day(req: Request, username: str = Depends(require_login(cfg))):
    amps = int(cfg["schedule"]["normal_grid_charge_amps"])
    apply_day_mode(cfg, username, amps=amps)
    audit_log(username, "manual_apply", f"day_mode amps={amps}")
    return RedirectResponse("/control", status_code=302)

@app.post("/control/custom")
def manual_custom(req: Request,
                  username: str = Depends(require_login(cfg)),
                  amps: int = Form(...),
                  mode: str = Form(...)):
    """
    mode:
      - night (Solar and utility simultaneously)
      - day (Solar only)
    """
    amps = int(amps)
    mode = mode.strip().lower()
    if mode == "night":
        apply_night_mode(cfg, username, amps=amps)
    elif mode == "day":
        apply_day_mode(cfg, username, amps=amps)
    else:
        audit_log(username, "manual_apply_error", f"invalid mode={mode}")
    audit_log(username, "manual_apply", f"custom mode={mode} amps={amps}")
    return RedirectResponse("/control", status_code=302)

@app.get("/logs", response_class=HTMLResponse)
def logs(req: Request, username: str = Depends(require_login(cfg))):
    return render("logs.html", app=cfg["app"]["name"], username=username, logs=audit_list())

@app.get("/settings", response_class=HTMLResponse)
def settings(req: Request, username: str = Depends(require_login(cfg))):
    return render("settings.html", app=cfg["app"]["name"], username=username, cfg=cfg, dry_run=cfg["control"].get("dry_run", True))

@app.post("/settings/dryrun")
def set_dryrun(req: Request, username: str = Depends(require_login(cfg)),
               dry_run: str = Form(...)):
    cfg["control"]["dry_run"] = (dry_run.lower() == "true")
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        yaml.safe_dump(cfg, f, sort_keys=False, allow_unicode=True)
    audit_log(username, "settings_update", f"dry_run={cfg['control']['dry_run']}")
    return RedirectResponse("/settings", status_code=302)

@app.get("/api/status")
def api_status(req: Request, username: str = Depends(require_login(cfg))):
    return JSONResponse({
        "ts": now_local_iso(),
        "weather_last": kv_get("weather_last", {}),
        "bad_pv_tomorrow": kv_get("bad_pv_tomorrow", {"value": False}),
        "auto_enabled": kv_get("auto_enabled", True),
        "last_applied": kv_get("last_applied", {}),
        "dry_run": cfg["control"].get("dry_run", True),
        "sa_response": mqtt_state.get(SA_RESPONSE_TOPIC, {"payload": "—", "ts": "—"}),
    })


# =========================================================
# MAIN
# =========================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=False)
