"""
Diamond Points - Streamlit version
Staff log in with Staff ID + PIN, scan vendor/booth QR codes, spend or earn diamonds.
Committee has a separate console to manage staff, QR codes and the log.

Run locally:   streamlit run app.py
"""
import hashlib
import hmac
import io
import random
import secrets
import textwrap
import time
from datetime import datetime
from zoneinfo import ZoneInfo

import cv2
import numpy as np
import pandas as pd
import qrcode
import streamlit as st
from PIL import Image, ImageDraw, ImageFont
from sqlalchemy import create_engine, text

st.set_page_config(page_title="Diamond Points", page_icon="💎", layout="centered")

TZ = ZoneInfo("Asia/Kuala_Lumpur")
MAX_ATTEMPTS = 5
LOCK_MINUTES = 15


# ----------------------------------------------------------------------------
# Settings (secrets). On your laptop these fall back to simple defaults.
# On Streamlit Cloud you set them in the app's "Secrets" box.
# ----------------------------------------------------------------------------
def secret(name, default):
    try:
        return str(st.secrets[name])
    except Exception:
        return default


ADMIN_PIN = secret("ADMIN_PIN", "2026")  # CHANGE THIS for the real event
QR_SECRET = secret("QR_SECRET", "change-this-secret")  # CHANGE THIS too
DATABASE_URL = secret("DATABASE_URL", "sqlite:///diamond.db")


# ----------------------------------------------------------------------------
# Database
# ----------------------------------------------------------------------------
@st.cache_resource
def get_engine():
    kwargs = {}
    if DATABASE_URL.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
    else:
        kwargs["pool_pre_ping"] = True
    return create_engine(DATABASE_URL, **kwargs)


engine = get_engine()


def rows(sql, **params):
    with engine.connect() as c:
        return c.execute(text(sql), params).mappings().all()


def execute(sql, **params):
    with engine.begin() as c:
        c.execute(text(sql), params)


def now_ms():
    return int(time.time() * 1000)


def fmt_time(t):
    return datetime.fromtimestamp(t / 1000, TZ).strftime("%I:%M %p")


# ---- PIN hashing (we never store the real PIN) ----
def hash_pin(pin, salt=None):
    salt = salt or secrets.token_hex(8)
    h = hashlib.pbkdf2_hmac("sha256", pin.encode(), salt.encode(), 100_000).hex()
    return f"{salt}${h}"


def verify_pin(pin, stored):
    salt, _ = stored.split("$", 1)
    return hmac.compare_digest(hash_pin(pin, salt), stored)


SCHEMA = [
    """CREATE TABLE IF NOT EXISTS staff (
        id TEXT PRIMARY KEY, name TEXT, dept TEXT, pin_hash TEXT,
        start_pts INTEGER, balance INTEGER, must_change INTEGER DEFAULT 1,
        failed INTEGER DEFAULT 0, locked_until BIGINT DEFAULT 0)""",
    "CREATE TABLE IF NOT EXISTS vendors (id TEXT PRIMARY KEY, name TEXT, amounts TEXT)",
    "CREATE TABLE IF NOT EXISTS booths (id TEXT PRIMARY KEY, name TEXT, points INTEGER)",
    """CREATE TABLE IF NOT EXISTS txns (
        ref TEXT PRIMARY KEY, t BIGINT, staff_id TEXT, kind TEXT,
        src TEXT, src_name TEXT, amt INTEGER, reason TEXT)""",
    """CREATE TABLE IF NOT EXISTS claims (
        staff_id TEXT, booth_id TEXT, PRIMARY KEY (staff_id, booth_id))""",
]


def seed_sample_data():
    """200 sample staff (PIN 1234), 6 vendors, 3 booths. For testing only."""
    r = random.Random(86)
    first = ["Nur Aisyah", "Muhammad Hafiz", "Siti Mariam", "Amirul", "Tan Wei", "Lim Jun Hao",
             "Wong Mei Xin", "Priya", "Arjun", "Kavitha", "Danial", "Anis"]
    last = ["Rahman", "Ismail", "Hassan", "Tan", "Lim", "Wong", "Pillai", "Nair", "Raj", "Omar"]
    depts = ["Sales", "Finance", "Legal", "Projects", "Marketing", "GPE",
             "Human Resources", "Procurement", "Customer Care", "Contracts"]
    shared_hash = hash_pin("1234")  # demo only: same hash reused so seeding is fast
    staff = []
    for i in range(1, 201):
        start = 5 * round((20 + r.random() * 100) / 5)
        staff.append(dict(id=f"LBS{i:04d}", name=f"{r.choice(first)} {r.choice(last)}",
                          dept=r.choice(depts), ph=shared_hash, s=start, b=start))
    vendors = [(f"V0{i+1}", n) for i, n in enumerate(
        ["Kopi & Teh Cart", "Nasi Lemak Corner", "Bubble Tea Bar",
         "Popcorn Stand", "Photo Booth Prints", "Merch Table"])]
    booths = [("B01", "Lucky Spin", 10), ("B02", "Trivia Corner", 5), ("B03", "Selfie Challenge", 5)]
    with engine.begin() as c:
        for t in ("txns", "claims", "staff", "vendors", "booths"):
            c.execute(text(f"DELETE FROM {t}"))
        c.execute(text("""INSERT INTO staff (id,name,dept,pin_hash,start_pts,balance,must_change)
                          VALUES (:id,:name,:dept,:ph,:s,:b,1)"""), staff)
        c.execute(text("INSERT INTO vendors (id,name,amounts) VALUES (:i,:n,:a)"),
                  [dict(i=i, n=n, a="1,5,10,20") for i, n in vendors])
        c.execute(text("INSERT INTO booths (id,name,points) VALUES (:i,:n,:p)"),
                  [dict(i=i, n=n, p=p) for i, n, p in booths])


@st.cache_resource
def init_db():
    with engine.begin() as c:
        for stmt in SCHEMA:
            c.execute(text(stmt))
    # Older databases don't have the "amounts" column yet. Add it (does nothing if it exists).
    try:
        with engine.begin() as c:
            c.execute(text("ALTER TABLE vendors ADD COLUMN amounts TEXT"))
    except Exception:
        pass
    if rows("SELECT COUNT(*) AS n FROM staff")[0]["n"] == 0:
        seed_sample_data()
    return True


init_db()


# ----------------------------------------------------------------------------
# QR codes: payload = DP1|S or E|source id|amount|name|signature
# The signature uses a secret that stays on the server, so codes can't be forged.
# ----------------------------------------------------------------------------
def clean(s):
    return "".join(ch for ch in str(s).replace("|", " ") if 32 <= ord(ch) < 127).strip()[:40]


def sign(body):
    return hmac.new(QR_SECRET.encode(), body.encode(), hashlib.sha256).hexdigest()[:10]


def make_payload(kind, src_id, amt, name):
    body = "|".join(["DP1", kind, src_id, str(amt), clean(name)])
    return body + "|" + sign(body)


def parse_payload(raw):
    p = str(raw or "").strip().split("|")
    if len(p) != 6 or p[0] != "DP1":
        return None, "This isn't a Diamond Points code."
    if not hmac.compare_digest(sign("|".join(p[:5])), p[5]):
        return None, "This code failed the security check. Ask the committee for an official code."
    try:
        amt = int(p[3])
    except ValueError:
        amt = 0
    if p[1] not in ("S", "E") or not 0 < amt <= 100:
        return None, "This code is damaged. Try scanning again."
    return {"kind": "spend" if p[1] == "S" else "earn", "src": p[2], "amt": amt, "name": p[4]}, None


@st.cache_data(show_spinner=False)
def qr_png(payload):
    img = qrcode.make(payload, box_size=8, border=2)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def _font(size):
    for name in ("DejaVuSans-Bold.ttf", "arialbd.ttf", "Arial Bold.ttf", "Helvetica.ttc"):
        try:
            return ImageFont.truetype(name, size)
        except Exception:
            pass
    try:
        return ImageFont.load_default(size=size)
    except Exception:
        return ImageFont.load_default()


@st.cache_data(show_spinner=False)
def qr_card(payload, title, value):
    """A printable card: stall name on top, the QR code, and what it is worth underneath."""
    qr = qrcode.make(payload, box_size=10, border=2).get_image().convert("RGB")
    lines = textwrap.wrap(title, 22) or [""]
    f_title, f_value = _font(30), _font(40)
    pad = 24
    w = max(qr.width, 420) + pad * 2
    h = pad + len(lines) * 40 + qr.height + 70 + pad
    img = Image.new("RGB", (w, h), "white")
    d = ImageDraw.Draw(img)
    y = pad
    for ln in lines:
        tw = d.textlength(ln, font=f_title)
        d.text(((w - tw) / 2, y), ln, fill="black", font=f_title)
        y += 40
    img.paste(qr, ((w - qr.width) // 2, y))
    y += qr.height + 8
    tw = d.textlength(value, font=f_value)
    d.text(((w - tw) / 2, y), value, fill="black", font=f_value)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def decode_qr(file_bytes):
    """Read a QR code out of a photo. Returns the text or ''."""
    img = cv2.imdecode(np.frombuffer(file_bytes, np.uint8), cv2.IMREAD_COLOR)
    if img is None:
        return ""
    detector = cv2.QRCodeDetector()
    for max_side in (1400, 1000, 700):
        h, w = img.shape[:2]
        scale = min(1.0, max_side / max(h, w))
        small = cv2.resize(img, None, fx=scale, fy=scale) if scale < 1 else img
        data, _, _ = detector.detectAndDecode(small)
        if data:
            return data
        data, _, _ = detector.detectAndDecode(cv2.cvtColor(small, cv2.COLOR_BGR2GRAY))
        if data:
            return data
    return ""


# ----------------------------------------------------------------------------
# Business logic
# ----------------------------------------------------------------------------
DEFAULT_AMOUNTS = [1, 5, 10, 20]


def get_amounts(vendor):
    """The list of QR values a vendor has, e.g. [1, 5, 10, 20]."""
    try:
        vals = sorted({int(x) for x in str(vendor["amounts"] or "").split(",") if x.strip()})
    except ValueError:
        vals = []
    return vals or DEFAULT_AMOUNTS


def parse_amounts(text_in):
    """Turn '1, 5, 10 20' into [1, 5, 10, 20]. Raises ValueError with a friendly message."""
    parts = [x for x in str(text_in).replace(",", " ").split() if x]
    if not parts:
        raise ValueError("Type at least one amount, for example: 1, 5, 10, 20")
    try:
        vals = sorted({int(x) for x in parts})
    except ValueError:
        raise ValueError("Amounts must be whole numbers separated by commas, for example: 1, 5, 10, 20")
    if any(v < 1 or v > 100 for v in vals):
        raise ValueError("Each amount must be between 1 and 100.")
    if len(vals) > 12:
        raise ValueError("That is a lot of codes. Please use 12 amounts or fewer.")
    return vals


def check_code(p):
    """Make sure a scanned code still matches a live vendor/booth. Uses the CURRENT name."""
    if p["kind"] == "spend":
        r = rows("SELECT * FROM vendors WHERE id=:i", i=p["src"])
        if not r:
            return None, "This vendor code is no longer active. Ask the committee for a new one."
        if p["amt"] not in get_amounts(r[0]):
            return None, "This code has been retired. Ask the committee for the current code."
    else:
        r = rows("SELECT * FROM booths WHERE id=:i", i=p["src"])
        if not r:
            return None, "This booth code is no longer active. Ask the committee for a new one."
        if p["amt"] != r[0]["points"]:
            return None, "This code has been retired. Ask the committee for the current code."
    return {**p, "name": r[0]["name"]}, None


def get_staff(sid):
    r = rows("SELECT * FROM staff WHERE id=:i", i=sid)
    return r[0] if r else None


def try_login(sid, pin):
    s = get_staff(sid)
    generic = "Staff ID or PIN doesn't match. Check both and try again."
    if not s:
        return None, generic
    if s["locked_until"] > now_ms():
        return None, "Too many wrong attempts. Try again in a few minutes or ask the committee."
    if verify_pin(pin, s["pin_hash"]):
        execute("UPDATE staff SET failed=0 WHERE id=:i", i=sid)
        return s, None
    failed = s["failed"] + 1
    if failed >= MAX_ATTEMPTS:
        execute("UPDATE staff SET failed=0, locked_until=:u WHERE id=:i",
                u=now_ms() + LOCK_MINUTES * 60_000, i=sid)
    else:
        execute("UPDATE staff SET failed=:f WHERE id=:i", f=failed, i=sid)
    return None, generic


def apply_scan(sid, p):
    """Deduct or add diamonds in ONE database transaction (prevents double spending)."""
    t = now_ms()
    ref = "TX" + secrets.token_hex(3).upper()
    signed = -p["amt"] if p["kind"] == "spend" else p["amt"]
    with engine.begin() as c:
        if p["kind"] == "spend":
            r = c.execute(text("UPDATE staff SET balance = balance - :a WHERE id=:i AND balance >= :a"),
                          dict(a=p["amt"], i=sid))
            if r.rowcount == 0:
                return None, "Not enough diamonds."
        else:
            r = c.execute(text("INSERT INTO claims (staff_id, booth_id) VALUES (:i,:b) ON CONFLICT DO NOTHING"),
                          dict(i=sid, b=p["src"]))
            if r.rowcount == 0:
                return None, f"You've already claimed {p['name']}."
            c.execute(text("UPDATE staff SET balance = balance + :a WHERE id=:i"), dict(a=p["amt"], i=sid))
        c.execute(text("""INSERT INTO txns (ref,t,staff_id,kind,src,src_name,amt,reason)
                          VALUES (:r,:t,:i,:k,:s,:n,:a,'')"""),
                  dict(r=ref, t=t, i=sid, k=p["kind"], s=p["src"], n=p["name"], a=signed))
        bal = c.execute(text("SELECT balance FROM staff WHERE id=:i"), dict(i=sid)).scalar()
    return dict(ref=ref, t=t, amt=signed, balance=bal, name=p["name"], kind=p["kind"]), None


# ----------------------------------------------------------------------------
# Navigation helpers
# ----------------------------------------------------------------------------
def go(view):
    st.session_state.view = view
    st.rerun()


def logout():
    for k in ("staff_id", "is_admin", "pending", "done", "scan_err"):
        st.session_state.pop(k, None)
    go("login")


st.session_state.setdefault("view", "login")

st.markdown("""
<style>
.balance{background:var(--secondary-background-color);border-radius:20px;padding:20px 22px;margin:8px 0 14px}
.balance small{opacity:.7;text-transform:uppercase;letter-spacing:.08em;font-weight:600}
.balance .n{font-size:4rem;font-weight:800;line-height:1.05}
.ticket{background:var(--secondary-background-color);border-radius:20px;padding:20px 22px;margin:8px 0 14px}
.ticket .big{font-size:3.6rem;font-weight:800;line-height:1.05}
.stButton>button,.stFormSubmitButton>button{min-height:3rem;border-radius:12px;font-weight:600}
</style>
""", unsafe_allow_html=True)


# ----------------------------------------------------------------------------
# Views: login
# ----------------------------------------------------------------------------
def view_login():
    st.markdown("## 💎 Diamond Points")
    st.write("Log in, scan the QR code at the stall, and your points are deducted once you confirm.")
    with st.form("login"):
        sid = st.text_input("Staff ID", placeholder="e.g. LBS0001")
        pin = st.text_input("PIN", type="password", max_chars=8)
        ok = st.form_submit_button("Log in", type="primary", width="stretch")
    if ok:
        s, err = try_login(sid.strip().upper(), pin.strip())
        if err:
            st.error(err)
        else:
            st.session_state.staff_id = s["id"]
            go("change_pin" if s["must_change"] else "home")
    st.caption("Sample data: staff IDs LBS0001 to LBS0200, PIN 1234 (you'll be asked to set your own PIN).")
    with st.expander("Committee login"):
        with st.form("admin_login"):
            ap = st.text_input("Committee PIN", type="password")
            if st.form_submit_button("Open committee console"):
                if hmac.compare_digest(ap.strip(), ADMIN_PIN):
                    st.session_state.is_admin = True
                    go("admin")
                else:
                    st.error("That committee PIN isn't right.")


def view_change_pin():
    sid = st.session_state.get("staff_id")
    if not sid:
        return go("login")
    st.markdown("## Set your own PIN")
    st.info("For your security, please choose a new 6-digit PIN before continuing.")
    with st.form("chg"):
        p1 = st.text_input("New PIN (6 digits)", type="password", max_chars=6)
        p2 = st.text_input("Confirm new PIN", type="password", max_chars=6)
        ok = st.form_submit_button("Save PIN", type="primary", width="stretch")
    if ok:
        weak = {"123456", "000000", "111111", "654321", "121212", "123123"}
        if p1 != p2:
            st.error("The two PINs don't match.")
        elif not (p1.isdigit() and len(p1) == 6):
            st.error("PIN must be exactly 6 digits.")
        elif p1 in weak or p1 == sid:
            st.error("That PIN is too easy to guess. Pick another.")
        else:
            execute("UPDATE staff SET pin_hash=:h, must_change=0 WHERE id=:i", h=hash_pin(p1), i=sid)
            go("home")


# ----------------------------------------------------------------------------
# Views: staff
# ----------------------------------------------------------------------------
def view_home():
    sid = st.session_state.get("staff_id")
    u = get_staff(sid) if sid else None
    if not u:
        return go("login")
    c1, c2 = st.columns([4, 1])
    c1.caption(u["dept"].upper())
    c1.markdown(f"### {u['name']}")
    if c2.button("Log out"):
        logout()
    st.markdown(
        f"""<div class="balance"><small>Diamonds available</small>
        <div class="n">💎 {u['balance']:,}</div><small>{u['id']}</small></div>""",
        unsafe_allow_html=True)
    if st.button("📷 Scan a QR code", type="primary", width="stretch"):
        st.session_state.scan_err = None
        go("scan")
    st.subheader("Your activity")
    mine = rows("SELECT * FROM txns WHERE staff_id=:i ORDER BY t DESC LIMIT 50", i=sid)
    if not mine:
        st.caption(f"No scans yet. Your starting balance is {u['start_pts']:,} diamonds.")
    for t in mine:
        label = "Adjusted by committee" if t["kind"] == "adjust" else t["src_name"]
        sub = fmt_time(t["t"]) + (f" · {t['reason']}" if t["reason"] else "")
        left, right = st.columns([4, 1])
        left.markdown(f"**{label}**  \n<small>{sub}</small>", unsafe_allow_html=True)
        right.markdown(f"**{'+' if t['amt'] > 0 else '−'}{abs(t['amt'])}**")


def to_confirm(raw):
    p, err = parse_payload(raw)
    if err:
        st.session_state.scan_err = err
        return st.rerun()
    p, err = check_code(p)
    if err:
        st.session_state.scan_err = err
        return st.rerun()
    st.session_state.scan_err = None
    st.session_state.pending = p
    go("confirm")


def view_scan():
    if not st.session_state.get("staff_id"):
        return go("login")
    c1, c2 = st.columns([4, 1])
    c1.markdown("### Scan the stall's QR")
    if c2.button("Cancel"):
        go("home")
    if st.session_state.get("scan_err"):
        st.error(st.session_state.scan_err)
    st.caption("Hold the code inside the frame and keep it sharp.")
    shot = st.camera_input("Take a photo of the QR code")
    if shot is not None:
        raw = decode_qr(shot.getvalue())
        if raw:
            return to_confirm(raw)
        st.error("Couldn't find a QR code in that photo. Fill the frame with the code and try again.")
    with st.expander("Demo only: simulate a scan (remove before the event)"):
        opts = {}
        for v in rows("SELECT * FROM vendors ORDER BY id"):
            for a in get_amounts(v):
                opts[f"{v['name']} · deduct {a}"] = make_payload("S", v["id"], a, v["name"])
        for b in rows("SELECT * FROM booths ORDER BY id"):
            opts[f"{b['name']} · earn {b['points']}"] = make_payload("E", b["id"], b["points"], b["name"])
        choice = st.selectbox("Code to simulate", list(opts))
        if st.button("Simulate this scan"):
            to_confirm(opts[choice])


def view_confirm():
    sid = st.session_state.get("staff_id")
    p = st.session_state.get("pending")
    u = get_staff(sid) if sid else None
    if not u or not p:
        return go("home" if u else "login")
    spend = p["kind"] == "spend"
    after = u["balance"] + (-p["amt"] if spend else p["amt"])
    warn = ""
    if spend and after < 0:
        warn = f"Not enough diamonds. You need {p['amt']} and have {u['balance']}."
    if not spend and rows("SELECT 1 FROM claims WHERE staff_id=:i AND booth_id=:b", i=sid, b=p["src"]):
        warn = f"You've already claimed {p['name']}. Each booth counts once per person."
    st.markdown(
        f"""<div class="ticket"><small>{'PAY VENDOR' if spend else 'CLAIM BOOTH REWARD'}</small>
        <h3 style="margin:.2rem 0">{p['name']}</h3>
        <div class="big">{'−' if spend else '+'}{p['amt']}</div><hr>
        Your balance now: <b>{u['balance']:,}</b><br>Balance after: <b>{after:,}</b></div>""",
        unsafe_allow_html=True)
    if warn:
        st.warning(warn)
    label = f"Confirm and pay {p['amt']}" if spend else f"Claim {p['amt']} diamonds"
    if st.button(label, type="primary", width="stretch", disabled=bool(warn)):
        p, err = check_code(p)  # the code could have been retired while this screen was open
        result = None
        if not err:
            result, err = apply_scan(sid, p)
        if err:
            st.session_state.scan_err = err
            st.session_state.pending = None
            return go("scan")
        st.session_state.pending = None
        st.session_state.done = result
        go("done")
    if st.button("Cancel", width="stretch"):
        st.session_state.pending = None
        go("home")


def view_done():
    sid = st.session_state.get("staff_id")
    d = st.session_state.get("done")
    u = get_staff(sid) if sid else None
    if not u or not d:
        return go("home" if u else "login")
    spend = d["kind"] == "spend"
    st.markdown(
        f"""<div class="ticket">
        <small>{'PAID TO' if spend else 'EARNED AT'}</small>
        <h3 style="margin:.2rem 0">✅ {d['name']}</h3>
        <div class="big" style="color:{'inherit' if spend else '#0F7A57'}">{'−' if spend else '+'}{abs(d['amt'])}</div>
        <hr>Staff: <b>{u['name']}</b><br>Reference: <code>{d['ref']}</code><br>
        New balance: <b>{d['balance']:,}</b></div>""",
        unsafe_allow_html=True)
    # Live clock: runs in the browser, so a screenshot can't fake it.
    st.iframe(
        """<div style="font:600 1.8rem ui-monospace,Menlo,monospace;color:#0F7A57;text-align:center">
        <span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:#0F7A57;margin-right:8px"></span>
        <span id="c"></span></div>
        <script>function t(){document.getElementById('c').textContent=
        new Date().toLocaleTimeString('en-MY',{hour:'2-digit',minute:'2-digit',second:'2-digit'})}
        t();setInterval(t,1000);</script>""", height=60)
    st.info("Show this screen to the stall. The live clock shows it isn't a screenshot.")
    if st.button("Done", type="primary", width="stretch"):
        st.session_state.done = None
        go("home")


# ----------------------------------------------------------------------------
# Views: committee console
# ----------------------------------------------------------------------------
@st.dialog("Adjust diamonds")
def adjust_dialog(sid):
    s = get_staff(sid)
    st.write(f"**{s['name']}** ({sid}) — balance **{s['balance']}**")
    n = st.number_input("Change (use minus to remove)", step=1, value=0)
    reason = st.text_input("Reason", placeholder="e.g. Won lucky draw, scanner error refund")
    if st.button("Save adjustment", type="primary"):
        if n == 0:
            st.error("Enter a number other than zero.")
        elif not reason.strip():
            st.error("Add a reason so the log explains the change.")
        else:
            with engine.begin() as c:
                r = c.execute(text("UPDATE staff SET balance = balance + :n WHERE id=:i AND balance + :n >= 0"),
                              dict(n=int(n), i=sid))
                if r.rowcount == 0:
                    st.error("That would take the balance below zero.")
                    return
                c.execute(text("""INSERT INTO txns (ref,t,staff_id,kind,src,src_name,amt,reason)
                                  VALUES (:r,:t,:i,'adjust','COMMITTEE','Committee',:a,:why)"""),
                          dict(r="ADJ" + secrets.token_hex(3).upper(), t=now_ms(), i=sid,
                               a=int(n), why=reason.strip()))
            st.rerun()


def admin_overview():
    held = rows("SELECT COALESCE(SUM(balance),0) AS v FROM staff")[0]["v"]
    spent = rows("SELECT COALESCE(-SUM(amt),0) AS v FROM txns WHERE kind='spend'")[0]["v"]
    earned = rows("SELECT COALESCE(SUM(amt),0) AS v FROM txns WHERE kind='earn'")[0]["v"]
    n_staff = rows("SELECT COUNT(*) AS v FROM staff")[0]["v"]
    active = rows("SELECT COUNT(DISTINCT staff_id) AS v FROM txns")[0]["v"]
    a, b = st.columns(2)
    a.metric("Eligible staff", f"{n_staff:,}", f"{active} active")
    b.metric("Diamonds still held", f"{held:,}")
    a.metric("Spent at vendors", f"{spent:,}")
    b.metric("Earned at booths", f"{earned:,}")
    st.subheader("Vendors")
    st.dataframe(pd.DataFrame(rows("""SELECT v.name AS Vendor, COUNT(t.ref) AS Scans,
        COALESCE(-SUM(t.amt),0) AS Diamonds FROM vendors v
        LEFT JOIN txns t ON t.src=v.id AND t.kind='spend' GROUP BY v.id, v.name ORDER BY v.id""")),
        width="stretch", hide_index=True)
    st.subheader("Earning booths")
    st.dataframe(pd.DataFrame(rows("""SELECT b.name AS Booth, b.points AS Reward, COUNT(t.ref) AS Claims,
        COALESCE(SUM(t.amt),0) AS "Diamonds given" FROM booths b
        LEFT JOIN txns t ON t.src=b.id AND t.kind='earn' GROUP BY b.id, b.name, b.points ORDER BY b.id""")),
        width="stretch", hide_index=True)
    with st.expander("Reset to sample data"):
        st.caption("Restores 200 sample staff, sample vendors and booths, and clears every scan.")
        if st.checkbox("Yes, wipe everything and restore the sample data") and st.button("Reset now"):
            seed_sample_data()
            st.success("Sample data restored.")
            st.rerun()


def admin_staff():
    q = st.text_input("Search by name, staff ID or department")
    like = f"%{q.strip().lower()}%"
    found = rows("""SELECT id, name, dept, start_pts, balance FROM staff
                    WHERE LOWER(id || ' ' || name || ' ' || dept) LIKE :q ORDER BY id LIMIT 100""", q=like)
    df = pd.DataFrame(found).rename(columns={"id": "Staff ID", "name": "Name", "dept": "Department",
                                             "start_pts": "Start", "balance": "Balance"})
    st.dataframe(df, width="stretch", hide_index=True)
    st.caption(f"Showing up to 100 matches ({len(found)} shown). Search to narrow down.")
    if found:
        ids = [r["id"] for r in found]
        names = {r["id"]: f"{r['id']} — {r['name']}" for r in found}
        pick = st.selectbox("Choose a staff member", ids, format_func=names.get)
        c1, c2 = st.columns(2)
        if c1.button("Adjust diamonds", width="stretch"):
            adjust_dialog(pick)
        if c2.button("Reset PIN", width="stretch"):
            temp = f"{secrets.randbelow(900000) + 100000}"
            execute("UPDATE staff SET pin_hash=:h, must_change=1, failed=0, locked_until=0 WHERE id=:i",
                    h=hash_pin(temp), i=pick)
            st.success(f"Temporary PIN for {pick}: **{temp}** — tell them privately. They must set a new one at next login.")
    with st.expander("Import staff list (CSV)"):
        st.caption("Columns: staff_id, name, department, pin, points. The pin column is the temporary PIN. "
                   "**This replaces the current staff list and clears the log.**")
        template = "staff_id,name,department,pin,points\nLBS0001,Nur Aisyah Rahman,Finance,482913,85\n"
        st.download_button("Download CSV template", template, "staff_template.csv", "text/csv")
        up = st.file_uploader("CSV file", type=["csv"])
        if up is not None:
            try:
                df = pd.read_csv(up, dtype=str).fillna("")
                df.columns = [c.strip().lower() for c in df.columns]
                need = ["staff_id", "name", "department", "pin", "points"]
                if [c for c in need if c not in df.columns]:
                    raise ValueError("Missing columns. Need: " + ", ".join(need))
                df["staff_id"] = df["staff_id"].str.strip().str.upper()
                df["points"] = pd.to_numeric(df["points"], errors="raise").astype(int)
                if df["staff_id"].duplicated().any():
                    raise ValueError("A staff ID appears twice.")
                if (df["points"] < 0).any():
                    raise ValueError("Points must be 0 or more.")
                st.success(f"{len(df)} staff ready to import.")
                if st.checkbox("I understand this replaces all staff and clears the log") and st.button("Replace staff list"):
                    data = [dict(id=r.staff_id, name=r.name, dept=r.department,
                                 ph=hash_pin(str(r.pin)), s=int(r.points), b=int(r.points))
                            for r in df.itertuples()]
                    with engine.begin() as c:
                        c.execute(text("DELETE FROM txns"))
                        c.execute(text("DELETE FROM claims"))
                        c.execute(text("DELETE FROM staff"))
                        c.execute(text("""INSERT INTO staff (id,name,dept,pin_hash,start_pts,balance,must_change)
                                          VALUES (:id,:name,:dept,:ph,:s,:b,1)"""), data)
                    st.success(f"Imported {len(data)} staff.")
            except Exception as e:
                st.error(f"Couldn't read that file: {e}")


def codes_grid(cards, per_row=3):
    """Show QR cards in rows. cards = [(png_bytes, file_name, key)]"""
    for i in range(0, len(cards), per_row):
        cols = st.columns(per_row)
        for col, (png, fname, key) in zip(cols, cards[i:i + per_row]):
            col.image(png)
            col.download_button("Download", png, fname, "image/png", key=key, width="stretch")


def admin_codes():
    st.info("Each vendor has one QR code per amount. Change the name or the amounts, press Save, "
            "and the codes below update. Codes you remove stop working straight away, "
            "so reprint any new ones. Renaming keeps old printed codes working, but they show the new name.")

    # ---------------- vendors ----------------
    st.subheader("Vendor codes (deduct)")
    vendors = rows("SELECT * FROM vendors ORDER BY id")
    if not vendors:
        st.caption("No vendors yet. Add one below.")
    for v in vendors:
        amts = get_amounts(v)
        with st.expander(f"{v['name']}  ·  {len(amts)} codes: {', '.join(map(str, amts))}"):
            with st.form(f"edit_vendor_{v['id']}"):
                new_name = st.text_input("Vendor name", value=v["name"], key=f"vn_{v['id']}_{v['name']}")
                new_amts = st.text_input("Amounts (one QR code each, separated by commas)",
                                         value=", ".join(map(str, amts)),
                                         key=f"va_{v['id']}_{'_'.join(map(str, amts))}",
                                         help="Example: 1, 5, 10, 20 makes four codes. Use whole numbers from 1 to 100.")
                if st.form_submit_button("Save changes", type="primary"):
                    try:
                        vals = parse_amounts(new_amts)
                        if not clean(new_name):
                            raise ValueError("The vendor name can't be empty.")
                        execute("UPDATE vendors SET name=:n, amounts=:a WHERE id=:i",
                                n=clean(new_name), a=",".join(map(str, vals)), i=v["id"])
                        st.rerun()
                    except ValueError as e:
                        st.error(str(e))
            cards = [(qr_card(make_payload("S", v["id"], a, v["name"]), v["name"], f"Pay {a} diamonds"),
                      f"{clean(v['name'])}_{a}.png", f"dl_{v['id']}_{a}") for a in amts]
            codes_grid(cards)
            if st.checkbox("I want to delete this vendor", key=f"delchk_v_{v['id']}"):
                if st.button("Delete vendor and its codes", key=f"del_v_{v['id']}"):
                    execute("DELETE FROM vendors WHERE id=:i", i=v["id"])
                    st.rerun()
    with st.form("add_vendor", clear_on_submit=True):
        st.markdown("**Add a vendor**")
        n = st.text_input("New vendor name")
        a = st.text_input("Amounts (one QR code each)", value="1, 5, 10, 20")
        if st.form_submit_button("Add vendor"):
            try:
                vals = parse_amounts(a)
                if not clean(n):
                    raise ValueError("Type a vendor name.")
                execute("INSERT INTO vendors (id,name,amounts) VALUES (:i,:n,:a)",
                        i="V" + secrets.token_hex(2).upper(), n=clean(n), a=",".join(map(str, vals)))
                st.rerun()
            except ValueError as e:
                st.error(str(e))

    # ---------------- booths ----------------
    st.subheader("Booth codes (earn, once per person)")
    booths = rows("SELECT * FROM booths ORDER BY id")
    if not booths:
        st.caption("No booths yet. Add one below.")
    for b in booths:
        with st.expander(f"{b['name']}  ·  +{b['points']} diamonds"):
            with st.form(f"edit_booth_{b['id']}"):
                new_name = st.text_input("Booth name", value=b["name"], key=f"bn_{b['id']}_{b['name']}")
                new_pts = st.number_input("Diamonds given (1 to 100)", min_value=1, max_value=100,
                                          value=int(b["points"]), step=1, key=f"bp_{b['id']}_{b['points']}")
                if st.form_submit_button("Save changes", type="primary"):
                    if not clean(new_name):
                        st.error("The booth name can't be empty.")
                    else:
                        execute("UPDATE booths SET name=:n, points=:p WHERE id=:i",
                                n=clean(new_name), p=int(new_pts), i=b["id"])
                        st.rerun()
            codes_grid([(qr_card(make_payload("E", b["id"], b["points"], b["name"]), b["name"],
                                 f"Earn {b['points']} diamonds"),
                         f"{clean(b['name'])}_{b['points']}.png", f"dl_{b['id']}")], per_row=3)
            if st.checkbox("I want to delete this booth", key=f"delchk_b_{b['id']}"):
                if st.button("Delete booth and its code", key=f"del_b_{b['id']}"):
                    execute("DELETE FROM booths WHERE id=:i", i=b["id"])
                    st.rerun()
    with st.form("add_booth", clear_on_submit=True):
        st.markdown("**Add a booth**")
        n = st.text_input("New booth name")
        pts = st.number_input("Diamonds given (1 to 100)", min_value=1, max_value=100, value=5, step=1)
        if st.form_submit_button("Add booth"):
            if not clean(n):
                st.error("Type a booth name.")
            else:
                execute("INSERT INTO booths (id,name,points) VALUES (:i,:n,:p)",
                        i="B" + secrets.token_hex(2).upper(), n=clean(n), p=int(pts))
                st.rerun()
    st.caption("Tip: press Download under a code to get a picture with the stall name and amount on it, ready to print. "
               "Only plain letters, numbers and symbols are kept in names (no emoji or special accents).")


def admin_log():
    kinds = {"All entries": None, "Vendor deductions": "spend", "Booth earnings": "earn", "Manual adjustments": "adjust"}
    kind = kinds[st.selectbox("Filter", list(kinds))]
    data = rows("""SELECT t.t, t.ref, t.staff_id, s.name, t.kind, t.src_name, t.amt, t.reason
                   FROM txns t LEFT JOIN staff s ON s.id=t.staff_id
                   WHERE (:k IS NULL OR t.kind=:k) ORDER BY t.t DESC LIMIT 1000""", k=kind)
    df = pd.DataFrame(data)
    if df.empty:
        return st.caption("No entries yet.")
    df["time"] = df["t"].apply(lambda x: datetime.fromtimestamp(x / 1000, TZ).strftime("%Y-%m-%d %H:%M:%S"))
    df = df[["time", "ref", "staff_id", "name", "kind", "src_name", "amt", "reason"]]
    st.dataframe(df, width="stretch", hide_index=True)
    st.download_button("Download as CSV", df.to_csv(index=False), "diamond_log.csv", "text/csv")


def view_admin():
    if not st.session_state.get("is_admin"):
        return go("login")
    c1, c2 = st.columns([4, 1])
    c1.markdown("### 💎 Committee console")
    if c2.button("Exit"):
        logout()
    t1, t2, t3, t4 = st.tabs(["Overview", "Staff", "QR codes", "Log"])
    with t1:
        admin_overview()
    with t2:
        admin_staff()
    with t3:
        admin_codes()
    with t4:
        admin_log()


# ----------------------------------------------------------------------------
# Router
# ----------------------------------------------------------------------------
{
    "login": view_login,
    "change_pin": view_change_pin,
    "home": view_home,
    "scan": view_scan,
    "confirm": view_confirm,
    "done": view_done,
    "admin": view_admin,
}.get(st.session_state.view, view_login)()
