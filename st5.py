# ==============================================================
# Smart Lost & Found — Phase 1.0 + Auth + CSS
# Core: Deposit / View / Claim / Report / Admin  (protected)
# Auth: Login / Register / Forgot + Reset Page
# Storage: CSV files + images folder
# Deps: streamlit, pandas, pillow, qrcode
# ==============================================================

from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict
import json, uuid, secrets, hashlib

import streamlit as st
import pandas as pd
from PIL import Image
import qrcode

# ------------------------------- Config -------------------------------
APP_TITLE = "Smart Lost & Found"
DATA_DIR = Path("data")
IMG_DIR = DATA_DIR / "images"
ITEMS_CSV = DATA_DIR / "items.csv"
TOKENS_CSV = DATA_DIR / "tokens.csv"
LOGS_CSV = DATA_DIR / "logs.csv"
USERS_CSV = DATA_DIR / "users.csv"  # auth store

# Lockers (simple demo config)
LOCKERS = {
    "owner_known": [f"OK-{i:02d}" for i in range(1, 11)],
    "unknown":     [f"UK-{i:02d}" for i in range(1, 11)],
    "big":         [f"BG-{i:02d}" for i in range(1, 6)],
}
QR_EXPIRY_MIN = 30
RESET_CODE_MINUTES = 15

# ------------------------------ Utilities ------------------------------
def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def now_iso() -> str:
    return now_utc().isoformat()

def gen_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:10]}"

def ensure_fs():
    DATA_DIR.mkdir(exist_ok=True)
    IMG_DIR.mkdir(exist_ok=True)
    if not ITEMS_CSV.exists():
        pd.DataFrame(columns=[
            "id","name","descr","category","size","photo_path",
            "found_location","found_datetime","locker_id","status",
            "verification_question","verification_answer","owner_email",
            "created_by","created_at","claimed_at"
        ]).to_csv(ITEMS_CSV, index=False)
    if not TOKENS_CSV.exists():
        pd.DataFrame(columns=["id","item_id","token","action","expires_at","used"]).to_csv(TOKENS_CSV, index=False)
    if not LOGS_CSV.exists():
        pd.DataFrame(columns=["ts","kind","who","meta"]).to_csv(LOGS_CSV, index=False)
    if not USERS_CSV.exists():
        pd.DataFrame(columns=[
            "id","email","name","salt_hex","pwd_hash_hex","created_at",
            "reset_code","reset_expires_at"
        ]).to_csv(USERS_CSV, index=False)

def load_df(p: Path) -> pd.DataFrame:
    return pd.read_csv(p, dtype=str, keep_default_na=False)

def save_df(p: Path, df: pd.DataFrame):
    df.to_csv(p, index=False)

def log_event(kind: str, who: str, meta: Dict):
    df = load_df(LOGS_CSV)
    df.loc[len(df)] = [now_iso(), kind, who, json.dumps(meta, ensure_ascii=False)]
    save_df(LOGS_CSV, df)

# ------------------------------ Passwords ------------------------------
def hash_password(password: str, salt: Optional[bytes] = None) -> Dict[str, str]:
    if salt is None:
        salt = secrets.token_bytes(16)
    pwd_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 120_000)
    return {"salt_hex": salt.hex(), "pwd_hash_hex": pwd_hash.hex()}

def verify_password(password: str, salt_hex: str, pwd_hash_hex: str) -> bool:
    try:
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(pwd_hash_hex)
        check = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 120_000)
        return secrets.compare_digest(check, expected)
    except Exception:
        return False

# ------------------------------ Users (CSV) ------------------------------
def user_by_email(email: str) -> Optional[dict]:
    df = load_df(USERS_CSV)
    r = df[df["email"].str.lower() == (email or "").strip().lower()]
    if r.empty:
        return None
    return r.iloc[0].to_dict()

def create_user(email: str, name: str, password: str) -> Optional[dict]:
    email = (email or "").strip().lower()
    name = (name or "").strip()
    if not email or not password or not name:
        return None
    if user_by_email(email):
        return None
    creds = hash_password(password)
    df = load_df(USERS_CSV)
    uid = gen_id("usr")
    df.loc[len(df)] = [
        uid, email, name, creds["salt_hex"], creds["pwd_hash_hex"], now_iso(), "", ""
    ]
    save_df(USERS_CSV, df)
    return {"id": uid, "email": email, "name": name}

def set_reset_code(email: str) -> Optional[str]:
    df = load_df(USERS_CSV)
    idx = df.index[df["email"].str.lower() == email.strip().lower()]
    if len(idx) == 0:
        return None
    code = f"{secrets.randbelow(1_000_000):06d}"  # 000000-999999
    exp = (now_utc() + timedelta(minutes=RESET_CODE_MINUTES)).isoformat()
    df.at[idx[0], "reset_code"] = code
    df.at[idx[0], "reset_expires_at"] = exp
    save_df(USERS_CSV, df)
    log_event("password_reset_code", email, {"code": code, "expires_at": exp})
    return code

def verify_reset_code(email: str, code: str) -> bool:
    u = user_by_email(email)
    if not u or not u.get("reset_code"):
        return False
    try:
        exp = datetime.fromisoformat(u["reset_expires_at"])
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
    except Exception:
        return False
    if now_utc() > exp:
        return False
    return secrets.compare_digest((code or "").strip(), u["reset_code"])

def change_password(email: str, new_password: str) -> bool:
    df = load_df(USERS_CSV)
    idx = df.index[df["email"].str.lower() == email.strip().lower()]
    if len(idx) == 0:
        return False
    creds = hash_password(new_password)
    df.at[idx[0], "salt_hex"] = creds["salt_hex"]
    df.at[idx[0], "pwd_hash_hex"] = creds["pwd_hash_hex"]
    df.at[idx[0], "reset_code"] = ""
    df.at[idx[0], "reset_expires_at"] = ""
    save_df(USERS_CSV, df)
    log_event("password_changed", email, {})
    return True

# ---------------------------- Locker/Token -----------------------------
def used_lockers() -> set:
    df = load_df(ITEMS_CSV)
    df = df[df["status"].isin(["stored","pending_claim"])]
    return set(df["locker_id"].tolist())

def free_locker(compartment: str) -> Optional[str]:
    pool = {"owner_known": LOCKERS["owner_known"], "unknown": LOCKERS["unknown"], "big": LOCKERS["big"]}[compartment]
    used = used_lockers()
    for lid in pool:
        if lid not in used:
            return lid
    return None

def create_token(item_id: str, action: str) -> Dict[str, str]:
    df = load_df(TOKENS_CSV)
    tid = gen_id("tok")
    tok = gen_id("t")
    exp = (now_utc() + timedelta(minutes=QR_EXPIRY_MIN)).isoformat()
    df.loc[len(df)] = [tid, item_id, tok, action, exp, "False"]
    save_df(TOKENS_CSV, df)
    return {"id": tid, "token": tok, "expires_at": exp, "action": action}

def get_active_token(item_id: str, action: str) -> Optional[dict]:
    df = load_df(TOKENS_CSV)
    rows = df[(df["item_id"] == item_id) & (df["action"] == action) & (df["used"] == "False")]
    if rows.empty:
        return None
    return rows.iloc[-1].to_dict()

def invalidate_token(token_id: str):
    df = load_df(TOKENS_CSV)
    df.loc[df["id"] == token_id, "used"] = "True"
    save_df(TOKENS_CSV, df)

def token_valid(row: dict, provided: str) -> bool:
    if not row or row.get("used") == "True":
        return False
    try:
        if (provided or "").strip() != row["token"]:
            return False
        exp = datetime.fromisoformat(row["expires_at"])
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return now_utc() <= exp
    except Exception:
        return False

# ----------------------------- Helpers ------------------------------
def save_image(upload) -> Optional[str]:
    if not upload:
        return None
    img = Image.open(upload).convert("RGB")
    fname = f"{uuid.uuid4().hex[:12]}.png"
    path = IMG_DIR / fname
    img.save(path)
    return str(path)

def make_qr(payload: dict) -> Image.Image:
    qr = qrcode.QRCode(border=2, box_size=8)
    qr.add_data(json.dumps(payload))
    qr.make(fit=True)
    return qr.make_image()

def dashboard_counts():
    df = load_df(ITEMS_CSV)
    found = len(df[df["status"].isin(["stored","pending_claim","claimed"])])
    claimed = len(df[df["status"] == "claimed"])
    pending = len(df[df["status"] == "pending_claim"])
    return found, claimed, pending

# ------------------------------ CSS ------------------------------
def inject_css():
    st.markdown("""
    <style>
    /* -------- Modern Semi-Dark Theme -------- */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
    :root{
      --bg:#0f172a;           /* slate-900 */
      --panel:#111827;        /* gray-900 */
      --panel-2:#0b1220;      /* navy tint */
      --text:#e5e7eb;         /* slate-200 */
      --muted:#9ca3af;        /* gray-400 */
      --primary:#0ea5e9;      /* sky-500 */
      --primary-2:#22d3ee;    /* cyan-400 */
      --border:rgba(148,163,184,.25);
    }
    html, body, [class*="stApp"] { font-family: 'Inter', system-ui, -apple-system, Segoe UI, Roboto, sans-serif; }
    .stApp {
      background: radial-gradient(1200px 800px at 10% 0%, var(--panel-2) 0%, var(--bg) 55%, #0b1324 100%);
      color: var(--text);
    }
    .block-container { max-width: 1100px; padding-top: 1rem; padding-bottom: 2.5rem; }

    /* Sidebar */
    section[data-testid="stSidebar"]{
      background: linear-gradient(180deg, #0b1324 0%, var(--panel) 70%, #0b1324 100%);
      color: var(--text);
      border-right: 1px solid var(--border);
      backdrop-filter: blur(4px);
    }
    section[data-testid="stSidebar"] * { color: var(--text) !important; }

    /* Headings */
    h1, .stMarkdown h1 { color: #f1f5f9; letter-spacing: -.02em; font-weight: 700; }
    h2, .stMarkdown h2 { color: #e2e8f0; letter-spacing: -.01em; font-weight: 700; margin-top: .3rem; }

    /* Buttons / link buttons */
    .stButton > button, .stLinkButton > a {
      border-radius: 12px;
      padding: .6rem 1rem;
      border: 1px solid var(--border);
      background: linear-gradient(135deg, rgba(34,211,238,.16), rgba(14,165,233,.16));
      color: #e6faff !important;
      box-shadow: 0 8px 18px -10px rgba(2,6,23,.6);
      transition: transform .02s ease, box-shadow .2s ease, background .2s ease, border-color .2s ease;
    }
    .stButton > button:hover, .stLinkButton > a:hover {
      transform: translateY(-1px);
      border-color: rgba(34,211,238,.55);
      background: linear-gradient(135deg, rgba(34,211,238,.26), rgba(14,165,233,.26));
      box-shadow: 0 12px 28px -12px rgba(2,6,23,.7);
    }

    /* Inputs */
    .stTextInput > div > div > input,
    .stTextArea textarea,
    .stSelectbox > div > div,
    .stDateInput input, .stTimeInput input, .stFileUploader, .stNumberInput input {
      border-radius: 12px !important;
      border: 1px solid var(--border);
      background: rgba(17,24,39,.65);
      color: var(--text) !important;
    }
    .stTextArea textarea::placeholder,
    .stTextInput input::placeholder { color: var(--muted); }

    /* Metrics & cards */
    [data-testid="stMetric"], details, .stAlert {
      background: rgba(17,24,39,.55);
      border: 1px solid var(--border);
      border-radius: 16px;
      box-shadow: 0 10px 28px -18px rgba(2,6,23,.7);
      color: var(--text);
    }
    [data-testid="stMetric"] [data-testid="stMetricLabel"] { color: #93c5fd; font-weight: 600; }
    [data-testid="stMetric"] [data-testid="stMetricValue"] { color: #eaf7ff; font-weight: 800; }

    /* Expanders spacing */
    details { padding: .25rem .75rem .75rem .75rem !important; margin-bottom: .75rem !important; }
    summary { font-weight: 600; color: #e2e8f0; }

    /* Images & QR */
    img { border-radius: 12px; box-shadow: 0 10px 30px -16px rgba(2,6,23,.7); }
    .qr-wrap img { border: 1px dashed var(--border); padding: 8px; background: rgba(17,24,39,.55); }

    /* Links / captions */
    a { color: var(--primary-2); }
    .stCaption, .st-emotion-cache-0 { color: var(--muted) !important; }

    /* Dividers */
    hr { border-color: var(--border); }
    </style>
    """, unsafe_allow_html=True)

# ------------------------------ Navigation Helpers ------------------------------
def link_to(page_key: str):
    st.session_state["auth_page"] = page_key
    st.rerun()

# ------------------------------ Auth Pages ------------------------------
def page_login():
    st.title("Login")
    with st.form("login_form"):
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
        submit = st.form_submit_button("Login")
    if submit:
        u = user_by_email(email)
        if not u or not verify_password(password, u["salt_hex"], u["pwd_hash_hex"]):
            st.error("Invalid email or password.")
            return
        st.session_state["user"] = {"id": u["id"], "email": u["email"], "name": u["name"]}
        st.success(f"Welcome back, {u['name']}!")
        st.rerun()

    col = st.columns(2)
    if col[0].button("Create account"):
        link_to("register")
    if col[1].button("Forgot password"):
        link_to("forgot")

def page_register():
    st.title("Create Account")
    with st.form("register_form"):
        name = st.text_input("Full name")
        email = st.text_input("Email")
        p1 = st.text_input("Password", type="password")
        p2 = st.text_input("Confirm password", type="password")
        ok = st.form_submit_button("Register")
    if ok:
        if p1 != p2:
            st.error("Passwords do not match.")
            return
        if len(p1) < 6:
            st.error("Password must be at least 6 characters.")
            return
        if user_by_email(email):
            st.error("An account with this email already exists.")
            return
        u = create_user(email, name, p1)
        if not u:
            st.error("Registration failed. Check your inputs.")
            return
        st.success("Account created.")
        if st.button("Go to Login"):
            link_to("login")

def page_forgot():
    st.title("Forgot Password")
    st.caption("Enter your email to receive a reset code. (Demo: code shows on screen & logs.)")
    with st.form("forgot_form"):
        email = st.text_input("Email")
        ok = st.form_submit_button("Send reset code")
    if ok:
        u = user_by_email(email)
        if not u:
            st.error("No account found with that email.")
            return
        code = set_reset_code(email)
        if not code:
            st.error("Could not set reset code.")
            return
        st.success(f"Reset code generated (valid {RESET_CODE_MINUTES} min).")
        st.info(f"Demo reset code: **{code}**")
        st.session_state["reset_email"] = email.strip()
        link_to("reset")  # auto-redirect to separate reset page

def page_reset():
    st.title("Reset Password")
    default_email = st.session_state.get("reset_email", "")
    with st.form("reset_form"):
        email2 = st.text_input("Email", value=default_email)
        code2 = st.text_input("6-digit reset code")
        newp1 = st.text_input("New password", type="password")
        newp2 = st.text_input("Confirm new password", type="password")
        ok2 = st.form_submit_button("Change password")
    if ok2:
        if newp1 != newp2:
            st.error("Passwords do not match.")
            return
        if len(newp1) < 6:
            st.error("Password must be at least 6 characters.")
            return
        if not verify_reset_code(email2, code2):
            st.error("Invalid or expired code.")
            return
        if change_password(email2, newp1):
            st.success("Password updated.")
            if st.button("Go to Login"):
                st.session_state.pop("reset_email", None)
                link_to("login")
        else:
            st.error("Failed to change password.")
    st.caption("Need a new code?")
    if st.button("Send new code"):
        if not default_email:
            st.warning("Enter your email on the Forgot Password page first.")
        else:
            code = set_reset_code(default_email)
            if code:
                st.success("New code sent (demo: shown below).")
                st.info(f"Demo reset code: **{code}**")
            else:
                st.error("Could not generate a new code.")

# ------------------------------ App Pages ------------------------------
def page_home():
    st.title("Smart Lost & Found")
    st.write("A secure & easy-to-use system for reporting and finding lost items.")
    c1, c2, c3, c4 = st.columns(4)
    c1.link_button("➕ Report Lost Item", "#report")
    c2.link_button("🔍 View Found Items", "#view")
    c3.link_button("⬇️ Deposit Item", "#deposit")
    c4.link_button("✅ Claim Item", "#claim")
    st.divider()
    f, c, p = dashboard_counts()
    col = st.columns(3)
    col[0].metric("Items Found", f)
    col[1].metric("Items Claimed", c)
    col[2].metric("Items Pending", p)

def page_deposit():
    st.header("Deposit Item (Finder)")
    with st.form("deposit_form"):
        c1, c2 = st.columns(2)
        owner_known = c1.selectbox("Is the owner known?", ["Owner Known", "Unknown Owner"])
        size = c2.selectbox("Item size / compartment", ["Normal", "Big"])
        name = st.text_input("Item name (e.g., Wallet, Bottle)")
        descr = st.text_area("Short description (brand, color, stickers, etc.)")
        where = st.text_input("Found at (location)")
        when = st.date_input("Date found")
        t = st.time_input("Time found")
        photo = st.file_uploader("Upload a photo (optional)", type=["png","jpg","jpeg"])
        submit = st.form_submit_button("Assign Locker & Generate Deposit QR")
    if submit:
        cmp = "big" if size == "Big" else ("owner_known" if owner_known == "Owner Known" else "unknown")
        locker = free_locker(cmp)
        if not locker:
            st.error("No free locker available for this compartment right now.")
            return
        item_id = gen_id("itm")
        path = save_image(photo)
        df = load_df(ITEMS_CSV)
        df.loc[len(df)] = [
            item_id, (name or "Item").strip(), descr or "",
            "owner_known" if owner_known == "Owner Known" else "unknown",
            size.lower(), path or "", where or "", f"{when} {t}",
            locker, "stored", "", "", st.session_state["user"]["email"],
            st.session_state["user"]["email"], now_iso(), ""
        ]
        save_df(ITEMS_CSV, df)
        tok = create_token(item_id, "deposit")
        st.success(f"Locker **{locker}** reserved. Scan the QR at the locker.")
        st.markdown('<div class="qr-wrap">', unsafe_allow_html=True)
        st.image(make_qr({"type":"deposit","item_id":item_id,"token":tok["token"]}),
                 caption="Deposit QR (single-use, 30 min)")
        st.markdown('</div>', unsafe_allow_html=True)

def page_view():
    st.header("View Found Items")
    q = st.text_input("Search by name / description / location")
    owner_known_only = st.checkbox("Owner-known only", value=False)
    unknown_only = st.checkbox("Unknown only", value=False)
    df = load_df(ITEMS_CSV)
    df = df[df["status"].isin(["stored","pending_claim"])]
    if owner_known_only:
        df = df[df["category"]=="owner_known"]
    if unknown_only:
        df = df[df["category"]=="unknown"]
    if q.strip():
        mask = (
            df["name"].str.lower().str.contains(q.lower()) |
            df["descr"].str.lower().str.contains(q.lower()) |
            df["found_location"].str.lower().str.contains(q.lower())
        )
        df = df[mask]
    if df.empty:
        st.info("No items match right now.")
        return
    for _, r in df.iterrows():
        with st.expander(f'🧩 {r["name"]} — Locker {r["locker_id"]} — {r["status"]}'):
            c1, c2 = st.columns([2,3])
            if r["photo_path"] and Path(r["photo_path"]).exists():
                c1.image(Image.open(r["photo_path"]), width=240)
            c2.markdown(
                f"- **Desc:** {r['descr'] or '-'}\n"
                f"- **Found at:** {r['found_location'] or '-'}\n"
                f"- **Time:** {r['found_datetime'] or '-'}\n"
                f"- **Item ID:** `{r['id']}`"
            )

def page_claim():
    st.header("Claim Item (Owner)")
    df = load_df(ITEMS_CSV)
    df = df[df["status"].isin(["stored","pending_claim"])]
    if df.empty:
        st.info("No claimable items yet.")
        return
    choices = {f"{r['name']} — Locker {r['locker_id']} — [{r['id']}]": r['id'] for _, r in df.iterrows()}
    picked = st.selectbox("Select your item", list(choices.keys()))
    item_id = choices[picked]
    chosen = df[df["id"] == item_id].iloc[0]

    st.subheader("Verify ownership")
    if chosen["category"] == "unknown":
        q = st.text_input("Create a verification question (e.g., What brand/color?)")
        a = st.text_input("Your answer (exact word/phrase)")
        if st.button("Submit claim & get pickup QR"):
            df2 = load_df(ITEMS_CSV)
            idx = df2.index[df2["id"] == item_id][0]
            df2.at[idx,"verification_question"] = q.strip() or "What is the identifying detail?"
            df2.at[idx,"verification_answer"] = (a or "").strip().lower()
            df2.at[idx,"owner_email"] = st.session_state["user"]["email"]
            df2.at[idx,"status"] = "pending_claim"
            save_df(ITEMS_CSV, df2)
            tok = create_token(item_id, "claim")
            st.success("Claim created. Use this QR at the locker to unlock and take your item.")
            st.markdown('<div class="qr-wrap">', unsafe_allow_html=True)
            st.image(make_qr({"type":"claim","item_id": item_id,"token": tok["token"]}),
                     caption="Pickup QR (single-use, 30 min)")
            st.markdown('</div>', unsafe_allow_html=True)
    else:
        if st.button("Generate pickup QR (owner-known)"):
            df2 = load_df(ITEMS_CSV)
            idx = df2.index[df2["id"] == item_id][0]
            df2.at[idx,"owner_email"] = st.session_state["user"]["email"]
            df2.at[idx,"status"] = "pending_claim"
            save_df(ITEMS_CSV, df2)
            tok = create_token(item_id, "claim")
            st.success("Pickup QR generated. Go to the locker and scan to open.")
            st.markdown('<div class="qr-wrap">', unsafe_allow_html=True)
            st.image(make_qr({"type":"claim","item_id": item_id,"token": tok["token"]}),
                     caption="Pickup QR (single-use, 30 min)")
            st.markdown('</div>', unsafe_allow_html=True)

    st.divider()
    st.subheader("Demo: Simulate pickup (validate token + answer)")
    sim_tok = st.text_input("Paste claim token")
    sim_ans = st.text_input("Answer (if unknown-owner)")
    if st.button("Simulate unlock & claim"):
        tok_row = get_active_token(item_id, "claim")
        if not tok_row or not token_valid(tok_row, sim_tok):
            st.error("Invalid/expired token.")
            return
        df3 = load_df(ITEMS_CSV)
        idx = df3.index[df3["id"] == item_id][0]
        if chosen["category"] == "unknown":
            expected = (df3.at[idx,"verification_answer"] or "")
            if (sim_ans or "").strip().lower() != expected:
                st.error("Verification answer mismatch.")
                return
        invalidate_token(tok_row["id"])
        df3.at[idx,"status"] = "claimed"
        df3.at[idx,"claimed_at"] = now_iso()
        save_df(ITEMS_CSV, df3)
        st.success("✅ Claimed. Locker cycle closed.")

def page_report():
    st.header("Report Lost Item")
    with st.form("lost_report"):
        name = st.text_input("Item name")
        where = st.text_input("Where you might’ve lost it")
        descr = st.text_area("Describe your item (color, brand, stickers, etc.)")
        ok = st.form_submit_button("Submit report")
    if ok:
        who = st.session_state["user"]["email"] if "user" in st.session_state else "guest"
        log_event("lost_report", who, {"name":name,"where":where,"descr":descr})
        st.success("Saved. We’ll match this against newly deposited items.")

def page_admin():
    st.header("Admin Dashboard (demo)")
    f, c, p = dashboard_counts()
    col = st.columns(3)
    col[0].metric("Items Found", f)
    col[1].metric("Items Claimed", c)
    col[2].metric("Items Pending", p)

    st.subheader("All Items")
    df = load_df(ITEMS_CSV).sort_values("created_at", ascending=False)
    if df.empty:
        st.info("No items yet.")
        return
    for _, it in df.iterrows():
        with st.expander(f'{it["name"]} • {it["locker_id"]} • {it["status"]} • ({it["id"]})'):
            st.json(it.to_dict())
            dep = get_active_token(it["id"], "deposit")
            clm = get_active_token(it["id"], "claim")
            c1, c2 = st.columns(2)
            if dep and c1.button(f"Mark deposit token used → {it['id']}", key=f"dep_{it['id']}"):
                invalidate_token(dep["id"])
                st.success("Deposit token marked used.")
            if clm and c2.button(f"Expire claim token → {it['id']}", key=f"clm_{it['id']}"):
                toks = load_df(TOKENS_CSV)
                toks.loc[toks["id"]==clm["id"], "expires_at"] = (now_utc() - timedelta(seconds=1)).isoformat()
                save_df(TOKENS_CSV, toks)
                st.success("Claim token expired.")

# ------------------------------ Router & Shell ------------------------------
PAGES_PUBLIC = {
    "login":    page_login,
    "register": page_register,
    "forgot":   page_forgot,
    "reset":    page_reset,   # separate reset page
}
PAGES_PRIVATE = {
    "Home":             page_home,
    "Deposit Item":     page_deposit,
    "View Found Items": page_view,
    "Claim Item":       page_claim,
    "Report Lost Item": page_report,
    "Admin":            page_admin,
}

def sidebar_nav():
    st.sidebar.title("Smart Lost & Found")
    user = st.session_state.get("user")
    if user:
        st.sidebar.success(f"Signed in as {user['name']}")
        options = list(PAGES_PRIVATE.keys())

        # Ensure a default selection exists for programmatic jumps
        if "nav_private" not in st.session_state:
            st.session_state["nav_private"] = options[0]

        choice = st.sidebar.radio("Navigation", options, key="nav_private")
        if st.sidebar.button("Logout"):
            st.session_state.pop("user", None)
            st.rerun()
        return choice, True
    else:
        current = st.session_state.get("auth_page", "login")
        mapping = {
            "Login": "login",
            "Register": "register",
            "Forgot Password": "forgot",
            "Reset Password": "reset",
        }
        inv_map = {v: k for k, v in mapping.items()}
        names = list(mapping.keys())
        idx = names.index(inv_map.get(current, "Login"))
        picked_name = st.sidebar.radio("Authentication", names, index=idx)
        st.session_state["auth_page"] = mapping[picked_name]
        return st.session_state["auth_page"], False


def router():
    page_key, authed = sidebar_nav()
    if authed:
        PAGES_PRIVATE[page_key]()
    else:
        PAGES_PUBLIC[page_key]()

# ------------------------------ Main ------------------------------
st.set_page_config(page_title=APP_TITLE, page_icon="🧩", layout="wide")
inject_css()
ensure_fs()
router()
