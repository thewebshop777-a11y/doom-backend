"""DOOM live server. Put keys in .env. Users never see the provider."""
import os
import asyncio
import uuid
import base64
import hashlib
import hmac
import json
import secrets
import time
from contextlib import contextmanager
from pathlib import Path

import httpx
import psycopg
from dotenv import load_dotenv
from fastapi import FastAPI, Header, HTTPException, UploadFile, File, Form, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

load_dotenv(Path(__file__).with_name(".env"))
app = FastAPI(title="DOOM")
ALLOWED_ORIGINS = [x.strip() for x in os.environ.get("ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:5173").split(",") if x.strip()]
app.add_middleware(CORSMiddleware, allow_origins=ALLOWED_ORIGINS, allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
Path("generated").mkdir(exist_ok=True)
Path("sites").mkdir(exist_ok=True)
app.mount("/files", StaticFiles(directory="generated"), name="files")

# --- Production security / persistence helpers ---
# The old V10 build trusted x-user-id and local .ok files.  The implementation
# below keeps a development escape hatch, but production requests must use a
# signed bearer session stored in PostgreSQL.  Provider credentials never reach
# the browser.
SESSION_TTL = int(os.environ.get("SESSION_TTL_SECONDS", "2592000"))
DEV_MODE = os.environ.get("DOOM_DEV_MODE", "false").lower() == "true"


def _secret():
    value = os.environ.get("DOOM_SESSION_SECRET", "")
    if len(value) < 32:
        if not DEV_MODE:
            raise HTTPException(500, "DOOM_SESSION_SECRET must be set to a 32+ character secret")
        value = "dev-only-change-me-doom-session-secret"
    return value.encode()


def hash_password(password: str) -> str:
    if len(password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 210_000)
    return base64.urlsafe_b64encode(salt + digest).decode()


def verify_password(password: str, encoded: str) -> bool:
    try:
        raw = base64.urlsafe_b64decode(encoded.encode())
        salt, digest = raw[:16], raw[16:]
        check = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 210_000)
        return hmac.compare_digest(check, digest)
    except Exception:
        return False


def issue_session(user_id: str, client: str = "web") -> str:
    sid = secrets.token_urlsafe(32)
    exp = int(time.time()) + SESSION_TTL
    payload = f"{sid}.{user_id}.{client}.{exp}"
    sig = hmac.new(_secret(), payload.encode(), hashlib.sha256).hexdigest()
    token = f"{payload}.{sig}"
    with db() as conn:
        conn.execute("CREATE SCHEMA IF NOT EXISTS doom")
        conn.execute("CREATE TABLE IF NOT EXISTS doom.sessions (session_id TEXT PRIMARY KEY, user_id TEXT NOT NULL, client TEXT NOT NULL, expires_at TIMESTAMPTZ NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())")
        conn.execute("INSERT INTO doom.sessions(session_id,user_id,client,expires_at) VALUES (%s,%s,%s,to_timestamp(%s))", (sid,user_id,client,exp))
        conn.commit()
    return token


def resolve_user(x_user_id: str | None = None, authorization: str | None = None) -> str:
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
        parts = token.split(".")
        if len(parts) != 5:
            raise HTTPException(401, "Invalid session")
        sid, user_id, client, exp_s, sig = parts
        payload = ".".join(parts[:4])
        if not hmac.compare_digest(hmac.new(_secret(), payload.encode(), hashlib.sha256).hexdigest(), sig):
            raise HTTPException(401, "Invalid session")
        if int(exp_s) < int(time.time()):
            raise HTTPException(401, "Session expired")
        with db() as conn:
            row = conn.execute("SELECT user_id FROM doom.sessions WHERE session_id=%s AND user_id=%s AND expires_at>NOW()", (sid,user_id)).fetchone()
        if not row:
            raise HTTPException(401, "Session expired or revoked")
        return row[0]
    if DEV_MODE and x_user_id:
        return x_user_id
    raise HTTPException(401, "Authentication required. Use a DOOM bearer session.")


def ensure_security_tables():
    with db() as conn:
        conn.execute("CREATE SCHEMA IF NOT EXISTS doom")
        conn.execute("ALTER TABLE doom.users ADD COLUMN IF NOT EXISTS password_hash TEXT")
        conn.execute("CREATE TABLE IF NOT EXISTS doom.tool_connections (connection_id TEXT PRIMARY KEY, user_id TEXT NOT NULL, workspace_id TEXT, app_name TEXT NOT NULL, provider_account_id TEXT, status TEXT NOT NULL DEFAULT 'pending', updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), UNIQUE(user_id, app_name))")
        conn.execute("CREATE TABLE IF NOT EXISTS doom.approval_requests (approval_id TEXT PRIMARY KEY, user_id TEXT NOT NULL, workspace_id TEXT, app_name TEXT NOT NULL, action TEXT NOT NULL, params JSONB NOT NULL DEFAULT '{}'::jsonb, status TEXT NOT NULL DEFAULT 'pending', created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), resolved_at TIMESTAMPTZ)")
        conn.execute("CREATE TABLE IF NOT EXISTS doom.audit_logs (audit_id BIGSERIAL PRIMARY KEY, user_id TEXT NOT NULL, workspace_id TEXT, event TEXT NOT NULL, app_name TEXT, action TEXT, details JSONB NOT NULL DEFAULT '{}'::jsonb, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())")
        conn.execute("CREATE TABLE IF NOT EXISTS doom.company_rules (workspace_id TEXT PRIMARY KEY, rules JSONB NOT NULL DEFAULT '{}'::jsonb)")
        conn.execute("CREATE TABLE IF NOT EXISTS doom.workspace_permissions (workspace_id TEXT NOT NULL, role TEXT NOT NULL, app_name TEXT NOT NULL, action TEXT NOT NULL, effect TEXT NOT NULL DEFAULT 'allow', PRIMARY KEY(workspace_id, role, app_name, action))")
        conn.execute("CREATE TABLE IF NOT EXISTS doom.workspace_invitations (invitation_id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, invited_email TEXT NOT NULL, role TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, expires_at TIMESTAMPTZ NOT NULL, status TEXT NOT NULL DEFAULT 'pending', created_by TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), accepted_at TIMESTAMPTZ)")
        conn.commit()


def audit(user_id, event, workspace_id=None, app_name=None, action=None, details=None):
    try:
        with db() as conn:
            conn.execute("INSERT INTO doom.audit_logs(user_id,workspace_id,event,app_name,action,details) VALUES (%s,%s,%s,%s,%s,%s)", (user_id,workspace_id,event,app_name,action,json.dumps(details or {})))
            conn.commit()
    except Exception:
        pass


def workspace_for(user_id: str):
    with db() as conn:
        row = conn.execute("SELECT workspace_id, role, status FROM doom.memberships WHERE user_id=%s AND status='active' ORDER BY workspace_id LIMIT 1", (user_id,)).fetchone()
        if row:
            return row[0], row[1]
        row = conn.execute("SELECT workspace_id, 'owner' FROM doom.workspaces WHERE owner_user_id=%s ORDER BY created_at LIMIT 1", (user_id,)).fetchone()
        if row:
            return row[0], row[1]
    return None, "viewer"


def authorized_tool(user_id: str, app_name: str, action: str, workspace_id: str | None = None, role: str | None = None):
    workspace_id = workspace_id or workspace_for(user_id)[0]
    role = role or workspace_for(user_id)[1]
    if role not in ("owner", "admin", "operator"):
        return False, "Workspace role cannot execute external tools."
    if workspace_id:
        with db() as conn:
            row = conn.execute("SELECT effect FROM doom.workspace_permissions WHERE workspace_id=%s AND role=%s AND app_name=%s AND action=%s", (workspace_id,role,app_name,action)).fetchone()
            if row and row[0] != "allow":
                return False, "Workspace permission blocks this action."
            row = conn.execute("SELECT rules FROM doom.company_rules WHERE workspace_id=%s", (workspace_id,)).fetchone()
        rules = row[0] if row else {}
        blocked = (rules or {}).get("blocked_actions", [])
        if f"{app_name}:{action}" in blocked or action in blocked:
            return False, "Company rules block this action."
    return True, ""


def approval_required(user_id: str, app_name: str, action: str, workspace_id: str | None):
    if not workspace_id:
        return False
    with db() as conn:
        row = conn.execute("SELECT rules FROM doom.company_rules WHERE workspace_id=%s", (workspace_id,)).fetchone()
    rules = row[0] if row else {}
    required = (rules or {}).get("approval_required", [])
    return f"{app_name}:{action}" in required or action in required

PLANS = {
    "free": (2_000_000, 50, 1, 100_000_000, False),
    "basic": (100_000_000, 1_000, 3, 5_000_000_000, True),
    "pro": (200_000_000, 4_000, 5, 20_000_000_000, True),
    "business": (500_000_000, 6_000, 15, 50_000_000_000, True),
    "enterprise": (900_000_000, 10_000, 40, 200_000_000_000, True),
}


@contextmanager
def db():
    url = os.environ.get("DATABASE_URL")
    if not url:
        raise HTTPException(500, "DATABASE_URL missing")
    with psycopg.connect(url) as conn:
        yield conn


class ChatIn(BaseModel):
    prompt: str
    persona: str = ""
    chat_id: str | None = None


class CreditIn(BaseModel):
    user_id: str
    email: str
    tier: str = "basic"
    password: str | None = None


def pick_model(prompt: str) -> str:
    override = os.environ.get("OPENROUTER_MODEL")
    if override:
        return override
    if len(prompt) > 800 or any(w in prompt.lower() for w in ("code", "debug", "forecast", "report")):
        return "deepseek/deepseek-chat"
    return "openai/gpt-4o-mini"


@app.on_event("startup")
async def security_startup():
    ensure_security_tables()


class LoginIn(BaseModel):
    email: str
    password: str
    client: str = "web"

@app.post("/auth/login")
def login(body: LoginIn):
    with db() as conn:
        row = conn.execute("SELECT user_id, password_hash FROM doom.users WHERE lower(email)=lower(%s)", (body.email,)).fetchone()
    if not row or not row[1] or not verify_password(body.password, row[1]):
        raise HTTPException(401, "Invalid email or password")
    token = issue_session(row[0], body.client if body.client in ("web","app") else "web")
    audit(row[0], "auth.login", details={"client": body.client})
    return {"access_token": token, "token_type": "bearer", "user_id": row[0]}

@app.post("/auth/revoke")
def revoke(authorization: str = Header(default="")):
    user_id = resolve_user(authorization=authorization)
    token = authorization.split(" ",1)[1].strip()
    sid = token.split(".",1)[0]
    with db() as conn:
        conn.execute("DELETE FROM doom.sessions WHERE session_id=%s AND user_id=%s", (sid,user_id)); conn.commit()
    return {"ok": True}

@app.get("/health")
def health():
    return {
        "ok": True,
        "openrouter": bool(os.environ.get("OPENROUTER_API_KEY")),
        "composio": bool(os.environ.get("COMPOSIO_API_KEY")),
        "database": bool(os.environ.get("DATABASE_URL")),
    }


@app.post("/credit")
def credit(body: CreditIn, x_admin_key: str = Header(default="")):
    expected = os.environ.get("ADMIN_KEY", "").strip()
    if not expected or not hmac.compare_digest(x_admin_key, expected):
        raise HTTPException(401, "admin key required")
    if body.tier not in PLANS:
        raise HTTPException(400, "unknown tier")
    tokens, tools, seats, storage, local = PLANS[body.tier]
    with db() as conn:
        conn.execute(
            "INSERT INTO doom.users (user_id, email, password_hash) VALUES (%s, %s, %s) ON CONFLICT (user_id) DO UPDATE SET email = EXCLUDED.email, password_hash = COALESCE(EXCLUDED.password_hash, doom.users.password_hash)",
            (body.user_id, body.email, hash_password(body.password) if body.password else None),
        )
        conn.execute(
            """INSERT INTO doom.subscriptions (user_id, tier, status)
               VALUES (%s, %s, 'active')
               ON CONFLICT (user_id) DO UPDATE SET tier = EXCLUDED.tier, status = 'active', updated_at = NOW()""",
            (body.user_id, body.tier),
        )
        conn.execute(
            """INSERT INTO doom.entitlements
               (user_id, monthly_tokens, tokens_remaining, daily_tool_limit, daily_tools_remaining, seats, storage_bytes, local_unlocked)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
               ON CONFLICT (user_id) DO UPDATE SET
                 monthly_tokens = EXCLUDED.monthly_tokens,
                 tokens_remaining = EXCLUDED.tokens_remaining,
                 daily_tool_limit = EXCLUDED.daily_tool_limit,
                 daily_tools_remaining = EXCLUDED.daily_tools_remaining,
                 seats = EXCLUDED.seats,
                 storage_bytes = EXCLUDED.storage_bytes,
                 local_unlocked = EXCLUDED.local_unlocked,
                 updated_at = NOW()""",
            (body.user_id, tokens, tokens, tools, tools, seats, storage, local),
        )
        conn.commit()
    return {"credited": body.user_id, "tier": body.tier, "tokens": tokens, "daily_tools": tools}


@app.post("/chat")
async def chat(body: ChatIn, x_user_id: str = Header(default=""), authorization: str = Header(default="")):
    user_id = resolve_user(x_user_id, authorization)
    with db() as conn:
        row = conn.execute("SELECT tokens_remaining FROM doom.entitlements WHERE user_id = %s", (user_id,)).fetchone()
        if not row:
            raise HTTPException(403, "No plan on this account. Credit the user first.")
        if row[0] <= 0:
            raise HTTPException(403, "Monthly credits used. Upgrade or wait for refresh.")
        # Keep normal DOOM conversation contextual without trusting client-supplied history.
        history = []
        if body.chat_id:
            owner = conn.execute("SELECT user_id FROM doom.chats WHERE chat_id=%s", (body.chat_id,)).fetchone()
            if owner and owner[0] != user_id:
                raise HTTPException(403, "Chat does not belong to this account.")
            rows = conn.execute("SELECT role, body FROM doom.messages WHERE chat_id=%s ORDER BY message_id DESC LIMIT 20", (body.chat_id,)).fetchall()
            for role, msg in reversed(rows):
                mapped = "assistant" if role == "doom" else ("user" if role == "user" else role)
                if mapped in ("user", "assistant", "system"):
                    history.append({"role": mapped, "content": msg})
    key = os.environ.get("OPENROUTER_API_KEY")
    if not key:
        raise HTTPException(500, "OPENROUTER_API_KEY missing in .env")
    server_persona = os.environ.get("DOOM_PERSONA", "You are DOOM: direct, strategic, commanding, concise and highly intelligent. Lead with the answer. Never mention providers, models, routing, or hidden infrastructure. Speak as one coherent entity.")
    persona = server_persona + ("\n\nAdditional power context:\n" + body.persona.strip() if body.persona.strip() else "")
    messages = [{"role": "system", "content": persona}] + history + [{"role": "user", "content": body.prompt}]
    async with httpx.AsyncClient(timeout=90) as client:
        r = await client.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
            json={"model": pick_model(body.prompt), "messages": messages},
        )
    try:
        data = r.json()
    except Exception:
        data = {}
    if r.status_code >= 400:
        raise HTTPException(502, "Intelligence provider failed")
    try:
        text = data["choices"][0]["message"]["content"]
    except Exception:
        raise HTTPException(502, "Intelligence provider returned no usable response")
    used = int((data.get("usage") or {}).get("total_tokens") or 0)
    chat_id = body.chat_id or str(uuid.uuid4())
    with db() as conn:
        conn.execute("INSERT INTO doom.chats (chat_id, user_id, title) VALUES (%s, %s, %s) ON CONFLICT (chat_id) DO NOTHING", (chat_id, user_id, body.prompt[:80]))
        conn.execute("INSERT INTO doom.messages (chat_id, role, body) VALUES (%s, 'user', %s), (%s, 'doom', %s)", (chat_id, body.prompt, chat_id, text))
        conn.execute("UPDATE doom.entitlements SET tokens_remaining = GREATEST(tokens_remaining - %s, 0) WHERE user_id = %s", (used, user_id))
        conn.commit()
    audit(user_id, "chat.completed", details={"chat_id": chat_id, "tokens_used": used})
    return {"text": text, "chat_id": chat_id, "tokens_used": used}

@app.get("/session")
def session_info(x_user_id: str = Header(default=""), authorization: str = Header(default="")):
    user_id = resolve_user(x_user_id, authorization)
    workspace_id, role = workspace_for(user_id)
    with db() as conn:
        row = conn.execute("SELECT a.email, COALESCE(s.tier,'free'), COALESCE(s.status,'inactive') FROM doom.users a LEFT JOIN doom.subscriptions s ON s.user_id=a.user_id WHERE a.user_id=%s", (user_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Account not found")
    return {"user_id": user_id, "email": row[0], "tier": row[1], "subscription_status": row[2], "workspace_id": workspace_id, "role": role}

@app.get("/chats")
def chats(x_user_id: str = Header(default=""), authorization: str = Header(default="")):
    x_user_id = resolve_user(x_user_id, authorization)
    with db() as conn:
        rows = conn.execute(
            """SELECT c.chat_id, c.title, m.role, m.body
               FROM doom.chats c
               LEFT JOIN doom.messages m ON m.chat_id = c.chat_id
               WHERE c.user_id = %s
               ORDER BY c.created_at, m.message_id""",
            (x_user_id,),
        ).fetchall()
    grouped = {}
    for chat_id, title, role, body in rows:
        grouped.setdefault(chat_id, {"id": chat_id, "title": title, "messages": []})
        if role:
            grouped[chat_id]["messages"].append({"role": role, "text": body})
    return {"chats": list(grouped.values())}


class InviteIn(BaseModel):
    email: str
    role: str = "operator"
    workspace: str = "Web Shop"
    founder: str = "Founder"


class JoinIn(BaseModel):
    token: str
    email: str
    password: str


def mail_invite(to: str, link: str, workspace: str, founder: str, role: str):
    host = os.environ.get("SMTP_HOST")
    if not host:
        return False
    import smtplib
    from email.message import EmailMessage
    msg = EmailMessage()
    msg["Subject"] = f"You are invited to {workspace} on DOOM"
    msg["From"] = os.environ.get("SMTP_FROM", os.environ.get("SMTP_USER"))
    msg["To"] = to
    msg.set_content(
        f"{founder} invited you to {workspace} on DOOM.\n"
        f"Role: {role}\n"
        f"Your access is sponsored. You do not pay.\n"
        f"Open this link, then sign up with this exact email:\n{link}\n"
    )
    with smtplib.SMTP(host, int(os.environ.get("SMTP_PORT", "587"))) as s:
        s.starttls()
        s.login(os.environ["SMTP_USER"], os.environ["SMTP_PASSWORD"])
        s.send_message(msg)
    return True


@app.post("/invites")
def invite(body: InviteIn, x_user_id: str = Header(default=""), authorization: str = Header(default="")):
    owner_id = resolve_user(x_user_id, authorization)
    workspace_id, role = workspace_for(owner_id)
    if role not in ("owner", "admin"):
        raise HTTPException(403, "Only workspace owners/admins can invite members")
    if not workspace_id:
        workspace_id = "ws-" + owner_id
        with db() as conn:
            conn.execute("INSERT INTO doom.workspaces(workspace_id,name,owner_user_id) VALUES(%s,%s,%s) ON CONFLICT DO NOTHING", (workspace_id,body.workspace,owner_id))
            conn.commit()
    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    invitation_id = "inv_" + uuid.uuid4().hex
    link = os.environ.get("PUBLIC_BASE_URL", "http://localhost:8790") + "/join?token=" + raw_token + "&email=" + body.email
    with db() as conn:
        conn.execute("INSERT INTO doom.workspace_invitations(invitation_id,workspace_id,invited_email,role,token_hash,expires_at,created_by) VALUES(%s,%s,%s,%s,%s,NOW()+INTERVAL '48 hours',%s)", (invitation_id,workspace_id,body.email.lower(),body.role,token_hash,owner_id))
        conn.commit()
    sent = mail_invite(body.email, link, body.workspace, body.founder, body.role)
    audit(owner_id,"workspace.invitation.created",workspace_id,details={"email":body.email.lower(),"role":body.role})
    return {"invitation_id": invitation_id, "link": link, "email_sent": sent, "expires_hours": 48}


@app.post("/join")
def join(body: JoinIn):
    token_hash = hashlib.sha256(body.token.encode()).hexdigest()
    with db() as conn:
        row = conn.execute("SELECT invitation_id,workspace_id,invited_email,role FROM doom.workspace_invitations WHERE token_hash=%s AND status='pending' AND expires_at>NOW()", (token_hash,)).fetchone()
        if not row:
            raise HTTPException(400, "Invalid, expired, or already used invitation")
        if row[2].lower() != body.email.lower():
            raise HTTPException(403, "Use the exact invited email")
        existing = conn.execute("SELECT user_id FROM doom.users WHERE lower(email)=lower(%s)", (body.email,)).fetchone()
        user_id = existing[0] if existing else "emp_" + uuid.uuid4().hex
        conn.execute("INSERT INTO doom.users(user_id,email,password_hash) VALUES(%s,%s,%s) ON CONFLICT(user_id) DO UPDATE SET password_hash=EXCLUDED.password_hash", (user_id,body.email.lower(),hash_password(body.password)))
        conn.execute("UPDATE doom.memberships SET user_id=%s,status='active' WHERE workspace_id=%s AND lower(email)=lower(%s)", (user_id,row[1],body.email))
        conn.execute("INSERT INTO doom.memberships(membership_id,workspace_id,user_id,email,role,status) VALUES(%s,%s,%s,%s,%s,'active') ON CONFLICT(workspace_id,email) DO UPDATE SET user_id=EXCLUDED.user_id,role=EXCLUDED.role,status='active'", (row[0],row[1],user_id,body.email.lower(),row[3]))
        conn.execute("UPDATE doom.workspace_invitations SET status='accepted',accepted_at=NOW() WHERE invitation_id=%s", (row[0],))
        conn.commit()
    token=issue_session(user_id,"app")
    audit(user_id,"workspace.invitation.accepted",row[1],details={"email":body.email.lower()})
    return {"access_token":token,"token_type":"bearer","user_id":user_id,"role":row[3],"email":body.email.lower(),"workspace_id":row[1]}


from fastapi.responses import HTMLResponse

@app.get("/join", response_class=HTMLResponse)
def join_page(token: str = "", email: str = ""):
    return f"""<!doctype html><html><body style="background:#050505;color:#eee;font-family:sans-serif;padding:40px">
    <h1>Join DOOM</h1>
    <p>Use the email that received this invite. You do not pay.</p>
    <form id="f">
      <input id="email" value="{email}" placeholder="email" style="display:block;margin:8px 0;padding:8px;width:280px"/>
      <input id="password" type="password" placeholder="password" style="display:block;margin:8px 0;padding:8px;width:280px"/>
      <button>Create account and enter</button>
    </form>
    <p id="out"></p>
    <script>
      document.getElementById("f").onsubmit = async (e) => {{
        e.preventDefault();
        const r = await fetch("/join", {{method:"POST", headers:{{"content-type":"application/json"}},
          body: JSON.stringify({{token:"{token}", email: email.value, password: password.value}})}});
        const d = await r.json();
        document.getElementById("out").textContent = r.ok ? ("Joined as " + d.role + ". Your id is " + d.user_id) : JSON.stringify(d);
      }};
    </script></body></html>"""


from fastapi.responses import FileResponse

@app.get("/download")
def download_app(x_user_id: str = Header(default=""), authorization: str = Header(default="")):
    x_user_id = resolve_user(x_user_id, authorization)
    with db() as conn:
        row = conn.execute(
            "SELECT s.tier, s.status FROM doom.subscriptions s WHERE s.user_id = %s",
            (x_user_id,),
        ).fetchone()
    if not row or row[1] != "active" or row[0] == "free":
        raise HTTPException(402, "Pay for a plan before downloading DOOM.")
    zip_path = Path(__file__).with_name("DOOM-desktop.zip")
    if not zip_path.exists():
        raise HTTPException(404, "Desktop package is not built on this server yet.")
    return FileResponse(zip_path, filename=f"DOOM-{row[0]}.zip")


class ActIn(BaseModel):
    feature: str
    prompt: str
    persona: str = ""


@app.post("/act")
async def act(body: ActIn, x_user_id: str = Header(default=""), authorization: str = Header(default="")):
    x_user_id = resolve_user(x_user_id, authorization)
    feature_prompt = {
        "business": "You are DOOM running business management. Give the report, the decision, and the next action.",
        "website": "You are DOOM running website management. Inspect the issue, name the weak point, and give the fix.",
        "content": "You are DOOM running content. Write the post ready to publish.",
        "predictor": "You are DOOM running prediction. Give the likely outcome and say it is a forecast, not a guarantee.",
        "workflow": "You are DOOM running the founder day. Return a timed plan in AM/PM.",
        "local": "You are DOOM in private mode. Do not claim a local model is running if this request reached the server.",
    }.get(body.feature, "You are DOOM. Lead with the answer.")
    persona = body.persona.strip() or feature_prompt
    return await chat(ChatIn(prompt=body.prompt, persona=persona), x_user_id, authorization)


@app.post("/connectors/connect")
async def connect_app(app_name: str, x_user_id: str = Header(default=""), authorization: str = Header(default="")):
    # Compatibility route: Connect always means approval, never direct tool execution.
    return await approval(app_name, x_user_id, authorization)


class RunIn(BaseModel):
    task: str
    prompt: str = ""
    persona: str = ""


@app.post("/run")
async def run_task(body: RunIn, x_user_id: str = Header(default=""), authorization: str = Header(default="")):
    x_user_id = resolve_user(x_user_id, authorization)
    orders = {
        "voice": "Turn this spoken request into the action DOOM should take, then do it.",
        "audio": "Prepare the spoken reply DOOM should say. Return the script only.",
        "image": "Write the exact image prompt and a short caption. Do not claim a file was saved.",
        "employee": "Create an AI employee brief: name, job, daily actions, and the first task.",
        "workflow": "Build a timed AM/PM workflow for this request.",
        "post": "Write the social post and say which network it is for.",
        "website": "Return the website fix as concrete steps and the code change.",
    }
    persona = body.persona.strip() or orders.get(body.task, "You are DOOM. Do the task. Lead with the result.")
    return await chat(ChatIn(prompt=body.prompt or body.task, persona=persona), x_user_id, authorization)


EMPLOYEES = []
EMPLOYEE_FILE = Path("employees.json")

def load_employees():
    global EMPLOYEES
    if EMPLOYEE_FILE.exists():
        import json
        EMPLOYEES = json.loads(EMPLOYEE_FILE.read_text() or "[]")

def save_employees():
    import json
    EMPLOYEE_FILE.write_text(json.dumps(EMPLOYEES))



async def _save_media_record(user_id: str, kind: str, name: str, path: Path):
    workspace_id, _ = workspace_for(user_id)
    try:
        with db() as conn:
            conn.execute("INSERT INTO doom.files(file_id,owner_user_id,workspace_id,kind,name,storage_key,bytes) VALUES(%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING", ("file_"+uuid.uuid4().hex,user_id,workspace_id,kind,name,str(path),path.stat().st_size))
            conn.commit()
    except Exception:
        pass

@app.post("/media")
async def make_media(kind: str = "image", prompt: str = "", x_user_id: str = Header(default=""), authorization: str = Header(default="")):
    user_id = resolve_user(x_user_id, authorization)
    key = os.environ.get("OPENROUTER_API_KEY")
    if not key: raise HTTPException(500, "OPENROUTER_API_KEY missing")
    if kind not in ("image", "video"): raise HTTPException(400, "kind must be image or video")
    if not prompt.strip(): raise HTTPException(400, "prompt is required")
    async with httpx.AsyncClient(timeout=60) as client:
        if kind == "image":
            model = os.environ.get("OPENROUTER_IMAGE_MODEL", "google/gemini-3.1-flash-image-preview")
            r = await client.post("https://openrouter.ai/api/v1/images", headers={"Authorization":f"Bearer {key}","Content-Type":"application/json"}, json={"model":model,"prompt":prompt})
            if r.status_code >= 400: raise HTTPException(502, "Image generation failed")
            data=r.json(); items=data.get("data") or []
            if not items or not items[0].get("b64_json"): raise HTTPException(502,"Image provider returned no real image")
            raw=base64.b64decode(items[0]["b64_json"])
            name=f"{user_id}-{uuid.uuid4().hex[:10]}.png"; path=Path("generated")/name; path.write_bytes(raw)
            if path.stat().st_size <= 0: raise HTTPException(502,"Image provider returned an empty file")
            await _save_media_record(user_id,"image",name,path)
            return {"file":f"/files/{name}","saved":True,"real":True,"kind":"image","bytes":path.stat().st_size}
        model=os.environ.get("OPENROUTER_VIDEO_MODEL","google/veo-3.1")
        r=await client.post("https://openrouter.ai/api/v1/videos",headers={"Authorization":f"Bearer {key}","Content-Type":"application/json"},json={"model":model,"prompt":prompt,"resolution":os.environ.get("OPENROUTER_VIDEO_RESOLUTION","720p"),"aspect_ratio":os.environ.get("OPENROUTER_VIDEO_ASPECT_RATIO","16:9")})
        if r.status_code >= 400: raise HTTPException(502,"Video generation request failed")
        job=r.json(); job_id=job.get("id")
        if not job_id: raise HTTPException(502,"Video provider returned no job id")
        return {"job_id":job_id,"status":job.get("status","pending"),"saved":False,"real":True,"kind":"video"}

@app.get("/media/video/{job_id}")
async def poll_video(job_id: str, x_user_id: str = Header(default=""), authorization: str = Header(default="")):
    user_id=resolve_user(x_user_id, authorization)
    key=os.environ.get("OPENROUTER_API_KEY")
    if not key: raise HTTPException(500,"OPENROUTER_API_KEY missing")
    async with httpx.AsyncClient(timeout=60) as client:
        r=await client.get(f"https://openrouter.ai/api/v1/videos/{job_id}",headers={"Authorization":f"Bearer {key}"})
        if r.status_code>=400: raise HTTPException(502,"Video status request failed")
        data=r.json(); status=data.get("status")
        if status != "completed":
            if status in ("failed","cancelled","expired"): return {"saved":False,"real":False,"kind":"video","status":status,"error":data.get("error") or "Video generation failed"}
            return {"saved":False,"real":True,"kind":"video","status":status or "pending"}
        urls=data.get("unsigned_urls") or []
        if not urls: raise HTTPException(502,"Video completed without a content URL")
        asset=await client.get(urls[0],headers={"Authorization":f"Bearer {key}"})
        if asset.status_code>=400 or not asset.content: raise HTTPException(502,"Video content download failed")
        name=f"{user_id}-{uuid.uuid4().hex[:10]}.mp4"; path=Path("generated")/name; path.write_bytes(asset.content)
        await _save_media_record(user_id,"video",name,path)
        return {"file":f"/files/{name}","saved":True,"real":True,"kind":"video","bytes":path.stat().st_size}

@app.post("/post")
async def post_social(network: str, text: str, x_user_id: str = Header(default=""), authorization: str = Header(default="")):
    x_user_id = resolve_user(x_user_id, authorization)
    # External actions must use the same authorization pipeline as split execution.
    result = await execute_split_request(x_user_id, {"app": network.lower(), "action": "post", "params": {"text": text, "caption": text}, "raw_request": text})
    return result


@app.post("/site/edit")
async def edit_site(change: str, path: str = "index.html", x_user_id: str = Header(default=""), authorization: str = Header(default="")):
    x_user_id = resolve_user(x_user_id, authorization)
    workspace_id, role = workspace_for(x_user_id)
    if role not in ("owner", "admin"):
        raise HTTPException(403, "Only workspace owners/admins can edit the site")
    token = os.environ.get("GITHUB_TOKEN")
    repo = os.environ.get("GITHUB_REPO")
    if not token or not repo:
        raise HTTPException(400, "Set GITHUB_TOKEN and GITHUB_REPO in .env so DOOM can write the live site.")
    async with httpx.AsyncClient(timeout=40) as client:
        url = f"https://api.github.com/repos/{repo}/contents/{path}"
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
        current = await client.get(url, headers=headers)
        sha = current.json().get("sha") if current.status_code < 400 else None
        import base64
        body = {"message": "DOOM site edit", "content": base64.b64encode(change.encode()).decode()}
        if sha:
            body["sha"] = sha
        wrote = await client.put(url, headers=headers, json=body)
    if wrote.status_code >= 400:
        raise HTTPException(502, "Host rejected the write")
    return {"ok": True, "repo": repo, "path": path}


@app.post("/voice")
async def voice(x_user_id: str = Header(default=""), authorization: str = Header(default="")):
    # Voice upload is intentionally disabled. DOOM uses browser speech-to-text and the normal chat route.
    resolve_user(x_user_id, authorization)
    raise HTTPException(410, "Voice uploads are disabled. Use browser speech recognition; transcript is sent through /split.")


@app.post("/employees")
async def add_employee(name: str, task: str, x_user_id: str = Header(default=""), authorization: str = Header(default="")):
    x_user_id = resolve_user(x_user_id, authorization)
    load_employees()
    EMPLOYEES.append({"user_id": x_user_id, "name": name, "task": task})
    save_employees()
    return {"ok": True, "count": len(EMPLOYEES)}


@app.post("/employees/tick")
async def tick_employees(x_user_id: str = Header(default=""), authorization: str = Header(default="")):
    x_user_id = resolve_user(x_user_id, authorization)
    load_employees()
    mine = [e for e in EMPLOYEES if e["user_id"] == x_user_id]
    results = []
    for e in mine:
        out = await chat(ChatIn(prompt=e["task"], persona=f"You are AI employee {e['name']}. Do the task."), x_user_id)
        results.append({"name": e["name"], "text": out.get("text")})
    return {"ran": results}


async def employee_loop():
    while True:
        await asyncio.sleep(3600)
        load_employees()
        for e in list(EMPLOYEES):
            try:
                await chat(ChatIn(prompt=e["task"], persona=f"You are AI employee {e['name']}. Do the task."), e["user_id"])
            except Exception:
                pass

@app.on_event("startup")
async def start_timer():
    asyncio.create_task(employee_loop())


@app.get("/config")
def public_config():
    client = os.environ.get("ADSENSE_CLIENT", "").strip()
    slot = os.environ.get("ADSENSE_SLOT", "").strip()
    return {"adsense_client": client if client.startswith("ca-pub-") else "", "adsense_slot": slot if slot.isdigit() else ""}


@app.post("/connectors/approval")
async def approval(app_name: str, x_user_id: str = Header(default=""), authorization: str = Header(default="")):
    user_id = resolve_user(x_user_id, authorization)
    key = os.environ.get("COMPOSIO_API_KEY")
    if not key:
        raise HTTPException(500, "COMPOSIO_API_KEY missing")
    auth_config = os.environ.get(f"COMPOSIO_AUTH_CONFIG_{app_name.upper()}", app_name)
    workspace_id, _ = workspace_for(user_id)
    async with httpx.AsyncClient(timeout=40) as client:
        r = await client.post(
            "https://backend.composio.dev/api/v3/connected_accounts/link",
            headers={"x-api-key": key, "Content-Type": "application/json"},
            json={"user_id": user_id, "auth_config_id": auth_config},
        )
    if r.status_code >= 400:
        raise HTTPException(502, "Composio did not return an approval link")
    data = r.json()
    url = data.get("redirect_url") or data.get("redirectUrl") or data.get("url")
    if not url:
        raise HTTPException(502, "Composio returned no approval URL")
    provider_id = data.get("connected_account_id")
    with db() as conn:
        conn.execute("INSERT INTO doom.tool_connections(connection_id,user_id,workspace_id,app_name,provider_account_id,status) VALUES(%s,%s,%s,%s,%s,'pending') ON CONFLICT(user_id,app_name) DO UPDATE SET workspace_id=EXCLUDED.workspace_id,provider_account_id=EXCLUDED.provider_account_id,status='pending',updated_at=NOW()", ("tc_"+uuid.uuid4().hex,user_id,workspace_id,app_name.lower(),provider_id))
        conn.commit()
    audit(user_id,"tool.connection.started",workspace_id,app_name,details={"approval_url_returned":True,"provider_account_id":provider_id})
    return {"ok": True, "status": "requires approval", "url": url, "app": app_name.lower(), "provider_account_id": provider_id}

@app.get("/connectors/status")
async def connector_status(app_name: str, x_user_id: str = Header(default=""), authorization: str = Header(default="")):
    user_id = resolve_user(x_user_id, authorization)
    key = os.environ.get("COMPOSIO_API_KEY")
    if not key:
        raise HTTPException(500, "COMPOSIO_API_KEY missing")
    workspace_id, _ = workspace_for(user_id)
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.get("https://backend.composio.dev/api/v3/connected_accounts", headers={"x-api-key": key}, params={"user_id": user_id})
    if r.status_code >= 400:
        raise HTTPException(502, "Composio status failed")
    data = r.json()
    rows = data.get("items") if isinstance(data, dict) else data
    rows = rows or []
    target = app_name.lower()
    match = None
    for row in rows:
        if not isinstance(row, dict):
            continue
        toolkit = str(row.get("toolkit") or row.get("toolkit_slug") or row.get("app") or row.get("auth_config_id") or "").lower()
        status = str(row.get("status") or "").upper()
        if target in toolkit or target == str(row.get("auth_config_id") or "").lower():
            if status in ("ACTIVE", "CONNECTED", "ENABLED") or not status:
                match = row
                break
    connected = bool(match)
    provider_id = (match or {}).get("id") or (match or {}).get("connected_account_id") or (match or {}).get("nanoid")
    with db() as conn:
        conn.execute("INSERT INTO doom.tool_connections(connection_id,user_id,workspace_id,app_name,provider_account_id,status) VALUES(%s,%s,%s,%s,%s,%s) ON CONFLICT(user_id,app_name) DO UPDATE SET provider_account_id=EXCLUDED.provider_account_id,status=EXCLUDED.status,updated_at=NOW()", ("tc_"+uuid.uuid4().hex,user_id,workspace_id,target,provider_id,"connected" if connected else "disconnected"))
        conn.commit()
    return {"connected": connected, "app": target, "provider_account_id": provider_id}

@app.post("/connectors/confirm")
def connector_confirm(app_name: str, x_user_id: str = Header(default=""), authorization: str = Header(default="")):
    user_id = resolve_user(x_user_id, authorization)
    raise HTTPException(410,"Manual connection confirmation is disabled. Connection state is read from Composio.")

class SplitIn(BaseModel):
    request: str

async def make_plan(request: str) -> dict:
    key=os.environ.get("OPENROUTER_API_KEY")
    if not key: raise HTTPException(500,"OPENROUTER_API_KEY missing")
    schema="""Return ONLY JSON with keys app, action, params, requires_tool. app must be gmail|slack|notion|x|linkedin|instagram|none. action must be send_email|send_message|create_page|post|none. Never execute tools. If the request is conversational, app=none, action=none, requires_tool=false."""
    async with httpx.AsyncClient(timeout=90) as client:
        r=await client.post("https://openrouter.ai/api/v1/chat/completions",headers={"Authorization":f"Bearer {key}","Content-Type":"application/json"},json={"model":os.environ.get("OPENROUTER_MODEL","openai/gpt-4o-mini"),"messages":[{"role":"system","content":schema},{"role":"user","content":request}]})
    if r.status_code>=400: raise HTTPException(502,"OpenRouter planning failed")
    text=r.json()["choices"][0]["message"]["content"]
    match=__import__('re').search(r"\{.*\}",text,__import__('re').S)
    if not match: raise HTTPException(502,"OpenRouter returned no valid action plan")
    try: plan=json.loads(match.group(0))
    except Exception: raise HTTPException(502,"OpenRouter returned invalid action plan")
    if not isinstance(plan,dict): raise HTTPException(502,"Invalid action plan")
    plan["app"]=str(plan.get("app") or "none").lower()
    plan["action"]=str(plan.get("action") or "none").lower()
    plan["params"]=plan.get("params") if isinstance(plan.get("params"),dict) else {}
    plan["requires_tool"]=bool(plan.get("requires_tool", plan["app"]!="none" and plan["action"]!="none"))
    allowed_apps={"gmail","slack","notion","x","linkedin","instagram","none"}
    allowed_actions={"send_email","send_message","create_page","post","none"}
    if plan["app"] not in allowed_apps or plan["action"] not in allowed_actions:
        raise HTTPException(400,"OpenRouter proposed an unsupported tool action")
    if plan["app"]=="none" or plan["action"]=="none": plan["requires_tool"]=False
    return plan

async def execute_split_request(user_id: str, request_or_plan):
    if isinstance(request_or_plan, str):
        plan=await make_plan(request_or_plan); raw_request=request_or_plan
    else:
        plan=dict(request_or_plan); raw_request=plan.get("raw_request","")
        # Never allow a caller to invent an arbitrary action outside the same validation.
        if plan.get("app") not in {"gmail","slack","notion","x","linkedin","instagram","none"} or plan.get("action") not in {"send_email","send_message","create_page","post","none"}:
            raise HTTPException(400,"Unsupported split action")
    app_name=(plan.get("app") or "none").lower(); action=(plan.get("action") or "none").lower(); params=plan.get("params") or {}
    if app_name=="none" or action=="none" or not plan.get("requires_tool", True):
        return {"status":"success","executed":False,"plan":plan,"text":raw_request or "No external tool action required."}
    from app.providers.composio import run_action, ACTIONS, ACTION_ALIASES
    if app_name not in ACTIONS or (app_name, action) not in ACTION_ALIASES:
        raise HTTPException(400,"Tool action is not enabled in DOOM")
    workspace_id,role=workspace_for(user_id)
    allowed,msg=authorized_tool(user_id,app_name,action,workspace_id,role)
    if not allowed: raise HTTPException(403,msg)
    with db() as conn:
        row=conn.execute("SELECT status, provider_account_id FROM doom.tool_connections WHERE user_id=%s AND app_name=%s",(user_id,app_name)).fetchone()
        ent=conn.execute("SELECT daily_tools_remaining FROM doom.entitlements WHERE user_id=%s",(user_id,)).fetchone()
    if not ent or ent[0] <= 0: raise HTTPException(403,"Daily tool limit reached.")
    if not row or row[0] != "connected" or not row[1]:
        return {"status":"not connected","executed":False,"plan":plan,"text":f"Connect {app_name} first."}
    if approval_required(user_id,app_name,action,workspace_id):
        approval_id="apr_"+uuid.uuid4().hex
        with db() as conn:
            conn.execute("INSERT INTO doom.approval_requests(approval_id,user_id,workspace_id,app_name,action,params) VALUES(%s,%s,%s,%s,%s,%s)",(approval_id,user_id,workspace_id,app_name,action,json.dumps(params))); conn.commit()
        audit(user_id,"tool.approval.required",workspace_id,app_name,action,{"approval_id":approval_id})
        return {"status":"approval required","executed":False,"approval_id":approval_id,"plan":plan,"text":"Founder approval is required before this action can execute."}
    result=await run_action(user_id,app_name,params,action,connected_account_id=row[1])
    audit(user_id,"tool.executed" if result.get("ok") else "tool.failed",workspace_id,app_name,action,{"result":result.get("status")})
    if result.get("ok"):
        with db() as conn:
            conn.execute("UPDATE doom.entitlements SET daily_tools_remaining=GREATEST(daily_tools_remaining-1,0) WHERE user_id=%s",(user_id,)); conn.commit()
        return {"status":"success","executed":True,"plan":plan,"result":result,"text":f"Completed through {app_name}."}
    return {"status":"failed","executed":False,"plan":plan,"result":result,"text":result.get("detail") or "Tool execution failed."}

@app.post("/split")
async def split_execute(body: SplitIn, x_user_id: str = Header(default=""), authorization: str = Header(default="")):
    user_id=resolve_user(x_user_id, authorization)
    plan=await make_plan(body.request)
    # Normal conversation never executes Composio. It falls through to the same
    # authenticated DOOM chat path, while tool requests continue through the
    # explicit authorization -> Composio execution boundary.
    if not plan.get("requires_tool") or plan.get("app")=="none" or plan.get("action")=="none":
        return await chat(ChatIn(prompt=body.request), user_id, authorization)
    plan["raw_request"]=body.request
    return await execute_split_request(user_id, plan)

@app.post("/approvals/{approval_id}/approve")
async def approve_action(approval_id: str, x_user_id: str = Header(default=""), authorization: str = Header(default="")):
    user_id=resolve_user(x_user_id, authorization)
    with db() as conn:
        row=conn.execute("SELECT user_id,workspace_id,app_name,action,params,status FROM doom.approval_requests WHERE approval_id=%s",(approval_id,)).fetchone()
    if not row: raise HTTPException(404,"Approval not found")
    if row[0] != user_id: raise HTTPException(403,"Only the requesting user can approve this request")
    if row[5] != "pending": raise HTTPException(409,"Approval is no longer pending")
    result=await execute_split_request(user_id,{"app":row[2],"action":row[3],"params":row[4],"requires_tool":True,"raw_request":"approved action"})
    with db() as conn:
        conn.execute("UPDATE doom.approval_requests SET status=%s,resolved_at=NOW() WHERE approval_id=%s",("approved" if result.get("executed") else "failed",approval_id)); conn.commit()
    return result

