"""Dheeraja Matrimony - FastAPI backend."""
import os
import re
import uuid
import logging
import hashlib
from datetime import datetime, timezone, date, timedelta
from pathlib import Path
from typing import List, Optional, Literal
from collections import defaultdict, deque

import bcrypt
import jwt
from fastapi import FastAPI, APIRouter, HTTPException, Depends, UploadFile, File, Request, status, Query
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import Response
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, EmailStr, Field, field_validator

from storage_client import put_object, get_object, build_path, init_storage

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# ==== Config ====
MONGO_URL = os.environ['MONGO_URL']
DB_NAME = os.environ['DB_NAME']
JWT_SECRET = os.environ['JWT_SECRET']
JWT_ALG = os.environ.get('JWT_ALGORITHM', 'HS256')
JWT_EXPIRE_MINUTES = int(os.environ.get('JWT_EXPIRE_MINUTES', '10080'))
ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'admin@dheeraja.com')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'Admin@Dheeraja2026')
ADMIN_NAME = os.environ.get('ADMIN_NAME', 'Dheeraja Admin')

client = AsyncIOMotorClient(MONGO_URL)
db = client[DB_NAME]

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("dheeraja")

app = FastAPI(title="Dheeraja Matrimony API", docs_url=None, openapi_url=None, redoc_url=None)
api = APIRouter(prefix="/api")
security = HTTPBearer(auto_error=False)

# ==== Helpers ====
def utcnow():
    return datetime.now(timezone.utc)


def hash_password(pw: str) -> str:
    return bcrypt.hashpw(pw.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(pw: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(pw.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


def create_token(user_id: str, role: str) -> str:
    payload = {
        "sub": user_id,
        "role": role,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRE_MINUTES),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")


def sanitize(text: str) -> str:
    if not text:
        return ""
    # basic XSS defense — strip HTML tags & control chars
    text = re.sub(r"<[^>]*>", "", text)
    return text.strip()[:5000]


def calc_age(dob_str: str) -> Optional[int]:
    try:
        d = datetime.strptime(dob_str, "%Y-%m-%d").date()
        today = date.today()
        return today.year - d.year - ((today.month, today.day) < (d.month, d.day))
    except Exception:
        return None


def profile_completeness(p: dict) -> int:
    fields = [
        "full_name", "gender", "dob", "height_cm", "marital_status", "religion",
        "community", "mother_tongue", "country", "state", "city", "education",
        "occupation", "company", "income_range", "about_me", "family_details",
        "father_info", "mother_info", "profile_photo_id",
    ]
    filled = sum(1 for f in fields if p.get(f))
    return int(round(100.0 * filled / len(fields)))


def public_profile(p: dict, viewer_id: Optional[str] = None) -> dict:
    """Strip private fields depending on viewer / privacy settings."""
    if not p:
        return {}
    is_self = viewer_id and viewer_id == p.get("user_id")
    privacy = p.get("privacy", {}) or {}
    out = {
        "user_id": p.get("user_id"),
        "profile_id": p.get("profile_id"),
        "full_name": p.get("full_name"),
        "gender": p.get("gender"),
        "dob": p.get("dob") if is_self else None,
        "age": p.get("age"),
        "height_cm": p.get("height_cm"),
        "marital_status": p.get("marital_status"),
        "religion": p.get("religion"),
        "community": p.get("community"),
        "mother_tongue": p.get("mother_tongue"),
        "country": p.get("country"),
        "state": p.get("state"),
        "city": p.get("city"),
        "education": p.get("education"),
        "occupation": p.get("occupation"),
        "company": p.get("company"),
        "income_range": p.get("income_range"),
        "about_me": p.get("about_me"),
        "family_details": p.get("family_details"),
        "father_info": p.get("father_info"),
        "mother_info": p.get("mother_info"),
        "siblings": p.get("siblings"),
        "lifestyle": p.get("lifestyle"),
        "profile_photo_id": p.get("profile_photo_id") if (is_self or privacy.get("show_photos", True)) else None,
        "photo_ids": p.get("photo_ids", []) if (is_self or privacy.get("show_photos", True)) else [],
        "verified": p.get("verified", False),
        "profile_visibility": p.get("profile_visibility", True),
        "completeness": p.get("completeness", 0),
        "created_at": p.get("created_at"),
        "last_active": p.get("last_active"),
    }
    # contact info gated
    if is_self or privacy.get("show_email", False):
        out["email"] = p.get("email")
    if is_self or privacy.get("show_phone", False):
        out["phone"] = p.get("phone")
    return out


# ==== Rate limiter (in-memory sliding window) ====
_rl_buckets: dict = defaultdict(lambda: deque())


def rate_limit(key: str, limit: int, window_sec: int) -> bool:
    now = datetime.now(timezone.utc).timestamp()
    q = _rl_buckets[key]
    while q and now - q[0] > window_sec:
        q.popleft()
    if len(q) >= limit:
        return False
    q.append(now)
    return True


# ==== Settings, Plans & Entitlements ====
DEFAULT_SETTINGS = {
    "key": "app",
    "app_name": "Dheeraja Matrimony",
    "tagline": "Serious matches. Verified members.",
    "support_email": "support@dheeraja.com",
    "support_phone": "",
    "upi_id": "",
    "payment_instructions": "Pay the plan amount via UPI, then share the transaction ID with support. Admin will activate your plan within 24 hours.",
    "free_mode": True,
    "registration_open": True,
    "free_interests_per_month": 5,
    "free_can_message": True,
    "free_can_view_contacts": False,
    "announcement": "Launch offer: All premium features are FREE for a limited time!",
}

DEFAULT_PLANS = [
    {"name": "Free", "description": "Basic membership — browse profiles and send limited interests.", "price": 0, "duration_days": 0,
     "features": {"interests_per_month": 5, "can_message": True, "can_view_contacts": False, "profile_boost": False, "badge": ""}, "active": True, "sort_order": 0},
    {"name": "Gold", "description": "50 interests/month, chat freely and view contact details.", "price": 999, "duration_days": 90,
     "features": {"interests_per_month": 50, "can_message": True, "can_view_contacts": True, "profile_boost": False, "badge": "GOLD"}, "active": True, "sort_order": 1},
    {"name": "Premium", "description": "Unlimited interests, contact access and profile boost in search.", "price": 1999, "duration_days": 180,
     "features": {"interests_per_month": -1, "can_message": True, "can_view_contacts": True, "profile_boost": True, "badge": "PREMIUM"}, "active": True, "sort_order": 2},
]


async def get_app_settings() -> dict:
    s = await db.settings.find_one({"key": "app"}, {"_id": 0})
    return {**DEFAULT_SETTINGS, **(s or {})}


async def get_active_subscription(user_id: str) -> Optional[dict]:
    return await db.subscriptions.find_one(
        {"user_id": user_id, "status": "active", "$or": [{"expires_at": None}, {"expires_at": {"$gt": utcnow()}}]},
        {"_id": 0}, sort=[("created_at", -1)],
    )


async def get_entitlements(user_id: str) -> dict:
    s = await get_app_settings()
    if s.get("free_mode"):
        return {"plan_name": "Launch Offer — All Free", "source": "free_mode", "interests_per_month": -1,
                "can_message": True, "can_view_contacts": True, "badge": "FREE", "expires_at": None}
    sub = await get_active_subscription(user_id)
    if sub:
        f = sub.get("plan_features", {}) or {}
        return {"plan_name": sub.get("plan_name", "Plan"), "source": sub.get("source", "manual"),
                "interests_per_month": f.get("interests_per_month", 0), "can_message": f.get("can_message", True),
                "can_view_contacts": f.get("can_view_contacts", False), "badge": f.get("badge", ""),
                "expires_at": sub.get("expires_at")}
    return {"plan_name": "Free", "source": "default", "interests_per_month": int(s.get("free_interests_per_month", 5)),
            "can_message": bool(s.get("free_can_message", True)), "can_view_contacts": bool(s.get("free_can_view_contacts", False)),
            "badge": "", "expires_at": None}


async def interests_used_this_month(user_id: str) -> int:
    now = utcnow()
    month_start = datetime(now.year, now.month, 1, tzinfo=timezone.utc)
    return await db.interests.count_documents({"from_user_id": user_id, "created_at": {"$gte": month_start}})


async def create_subscription(user_id: str, plan: dict, source: str, duration_days: Optional[int] = None,
                              admin_id: Optional[str] = None, voucher_code: Optional[str] = None) -> dict:
    days = duration_days if duration_days is not None else plan.get("duration_days", 0)
    expires = utcnow() + timedelta(days=days) if days and days > 0 else None
    await db.subscriptions.update_many({"user_id": user_id, "status": "active"}, {"$set": {"status": "replaced"}})
    doc = {
        "subscription_id": str(uuid.uuid4()),
        "user_id": user_id,
        "plan_id": plan["plan_id"],
        "plan_name": plan["name"],
        "plan_features": plan.get("features", {}),
        "source": source,
        "voucher_code": voucher_code,
        "assigned_by": admin_id,
        "status": "active",
        "starts_at": utcnow(),
        "expires_at": expires,
        "created_at": utcnow(),
    }
    await db.subscriptions.insert_one(doc)
    doc.pop("_id", None)
    return doc


# ==== Auth dependencies ====
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    if not credentials:
        raise HTTPException(status_code=401, detail="Not authenticated")
    payload = decode_token(credentials.credentials)
    user = await db.users.find_one({"user_id": payload["sub"]}, {"_id": 0, "password_hash": 0})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    if user.get("status") == "suspended":
        raise HTTPException(status_code=403, detail="Account suspended")
    return user


async def get_admin_user(user: dict = Depends(get_current_user)) -> dict:
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


# ==== Pydantic Models ====
class RegisterIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    full_name: str = Field(min_length=2, max_length=100)
    gender: Literal["male", "female"]
    dob: str  # YYYY-MM-DD
    phone: Optional[str] = Field(default=None, max_length=20)

    @field_validator("dob")
    @classmethod
    def _dob(cls, v):
        age = calc_age(v)
        if age is None:
            raise ValueError("Invalid DOB format, use YYYY-MM-DD")
        if age < 18 or age > 100:
            raise ValueError("Age must be between 18 and 100")
        return v


class LoginIn(BaseModel):
    email: EmailStr
    password: str


class GoogleAuthIn(BaseModel):
    email: EmailStr
    full_name: str
    gender: Optional[Literal["male", "female"]] = None
    google_sub: Optional[str] = None


class ProfileUpdate(BaseModel):
    full_name: Optional[str] = None
    gender: Optional[Literal["male", "female"]] = None
    dob: Optional[str] = None
    height_cm: Optional[int] = Field(default=None, ge=120, le=230)
    marital_status: Optional[Literal["never_married", "divorced", "widowed", "separated"]] = None
    religion: Optional[str] = None
    community: Optional[str] = None
    mother_tongue: Optional[str] = None
    country: Optional[str] = None
    state: Optional[str] = None
    city: Optional[str] = None
    education: Optional[str] = None
    occupation: Optional[str] = None
    company: Optional[str] = None
    income_range: Optional[str] = None
    about_me: Optional[str] = None
    family_details: Optional[str] = None
    father_info: Optional[str] = None
    mother_info: Optional[str] = None
    siblings: Optional[str] = None
    lifestyle: Optional[str] = None
    phone: Optional[str] = None
    profile_visibility: Optional[bool] = None


class PrivacyUpdate(BaseModel):
    show_email: Optional[bool] = None
    show_phone: Optional[bool] = None
    show_photos: Optional[bool] = None


class MessageIn(BaseModel):
    text: str = Field(min_length=1, max_length=2000)


class ReportIn(BaseModel):
    target_user_id: str
    reason: str = Field(min_length=3, max_length=500)
    context: Optional[str] = Field(default=None, max_length=500)


class VerifyRequestIn(BaseModel):
    id_document_note: Optional[str] = Field(default=None, max_length=500)


class AdminActionIn(BaseModel):
    action: Literal["suspend", "activate", "verify_approve", "verify_reject", "delete"]
    reason: Optional[str] = None


class PlanFeatures(BaseModel):
    interests_per_month: int = Field(default=5, ge=-1, le=100000)  # -1 = unlimited
    can_message: bool = True
    can_view_contacts: bool = False
    profile_boost: bool = False
    badge: str = Field(default="", max_length=20)


class PlanIn(BaseModel):
    name: str = Field(min_length=2, max_length=50)
    description: str = Field(default="", max_length=300)
    price: float = Field(default=0, ge=0)
    duration_days: int = Field(default=0, ge=0, le=3650)  # 0 = lifetime
    features: PlanFeatures = PlanFeatures()
    active: bool = True
    sort_order: int = 0


class VoucherIn(BaseModel):
    code: Optional[str] = Field(default=None, min_length=4, max_length=30)
    plan_id: str
    duration_days: Optional[int] = Field(default=None, ge=1, le=3650)
    max_uses: int = Field(default=1, ge=1, le=100000)
    expires_at: Optional[str] = None  # YYYY-MM-DD


class RedeemIn(BaseModel):
    code: str = Field(min_length=4, max_length=30)


class AssignSubIn(BaseModel):
    user_id: str
    plan_id: str
    duration_days: Optional[int] = Field(default=None, ge=1, le=3650)


class SettingsUpdate(BaseModel):
    app_name: Optional[str] = Field(default=None, max_length=80)
    tagline: Optional[str] = Field(default=None, max_length=200)
    support_email: Optional[str] = Field(default=None, max_length=120)
    support_phone: Optional[str] = Field(default=None, max_length=20)
    upi_id: Optional[str] = Field(default=None, max_length=80)
    payment_instructions: Optional[str] = Field(default=None, max_length=1000)
    free_mode: Optional[bool] = None
    registration_open: Optional[bool] = None
    free_interests_per_month: Optional[int] = Field(default=None, ge=0, le=100000)
    free_can_message: Optional[bool] = None
    free_can_view_contacts: Optional[bool] = None
    announcement: Optional[str] = Field(default=None, max_length=300)


import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import random

# ==== Email Config ====
SMTP_SERVER = os.environ.get("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "dheerajamatrimony@gmail.com")
SMTP_PASS = os.environ.get("SMTP_PASS", "pklcefnfxvnzfqxq").replace(" ", "")

def send_otp_email(to_email: str, otp: str, subject_title: str = "Dheeraja Verification Code"):
    if not SMTP_USER or not SMTP_PASS:
        logger.warning("Email credentials not set. OTP for %s is: %s", to_email, otp)
        return False

    msg = MIMEMultipart()
    msg['From'] = f"Dheeraja Matrimony <{SMTP_USER}>"
    msg['To'] = to_email
    msg['Subject'] = f"{otp} is your {subject_title}"

    body = f"""
    <div style="font-family: Arial, sans-serif; padding: 20px; background-color: #FCFBF9; border-radius: 10px;">
      <h2 style="color: #8B1E32;">Dheeraja Matrimony</h2>
      <p>Hello,</p>
      <p>Your verification OTP code is:</p>
      <h1 style="color: #8B1E32; letter-spacing: 5px; background: #EAE3DD; padding: 10px 20px; display: inline-block; border-radius: 8px;">{otp}</h1>
      <p>This code is valid for 10 minutes. Do not share it with anyone.</p>
      <hr style="border: none; border-top: 1px solid #EAE3DD; margin-top: 20px;" />
      <p style="font-size: 12px; color: #78716C;">Dheeraja Matrimony — Serious Matchmaking in India</p>
    </div>
    """
    msg.attach(MIMEText(body, 'html'))

    try:
        # Try SSL port 465 first (Hostinger friendly)
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=10) as server:
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
            logger.info("Successfully sent OTP email to %s via SSL 465", to_email)
            return True
    except Exception as e1:
        logger.warning("SSL 465 failed (%s), trying TLS 587...", e1)
        try:
            with smtplib.SMTP("smtp.gmail.com", 587, timeout=10) as server:
                server.starttls()
                server.login(SMTP_USER, SMTP_PASS)
                server.send_message(msg)
                logger.info("Successfully sent OTP email to %s via TLS 587", to_email)
                return True
        except Exception as e2:
            logger.error("Failed to send email to %s on both ports: %s", to_email, e2)
            return False

# ==== New OTP Routes ====
@api.post("/auth/send-otp")
async def send_otp(body: dict):
    email = body.get("email", "").lower().strip()
    if not email:
        raise HTTPException(status_code=400, detail="Email is required")

    otp = str(random.randint(100000, 999999))
    # Store OTP in DB with 10 min expiry
    await db.otps.update_one(
        {"email": email},
        {"$set": {"otp": otp, "expires_at": utcnow() + timedelta(minutes=10)}},
        upsert=True
    )
    sent = await run_in_threadpool(send_otp_email, email, otp)
    res = {"message": "OTP sent to email"}
    if not sent:
        # Include fallback OTP so testing/registration is never blocked
        res["debug_otp"] = otp
        res["message"] = f"OTP for testing is {otp}"
    return res
@api.post("/auth/reset-password")
async def reset_password(body: dict):
    email = body.get("email", "").lower().strip()
    otp = body.get("otp", "").strip()
    new_password = body.get("new_password", "").strip()

    if not email or not otp or not new_password:
        raise HTTPException(status_code=400, detail="Email, OTP, and new password are required")

    record = await db.otps.find_one({"email": email})
    if not record or record.get("otp") != otp or record.get("expires_at") < utcnow():
        raise HTTPException(status_code=400, detail="Invalid or expired OTP")

    user = await db.users.find_one({"email": email})
    if not user:
        raise HTTPException(status_code=404, detail="User with this email does not exist")

    await db.users.update_one(
        {"email": email},
        {"$set": {"password_hash": hash_password(new_password)}}
    )
    await db.otps.delete_one({"email": email})
    return {"message": "Password reset successfully. You can now login with your new password."}

# ==== New OTP Routes ====
@api.post("/auth/send-otp")
async def send_otp(body: dict):
    email = body.get("email", "").lower()
    if not email:
        raise HTTPException(status_code=400, detail="Email is required")

    otp = str(random.randint(100000, 999999))
    # Store OTP in DB with 10 min expiry
    await db.otps.update_one(
        {"email": email},
        {"$set": {"otp": otp, "expires_at": utcnow() + timedelta(minutes=10)}},
        upsert=True
    )
    send_otp_email(email, otp)
    return {"message": "OTP sent to email"}

@api.post("/auth/verify-otp")
async def verify_otp(body: dict):
    email = body.get("email", "").lower()
    otp = body.get("otp")

    record = await db.otps.find_one({"email": email})
    if not record or record["otp"] != otp or record["expires_at"] < utcnow():
        raise HTTPException(status_code=400, detail="Invalid or expired OTP")

    await db.otps.delete_one({"email": email})
    return {"message": "OTP verified successfully"}

# ==== Startup ====
@app.on_event("startup")
async def on_startup():
    # indexes
    await db.users.create_index("email", unique=True)
    await db.users.create_index("user_id", unique=True)
    await db.profiles.create_index("user_id", unique=True)
    await db.profiles.create_index("profile_id", unique=True)
    await db.profiles.create_index([("gender", 1), ("religion", 1), ("age", 1)])
    await db.profiles.create_index([("last_active", -1)])
    await db.interests.create_index([("from_user_id", 1), ("to_user_id", 1)], unique=True)
    await db.interests.create_index("to_user_id")
    await db.shortlists.create_index([("user_id", 1), ("target_user_id", 1)], unique=True)
    await db.blocks.create_index([("user_id", 1), ("blocked_user_id", 1)], unique=True)
    await db.messages.create_index([("conversation_id", 1), ("created_at", 1)])
    await db.conversations.create_index([("participants", 1)])
    await db.reports.create_index("target_user_id")
    await db.verification_requests.create_index("user_id")
    await db.subscriptions.create_index([("user_id", 1), ("status", 1)])
    await db.vouchers.create_index("code", unique=True)
    await db.plans.create_index("plan_id", unique=True)

    # Seed settings & default plans
    if not await db.settings.find_one({"key": "app"}):
        await db.settings.insert_one(dict(DEFAULT_SETTINGS))
        logger.info("Default settings seeded")
    if await db.plans.count_documents({}) == 0:
        for p in DEFAULT_PLANS:
            await db.plans.insert_one({**p, "plan_id": str(uuid.uuid4()), "created_at": utcnow()})
        logger.info("Default plans seeded")

    # Seed admin
    existing = await db.users.find_one({"email": ADMIN_EMAIL})
    if not existing:
        admin_id = str(uuid.uuid4())
        await db.users.insert_one({
            "user_id": admin_id,
            "email": ADMIN_EMAIL,
            "password_hash": hash_password(ADMIN_PASSWORD),
            "role": "admin",
            "status": "active",
            "created_at": utcnow(),
        })
        logger.info("Admin seeded: %s", ADMIN_EMAIL)

    # Init storage best-effort
    try:
        await run_in_threadpool(init_storage)
        logger.info("Storage initialized")
    except Exception as e:
        logger.warning("Storage init failed (uploads will retry): %s", e)


# ==== Auth Routes ====
@api.post("/auth/register")
async def register(body: RegisterIn, request: Request):
    ip = request.client.host if request.client else "unknown"
    if not rate_limit(f"reg:{ip}", limit=5, window_sec=300):
        raise HTTPException(status_code=429, detail="Too many attempts, try later")

    s = await get_app_settings()
    if not s.get("registration_open", True):
        raise HTTPException(status_code=403, detail="New registrations are temporarily closed")

    exists = await db.users.find_one({"email": body.email.lower()})
    if exists:
        raise HTTPException(status_code=400, detail="Email already registered")

    user_id = str(uuid.uuid4())
    now = utcnow()
    profile_id = f"DM{uuid.uuid4().hex[:8].upper()}"
    age = calc_age(body.dob)

    await db.users.insert_one({
        "user_id": user_id,
        "email": body.email.lower(),
        "password_hash": hash_password(body.password),
        "role": "member",
        "status": "active",
        "created_at": now,
    })

    profile = {
        "user_id": user_id,
        "profile_id": profile_id,
        "email": body.email.lower(),
        "phone": body.phone,
        "full_name": sanitize(body.full_name),
        "gender": body.gender,
        "dob": body.dob,
        "age": age,
        "marital_status": "never_married",
        "profile_visibility": True,
        "verified": False,
        "privacy": {"show_email": False, "show_phone": False, "show_photos": True},
        "photo_ids": [],
        "created_at": now,
        "last_active": now,
    }
    profile["completeness"] = profile_completeness(profile)
    await db.profiles.insert_one(profile)

    token = create_token(user_id, "member")
    return {"token": token, "user": {"user_id": user_id, "email": body.email.lower(), "role": "member", "profile_id": profile_id}}


@api.post("/auth/login")
async def login(body: LoginIn, request: Request):
    ip = request.client.host if request.client else "unknown"
    if not rate_limit(f"login:{ip}", limit=10, window_sec=300):
        raise HTTPException(status_code=429, detail="Too many attempts, try later")

    user = await db.users.find_one({"email": body.email.lower()})
    if not user or not verify_password(body.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if user.get("status") == "suspended":
        raise HTTPException(status_code=403, detail="Account suspended")

    await db.profiles.update_one({"user_id": user["user_id"]}, {"$set": {"last_active": utcnow()}})
    token = create_token(user["user_id"], user.get("role", "member"))
    prof = await db.profiles.find_one({"user_id": user["user_id"]}, {"_id": 0})
    return {
        "token": token,
        "user": {
            "user_id": user["user_id"],
            "email": user["email"],
            "role": user.get("role", "member"),
            "profile_id": (prof or {}).get("profile_id"),
        },
    }


@api.post("/auth/google")
async def google_auth(body: GoogleAuthIn):
    """Simplified Google auth: creates or logs in a user by email (trusted from Google client-side)."""
    email = body.email.lower()
    user = await db.users.find_one({"email": email})
    if not user:
        user_id = str(uuid.uuid4())
        now = utcnow()
        profile_id = f"DM{uuid.uuid4().hex[:8].upper()}"
        # random password
        rnd = hashlib.sha256(os.urandom(32)).hexdigest()
        await db.users.insert_one({
            "user_id": user_id,
            "email": email,
            "password_hash": hash_password(rnd),
            "role": "member",
            "status": "active",
            "google_sub": body.google_sub,
            "created_at": now,
        })
        profile = {
            "user_id": user_id,
            "profile_id": profile_id,
            "email": email,
            "full_name": sanitize(body.full_name),
            "gender": body.gender,
            "profile_visibility": True,
            "verified": False,
            "privacy": {"show_email": False, "show_phone": False, "show_photos": True},
            "photo_ids": [],
            "created_at": now,
            "last_active": now,
        }
        profile["completeness"] = profile_completeness(profile)
        await db.profiles.insert_one(profile)
        user = await db.users.find_one({"email": email})

    token = create_token(user["user_id"], user.get("role", "member"))
    prof = await db.profiles.find_one({"user_id": user["user_id"]}, {"_id": 0})
    return {
        "token": token,
        "user": {
            "user_id": user["user_id"],
            "email": user["email"],
            "role": user.get("role", "member"),
            "profile_id": (prof or {}).get("profile_id"),
        },
    }


@api.get("/auth/me")
async def me(user: dict = Depends(get_current_user)):
    prof = await db.profiles.find_one({"user_id": user["user_id"]}, {"_id": 0})
    return {"user": {"user_id": user["user_id"], "email": user["email"], "role": user.get("role")}, "profile": public_profile(prof, user["user_id"]) if prof else None}


# ==== Profile Routes ====
@api.get("/profile/me")
async def get_my_profile(user: dict = Depends(get_current_user)):
    prof = await db.profiles.find_one({"user_id": user["user_id"]}, {"_id": 0})
    if not prof:
        raise HTTPException(status_code=404, detail="Profile not found")
    return public_profile(prof, user["user_id"])


@api.put("/profile/me")
async def update_my_profile(body: ProfileUpdate, user: dict = Depends(get_current_user)):
    update = {k: (sanitize(v) if isinstance(v, str) else v) for k, v in body.model_dump(exclude_unset=True).items() if v is not None}
    if "dob" in update:
        age = calc_age(update["dob"])
        if age is None or age < 18 or age > 100:
            raise HTTPException(status_code=400, detail="Invalid DOB")
        update["age"] = age
    prof = await db.profiles.find_one({"user_id": user["user_id"]})
    if not prof:
        raise HTTPException(status_code=404, detail="Profile not found")
    merged = {**prof, **update}
    update["completeness"] = profile_completeness(merged)
    update["last_active"] = utcnow()
    await db.profiles.update_one({"user_id": user["user_id"]}, {"$set": update})
    new_prof = await db.profiles.find_one({"user_id": user["user_id"]}, {"_id": 0})
    return public_profile(new_prof, user["user_id"])


@api.put("/profile/me/privacy")
async def update_privacy(body: PrivacyUpdate, user: dict = Depends(get_current_user)):
    updates = {f"privacy.{k}": v for k, v in body.model_dump(exclude_unset=True).items() if v is not None}
    if updates:
        await db.profiles.update_one({"user_id": user["user_id"]}, {"$set": updates})
    prof = await db.profiles.find_one({"user_id": user["user_id"]}, {"_id": 0})
    return {"privacy": prof.get("privacy", {})}


@api.get("/profile/{user_id}")
async def get_profile(user_id: str, user: dict = Depends(get_current_user)):
    if user_id == user["user_id"]:
        prof = await db.profiles.find_one({"user_id": user_id}, {"_id": 0})
        if not prof:
            raise HTTPException(404, "Not found")
        return public_profile(prof, user["user_id"])
    # Check block
    blocked = await db.blocks.find_one({"user_id": user_id, "blocked_user_id": user["user_id"]})
    if blocked:
        raise HTTPException(status_code=403, detail="Profile unavailable")
    prof = await db.profiles.find_one({"user_id": user_id}, {"_id": 0})
    if not prof:
        raise HTTPException(404, "Not found")
    if not prof.get("profile_visibility", True):
        raise HTTPException(status_code=403, detail="Profile hidden by member")
    out = public_profile(prof, user["user_id"])
    ent = await get_entitlements(user["user_id"])
    if not ent.get("can_view_contacts", False):
        out.pop("email", None)
        out.pop("phone", None)
        out["contacts_locked"] = True
    return out


# ==== Photo Upload ====
ALLOWED_IMAGE_TYPES = {"image/jpeg", "image/jpg", "image/png", "image/webp"}
MAX_PHOTO_BYTES = 6 * 1024 * 1024  # 6MB


@api.post("/photos/upload")
async def upload_photo(file: UploadFile = File(...), user: dict = Depends(get_current_user)):
    if file.content_type not in ALLOWED_IMAGE_TYPES:
        raise HTTPException(status_code=400, detail="Only JPEG/PNG/WEBP images allowed")
    data = await file.read()
    if len(data) == 0:
        raise HTTPException(400, "Empty file")
    if len(data) > MAX_PHOTO_BYTES:
        raise HTTPException(status_code=400, detail="Image exceeds 6MB")
    ext = (file.filename or "img.jpg").split(".")[-1].lower()
    if ext not in {"jpg", "jpeg", "png", "webp"}:
        ext = "jpg"
    path = build_path(user["user_id"], ext)
    try:
        result = await run_in_threadpool(put_object, path, data, file.content_type)
    except Exception as e:
        logger.exception("upload failed")
        raise HTTPException(status_code=502, detail="Storage upload failed")

    photo_id = str(uuid.uuid4())
    await db.photos.insert_one({
        "photo_id": photo_id,
        "user_id": user["user_id"],
        "storage_path": result["path"],
        "content_type": file.content_type,
        "size": result.get("size", len(data)),
        "created_at": utcnow(),
        "deleted": False,
    })
    # Attach to profile
    prof = await db.profiles.find_one({"user_id": user["user_id"]})
    updates: dict = {"$push": {"photo_ids": photo_id}, "$set": {"last_active": utcnow()}}
    if not prof.get("profile_photo_id"):
        updates["$set"]["profile_photo_id"] = photo_id
    await db.profiles.update_one({"user_id": user["user_id"]}, updates)

    return {"photo_id": photo_id}


@api.get("/photos/{photo_id}")
async def get_photo(photo_id: str, token: Optional[str] = Query(default=None), credentials: HTTPAuthorizationCredentials = Depends(security)):
    # allow token via query string for web <img>
    auth_token = token or (credentials.credentials if credentials else None)
    if not auth_token:
        raise HTTPException(401, "Auth required")
    payload = decode_token(auth_token)
    viewer_id = payload["sub"]
    ph = await db.photos.find_one({"photo_id": photo_id, "deleted": False}, {"_id": 0})
    if not ph:
        raise HTTPException(404, "Not found")
    owner_id = ph["user_id"]
    if owner_id != viewer_id:
        blocked = await db.blocks.find_one({"user_id": owner_id, "blocked_user_id": viewer_id})
        if blocked:
            raise HTTPException(403, "Forbidden")
        prof = await db.profiles.find_one({"user_id": owner_id})
        if not prof or not prof.get("profile_visibility", True):
            raise HTTPException(403, "Hidden")
        if not (prof.get("privacy", {}) or {}).get("show_photos", True):
            raise HTTPException(403, "Photos private")
    try:
        content, ctype = await run_in_threadpool(get_object, ph["storage_path"])
    except Exception:
        raise HTTPException(502, "Storage read failed")
    return Response(content=content, media_type=ctype)


@api.delete("/photos/{photo_id}")
async def delete_photo(photo_id: str, user: dict = Depends(get_current_user)):
    ph = await db.photos.find_one({"photo_id": photo_id})
    if not ph or ph["user_id"] != user["user_id"]:
        raise HTTPException(404, "Not found")
    await db.photos.update_one({"photo_id": photo_id}, {"$set": {"deleted": True}})
    prof = await db.profiles.find_one({"user_id": user["user_id"]})
    photo_ids = [p for p in prof.get("photo_ids", []) if p != photo_id]
    updates = {"photo_ids": photo_ids}
    if prof.get("profile_photo_id") == photo_id:
        updates["profile_photo_id"] = photo_ids[0] if photo_ids else None
    await db.profiles.update_one({"user_id": user["user_id"]}, {"$set": updates})
    return {"ok": True}


@api.put("/photos/{photo_id}/set-primary")
async def set_primary_photo(photo_id: str, user: dict = Depends(get_current_user)):
    ph = await db.photos.find_one({"photo_id": photo_id, "user_id": user["user_id"], "deleted": False})
    if not ph:
        raise HTTPException(404, "Not found")
    await db.profiles.update_one({"user_id": user["user_id"]}, {"$set": {"profile_photo_id": photo_id}})
    return {"ok": True}


# ==== Search ====
@api.get("/search")
async def search_profiles(
    gender: Optional[str] = None,
    min_age: Optional[int] = None,
    max_age: Optional[int] = None,
    religion: Optional[str] = None,
    community: Optional[str] = None,
    mother_tongue: Optional[str] = None,
    marital_status: Optional[str] = None,
    education: Optional[str] = None,
    occupation: Optional[str] = None,
    min_height: Optional[int] = None,
    max_height: Optional[int] = None,
    income_range: Optional[str] = None,
    country: Optional[str] = None,
    state: Optional[str] = None,
    city: Optional[str] = None,
    sort: Literal["newest", "recent", "relevance"] = "recent",
    page: int = 1,
    limit: int = 20,
    user: dict = Depends(get_current_user),
):
    limit = min(max(limit, 1), 50)
    page = max(page, 1)
    q: dict = {"user_id": {"$ne": user["user_id"]}, "profile_visibility": True}
    if gender:
        q["gender"] = gender
    if religion:
        q["religion"] = religion
    if community:
        q["community"] = community
    if mother_tongue:
        q["mother_tongue"] = mother_tongue
    if marital_status:
        q["marital_status"] = marital_status
    if education:
        q["education"] = {"$regex": re.escape(education), "$options": "i"}
    if occupation:
        q["occupation"] = {"$regex": re.escape(occupation), "$options": "i"}
    if country:
        q["country"] = country
    if state:
        q["state"] = state
    if city:
        q["city"] = {"$regex": re.escape(city), "$options": "i"}
    if income_range:
        q["income_range"] = income_range
    age_q = {}
    if min_age is not None:
        age_q["$gte"] = min_age
    if max_age is not None:
        age_q["$lte"] = max_age
    if age_q:
        q["age"] = age_q
    h_q = {}
    if min_height is not None:
        h_q["$gte"] = min_height
    if max_height is not None:
        h_q["$lte"] = max_height
    if h_q:
        q["height_cm"] = h_q

    # exclude blocks (both directions)
    my_blocks = await db.blocks.find({"user_id": user["user_id"]}, {"_id": 0, "blocked_user_id": 1}).to_list(1000)
    blocked_me = await db.blocks.find({"blocked_user_id": user["user_id"]}, {"_id": 0, "user_id": 1}).to_list(1000)
    excl = {b["blocked_user_id"] for b in my_blocks} | {b["user_id"] for b in blocked_me}
    if excl:
        q["user_id"] = {"$ne": user["user_id"], "$nin": list(excl)}

    sort_map = {"newest": [("created_at", -1)], "recent": [("last_active", -1)], "relevance": [("completeness", -1), ("last_active", -1)]}
    cursor = db.profiles.find(q, {"_id": 0}).sort(sort_map[sort]).skip((page - 1) * limit).limit(limit)
    items = [public_profile(p, user["user_id"]) for p in await cursor.to_list(limit)]
    total = await db.profiles.count_documents(q)
    return {"items": items, "page": page, "limit": limit, "total": total, "has_more": page * limit < total}


@api.get("/recommendations")
async def recommendations(user: dict = Depends(get_current_user), limit: int = 10):
    prof = await db.profiles.find_one({"user_id": user["user_id"]})
    if not prof:
        raise HTTPException(404, "No profile")
    opp = "female" if prof.get("gender") == "male" else "male"
    q = {"user_id": {"$ne": user["user_id"]}, "profile_visibility": True, "gender": opp}
    cursor = db.profiles.find(q, {"_id": 0}).sort([("completeness", -1), ("last_active", -1)]).limit(limit)
    items = [public_profile(p, user["user_id"]) for p in await cursor.to_list(limit)]
    return {"items": items}


# ==== Interests ====
@api.post("/interests/{target_user_id}")
async def send_interest(target_user_id: str, user: dict = Depends(get_current_user)):
    if target_user_id == user["user_id"]:
        raise HTTPException(400, "Cannot send interest to yourself")
    target = await db.profiles.find_one({"user_id": target_user_id})
    if not target:
        raise HTTPException(404, "Profile not found")
    blocked = await db.blocks.find_one({"$or": [
        {"user_id": user["user_id"], "blocked_user_id": target_user_id},
        {"user_id": target_user_id, "blocked_user_id": user["user_id"]},
    ]})
    if blocked:
        raise HTTPException(403, "Cannot send interest")
    existing = await db.interests.find_one({"from_user_id": user["user_id"], "to_user_id": target_user_id})
    if existing:
        raise HTTPException(409, "Interest already sent")
    ent = await get_entitlements(user["user_id"])
    limit_n = ent.get("interests_per_month", 0)
    if limit_n != -1:
        used = await interests_used_this_month(user["user_id"])
        if used >= limit_n:
            raise HTTPException(403, f"Monthly interest limit ({limit_n}) reached. Upgrade your plan to send more interests.")
    doc = {
        "interest_id": str(uuid.uuid4()),
        "from_user_id": user["user_id"],
        "to_user_id": target_user_id,
        "status": "pending",
        "created_at": utcnow(),
        "updated_at": utcnow(),
    }
    await db.interests.insert_one(doc)
    return {"ok": True, "status": "pending"}


@api.post("/interests/{interest_id}/accept")
async def accept_interest(interest_id: str, user: dict = Depends(get_current_user)):
    intr = await db.interests.find_one({"interest_id": interest_id})
    if not intr or intr["to_user_id"] != user["user_id"]:
        raise HTTPException(404, "Interest not found")
    if intr["status"] != "pending":
        raise HTTPException(409, f"Interest already {intr['status']}")
    await db.interests.update_one({"interest_id": interest_id}, {"$set": {"status": "accepted", "updated_at": utcnow()}})
    # create conversation
    participants = sorted([intr["from_user_id"], intr["to_user_id"]])
    conv = await db.conversations.find_one({"participants": participants})
    if not conv:
        await db.conversations.insert_one({
            "conversation_id": str(uuid.uuid4()),
            "participants": participants,
            "created_at": utcnow(),
            "last_message_at": utcnow(),
        })
    return {"ok": True, "status": "accepted"}


@api.post("/interests/{interest_id}/reject")
async def reject_interest(interest_id: str, user: dict = Depends(get_current_user)):
    intr = await db.interests.find_one({"interest_id": interest_id})
    if not intr or intr["to_user_id"] != user["user_id"]:
        raise HTTPException(404, "Interest not found")
    if intr["status"] != "pending":
        raise HTTPException(409, f"Interest already {intr['status']}")
    await db.interests.update_one({"interest_id": interest_id}, {"$set": {"status": "rejected", "updated_at": utcnow()}})
    return {"ok": True}


@api.delete("/interests/{interest_id}")
async def withdraw_interest(interest_id: str, user: dict = Depends(get_current_user)):
    intr = await db.interests.find_one({"interest_id": interest_id})
    if not intr or intr["from_user_id"] != user["user_id"]:
        raise HTTPException(404, "Interest not found")
    if intr["status"] != "pending":
        raise HTTPException(409, "Cannot withdraw non-pending interest")
    await db.interests.delete_one({"interest_id": interest_id})
    return {"ok": True}


async def _hydrate_interests(cursor, user_id, key):
    items = []
    for it in await cursor.to_list(200):
        other_id = it[key]
        prof = await db.profiles.find_one({"user_id": other_id}, {"_id": 0})
        items.append({
            "interest_id": it["interest_id"],
            "status": it["status"],
            "created_at": it["created_at"],
            "profile": public_profile(prof, user_id) if prof else None,
        })
    return items


@api.get("/interests/sent")
async def list_sent(user: dict = Depends(get_current_user)):
    cursor = db.interests.find({"from_user_id": user["user_id"]}, {"_id": 0}).sort("created_at", -1)
    return {"items": await _hydrate_interests(cursor, user["user_id"], "to_user_id")}


@api.get("/interests/received")
async def list_received(user: dict = Depends(get_current_user)):
    cursor = db.interests.find({"to_user_id": user["user_id"]}, {"_id": 0}).sort("created_at", -1)
    return {"items": await _hydrate_interests(cursor, user["user_id"], "from_user_id")}


# ==== Shortlist ====
@api.post("/shortlist/{target_user_id}")
async def add_shortlist(target_user_id: str, user: dict = Depends(get_current_user)):
    if target_user_id == user["user_id"]:
        raise HTTPException(400, "Cannot shortlist yourself")
    exists = await db.profiles.find_one({"user_id": target_user_id})
    if not exists:
        raise HTTPException(404, "Profile not found")
    try:
        await db.shortlists.insert_one({
            "user_id": user["user_id"],
            "target_user_id": target_user_id,
            "created_at": utcnow(),
        })
    except Exception:
        pass
    return {"ok": True}


@api.delete("/shortlist/{target_user_id}")
async def remove_shortlist(target_user_id: str, user: dict = Depends(get_current_user)):
    await db.shortlists.delete_one({"user_id": user["user_id"], "target_user_id": target_user_id})
    return {"ok": True}


@api.get("/shortlist")
async def list_shortlist(user: dict = Depends(get_current_user)):
    items = []
    async for s in db.shortlists.find({"user_id": user["user_id"]}, {"_id": 0}).sort("created_at", -1):
        prof = await db.profiles.find_one({"user_id": s["target_user_id"]}, {"_id": 0})
        if prof:
            items.append({"created_at": s["created_at"], "profile": public_profile(prof, user["user_id"])})
    return {"items": items}


# ==== Blocks ====
@api.post("/blocks/{target_user_id}")
async def block_user(target_user_id: str, user: dict = Depends(get_current_user)):
    if target_user_id == user["user_id"]:
        raise HTTPException(400, "Cannot block yourself")
    try:
        await db.blocks.insert_one({
            "user_id": user["user_id"],
            "blocked_user_id": target_user_id,
            "created_at": utcnow(),
        })
    except Exception:
        pass
    return {"ok": True}


@api.delete("/blocks/{target_user_id}")
async def unblock_user(target_user_id: str, user: dict = Depends(get_current_user)):
    await db.blocks.delete_one({"user_id": user["user_id"], "blocked_user_id": target_user_id})
    return {"ok": True}


@api.get("/blocks")
async def list_blocks(user: dict = Depends(get_current_user)):
    items = []
    async for b in db.blocks.find({"user_id": user["user_id"]}, {"_id": 0}):
        prof = await db.profiles.find_one({"user_id": b["blocked_user_id"]}, {"_id": 0})
        if prof:
            items.append({"created_at": b["created_at"], "profile": public_profile(prof, user["user_id"])})
    return {"items": items}


# ==== Reports ====
@api.post("/reports")
async def report_user(body: ReportIn, user: dict = Depends(get_current_user)):
    if body.target_user_id == user["user_id"]:
        raise HTTPException(400, "Cannot report yourself")
    exists = await db.profiles.find_one({"user_id": body.target_user_id})
    if not exists:
        raise HTTPException(404, "Profile not found")
    await db.reports.insert_one({
        "report_id": str(uuid.uuid4()),
        "reporter_id": user["user_id"],
        "target_user_id": body.target_user_id,
        "reason": sanitize(body.reason),
        "context": sanitize(body.context or ""),
        "status": "pending",
        "created_at": utcnow(),
    })
    return {"ok": True}


# ==== Messaging ====
async def _get_conv(user_id: str, other_id: str):
    participants = sorted([user_id, other_id])
    conv = await db.conversations.find_one({"participants": participants}, {"_id": 0})
    return conv


@api.get("/conversations")
async def list_conversations(user: dict = Depends(get_current_user)):
    items = []
    async for c in db.conversations.find({"participants": user["user_id"]}, {"_id": 0}).sort("last_message_at", -1):
        other_id = [p for p in c["participants"] if p != user["user_id"]][0]
        prof = await db.profiles.find_one({"user_id": other_id}, {"_id": 0})
        last = await db.messages.find_one({"conversation_id": c["conversation_id"]}, {"_id": 0}, sort=[("created_at", -1)])
        unread = await db.messages.count_documents({
            "conversation_id": c["conversation_id"], "to_user_id": user["user_id"], "read": False
        })
        items.append({
            "conversation_id": c["conversation_id"],
            "other": public_profile(prof, user["user_id"]) if prof else None,
            "last_message": last,
            "unread": unread,
            "last_message_at": c.get("last_message_at"),
        })
    return {"items": items}


@api.get("/conversations/{other_user_id}/messages")
async def get_messages(other_user_id: str, user: dict = Depends(get_current_user)):
    # Must have accepted interest
    accepted = await db.interests.find_one({
        "$or": [
            {"from_user_id": user["user_id"], "to_user_id": other_user_id, "status": "accepted"},
            {"from_user_id": other_user_id, "to_user_id": user["user_id"], "status": "accepted"},
        ]
    })
    if not accepted:
        raise HTTPException(403, "Messaging unlocked only after an accepted interest")
    ent = await get_entitlements(user["user_id"])
    if not ent.get("can_message", True):
        raise HTTPException(403, "Messaging requires an active plan. Upgrade to chat.")
    conv = await _get_conv(user["user_id"], other_user_id)
    if not conv:
        return {"items": [], "conversation_id": None}
    msgs = await db.messages.find({"conversation_id": conv["conversation_id"]}, {"_id": 0}).sort("created_at", 1).to_list(500)
    # mark read
    await db.messages.update_many({"conversation_id": conv["conversation_id"], "to_user_id": user["user_id"], "read": False}, {"$set": {"read": True}})
    return {"items": msgs, "conversation_id": conv["conversation_id"]}


@api.post("/conversations/{other_user_id}/messages")
async def send_message(other_user_id: str, body: MessageIn, user: dict = Depends(get_current_user)):
    if other_user_id == user["user_id"]:
        raise HTTPException(400, "Cannot message yourself")
    # blocked either direction
    blocked = await db.blocks.find_one({"$or": [
        {"user_id": user["user_id"], "blocked_user_id": other_user_id},
        {"user_id": other_user_id, "blocked_user_id": user["user_id"]},
    ]})
    if blocked:
        raise HTTPException(403, "Cannot message this user")
    accepted = await db.interests.find_one({
        "$or": [
            {"from_user_id": user["user_id"], "to_user_id": other_user_id, "status": "accepted"},
            {"from_user_id": other_user_id, "to_user_id": user["user_id"], "status": "accepted"},
        ]
    })
    if not accepted:
        raise HTTPException(403, "Messaging unlocked only after an accepted interest")
    ent = await get_entitlements(user["user_id"])
    if not ent.get("can_message", True):
        raise HTTPException(403, "Messaging requires an active plan. Upgrade to chat.")
    conv = await _get_conv(user["user_id"], other_user_id)
    if not conv:
        conv_doc = {
            "conversation_id": str(uuid.uuid4()),
            "participants": sorted([user["user_id"], other_user_id]),
            "created_at": utcnow(),
            "last_message_at": utcnow(),
        }
        await db.conversations.insert_one(conv_doc)
        conv = conv_doc
    msg = {
        "message_id": str(uuid.uuid4()),
        "conversation_id": conv["conversation_id"],
        "from_user_id": user["user_id"],
        "to_user_id": other_user_id,
        "text": sanitize(body.text),
        "read": False,
        "created_at": utcnow(),
    }
    await db.messages.insert_one(msg)
    await db.conversations.update_one({"conversation_id": conv["conversation_id"]}, {"$set": {"last_message_at": utcnow()}})
    msg.pop("_id", None)
    return msg


# ==== Verification ====
@api.post("/verification/request")
async def request_verification(body: VerifyRequestIn, user: dict = Depends(get_current_user)):
    exists = await db.verification_requests.find_one({"user_id": user["user_id"], "status": "pending"})
    if exists:
        raise HTTPException(409, "Verification request already pending")
    await db.verification_requests.insert_one({
        "request_id": str(uuid.uuid4()),
        "user_id": user["user_id"],
        "note": sanitize(body.id_document_note or ""),
        "status": "pending",
        "created_at": utcnow(),
    })
    return {"ok": True}


@api.get("/verification/status")
async def verification_status(user: dict = Depends(get_current_user)):
    prof = await db.profiles.find_one({"user_id": user["user_id"]})
    req = await db.verification_requests.find_one({"user_id": user["user_id"]}, {"_id": 0}, sort=[("created_at", -1)])
    return {"verified": bool(prof.get("verified")), "request": req}


# ==== Dashboard ====
@api.get("/dashboard")
async def dashboard(user: dict = Depends(get_current_user)):
    prof = await db.profiles.find_one({"user_id": user["user_id"]}, {"_id": 0})
    if not prof:
        raise HTTPException(404, "Profile not found")
    sent_count = await db.interests.count_documents({"from_user_id": user["user_id"]})
    received_count = await db.interests.count_documents({"to_user_id": user["user_id"], "status": "pending"})
    shortlist_count = await db.shortlists.count_documents({"user_id": user["user_id"]})
    unread = await db.messages.count_documents({"to_user_id": user["user_id"], "read": False})
    return {
        "profile": public_profile(prof, user["user_id"]),
        "stats": {
            "completeness": prof.get("completeness", 0),
            "sent": sent_count,
            "received_pending": received_count,
            "shortlisted": shortlist_count,
            "unread_messages": unread,
            "verified": bool(prof.get("verified")),
            "visibility": bool(prof.get("profile_visibility", True)),
        },
    }


# ==== Admin ====
@api.get("/admin/stats")
async def admin_stats(admin: dict = Depends(get_admin_user)):
    s = await get_app_settings()
    return {
        "users": await db.users.count_documents({"role": "member"}),
        "profiles": await db.profiles.count_documents({}),
        "suspended": await db.users.count_documents({"status": "suspended"}),
        "verified": await db.profiles.count_documents({"verified": True}),
        "reports_pending": await db.reports.count_documents({"status": "pending"}),
        "verify_requests_pending": await db.verification_requests.count_documents({"status": "pending"}),
        "interests": await db.interests.count_documents({}),
        "messages": await db.messages.count_documents({}),
        "active_subscriptions": await db.subscriptions.count_documents({"status": "active"}),
        "active_vouchers": await db.vouchers.count_documents({"active": True}),
        "free_mode": bool(s.get("free_mode")),
    }


@api.get("/admin/members")
async def admin_members(q: Optional[str] = None, page: int = 1, limit: int = 20, admin: dict = Depends(get_admin_user)):
    limit = min(max(limit, 1), 50)
    page = max(page, 1)
    query: dict = {}
    if q:
        rx = re.escape(q)
        query = {"$or": [
            {"full_name": {"$regex": rx, "$options": "i"}},
            {"profile_id": {"$regex": rx, "$options": "i"}},
            {"email": {"$regex": rx, "$options": "i"}},
        ]}
    items = await db.profiles.find(query, {"_id": 0}).sort("created_at", -1).skip((page - 1) * limit).limit(limit).to_list(limit)
    # attach user status
    enriched = []
    for p in items:
        u = await db.users.find_one({"user_id": p["user_id"]}, {"_id": 0, "password_hash": 0})
        enriched.append({**public_profile(p, p["user_id"]), "status": (u or {}).get("status", "active"), "role": (u or {}).get("role", "member")})
    total = await db.profiles.count_documents(query)
    return {"items": enriched, "total": total, "page": page, "limit": limit}


@api.post("/admin/members/{user_id}/action")
async def admin_action(user_id: str, body: AdminActionIn, admin: dict = Depends(get_admin_user)):
    target = await db.users.find_one({"user_id": user_id})
    if not target:
        raise HTTPException(404, "User not found")
    action = body.action
    if action == "suspend":
        await db.users.update_one({"user_id": user_id}, {"$set": {"status": "suspended"}})
    elif action == "activate":
        await db.users.update_one({"user_id": user_id}, {"$set": {"status": "active"}})
    elif action == "verify_approve":
        await db.profiles.update_one({"user_id": user_id}, {"$set": {"verified": True}})
        await db.verification_requests.update_many({"user_id": user_id, "status": "pending"}, {"$set": {"status": "approved"}})
    elif action == "verify_reject":
        await db.verification_requests.update_many({"user_id": user_id, "status": "pending"}, {"$set": {"status": "rejected"}})
    elif action == "delete":
        await db.users.delete_one({"user_id": user_id})
        await db.profiles.delete_one({"user_id": user_id})
    await db.admin_actions.insert_one({
        "action_id": str(uuid.uuid4()),
        "admin_id": admin["user_id"],
        "target_user_id": user_id,
        "action": action,
        "reason": sanitize(body.reason or ""),
        "created_at": utcnow(),
    })
    return {"ok": True}


@api.get("/admin/reports")
async def admin_reports(admin: dict = Depends(get_admin_user)):
    items = await db.reports.find({}, {"_id": 0}).sort("created_at", -1).limit(200).to_list(200)
    return {"items": items}


@api.post("/admin/reports/{report_id}/resolve")
async def admin_resolve_report(report_id: str, admin: dict = Depends(get_admin_user)):
    await db.reports.update_one({"report_id": report_id}, {"$set": {"status": "resolved"}})
    return {"ok": True}


@api.get("/admin/verification-requests")
async def admin_verification_requests(admin: dict = Depends(get_admin_user)):
    items = await db.verification_requests.find({"status": "pending"}, {"_id": 0}).sort("created_at", -1).to_list(200)
    for i in items:
        p = await db.profiles.find_one({"user_id": i["user_id"]}, {"_id": 0})
        i["profile"] = public_profile(p, i["user_id"]) if p else None
    return {"items": items}


# ==== Plans, Subscriptions & Vouchers (member) ====
@api.get("/settings/public")
async def public_settings():
    s = await get_app_settings()
    keys = ["app_name", "tagline", "support_email", "support_phone", "upi_id",
            "payment_instructions", "free_mode", "announcement", "registration_open"]
    return {k: s.get(k) for k in keys}


@api.get("/plans")
async def list_plans(user: dict = Depends(get_current_user)):
    items = await db.plans.find({"active": True}, {"_id": 0}).sort("sort_order", 1).to_list(50)
    return {"items": items}


@api.get("/subscription/me")
async def my_subscription(user: dict = Depends(get_current_user)):
    ent = await get_entitlements(user["user_id"])
    sub = await get_active_subscription(user["user_id"])
    used = await interests_used_this_month(user["user_id"])
    s = await get_app_settings()
    return {"entitlements": ent, "subscription": sub,
            "usage": {"interests_used_this_month": used}, "free_mode": bool(s.get("free_mode"))}


@api.post("/vouchers/redeem")
async def redeem_voucher(body: RedeemIn, user: dict = Depends(get_current_user)):
    code = body.code.strip().upper()
    v = await db.vouchers.find_one({"code": code})
    if not v or not v.get("active", True):
        raise HTTPException(404, "Invalid voucher code")
    exp = v.get("expires_at")
    if exp:
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if exp < utcnow():
            raise HTTPException(400, "Voucher has expired")
    if v.get("used_count", 0) >= v.get("max_uses", 1):
        raise HTTPException(400, "Voucher fully used")
    if user["user_id"] in (v.get("used_by") or []):
        raise HTTPException(409, "You already redeemed this voucher")
    plan = await db.plans.find_one({"plan_id": v["plan_id"]}, {"_id": 0})
    if not plan:
        raise HTTPException(404, "Plan no longer available")
    sub = await create_subscription(user["user_id"], plan, "voucher", v.get("duration_days"), voucher_code=code)
    await db.vouchers.update_one({"code": code}, {"$inc": {"used_count": 1}, "$push": {"used_by": user["user_id"]}})
    return {"ok": True, "subscription": sub}


# ==== Admin: Plans ====
@api.get("/admin/plans")
async def admin_list_plans(admin: dict = Depends(get_admin_user)):
    items = await db.plans.find({}, {"_id": 0}).sort("sort_order", 1).to_list(100)
    return {"items": items}


@api.post("/admin/plans")
async def admin_create_plan(body: PlanIn, admin: dict = Depends(get_admin_user)):
    doc = body.model_dump()
    doc["features"] = body.features.model_dump()
    doc["plan_id"] = str(uuid.uuid4())
    doc["name"] = sanitize(doc["name"])
    doc["description"] = sanitize(doc["description"])
    doc["created_at"] = utcnow()
    await db.plans.insert_one(dict(doc))
    doc.pop("_id", None)
    return doc


@api.put("/admin/plans/{plan_id}")
async def admin_update_plan(plan_id: str, body: PlanIn, admin: dict = Depends(get_admin_user)):
    existing = await db.plans.find_one({"plan_id": plan_id})
    if not existing:
        raise HTTPException(404, "Plan not found")
    update = body.model_dump()
    update["features"] = body.features.model_dump()
    update["name"] = sanitize(update["name"])
    update["description"] = sanitize(update["description"])
    await db.plans.update_one({"plan_id": plan_id}, {"$set": update})
    out = await db.plans.find_one({"plan_id": plan_id}, {"_id": 0})
    return out


@api.delete("/admin/plans/{plan_id}")
async def admin_delete_plan(plan_id: str, admin: dict = Depends(get_admin_user)):
    r = await db.plans.delete_one({"plan_id": plan_id})
    if r.deleted_count == 0:
        raise HTTPException(404, "Plan not found")
    return {"ok": True}


# ==== Admin: Subscriptions ====
@api.get("/admin/subscriptions")
async def admin_list_subscriptions(admin: dict = Depends(get_admin_user)):
    items = await db.subscriptions.find({"status": "active"}, {"_id": 0}).sort("created_at", -1).limit(200).to_list(200)
    for i in items:
        p = await db.profiles.find_one({"user_id": i["user_id"]}, {"_id": 0, "full_name": 1, "profile_id": 1, "email": 1})
        i["member"] = p
    return {"items": items}


@api.post("/admin/subscriptions/assign")
async def admin_assign_subscription(body: AssignSubIn, admin: dict = Depends(get_admin_user)):
    target = await db.users.find_one({"user_id": body.user_id})
    if not target:
        raise HTTPException(404, "User not found")
    plan = await db.plans.find_one({"plan_id": body.plan_id}, {"_id": 0})
    if not plan:
        raise HTTPException(404, "Plan not found")
    sub = await create_subscription(body.user_id, plan, "manual", body.duration_days, admin_id=admin["user_id"])
    return {"ok": True, "subscription": sub}


@api.post("/admin/subscriptions/{subscription_id}/cancel")
async def admin_cancel_subscription(subscription_id: str, admin: dict = Depends(get_admin_user)):
    r = await db.subscriptions.update_one({"subscription_id": subscription_id}, {"$set": {"status": "cancelled"}})
    if r.matched_count == 0:
        raise HTTPException(404, "Subscription not found")
    return {"ok": True}


# ==== Admin: Vouchers ====
@api.get("/admin/vouchers")
async def admin_list_vouchers(admin: dict = Depends(get_admin_user)):
    items = await db.vouchers.find({}, {"_id": 0}).sort("created_at", -1).limit(200).to_list(200)
    return {"items": items}


@api.post("/admin/vouchers")
async def admin_create_voucher(body: VoucherIn, admin: dict = Depends(get_admin_user)):
    plan = await db.plans.find_one({"plan_id": body.plan_id}, {"_id": 0})
    if not plan:
        raise HTTPException(404, "Plan not found")
    code = (body.code or f"DM{uuid.uuid4().hex[:8].upper()}").strip().upper()
    if not re.fullmatch(r"[A-Z0-9\-]{4,30}", code):
        raise HTTPException(400, "Code must be 4-30 letters/numbers")
    if await db.vouchers.find_one({"code": code}):
        raise HTTPException(409, "Voucher code already exists")
    expires = None
    if body.expires_at:
        try:
            expires = datetime.strptime(body.expires_at, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except ValueError:
            raise HTTPException(400, "expires_at must be YYYY-MM-DD")
    doc = {
        "code": code,
        "plan_id": body.plan_id,
        "plan_name": plan["name"],
        "duration_days": body.duration_days,
        "max_uses": body.max_uses,
        "used_count": 0,
        "used_by": [],
        "active": True,
        "expires_at": expires,
        "created_by": admin["user_id"],
        "created_at": utcnow(),
    }
    await db.vouchers.insert_one(dict(doc))
    doc.pop("_id", None)
    return doc


@api.delete("/admin/vouchers/{code}")
async def admin_deactivate_voucher(code: str, admin: dict = Depends(get_admin_user)):
    r = await db.vouchers.update_one({"code": code.upper()}, {"$set": {"active": False}})
    if r.matched_count == 0:
        raise HTTPException(404, "Voucher not found")
    return {"ok": True}


# ==== Admin: Settings ====
@api.get("/admin/settings")
async def admin_get_settings(admin: dict = Depends(get_admin_user)):
    return await get_app_settings()


@api.put("/admin/settings")
async def admin_update_settings(body: SettingsUpdate, admin: dict = Depends(get_admin_user)):
    update = {k: (sanitize(v) if isinstance(v, str) else v) for k, v in body.model_dump(exclude_unset=True).items() if v is not None}
    if update:
        await db.settings.update_one({"key": "app"}, {"$set": update}, upsert=True)
    return await get_app_settings()


# ==== Health ====
@api.get("/")
async def root():
    return {"service": "Dheeraja Matrimony API", "status": "ok"}


app.include_router(api)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("shutdown")
async def shutdown():
    client.close()
