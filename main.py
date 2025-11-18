import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Form
from fastapi import WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
import jwt
from passlib.context import CryptContext

from database import db, create_document, get_documents
from schemas import User as UserSchema, Task as TaskSchema, Session as SessionSchema, Group as GroupSchema, GroupMember as GroupMemberSchema
from schemas import Message as MessageSchema, Attachment as AttachmentSchema, AIInsight as AIInsightSchema, Schedule as ScheduleSchema, TimetableUpload as TimetableUploadSchema

JWT_SECRET = os.getenv("JWT_SECRET", "devsecret")
JWT_ALG = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

app = FastAPI(title="FocusFlow API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------
# Auth Helpers
# -----------------------------
class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

class AuthUser(BaseModel):
    id: str
    name: str
    email: EmailStr
    avatar: Optional[str] = None
    timezone: str
    role: str
    theme: str
    ambient_theme: str
    sound: bool
    focus_mode_preferences: List[str] = []
    notifications: bool


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALG)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, password_hash: str) -> bool:
    return pwd_context.verify(plain_password, password_hash)


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict[str, Any]:
    token = credentials.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        user = db["user"].find_one({"_id": db.client.get_default_database().client.get_database(db.name).codec_options.uuid_representation if False else None})
        # Above line is a no-op to keep linter quiet in this environment
        user_doc = db["user"].find_one({"_id": user_id})
        if not user_doc:
            # Also support finding by string id stored as _id
            user_doc = db["user"].find_one({"_id": user_id})
        if not user_doc:
            raise HTTPException(status_code=401, detail="User not found")
        user_doc["id"] = user_doc.get("_id")
        return user_doc
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Could not validate credentials")


# -----------------------------
# Health / Root
# -----------------------------
@app.get("/")
def read_root():
    return {"message": "FocusFlow API running"}

@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": "❌ Not Set",
        "database_name": "❌ Not Set",
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
            response["database_name"] = db.name
            response["connection_status"] = "Connected"
            response["collections"] = db.list_collection_names()
    except Exception as e:
        response["database"] = f"Error: {str(e)[:80]}"
    return response

# -----------------------------
# Auth Endpoints
# -----------------------------
class SignupRequest(BaseModel):
    name: str
    email: EmailStr
    password: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

@app.post("/api/auth/signup", response_model=TokenResponse)
def signup(payload: SignupRequest):
    # Check existing
    existing = db["user"].find_one({"email": payload.email.lower()})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    user = UserSchema(
        name=payload.name,
        email=payload.email.lower(),
        password_hash=get_password_hash(payload.password)
    )
    user_id = create_document("user", user)
    token = create_access_token({"sub": user_id})
    return TokenResponse(access_token=token)

@app.post("/api/auth/login", response_model=TokenResponse)
def login(payload: LoginRequest):
    user = db["user"].find_one({"email": payload.email.lower()})
    if not user or not verify_password(payload.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token({"sub": user["_id"]})
    return TokenResponse(access_token=token)

@app.get("/api/auth/me", response_model=AuthUser)
def me(user=Depends(get_current_user)):
    # map to response
    return AuthUser(
        id=str(user.get("_id")),
        name=user.get("name"),
        email=user.get("email"),
        avatar=user.get("avatar"),
        timezone=user.get("timezone", "UTC"),
        role=user.get("role", "user"),
        theme=user.get("theme", "dark"),
        ambient_theme=user.get("ambient_theme", "Minimal White"),
        sound=bool(user.get("sound", True)),
        focus_mode_preferences=user.get("focus_mode_preferences", []),
        notifications=bool(user.get("notifications", True)),
    )

class UpdateSettings(BaseModel):
    name: Optional[str] = None
    avatar: Optional[str] = None
    timezone: Optional[str] = None
    theme: Optional[str] = None
    ambient_theme: Optional[str] = None
    sound: Optional[bool] = None
    focus_mode_preferences: Optional[List[str]] = None
    notifications: Optional[bool] = None

@app.put("/api/auth/settings")
def update_settings(payload: UpdateSettings, user=Depends(get_current_user)):
    updates = {k: v for k, v in payload.model_dump().items() if v is not None}
    if not updates:
        return {"updated": False}
    updates["updated_at"] = datetime.now(timezone.utc)
    db["user"].update_one({"_id": user["_id"]}, {"$set": updates})
    return {"updated": True}

@app.post("/api/auth/forgot-password")
def forgot_password(email: EmailStr):
    # Placeholder
    return {"status": "ok", "message": "If this email exists, reset link sent."}

# -----------------------------
# Tasks CRUD
# -----------------------------
class TaskIn(BaseModel):
    title: str
    subject: Optional[str] = None
    priority: Optional[str] = "medium"
    due_date: Optional[datetime] = None
    estimated_minutes: int = 25
    status: Optional[str] = "planned"

@app.get("/api/tasks")
def list_tasks(user=Depends(get_current_user)):
    docs = list(db["task"].find({"user_id": str(user["_id"])}).sort("_id", -1))
    for d in docs:
        d["id"] = str(d.get("_id"))
    return docs

@app.post("/api/tasks")
def create_task(payload: TaskIn, user=Depends(get_current_user)):
    task = TaskSchema(user_id=str(user["_id"]), **payload.model_dump())
    new_id = create_document("task", task)
    return {"id": new_id}

@app.put("/api/tasks/{task_id}")
def update_task(task_id: str, payload: TaskIn, user=Depends(get_current_user)):
    update = {k: v for k, v in payload.model_dump().items() if v is not None}
    db["task"].update_one({"_id": task_id, "user_id": str(user["_id"])}, {"$set": update})
    return {"updated": True}

@app.delete("/api/tasks/{task_id}")
def delete_task(task_id: str, user=Depends(get_current_user)):
    db["task"].delete_one({"_id": task_id, "user_id": str(user["_id"])})
    return {"deleted": True}

# -----------------------------
# Sessions
# -----------------------------
class SessionStart(BaseModel):
    mode: str
    subject: Optional[str] = None
    estimated_minutes: int = 25

class SessionEnd(BaseModel):
    interruptions: int = 0
    focus_score: Optional[int] = None

@app.post("/api/sessions/start")
def start_session(payload: SessionStart, user=Depends(get_current_user)):
    session = SessionSchema(
        user_id=str(user["_id"]),
        start=datetime.now(timezone.utc),
        end=None,
        mode=payload.mode,
        subject=payload.subject,
        interruptions=0,
        focus_score=None,
    )
    session_id = create_document("session", session)
    return {"session_id": session_id}

@app.post("/api/sessions/{session_id}/end")
def end_session(session_id: str, payload: SessionEnd, user=Depends(get_current_user)):
    db["session"].update_one({"_id": session_id, "user_id": str(user["_id"])}, {"$set": {
        "end": datetime.now(timezone.utc),
        "interruptions": payload.interruptions,
        "focus_score": payload.focus_score
    }})
    return {"ended": True}

@app.get("/api/sessions")
def list_sessions(user=Depends(get_current_user)):
    docs = list(db["session"].find({"user_id": str(user["_id"]) }).sort("start", -1))
    for d in docs:
        d["id"] = str(d.get("_id"))
    return docs

# -----------------------------
# AI Placeholder Endpoints
# -----------------------------
@app.post("/api/ai/scheduler/plan")
def ai_plan(user=Depends(get_current_user)):
    # Return a mocked schedule
    today = datetime.now().date().isoformat()
    blocks = [
        {"start": f"{today}T09:00:00Z", "end": f"{today}T09:25:00Z", "task": "Math review"},
        {"start": f"{today}T09:35:00Z", "end": f"{today}T10:00:00Z", "task": "Physics problems"},
    ]
    plan = ScheduleSchema(user_id=str(user["_id"]), period="daily", blocks=blocks)
    plan_id = create_document("schedule", plan)
    return {"plan_id": plan_id, "blocks": blocks}

@app.post("/api/ai/scheduler/rebalance")
def ai_rebalance(user=Depends(get_current_user)):
    return {"status": "ok", "message": "Tasks reprioritized", "diff": []}

@app.post("/api/ai/timetable/upload")
def ai_timetable_upload(user=Depends(get_current_user)):
    # Placeholder OCR result
    extracted = {"Monday": ["09:00 Math", "10:00 English"]}
    tt = TimetableUploadSchema(user_id=str(user["_id"]), original_name="timetable.pdf", file_url="/uploads/fake.pdf", extracted=extracted)
    _id = create_document("timetableupload", tt)
    return {"upload_id": _id, "extracted": extracted}

@app.post("/api/ai/notes/summarize")
def ai_summarize():
    return {"summary": "This is a concise summary of your notes."}

@app.post("/api/ai/notes/flashcards")
def ai_flashcards():
    return {"flashcards": [{"q": "What is photosynthesis?", "a": "Process plants use to convert light to energy."}]}

@app.post("/api/ai/notes/quizzes")
def ai_quizzes():
    return {"quiz": [{"question": "2+2?", "choices": ["3","4","5"], "answer": 1}]}

@app.post("/api/ai/notes/formulas")
def ai_formulas():
    return {"formulas": [{"topic": "Kinematics", "formula": "v = u + at"}]}

@app.post("/api/ai/coach/start-session-tip")
def coach_start():
    return {"tip": "Set a clear goal for this session and silence distractions."}

@app.post("/api/ai/coach/end-session-review")
def coach_end():
    return {"review": "Great job! You maintained focus. Next time, try a longer interval."}

# -----------------------------
# Groups & Social
# -----------------------------
class GroupIn(BaseModel):
    name: str
    description: Optional[str] = None
    subject: Optional[str] = None
    type: str = "public"

@app.post("/api/groups")
def create_group(payload: GroupIn, user=Depends(get_current_user)):
    group = GroupSchema(**payload.model_dump())
    gid = create_document("group", group)
    # owner membership
    gm = GroupMemberSchema(group_id=gid, user_id=str(user["_id"]), role="owner")
    create_document("groupmember", gm)
    return {"id": gid}

@app.get("/api/groups")
def list_groups():
    docs = list(db["group"].find().sort("created_at", -1))
    for d in docs:
        d["id"] = str(d.get("_id"))
    return docs

@app.get("/api/groups/{group_id}")
def get_group(group_id: str):
    g = db["group"].find_one({"_id": group_id})
    if not g:
        raise HTTPException(status_code=404, detail="Group not found")
    g["id"] = str(g.get("_id"))
    members = list(db["groupmember"].find({"group_id": group_id}))
    g["members"] = members
    return g

@app.post("/api/groups/{group_id}/join")
def join_group(group_id: str, user=Depends(get_current_user)):
    existing = db["groupmember"].find_one({"group_id": group_id, "user_id": str(user["_id"])})
    if existing:
        return {"joined": True}
    gm = GroupMemberSchema(group_id=group_id, user_id=str(user["_id"]), role="member")
    create_document("groupmember", gm)
    return {"joined": True}

@app.post("/api/groups/{group_id}/leave")
def leave_group(group_id: str, user=Depends(get_current_user)):
    db["groupmember"].delete_one({"group_id": group_id, "user_id": str(user["_id"])})
    return {"left": True}

# -----------------------------
# File Uploads
# -----------------------------
UPLOAD_DIR = os.getenv("UPLOAD_DIR", "uploads")
if not os.path.exists(UPLOAD_DIR):
    os.makedirs(UPLOAD_DIR, exist_ok=True)

@app.post("/api/upload")
async def upload_file(file: UploadFile = File(...), user=Depends(get_current_user)):
    filename = f"{uuid.uuid4().hex}_{file.filename}"
    path = os.path.join(UPLOAD_DIR, filename)
    with open(path, "wb") as f:
        f.write(await file.read())
    url = f"/uploads/{filename}"
    meta = AttachmentSchema(
        user_id=str(user["_id"]),
        filename=file.filename,
        content_type=file.content_type or "application/octet-stream",
        size=os.path.getsize(path),
        url=url
    )
    aid = create_document("attachment", meta)
    return {"attachment_id": aid, "url": url}

# -----------------------------
# Stats (placeholders with basic aggregation)
# -----------------------------
@app.get("/api/stats/summary")
def stats_summary(user=Depends(get_current_user)):
    today = datetime.now().date()
    sessions = list(db["session"].find({"user_id": str(user["_id"])}))
    minutes_today = 0
    tasks_done_today = db["task"].count_documents({"user_id": str(user["_id"]), "status": "done"})
    for s in sessions:
        start = s.get("start")
        end = s.get("end") or datetime.now(timezone.utc)
        if isinstance(start, str):
            # if stored as string (unlikely here), skip precise calc
            continue
        if start.date() == today:
            minutes_today += int((end - start).total_seconds() // 60)
    return {
        "hours_focused_today": round(minutes_today / 60.0, 2),
        "tasks_completed_today": tasks_done_today,
        "streak_days": 1
    }

@app.get("/api/stats/sessions")
def stats_sessions(user=Depends(get_current_user)):
    return list(db["session"].find({"user_id": str(user["_id"]) }).sort("start", -1))

@app.get("/api/stats/heatmap")
def stats_heatmap(user=Depends(get_current_user)):
    # Return 30 days of mock intensity
    out = []
    today = datetime.now().date()
    for i in range(30):
        d = today - timedelta(days=i)
        out.append({"date": d.isoformat(), "intensity": (i * 7) % 100})
    return list(reversed(out))

@app.get("/api/stats/insights")
def stats_insights(user=Depends(get_current_user)):
    return {"insights": [
        "Try studying math earlier in the day when your focus is higher.",
        "Increase break length to reduce interruptions.",
    ]}

# -----------------------------
# WebSocket Manager for Group Chat and Shared Timers
# -----------------------------
class ConnectionManager:
    def __init__(self):
        self.active: Dict[str, List[WebSocket]] = {}

    async def connect(self, group_id: str, websocket: WebSocket):
        await websocket.accept()
        self.active.setdefault(group_id, []).append(websocket)
        await self.broadcast(group_id, {"type": "presence", "message": "joined"})

    def disconnect(self, group_id: str, websocket: WebSocket):
        if group_id in self.active and websocket in self.active[group_id]:
            self.active[group_id].remove(websocket)

    async def broadcast(self, group_id: str, message: dict):
        for ws in list(self.active.get(group_id, [])):
            try:
                await ws.send_json(message)
            except Exception:
                # drop bad connections
                self.disconnect(group_id, ws)

manager = ConnectionManager()

@app.websocket("/ws/groups/{group_id}")
async def group_ws(websocket: WebSocket, group_id: str):
    await manager.connect(group_id, websocket)
    try:
        while True:
            data = await websocket.receive_json()
            # Persist messages if they are chat
            if data.get("type") == "chat":
                msg = MessageSchema(
                    group_id=group_id,
                    user_id=data.get("user_id", "anon"),
                    content=data.get("content")
                )
                create_document("message", msg)
            await manager.broadcast(group_id, data)
    except WebSocketDisconnect:
        manager.disconnect(group_id, websocket)
        await manager.broadcast(group_id, {"type": "presence", "message": "left"})

# Static files for uploads (serve if running via uvicorn directly)
from fastapi.staticfiles import StaticFiles
app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR), name="uploads")

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
