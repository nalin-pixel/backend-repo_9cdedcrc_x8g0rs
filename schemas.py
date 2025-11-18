"""
Database Schemas for FocusFlow (MongoDB)

Pydantic models define collections. Class name lowercased is collection name.
"""
from __future__ import annotations
from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List, Literal
from datetime import datetime

# Auth / Users
class User(BaseModel):
    name: str
    email: EmailStr
    password_hash: str
    avatar: Optional[str] = None
    timezone: str = "UTC"
    education_level: Optional[str] = None
    subjects: List[str] = []
    role: Literal["user", "admin"] = "user"
    theme: Literal["light","dark"] = "dark"
    ambient_theme: Literal["Kyoto Garden","Neon Tokyo","Minimal White","Outer Space","Pixel Retro"] = "Minimal White"
    sound: bool = True
    focus_mode_preferences: List[str] = []
    notifications: bool = True

# Focus sessions
class Session(BaseModel):
    user_id: str
    start: datetime
    end: Optional[datetime] = None
    mode: str
    subject: Optional[str] = None
    interruptions: int = 0
    focus_score: Optional[int] = None

# Tasks
class Task(BaseModel):
    user_id: str
    title: str
    subject: Optional[str] = None
    priority: Literal["low","medium","high"] = "medium"
    due_date: Optional[datetime] = None
    estimated_minutes: int = 25
    status: Literal["planned","in-progress","done"] = "planned"

# Groups and membership
class Group(BaseModel):
    name: str
    description: Optional[str] = None
    subject: Optional[str] = None
    type: Literal["public","private"] = "public"
    created_at: datetime = Field(default_factory=datetime.utcnow)

class GroupMember(BaseModel):
    group_id: str
    user_id: str
    role: Literal["owner","admin","member"] = "member"
    joined_at: datetime = Field(default_factory=datetime.utcnow)

# Messages & attachments
class Message(BaseModel):
    group_id: str
    user_id: str
    content: Optional[str] = None
    attachment_id: Optional[str] = None
    voice_note_id: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)

class Attachment(BaseModel):
    user_id: str
    group_id: Optional[str] = None
    filename: str
    content_type: str
    size: int
    url: str
    created_at: datetime = Field(default_factory=datetime.utcnow)

# AI insights & schedules
class AIInsight(BaseModel):
    user_id: str
    insight: str
    created_at: datetime = Field(default_factory=datetime.utcnow)

class Schedule(BaseModel):
    user_id: str
    period: Literal["daily","weekly"]
    blocks: list
    created_at: datetime = Field(default_factory=datetime.utcnow)

class TimetableUpload(BaseModel):
    user_id: str
    original_name: str
    file_url: str
    extracted: dict = {}
    created_at: datetime = Field(default_factory=datetime.utcnow)
