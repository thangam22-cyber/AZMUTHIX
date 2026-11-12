from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ORM(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class Credentials(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(min_length=10, max_length=128)


class LoginIn(BaseModel):
    username: str = Field(max_length=64)
    password: str = Field(max_length=128)


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str
    role: str


class CaseIn(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    description: str = Field(default="", max_length=5000)
    severity: Literal["low", "medium", "high", "critical"] = "medium"


class CasePatch(BaseModel):
    title: str | None = Field(default=None, min_length=3, max_length=200)
    description: str | None = Field(default=None, max_length=5000)
    severity: Literal["low", "medium", "high", "critical"] | None = None
    status: Literal["open", "investigating", "closed"] | None = None


class CaseOut(ORM):
    id: str
    title: str
    description: str
    severity: str
    status: str
    owner_id: int
    created_at: datetime
    updated_at: datetime


class ShareIn(BaseModel):
    username: str
    access: Literal["read", "write"] = "read"


class EvidenceOut(ORM):
    id: str
    case_id: str
    filename: str
    size_bytes: int
    sha256: str
    md5: str
    kind: str
    parsed_format: str
    status: str
    hash_ms: int
    uploaded_by: str
    created_at: datetime
    last_verified_at: datetime | None
    meta: dict


class EventOut(ORM):
    id: int
    evidence_id: str
    ts: datetime | None
    source: str
    host: str
    user: str
    ip: str
    action: str
    severity: str
    message: str
    line_no: int


class IndicatorOut(ORM):
    id: int
    evidence_id: str
    type: str
    value: str
    count: int
    first_seen: datetime | None
    last_seen: datetime | None
    is_internal: int


class FindingOut(ORM):
    id: int
    rule: str
    title: str
    severity: str
    confidence: int
    description: str
    mitre: str
    event_ids: list
    indicators: list
    created_at: datetime


class IntelOut(ORM):
    id: int
    indicator_type: str
    indicator_value: str
    source: str
    external: int
    verdict: str
    score: int
    summary: str
    details: dict
    retrieved_at: datetime


class NoteIn(BaseModel):
    text: str = Field(min_length=1, max_length=5000)
    kind: Literal["note", "decision"] = "note"
    refs: list[str] = Field(default_factory=list, max_length=20)


class NoteOut(ORM):
    id: int
    author: str
    kind: str
    text: str
    refs: list
    created_at: datetime


class LookupIn(BaseModel):
    value: str = Field(min_length=3, max_length=512)
    case_id: str | None = None


class AskIn(BaseModel):
    question: str = Field(default="", max_length=1000)


class TerminalIn(BaseModel):
    command: str = Field(max_length=500)
    case_id: str | None = None


class HashTextIn(BaseModel):
    text: str = Field(max_length=100_000)
