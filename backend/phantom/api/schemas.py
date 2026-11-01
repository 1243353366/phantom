"""Request/response models. Anything not declared here cannot be sent."""
from __future__ import annotations

from pydantic import BaseModel, Field


class EnrollRequest(BaseModel):
    gmail_address: str | None = Field(default=None, description="Optional")
    phone_number: str | None = Field(default=None, description="E.164, optional")
    work_email: str | None = Field(default=None, description="Optional")
    consent_gmail: bool = Field(default=False, description="Explicit opt-in for gmail_address")
    consent_phone: bool = Field(default=False, description="Explicit opt-in for SMS")
    consent_work_email: bool = Field(default=False, description="Explicit opt-in for work_email")
    ttl_days: int | None = 365


class EnrollResponse(BaseModel):
    id: str
    receipt_hash: str
    granted_at: str
    channels_authorised: list[str]
    stored_fields: list[str]
    not_stored: list[str]
    purpose: str
    policy_version: str
    how_to_revoke: str


class IngestRequest(BaseModel):
    raw_email: str = Field(description="Full RFC822 message as text")
    source_ref: str = Field(default="api-upload", description="Your own label for this message")


class ExposureRequest(BaseModel):
    contacts_csv: str = Field(description="CSV exported by you. Stays local.")
    exclude_domains: list[str] = Field(default_factory=list)
    exclude_categories: list[str] = Field(default_factory=list)
