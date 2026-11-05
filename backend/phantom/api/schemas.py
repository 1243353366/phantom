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
    attested_by: str = Field(
        default="",
        description=(
            "Who is stating that this permission exists. Required, and recorded "
            "verbatim. This is an attestation, not a verified identity: there is "
            "no participant authentication in a local single-operator install."
        ),
    )
    attestation: str = Field(
        default="",
        description="The words the person used. Required, and recorded verbatim.",
    )


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


#: A full RFC822 message with attachments is large, and a body with no ceiling is a
#: memory exhaustion bug. These are generous and they are refusals, not truncations:
#: a truncated message would parse into a graph that quietly omits evidence.
MAX_EMAIL_CHARS = 20 * 1024 * 1024
MAX_CONTACTS_CSV_CHARS = 8 * 1024 * 1024


class IngestRequest(BaseModel):
    raw_email: str = Field(
        max_length=MAX_EMAIL_CHARS,
        description="Full RFC822 message as text",
    )
    source_ref: str = Field(default="api-upload", description="Your own label for this message")


class ExposureRequest(BaseModel):
    contacts_csv: str = Field(
        max_length=MAX_CONTACTS_CSV_CHARS,
        description="CSV exported by you. Stays local.",
    )
    exclude_domains: list[str] = Field(default_factory=list)
    exclude_categories: list[str] = Field(default_factory=list)
