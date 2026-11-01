"""Explicit, per-field, revocable consent.

Rules this module enforces in code rather than in policy prose:

1. Three fields, three decisions. Agreeing to be emailed is not agreeing to be
   texted, and vice versa.
2. No field is stored without its own affirmative flag. Supplying a value is not
   consent; the consent has to be explicit.
3. Every grant records its purpose and policy version, and is revocable at any
   time with immediate effect.
4. Values are encrypted locally; a verification receipt hash is kept so a grant
   can be proved without decrypting it.
"""
from __future__ import annotations

import datetime as dt
import json
import re

from sqlalchemy import select
from sqlalchemy.orm import Session

from phantom import crypto
from phantom.models import ConsentRecord

POLICY_VERSION = "1.0"
PURPOSE = "Contact me about the PHANTOM privacy research project."

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")
PHONE_RE = re.compile(r"^\+[1-9]\d{6,14}$")

FIELDS = ("gmail_address", "phone_number", "work_email")


class ConsentError(ValueError):
    """Raised when data is offered without the permission that would justify it."""


class ConsentService:
    def __init__(self, session: Session) -> None:
        self.session = session

    def enroll(
        self,
        *,
        gmail_address: str | None = None,
        phone_number: str | None = None,
        work_email: str | None = None,
        consent_gmail: bool = False,
        consent_phone: bool = False,
        consent_work_email: bool = False,
        platforms: list[str] | None = None,
        purpose: str = PURPOSE,
        ttl_days: int | None = 365,
        attested_by: str = "",
        attestation: str = "",
    ) -> ConsentRecord:
        supplied = {
            "gmail_address": gmail_address,
            "phone_number": phone_number,
            "work_email": work_email,
        }
        flags = {
            "gmail_address": consent_gmail,
            "phone_number": consent_phone,
            "work_email": consent_work_email,
        }

        for field, value in supplied.items():
            value = (value or "").strip()
            if value and not flags[field]:
                raise ConsentError(
                    f"{field} was supplied without permission for it. "
                    "Nothing was stored. Each contact field needs its own opt-in."
                )

        platform_scope = sorted({p.strip().lower() for p in (platforms or []) if p.strip()})

        if not any((gmail_address, phone_number, work_email)) and not platform_scope:
            raise ConsentError("No contact details were supplied.")

        # Consent here is an attestation by the operator, and the record says so
        # rather than implying a signature it does not have. This is a design
        # position, not an oversight: PHANTOM is single-operator, and the honest
        # label is "the person running this says permission exists".
        attested_by = (attested_by or "").strip()
        attestation = (attestation or "").strip()
        if not attested_by or not attestation:
            raise ConsentError(
                "consent must be attested: supply attested_by (who is stating the "
                "permission) and attestation (the words they used). An unattributed "
                "flag is indistinguishable from someone ticking a box on another "
                "person's behalf."
            )

        if gmail_address and not EMAIL_RE.match(gmail_address):
            raise ConsentError("gmail_address does not look like an email address.")
        if work_email and not EMAIL_RE.match(work_email):
            raise ConsentError("work_email does not look like an email address.")
        if phone_number and not PHONE_RE.match(phone_number):
            raise ConsentError("phone_number must be E.164, for example +15551234567.")

        canonical = json.dumps(
            {
                "gmail_address": (gmail_address or "").strip().lower(),
                "phone_number": (phone_number or "").strip(),
                "work_email": (work_email or "").strip().lower(),
                "scopes": {
                    "gmail_address": bool(gmail_address),
                    "phone_number": bool(phone_number),
                    "work_email": bool(work_email),
                    "platforms": platform_scope,
                },
                "purpose": purpose,
                "policy_version": POLICY_VERSION,
                "attested_by": attested_by,
                "attestation": attestation,
            },
            sort_keys=True,
        )

        record = ConsentRecord(
            subject_token=crypto.hmac_hex(
                (
                    gmail_address
                    or phone_number
                    or work_email
                    or ",".join(platform_scope)
                    or ""
                ).strip().lower(),
                domain="subject",
            ),
            gmail_address=crypto.encrypt(gmail_address.strip().lower()) if gmail_address else None,
            phone_number=crypto.encrypt(phone_number.strip()) if phone_number else None,
            work_email=crypto.encrypt(work_email.strip().lower()) if work_email else None,
            scopes={
                "gmail_address": bool(gmail_address),
                "phone_number": bool(phone_number),
                "work_email": bool(work_email),
                "channels_authorised": [
                    name
                    for name, flag in (
                        ("email", bool(gmail_address) or bool(work_email)),
                        ("sms", bool(phone_number)),
                    )
                    if flag
                ],
                # Each platform is its own opt-in, so an import has something
                # specific to check rather than a blanket permission.
                "platforms": platform_scope,
            },
            purpose=purpose,
            policy_version=POLICY_VERSION,
            attested_by=attested_by,
            attestation=attestation,
            expires_at=(dt.datetime.now(dt.UTC) + dt.timedelta(days=ttl_days))
            if ttl_days
            else None,
            receipt_hash=crypto.receipt(canonical),
        )
        self.session.add(record)
        self.session.commit()
        return record

    def platforms_authorised(self) -> set[str]:
        """Platforms the operator has explicitly opted in, across active grants."""
        authorised: set[str] = set()
        for record in self.active():
            for platform in (record.scopes or {}).get("platforms", []):
                authorised.add(platform)
        return authorised

    def require_platform(self, platform: str) -> None:
        """Refuse an import unless that platform was opted in on its own."""
        platform = (platform or "").strip().lower()
        if platform in self.platforms_authorised():
            return
        raise ConsentError(
            f"no active consent covers '{platform}'. Each platform needs its own "
            "opt-in before its export is read. Run:\n"
            f"  phantom enroll --platform {platform} --attested-by <you> "
            f"--attestation '<why>'"
        )

    def clear_expired(self) -> int:
        """Drop the stored values for every expired grant.

        ``active()`` already refuses to hand out an expired record, but refusing
        to read something is not the same as not holding it. This is the half
        that matters for a retention promise.
        """
        now = dt.datetime.now(dt.UTC)
        cleared = 0
        for record in self.session.scalars(select(ConsentRecord)):
            exp = record.expires_at
            if exp is None:
                continue
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=dt.UTC)
            if exp >= now:
                continue
            if record.gmail_address or record.phone_number or record.work_email:
                record.gmail_address = None
                record.phone_number = None
                record.work_email = None
                record.scopes = {**record.scopes, "revoked": True, "expired": True}
                cleared += 1
        self.session.commit()
        return cleared

    def revoke(self, consent_id: str) -> ConsentRecord:
        record = self.session.get(ConsentRecord, consent_id)
        if record is None:
            raise ConsentError("no such consent record")
        record.revoked_at = dt.datetime.now(dt.UTC)
        record.gmail_address = None
        record.phone_number = None
        record.work_email = None
        record.scopes = {**record.scopes, "revoked": True}
        self.session.commit()
        return record

    def active(self) -> list[ConsentRecord]:
        now = dt.datetime.now(dt.UTC)
        out = []
        for record in self.session.scalars(select(ConsentRecord)):
            if record.revoked_at is not None:
                continue
            exp = record.expires_at
            if exp is not None:
                if exp.tzinfo is None:
                    exp = exp.replace(tzinfo=dt.UTC)
                if exp < now:
                    continue
            out.append(record)
        return out

    def view(self, record: ConsentRecord) -> dict:
        """Decrypted view of a single record, for the person who owns it."""
        return {
            "id": record.id,
            "gmail_address": crypto.decrypt(record.gmail_address) if record.gmail_address else None,
            "phone_number": crypto.decrypt(record.phone_number) if record.phone_number else None,
            "work_email": crypto.decrypt(record.work_email) if record.work_email else None,
            "scopes": record.scopes,
            "purpose": record.purpose,
            "policy_version": record.policy_version,
            "granted_at": record.granted_at.isoformat(),
            "expires_at": record.expires_at.isoformat() if record.expires_at else None,
            "revoked_at": record.revoked_at.isoformat() if record.revoked_at else None,
            "attested_by": record.attested_by,
            "attestation": record.attestation,
            "attestation_is_verified_identity": False,
            "receipt_hash": record.receipt_hash,
        }
