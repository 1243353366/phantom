"""Consent is enforced in code. These tests are the enforcement's own receipts."""
from __future__ import annotations

import pytest

from phantom.auth.consent import ConsentError, ConsentService


def _enroll(service, **kwargs):
    """Consent now has to be attributed to someone. Tests say who, as the
    operator would."""
    kwargs.setdefault("attested_by", "aadi")
    kwargs.setdefault("attestation", "I am the person whose details these are")
    return type(service).enroll(service, **kwargs)



def test_field_without_its_own_flag_is_refused(session):
    service = ConsentService(session)
    with pytest.raises(ConsentError) as exc:
        _enroll(service, phone_number="+15551234567", consent_gmail=True)
    assert "without permission" in str(exc.value)


def test_nothing_is_stored_when_consent_is_refused(session):
    from phantom.models import ConsentRecord

    service = ConsentService(session)
    with pytest.raises(ConsentError):
        _enroll(service, work_email="a@b.com")
    assert session.query(ConsentRecord).count() == 0


def test_each_field_needs_its_own_opt_in(session):
    service = ConsentService(session)
    record = _enroll(service, 
        gmail_address="person@gmail.com",
        consent_gmail=True,
    )
    assert record.scopes["gmail_address"] is True
    assert record.scopes["phone_number"] is False
    assert record.scopes["channels_authorised"] == ["email"]


def test_all_three_channels_can_be_granted_together(session):
    record = _enroll(ConsentService(session), 
        gmail_address="person@gmail.com",
        phone_number="+15551234567",
        work_email="person@company.com",
        consent_gmail=True,
        consent_phone=True,
        consent_work_email=True,
    )
    assert set(record.scopes["channels_authorised"]) == {"email", "sms"}


def test_phone_must_be_e164(session):
    with pytest.raises(ConsentError):
        _enroll(ConsentService(session), phone_number="555-1234", consent_phone=True)


def test_values_are_encrypted_at_rest_and_readable_by_their_owner(session):
    service = ConsentService(session)
    record = _enroll(service, gmail_address="Person@Gmail.com", consent_gmail=True)
    assert record.gmail_address.startswith("enc:")
    assert "gmail.com" not in record.gmail_address
    assert service.view(record)["gmail_address"] == "person@gmail.com"


def test_revocation_clears_the_values_immediately(session):
    service = ConsentService(session)
    record = _enroll(service, 
        gmail_address="p@gmail.com", phone_number="+15551234567",
        consent_gmail=True, consent_phone=True,
    )
    revoked = service.revoke(record.id)
    assert revoked.revoked_at is not None
    assert revoked.gmail_address is None
    assert revoked.phone_number is None
    assert service.active() == []


def test_purpose_and_policy_are_recorded(session):
    record = _enroll(ConsentService(session), gmail_address="p@gmail.com", consent_gmail=True)
    assert record.purpose
    assert record.policy_version == "1.0"
    assert len(record.receipt_hash) == 64


def test_receipt_hash_is_stable_for_identical_grants(session):
    service = ConsentService(session)
    a = _enroll(service, gmail_address="p@gmail.com", consent_gmail=True)
    b = _enroll(service, gmail_address="p@gmail.com", consent_gmail=True)
    assert a.receipt_hash == b.receipt_hash
    assert a.id != b.id
