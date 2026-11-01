"""Counter-observation: turning an extraction attempt into intelligence about itself.

The mechanism is passive by construction. PHANTOM presents surfaces that only an
automated collector touches, records the metadata that request carries, and
groups those requests into campaigns. It never sends anything back to the
requester beyond the bytes the request asked for, never follows anything they
supplied, and never exploits a client.

Why the limit is structural and not a preference: retaliation is illegal in most
jurisdictions (CFAA in the US, Computer Misuse Act in the UK, and equivalents
across the EU), it is indistinguishable from attacking an innocent third party
whose host was compromised to do the scraping, and it would make PHANTOM the
thing it exists to expose.
"""
from phantom.mirror.fingerprint import AttemptFingerprint, fingerprint
from phantom.mirror.tokens import CanaryToken, mint, verify

#: Hard-coded, not configurable. If this ever needs to change, the change is a
#: fork, not a setting.
RETALIATION_ENABLED = False

__all__ = [
    "CanaryToken", "mint", "verify",
    "AttemptFingerprint", "fingerprint",
    "RETALIATION_ENABLED",
]
