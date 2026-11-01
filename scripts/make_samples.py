"""Generate the sample corpus in samples/.

Synthetic messages built to exercise the pipeline: shared infrastructure between
unrelated senders, an email-analytics pixel, a click-tracking redirector, and one
sender whose tracker disappears in a later message.

Nothing here involves real people, domains or mailboxes.
"""
from __future__ import annotations

from email.message import EmailMessage
from email.utils import format_datetime
from pathlib import Path
from datetime import datetime, timezone

OUT = Path(__file__).resolve().parent.parent / "samples"
OUT.mkdir(parents=True, exist_ok=True)

ACME_PIXEL = '<img src="https://acme-store.us1.list-manage.com/track/open.php?u=8f21&id=9ab3c1" width="1" height="1" alt="">'
NORTHWIND_PIXEL = '<img src="https://northwind-supply.us1.list-manage.com/track/open.php?u=4d77&id=c4e2" width="1" height="1" alt="">'

MESSAGES = {
    "01-acme-store.eml": dict(
        sender=("Acme Store", "billing@acme-store.com"),
        date=datetime(2026, 9, 2, 14, 12, tzinfo=timezone.utc),
        subject="Your September invoice",
        dkim="acme-store.com",
        selector="k1",
        received=[
            "from mail.acme-store.com (mail.acme-store.com [203.0.113.24]) by mx.list-manage.com with SMTP id a1b2c3; Wed, 2 Sep 2026 14:12:09 +0000",
            "from mx.list-manage.com (mx.list-manage.com [198.51.100.7]) by mx.google.com with SMTPS id f9e8d7; Wed, 2 Sep 2026 14:12:11 +0000",
        ],
        html=f"""<html><body>
<p>Hi there, your invoice is ready.</p>
<p><a href="https://acme-store.us1.list-manage.com/track/click?u=8f21&amp;id=9ab3&amp;e=72f1">View invoice</a></p>
<p><a href="https://acme-store.us1.list-manage.com/track/click?u=8f21&amp;id=9ab3&amp;e=72f1&amp;url=https%3A%2F%2Fklaviyo.com%2Fp%2Fopen">Manage preferences</a></p>
{ACME_PIXEL}
</body></html>""",
    ),
    "02-northwind-supply.eml": dict(
        sender=("Northwind Supply", "orders@northwind-supply.com"),
        date=datetime(2026, 9, 5, 9, 3, tzinfo=timezone.utc),
        subject="Order NW-44821 shipped",
        dkim="northwind-supply.com",
        selector="k1",
        received=[
            "from relay.northwind-supply.com (relay.northwind-supply.com [203.0.113.91]) by mx.list-manage.com with SMTP id b7c8d9; Sat, 5 Sep 2026 09:03:44 +0000",
            "from mx.list-manage.com (mx.list-manage.com [198.51.100.7]) by mx.google.com with SMTPS id c1d2e3; Sat, 5 Sep 2026 09:03:46 +0000",
        ],
        html=f"""<html><body>
<p>Your order is on its way.</p>
<p><a href="https://northwind-supply.us1.list-manage.com/track/click?u=4d77&amp;id=c4e2&amp;e=9910&amp;url=https%3A%2F%2Fnorthwind-supply.com%2Forders%2FNW-44821">Track shipment</a></p>
{NORTHWIND_PIXEL}
</body></html>""",
    ),
    "03-acme-store-later.eml": dict(
        sender=("Acme Store", "billing@acme-store.com"),
        date=datetime(2026, 10, 18, 8, 30, tzinfo=timezone.utc),
        subject="Your October invoice",
        dkim="acme-store.com",
        selector="k1",
        received=[
            "from mail.acme-store.com (mail.acme-store.com [203.0.113.24]) by mx.sendgrid.net with SMTP id z9y8x7; Sun, 18 Oct 2026 08:30:02 +0000",
            "from mx.sendgrid.net (mx.sendgrid.net [192.0.2.55]) by mx.google.com with SMTPS id q1w2e3; Sun, 18 Oct 2026 08:30:04 +0000",
        ],
        # No pixel, and only one redirect hop: the disappearance case.
        html="""<html><body>
<p>Hi there, your invoice is ready.</p>
<p><a href="https://acme-store.us1.list-manage.com/track/click?u=8f21&amp;id=aa11">View invoice</a></p>
</body></html>""",
    ),
    "04-acme-store-rebrand.eml": dict(
        sender=("Acme Store", "billing@acme-supply.co"),
        date=datetime(2026, 10, 26, 11, 5, tzinfo=timezone.utc),
        subject="We have a new domain",
        dkim="acme-supply.co",
        selector="k1",
        received=[
            "from mail.acme-supply.co (mail.acme-supply.co [203.0.113.25]) by mx.sendgrid.net with SMTP id m4n5o6; Mon, 26 Oct 2026 11:05:12 +0000",
        ],
        html="""<html><body>
<p>New domain, same invoices.</p>
<img src="https://track.mailtrack.io/open/9f2a.gif" width="1" height="1" alt="">
</body></html>""",
    ),
    "05-northwind-supply-later.eml": dict(
        sender=("Northwind Supply", "orders@northwind-supply.com"),
        date=datetime(2026, 10, 28, 16, 44, tzinfo=timezone.utc),
        subject="Order NW-45010 shipped",
        dkim="northwind-supply.com",
        selector="k1",
        received=[
            "from relay.northwind-supply.com (relay.northwind-supply.com [203.0.113.91]) by mx.list-manage.com with SMTP id w2x3y4; Wed, 28 Oct 2026 16:44:19 +0000",
        ],
        html=f"""<html><body>
<p>Your order is on its way.</p>
<p><a href="https://northwind-supply.us1.list-manage.com/track/click?u=4d77&amp;id=d5f3&amp;e=9910&amp;url=https%3A%2F%2Fnorthwind-supply.com%2Forders%2FNW-45010">Track shipment</a></p>
{NORTHWIND_PIXEL}
</body></html>""",
    ),
    "06-acme-store-pixel-returns.eml": dict(
        sender=("Acme Store", "billing@acme-store.com"),
        date=datetime(2026, 10, 30, 7, 15, tzinfo=timezone.utc),
        subject="Your November invoice",
        dkim="acme-store.com",
        selector="k2",
        received=[
            "from mail.acme-store.com (mail.acme-store.com [203.0.113.24]) by mx.sendgrid.net with SMTP id p7q8r9; Fri, 30 Oct 2026 07:15:02 +0000",
        ],
        html=f"""<html><body>
<p>Hi there, your invoice is ready.</p>
<p><a href="https://acme-store.us1.list-manage.com/track/click?u=8f21&amp;id=bb22">View invoice</a></p>
{ACME_PIXEL}
</body></html>""",
    ),
}


def build(name: str, spec: dict) -> None:
    msg = EmailMessage()
    display, addr = spec["sender"]
    msg["From"] = f"{display} <{addr}>"
    msg["To"] = "you@example.com"
    msg["Subject"] = spec["subject"]
    msg["Date"] = format_datetime(spec["date"])
    msg["Message-ID"] = f"<{name.replace('.eml', '')}@mail.example>"
    msg["Return-Path"] = f"<bounce@{addr.split('@')[1]}>"
    msg["Reply-To"] = f"{display} <{addr}>"
    msg["Authentication-Results"] = (
        f"mx.google.com; spf=pass smtp.mailfrom={addr.split('@')[1]}; "
        f"dkim=pass header.d={spec['dkim']}; dmarc=pass header.from={addr.split('@')[1]}"
    )
    msg["DKIM-Signature"] = (
        f"v=1; a=rsa-sha256; c=relaxed/relaxed; d={spec['dkim']}; s={spec['selector']}; "
        "h=from:to:subject:date; bh=fakebodyhash; b=fakesignature"
    )
    for hop in spec["received"]:
        msg["Received"] = hop
    msg["List-Unsubscribe"] = f"<https://{addr.split('@')[1]}/unsubscribe>"
    msg.set_content("This message requires an HTML capable client.")
    msg.add_alternative(spec["html"], subtype="html")
    (OUT / name).write_bytes(bytes(msg))


for fname, spec in MESSAGES.items():
    build(fname, spec)

print(f"wrote {len(MESSAGES)} samples to {OUT}")
