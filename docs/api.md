# API

Local only. `uvicorn phantom.main:app --app-dir backend`. Interactive docs at
`/docs`.

Nothing here sends mail, uploads contacts, or forwards data to a third party.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/health` | Liveness, allowed outbound hosts, and what it refuses to do |
| POST | `/api/ingest/eml` | Ingest one RFC822 message |
| GET | `/api/graph` | Cytoscape elements + stats + legend + standing caveats |
| GET | `/api/graph/edge/{id}` | Full provenance for one edge |
| GET | `/api/negative-space` | Recorded changes in observability |
| POST | `/api/negative-space/scan` | Re-run the comparison, return new events |
| GET | `/api/selfaudit` | PHANTOM's own footprint |
| GET | `/api/egress` | Raw egress log tail |
| GET | `/api/auth/gmail/start` | Build the consent URL for a chosen tier |
| POST | `/api/consent/enroll` | Record a per-field consent grant |
| GET | `/api/consent/{id}` | Read back exactly what is held |
| POST | `/api/consent/{id}/revoke` | Delete the values immediately |
| POST | `/api/exposure/scan` | Local contact intersection analysis |

## Examples

Ingest a message:

```bash
curl -s localhost:8000/api/ingest/eml -H 'content-type: application/json' -d '{
  "raw_email": "From: Acme <billing@acme-store.com>\nDate: ...\n\n<html>...</html>",
  "source_ref": "curl:1"
}'
```

Response:

```json
{
  "ingested": {
    "sender_domain": "acme-store.com",
    "pixels": 1, "redirectors": 1,
    "providers": ["Mailchimp"], "dmarc": "pass"
  },
  "pixels": [{"host": "acme-store.us1.list-manage.com", "reasons": ["explicit size 1x1"], "confidence": 0.6}],
  "redirectors": [{"host": "acme-store.us1.list-manage.com", "target": "klaviyo.com"}]
}
```

Read an edge's proof:

```bash
curl -s localhost:8000/api/graph/edge/<id>
```

```json
{
  "relation": "uses_provider",
  "classification": "observed",
  "rule_id": "R-OBS-2",
  "confidence": 0.95,
  "observations": 2,
  "caveat": null,
  "evidence": [
    {"kind": "registry_match", "detail": "list-manage.com attributed to Mailchimp (esp) per vendor docs",
     "source_ref": "eml:01-acme-store.eml:provider:Mailchimp", "observed_at": "2026-09-02T14:12:00Z"}
  ]
}
```

Consent, including the refusal case:

```bash
curl -s -X POST localhost:8000/api/consent/enroll -H 'content-type: application/json' \
  -d '{"phone_number":"+15551234567"}'
# 400 {"detail":"phone_number was supplied without permission for it. Nothing was stored. Each contact field needs its own opt-in."}
```

Gmail URL, metadata tier by default:

```bash
curl -s "localhost:8000/api/auth/gmail/start?client_id=$ID&redirect_uri=$URI&state=$NONCE"
```
