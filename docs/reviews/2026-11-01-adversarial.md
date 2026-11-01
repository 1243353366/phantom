# Adversarial review, 2026-11-01: dispositions

Ten findings. Nine were real. One does not reproduce. Each disposition names the
test that fails if the defect returns, because a finding closed in prose reopens
on the next refactor.

| # | Finding | Disposition | Pinned by |
| --- | --- | --- | --- |
| 1 | Egress allowlist checked the name and never the scheme | **Fixed.** HTTPS-only, port 443, user-info rejected, IP literals rejected, resolved address must be public | `test_egress_refuses_these_destinations`, `test_egress_refuses_a_name_that_resolves_somewhere_private` |
| 2 | A caller could grant itself a MirrorLock read | **Fixed.** Grants need a code derived from the local key, bound to blob and duration, printed only by `phantom approve` | `test_a_grant_needs_the_operator_code`, `test_the_approval_code_is_bound_to_object_and_duration` |
| 3 | An OAuth token reached a log through a query string | **Fixed.** Token moves to the request body; every query value is dropped from logs; old lines scrubbed by `phantom retention` | `test_revocation_puts_the_token_in_the_body`, `test_logged_urls_never_carry_query_values`, `test_legacy_log_lines_are_scrubbed` |
| 4 | The vault verified its chain, not the evidence | **Fixed.** Canonical form covers all fifteen fields with a version; `verify` re-derives each fingerprint from the stored row and separates chain edits, splices, and rewritten contents | `test_vault_detects_rewritten_event_contents`, `test_vault_detects_rewritten_alternative_explanations` |
| 5 | A forged display name could create a relationship | **Fixed.** R-HYP-1 requires shared mail infrastructure; an uncorroborated claim is reported as negative space, not dropped | `test_the_same_display_name_alone_creates_no_edge`, `test_the_same_display_name_with_shared_infrastructure_is_a_hypothesis` |
| 6 | Duplicate observations from one message | **Does not reproduce.** `message_ref` keys correctly, so a pixel and a redirect to the same provider collapse to one observation. The construction was fragile (a `split` that did nothing when its delimiter was absent), so it was made an explicit parameter and pinned | `test_a_pixel_and_a_redirect_to_one_provider_count_once` |
| 7 | Consent flags were purely caller-supplied | **Fixed.** `enroll` refuses without `attested_by` and `attestation`; every record reports `attestation_is_verified_identity: false` | `test_consent_without_an_attribution_is_refused` |
| 8 | Stated expiries were not enforced | **Fixed.** `retention.enforce_all` runs on service start and via `phantom retention`; expired grants stop holding their values | `test_an_expired_grant_stops_holding_the_values` |
| 9 | A public endpoint could grow a table without limit | **Fixed.** Per-token total and per-hour budgets; an exhausted budget is invisible at the edge | `test_a_canary_stops_recording_past_its_budget` |
| 10 | Metadata is still data: URLs, parameters and addresses | **Fixed.** Query values are dropped and parameter names kept; IP literals are withheld; the canary token is removed from the recorded path | `test_stored_observations_do_not_keep_recipient_identifiers`, `test_stored_observations_withhold_ip_addresses`, `test_the_canary_token_is_not_stored_in_the_recorded_path` |

## What the review changed about the design

Not just the code. Finding 5 established that a field the sender controls must
never be sufficient evidence on its own, which is now a rule rather than a patch.
Finding 2 established that requesting access and authorising access must be
different acts, which is now an architectural boundary. Finding 4 established that
a hash chain proves sequence, not content, and the vault now does both.

## Not fixed, and recorded as such

The egress DNS rebinding window (1) is narrowed, not closed. Closing it needs a
connection bound to the validated address. It is listed in
`docs/trust-boundaries.md` under residual risk rather than described as solved.
