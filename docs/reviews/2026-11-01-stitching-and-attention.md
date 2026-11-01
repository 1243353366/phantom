# Audit: account stitching and the attention counter

Scope: the boundaries that decide what the inventory may join and what the
attention counter may claim. No new surface was added. Method was to probe the
code with adversarial inputs before reading it, so the defects came out of
behaviour rather than out of the comments.

Result: **four defects, all fixed, each pinned by a test named below.** Two
properties held under probing and are now pinned so they cannot regress.

## Stitching boundaries

| # | Property | Before | Disposition |
| --- | --- | --- | --- |
| 1 | Denied keys are refused at every depth | held | `test_a_denied_key_inside_a_container_is_refused_at_depth` |
| 2 | Denied keys inside an allowed subtree are refused | held | `test_a_denied_key_nested_inside_an_allowed_facet_subtree_is_refused` |
| 3 | An unreached denied key yields nothing | held, and was not claimed as read | `test_an_unreached_denied_key_yields_nothing_and_is_not_reported` |
| 4 | Identical emails normalise consistently | held | `test_email_case_and_padding_never_split_a_match` |
| 5 | Identical phones normalise consistently | **failed** | fixed, `test_phone_punctuation_is_removed_so_one_number_matches_itself` |
| 6 | A country code is never inferred | held, now required | `test_a_country_code_is_never_inferred_onto_a_number` |
| 7 | Every matching identifier keeps its source | **failed** | fixed, `test_every_matching_identifier_keeps_its_source` |
| 8 | Ambiguous and observed matches stay distinguishable | **failed** | fixed, `test_a_reused_handle_alone_is_reported_as_correlated` |
| 9 | A shared value is never proof of ownership | **failed** | fixed, `test_a_shared_value_is_never_presented_as_proof_of_ownership` |

### 1-3, denied keys

The walk refuses a denied key wherever it meets one, including inside an allowed
facet subtree such as `emails: {emails: [...], friends: [...]}`. The third row is
a correction to how refusals were being described: a denied key inside a subtree
the walk never enters is inert, not "refused", because `refusals` records what was
encountered and declined. Counting an unopened branch as a refusal overstates what
the adapter examined. Both facts now have a test, since they pull in opposite
directions.

### 5, phones were never normalised

`Facet.normalised` lowercased everything and stripped separators from handles, and
did nothing else. So `+1 (555) 010-0100` and `+15550100100` hashed differently, and
a phone number shared between two accounts **was silently not matched**. The one
identifier most likely to join accounts was the one identifier that never did.

Fixed by removing punctuation and keeping the leading `+` and every digit. A
country code is never added or removed, so `5550100100` and `+15550100100` stay
apart. That is a real gap left open on purpose: closing it would mean inferring
that two numbers are the same, which is exactly the class of guess this project
refuses. The cost is that the same number written nationally on one platform and
internationally on another will not join, and the limitation is stated rather than
hidden.

This changes stored digests for phone identifiers. Rebuild with
`phantom rebuild-graph`; raw observations are unchanged, so nothing is lost.

### 7, provenance was dropped

Clusters reported `platforms`, `handles`, `accounts`, `stitchable` and `joined_by`,
and nothing about *which* identifier joined them, at what confidence, or from
which source. The edges carried it: `R-INV-1` sets `source_ref`, and the writer
attaches it to `Evidence` rows. The report was reading `Edge.source_ref`, a column
the writer never populates, so provenance was silently `None`.

Fixed by reading the evidence rows. Every cluster now carries `evidence` with
`rule`, `identifier_kind`, `platforms`, `confidence` and `source_refs` per match.

### 8 and 9, observed versus correlated, and the ownership caveat

A shared email and a reused handle both produced `stitchable: true` with
`joined_by: []`, so the report could not tell an observed link from a correlated
one. That is the distinction the whole edge model exists for, so the output was
understating what it knew and overstating how much it knew it.

Clusters now carry `link` (`shared_identifier`, `reused_handle`,
`shared_identifier_and_handle`, `none`), `link_class` (`observed`, `correlated`,
`observed+correlated`), a `confidence` that is the minimum over the decisive
evidence, and a `not_proof_of_ownership` caveat on every cluster. `R-INV-1`
confidences stay below 1.0 on purpose: two accounts carrying the same email shows
the same value appears twice, which is evidence of a shared identifier and not
proof of common ownership. A household address, a recycled handle and a work phone
produce identical evidence.

## Attention counter

| # | Property | Before | Disposition |
| --- | --- | --- | --- |
| 10 | Exactly the 20-minute threshold is not a break | held | `test_exactly_the_gap_threshold_is_not_a_break` |
| 11 | One second past it is a break | held | `test_one_second_past_the_threshold_is_a_break` |
| 12 | A backwards clock cannot erase a sitting | **failed** | fixed, `test_a_clock_that_jumps_backwards_does_not_erase_a_sitting` |
| 13 | A naive timestamp cannot crash the command | **failed** | fixed, `test_a_naive_timestamp_does_not_crash_the_command` |
| 14 | A restart does not split a sitting | held | `test_a_restart_keeps_the_sitting` |
| 15 | A breach is described as a threshold, not a condition | **failed wording** | fixed, `test_a_breach_is_described_as_a_threshold_not_a_condition` |

### 12, clock changes

Sittings were computed from timestamps sorted ascending. A clock correction that
moved time backwards made the sorted order disagree with the real order, so a
30-minute sitting was reported as **0 minutes** with no error. Fixed by measuring
in append order, which is the order the operator actually worked, and spanning
each sitting by its earliest and latest look. A negative gap is treated as no gap,
because a clock correction is not a break in attention.

### 13, restarts and damaged lines

Restarts were already safe: the log is the state, and a fresh process measures the
same sitting. A hand-edited or legacy line with a naive timestamp was not: mixing
naive and aware datetimes raises `TypeError`, which took down the whole command
rather than one row. Naive timestamps are now assumed UTC and unparseable lines are
skipped.

The budget day is now the operator's local day rather than UTC, since a budget that
resets at 03:00 local is not a day anyone recognises.

### 15, what a breach means

The report said "not a health measurement", which is true but narrower than
needed. It now says a breach means a threshold the operator configured was
crossed: not a diagnosis, not a measure of severity, and not evidence that there
is a problem. The counter measures how often this program's own view commands were
invoked. It does not measure screen time, compulsion, or clinical severity, and
cannot, because it has no source for any of them.

## What this audit does not establish

A passing suite with these pins is evidence about these properties, not about the
absence of others. Not audited here:

- Whether a platform's export layout matches what the adapters assume. That needs
  real exports, not fixtures.
- The engine's cross-layer separation (`R-SHD-4`), audited separately.
- Anything about a second person's data, which the architecture does not collect
  and therefore cannot be tested for.
