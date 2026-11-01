# Own-account inventory

**The question it answers:** which of my own accounts are already linked to each
other by something I published, and what did the linking?

It does not answer "who am I connected to". It reads an export of the operator's
own account and maps the operator's own presence. No other person appears in this
layer, by construction rather than by intention.

## Why an export and not an API

A data export is a file the operator requested from the platform, about
themselves, already complete and already local. Reading it means no OAuth grant,
no live account access, no rate limits, and no code that can reach the network at
all: `phantom/inventory/adapters.py` contains no HTTP client.

It also means the platform cannot answer silently. The file is the whole of what
this layer knows.

## The boundary is a list, and the denial wins

`phantom/inventory/facets.py` holds two lists:

- `ALLOWED_KEYS`: `username`, `email`, `phone`, `id` and their aliases. Each
  yields one facet about the operator.
- `DENIED_MARKERS`: message, friend, member, server, channel, thread,
  attachment, reaction, login, session, ip, payment, and the rest.

A denied marker beats an allowed key, and matching is done on the whole relative
path, so `messages/index.csv` is refused because of its directory even though
`index.csv` alone looks innocent. Everything refused is *reported*, so the
boundary is visible to the operator instead of being a claim in a README.

`global_name` is deliberately not read. It is a free-text display name the
operator chose, not an identifier, and parsing it would invite name matching.

## Three commands

```bash
# say yes to one platform, on its own
phantom enroll --platform discord --attested-by "you" --attestation "my own export"

# see exactly what would be read, storing nothing
phantom inventory-inspect ~/Downloads/discord-package

# read it in, then see what it links
phantom inventory-import ~/Downloads/discord-package
phantom inventory-report
```

`inventory-import` checks the platform consent *before* opening the file, so an
unauthorised platform is never parsed.

## What is stored

An own-account inventory is a second **observation source**, not a second store.
It goes into the same append-only raw table as message metadata, which means
`phantom rebuild-graph` re-derives the inventory graph from what was recorded
instead of trusting rows written under older rules. The rebuild invariant covers
it: the digest is byte-identical across a full replay.

Email, phone and account id are stored as keyed HMACs. The system can recognise
the same identifier again without the database holding a contactable address for
anyone. The handle is stored as text, because a handle is public by definition and
is the thing being mapped.

## What it proves, and what it does not

Two rules, and the split between them is the point:

| Rule | Class | Claim |
| --- | --- | --- |
| `R-INV-1` | Observed | The export listed this identifier on this account. |
| `R-INV-2` | Correlated | Two of my accounts use the same handle string. |

`R-INV-2` carries its caveat in the graph: identical strings are not a verified
identity. Anyone may reuse a handle, and variants are not linked. Separators
removed are whitespace, underscores and hyphens only, so `aadi.s` and `aadis`
stay apart rather than being joined on a guess.

A shared email or phone joins two accounts *through* the identifier node, which is
an observed fact about the operator's own account rather than an inference about
who they are.

## Platforms

Two adapters: `discord` and `meta`. Each is one class in `ADAPTERS` plus a
fixture, on purpose: an export format is a claim about someone else's file layout,
and a parser that claims to handle all of them would silently misread whichever
one changed.

Meta's export buries four useful fields in a large tree of everything else, so its
adapter walks only the containers named in `META_CONTAINER_KEYS`, to a fixed depth,
and reports every other top-level directory without opening it.

Adding a third is a class and a fixture. The correlation core already handles any
number of platforms: two accounts sharing an email land in one cluster, and a
reused handle raises `R-INV-2`.
