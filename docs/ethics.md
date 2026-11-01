# Ethics: the line this project must not cross

PHANTOM is a privacy intelligence tool. The moment it becomes a people-tracking
tool it has failed, and the failure would be quiet: the code would still be
useful, still elegant, and now harmful.

## The line, stated concretely

| Acceptable | Not acceptable |
| --- | --- |
| Mapping domains and infrastructure | Mapping people and their associations |
| "This sender uses this provider" | "These two people both received mail from X" |
| Contact domains compared to observed infrastructure, locally | Contact lists uploaded, stored, or shared |
| Recording that a tracker disappeared | Claiming tracking stopped |
| Naming a provider with a public source | Guessing ownership from shared hosts |
| Informing the user about their own exposure | Enriching a third party's view of someone |

## Counter-observation: where the line sits

Turning an extraction attempt into intelligence about itself is legitimate
defensive work, and it is easy to slide from there into offense. The line:

| Acceptable | Not acceptable |
| --- | --- |
| Serving the image the request asked for | Sending anything the request did not ask for |
| Recording what the request volunteered | Interrogating the client to extract more |
| Bounded tarpit, capped in code, off by default | Holding connections until they fail |
| Local ASN lookup | Handing the hit to an IP-intelligence API |
| Grouping by client stack and network | Inferring identity from infrastructure |
| Saying "same tooling" | Saying "same operator" |

Hacking back is not a grey area. It is unauthorised access to a system in most
jurisdictions, the host making the request is often itself a victim, and a privacy
tool that acquires an offensive capability has become the thing it was built to
expose. `RETALIATION_ENABLED = False` is hard-coded for that reason, and a test
asserts it.

## Layer 3: observing attempts, not people

ShadowTrace records interactions with infrastructure you own or control. That
includes refusals, which are the most sensitive rows in the database because a
refused request invites the reading "someone was doing something wrong".

The rule: **a refusal is not an accusation.** An expired grant, a lost device, a
stale integration and a hostile probe all produce the same record. The report says
so next to the count, and every event carries at least one innocent explanation that
is stored with it, not generated later.

| Acceptable | Not acceptable |
| --- | --- |
| Recording that a request arrived | Probing the requester's systems to learn more |
| Refusing by default and logging it | Returning a decoy or poisoned response |
| Correlating observables | Naming an operator |
| Proposing a bridge between layers | Merging the layers automatically |
| Keeping a payload encrypted, unopened | Executing, unpacking or rendering a sample |
| Recording a request that contained a secret | Keeping the secret |

Active probing deserves its own line. Following a requester back, scanning their
host, or querying a third-party enrichment API would turn PHANTOM into a participant
in the ecosystem it maps, and would make every future claim about "the activity
around my data" a claim about activity PHANTOM provoked.

## Four relationship kinds, never merged

```
contact_record             you have this address in your contacts. nothing more.
technical_relationship     observed infrastructure link between two domains.
communication_relationship you have corresponded with this address.
speculative_association    suggested by pattern only. unverified.
```

Conflating `contact_record` with `communication_relationship` would produce a lie:
having someone's address in an address book does not mean you have ever exchanged
a message with them. Conflating either with `technical_relationship` would produce
a worse lie: sharing a mail provider is not a relationship between people.

## Contact analysis: why local-only is not a limitation

The temptation is to upload the address book "to build a better graph". That
converts one person's consent into data about hundreds of people who did not
consent. Local-only analysis is not a compromise; it is the only version of this
feature that has a defensible consent story.

Practical rules the code enforces:

1. Names and raw addresses are discarded during parsing.
2. Only domains are matched, and only against infrastructure already observed.
3. Results are labelled `contact_record` with an explicit note that a shared
   domain is not evidence about a person.
4. Exclusions by domain and by category are honoured before matching.

## Consent

Three fields, three decisions. `gmail_address`, `phone_number`, `work_email` each
require their own affirmative flag. Supplying a value is not consent; the flag is.
`ConsentError` is raised and nothing is stored when the flag is absent. This is
tested, because a consent model that is not enforced in code is a preference.

## Language discipline

The tool's wording is part of its ethics. Prefer:

- "observed", never "confirmed link" for a hypothesis
- "shared infrastructure does not establish common ownership" beside the edge
- "an observation of absence", never "tracking stopped"
- "leading hypothesis", never "identification"

## Kill criteria

If a future feature requires any of the following, it should be rejected in review
regardless of demand:

- storing a third party's identifiers
- returning an enriched contact list
- identifying individuals from infrastructure
- a server component that receives graph data
- removing the per-field consent flags
