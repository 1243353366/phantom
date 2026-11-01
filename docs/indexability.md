# robots.txt vs noindex

Two directives, often treated as one, and the confusion runs in a direction that
leaves pages in search results.

- **robots.txt** is crawler guidance. It asks a compliant crawler not to *fetch* a
  path.
- **noindex** is an indexing directive. It asks a search engine not to *include*
  the URL in results. Delivered by `<meta name="robots" content="noindex">` or an
  `X-Robots-Tag: noindex` header.

```console
$ phantom indexability https://your-domain.test/private/page
```

## The trap

`Disallow: /private` does not remove a page from an index. It prevents the
crawler from fetching the page, which means the `noindex` that would have removed
it is never read. A URL can sit in results for years behind a full disallow, kept
alive by a single inbound link.

The correct order is the opposite of the intuition:

1. Allow the crawl.
2. Serve `noindex`.
3. Wait for the engine to drop the URL on recrawl, which can take weeks.
4. Then, if you want, disallow it.

## Three separate answers

The command reports three things and refuses to collapse them:

| Field | Question |
| --- | --- |
| `crawl_allowed` | May a compliant crawler fetch this path, and which rule decided |
| `noindex_declared` | Did the page or its headers ask to be excluded from results |
| `indexable` | `yes`, `no`, or `unverifiable` |

`unverifiable` is the important one. When crawling is disallowed, the honest
answer is not "private" and not "public": it is that the indexing state cannot be
determined from outside, and the URL may still be indexed. Any tool that prints
"blocked" here is guessing.

An unreachable `robots.txt` (5xx, 401, 403) is treated as disallow-all, per
RFC 9309, which is also `unverifiable` rather than a pass.

## Parsing

RFC 9309 rules, in `phantom/exposure/indexability.py`: groups are per user-agent,
longest matching pattern wins, and `Allow` wins a tie. Wildcards (`*`) and end
anchors (`$`) are supported. An empty `Disallow:` means no restriction.

## Egress

The check fetches only hosts already declared in
`selfaudit/egress_allowlist.yaml`, and every fetch is recorded in the egress log
like any other. Testing your own domain therefore requires declaring it first,
which is the same rule that stops this tool from browsing on its own.

The search engine's own URL inspector is the only authority on what it has
indexed. This command reports what your site asks for; it cannot report what was
already kept.
