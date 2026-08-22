# Language gaps

Gaps a Gleam-to-Scarlet port hits. Each row is a ticket against this repo.
Costs are what the workaround costs, not what the feature costs.

## Costly but not blocking

| gap | ticket | what it costs to route around |
|---|---|---|
| No multi-scrutinee `match` | T-181 | Gleam's `case a, b { pattern, pattern -> ... }` matches several scrutinees at once. Scarlet's `match` takes one: `match a, b {` is `Expected '{', got ','`. Workaround is a tuple, which compiles and behaves: `match (a, b) { (3, _) -> 0 ... }`. Counted over Glyde at the read revision, excluding `case f(x, y) {` (a single scrutinee whose commas are inside parens): **34 sites — 30 in `src/` across 16 files, 4 in `test/` across 3 files.** `websocket/frame.gleam` has a three-scrutinee one (`case codepoint < 0x80, codepoint < 0x800, codepoint < 0x10000`). Cost is a tuple allocation per match and a pair of parens per arm; not a blocker for any wave. |
