# Rule Refactor: Composable `match.url`

## Goal
Support a compositional `match.url` object format that improves readability for complex route regex while preserving Oathkeeper's unique match behavior.

## Proposed Config Shape
```yaml
match:
  url:
    base: "{{ $ihost }}/api/v1"
    paths:
      - prefix: "/agencies/:agency_id"
        branches:
          - path: "/devices/:device_id?"
          - path: "/assignments/devices/:device_id"
          - path: "/participants/:participant_id?"
    path_params:
      - name: agency_id
        type: regex
        value: "[^/]+?"
      - name: device_id
        type: regex
        value: "[^/]+?"
      - name: participant_id
        type: regex
        value: "[^/]+?"
```

## Compatibility
- Keep current string `match.url` fully supported.
- Accept `match.url` as `string | object`.
- Compile object form into one canonical string URL pattern and store in `Match.URL`.

## Implementation Plan
1. Extend decoding in `rule/rule.go` to detect object form under `match.url`.
2. Add a compositional URL model (decode-only structs).
3. Compile object form to canonical regex (stable ordering, escaped literals, parameter substitution).
4. Keep matcher engines unchanged (`rule/engine_regexp.go` and `rule/engine_glob.go` consume compiled string).
5. Add schema support in `.schema/config.schema.json` and `spec/config.schema.json` using `oneOf` (`string` or object).
6. Add validation in `rule/validator.go`.

## Validation Rules
- `base` is required and non-empty.
- `paths` must be non-empty.
- `paths[].prefix` and `branches[].path` must start with `/`.
- `path_params.name` must be unique.
- `path_params.type` enum initially supports `regex` only.
- Every referenced `:param` must be defined.
- Every declared param should be referenced at least once.
- `:param?` is only valid as a full segment token.
- Query/fragment disallowed in `prefix` and branch `path`.
- `path_params.value` must compile as regex.
- Reject duplicate/ambiguous branch expansions within a composed URL.

## Uniqueness Strategy
- Compile each branch to normalized final regex.
- Canonicalize branch order (stable sort by expanded branch string).
- Emit a single deterministic regex string (prefer `<< >>` delimiters).
- Detect collisions early (at least exact duplicates; later add stronger overlap checks).

## Tests
- Object form decodes and compiles correctly.
- Existing string form remains unchanged.
- Optional parameter expansion (`:param?`) correctness.
- Missing/unused params.
- Invalid regex values.
- Duplicate/overlapping branch detection.
- Canonical output stability.

## Rollout
- Phase 1: schema + decode + compile + base validations.
- Phase 2: stronger overlap detection heuristics and richer diagnostics.
