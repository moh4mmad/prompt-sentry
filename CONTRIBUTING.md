# Contributing

Thanks for your interest. Contributions that improve detection coverage, fix false positives, or improve the API are welcome.

## Getting set up

```bash
git clone https://github.com/moh4mmad/prompt-sentry
cd prompt-sentry
python3.12 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest  # make sure everything passes before you start
```

## Adding a new detection rule

Rules live in `app/detectors/rules.py`. Each rule is a dataclass with a regex pattern, attack type, severity, and confidence score.

If you add a rule, add a test case for it in `tests/unit/test_scenarios.py` and a labeled sample in `attack_library/`.

Make sure your rule doesn't break any benign inputs — the `TestBenignInputs` class in `tests/unit/test_scenarios.py` is the false-positive guard.

## Adding attack library samples

Drop a `.jsonl` file in `attack_library/`. See [`docs/RED_TEAMING.md`](docs/RED_TEAMING.md) for the format.

Run the library suite to check your new cases pass:

```bash
curl -s -X POST http://localhost:8100/v1/red-team/run \
  -d '{"suite":"library"}' -H "content-type: application/json" | jq .pass_rate
```

## Test data rules

Use fake secrets only — never commit real keys, tokens, or credentials. Examples of acceptable test values:

```
sk-test-fake-key-1234567890abcdef
AKIATESTEXAMPLE123456789
ghp_testtoken_example1234567890
```

## Pull requests

- Keep PRs focused on one thing
- Tests required for new detection logic
- Update `docs/API_CONTRACT.md` if you change request/response shapes
- Describe what attack or false positive the change addresses

## Commit style

```
feat: add ROT13 decoder to normalizer
fix: homoglyph collapse missing Cyrillic 'а'
test: add identity spoofing edge cases
docs: update API contract for /dashboard/stats
```
