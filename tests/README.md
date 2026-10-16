# Session-token security tests

Run from the repository root using Python 3.9 or newer:

```sh
python -m venv .venv
# Activate .venv using the command for your shell, then:
python -m pip install -r tests/requirements.txt
python -m unittest discover -s tests -v
```

The tests exercise the actual token creation and verification helpers in
`lib.settings`, including real itsdangerous signatures. They cover valid tokens,
user/admin role separation, each role's configured expiry boundary, future-dated
tokens, payload and signature tampering, missing signatures, incorrect signing
keys, and malformed inputs.

Configuration and the signing clock are replaced with deterministic test fixtures.
No `env.json`, credentials, database, Redis, email service, or running API is needed.
The suite does not make network requests or sleep, and adds no runtime dependencies.
These are helper-level regression tests, not an end-to-end authentication audit.
