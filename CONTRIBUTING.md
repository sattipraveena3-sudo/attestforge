# Contributing

Thanks for reviewing AttestForge. Contributions are welcome, especially reproducible security reports, adversarial tests, interoperability tests, policy hardening, and documentation improvements.

1. Open a descriptive issue for larger changes; avoid posting undisclosed security vulnerabilities publicly.
2. Fork the repository and create a focused branch.
3. Run `python -m pip install -e '.[dev]'`, `make test`, `make lint`, and `make smoke`.
4. Include regression tests for changed security behavior; never weaken fail-closed behavior without a documented rationale.
5. Submit a PR explaining the threat addressed, tests, backwards compatibility, and limitations.

Do not commit private keys, credentials, real customer artifacts or personal data. Maintainer review does not constitute a formal security audit.
