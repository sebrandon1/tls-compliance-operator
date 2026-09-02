# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability, please report it responsibly:

1. **Do not** open a public GitHub issue for security vulnerabilities
2. Use [GitHub Security Advisories](https://github.com/sebrandon1/tls-compliance-operator/security/advisories/new) to report the issue privately
3. Include steps to reproduce, impact assessment, and any suggested fixes

You should receive an initial response within 72 hours.

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest release | Yes |
| Previous release | Best effort |
| Older releases | No |

## Security Scanning

This project runs automated security scans on every push and pull request:

- **govulncheck** — Go vulnerability database checks
- **Trivy** — Filesystem and container image scanning

Run `make security` locally to reproduce the gosec and govulncheck checks before
pushing. Trivy scans (filesystem and container image) run in CI only.

See `.github/workflows/security.yml` for the full scan configuration.

## Design Considerations

The operator connects to TLS endpoints with `InsecureSkipVerify: true` because
it is probing endpoint capabilities (TLS versions, cipher suites), not
establishing trusted connections. This is by design — the operator reports
certificate details without enforcing trust chain validation.
