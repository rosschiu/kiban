# Security policy

## Reporting a vulnerability

Use GitHub's private vulnerability reporting on this repository: the "Security" tab, then
"Report a vulnerability". This keeps the report and any discussion out of public issues until a
fix ships.

If that button is not available, open an issue that says only "I have a security report and
need a private channel" and a maintainer will arrange one. Do not put details in the issue.

Please do not report vulnerabilities through public issues, discussions, or pull requests.

## What to include

- The affected version or commit (`kiban_build_info{version,commit}` is exposed by every
  service's metrics endpoint).
- The deployment shape (Compose from a checkout, Compose from published images, Kubernetes).
- Steps to reproduce, and the impact as you understand it (what an attacker gains).
- Whether the issue is in Kiban's foundation code (`cmd/`, `internal/`, `migrations/`,
  `infra/`) or in a module (`modules/*`) — helps route the report correctly.

## Supported versions

Kiban is pre-release. There is no long-term-support branch and no back-porting of fixes to old
tags.

| Version | Supported |
|---|---|
| `0.1.x` (pre-release) | Yes — the only supported line while pre-1.0 |
| `< 0.1.0` | No |

Before `1.0.0`, a fix targets only the latest tagged `0.1.x` release or `main`. Once `1.0.0` is
cut, this table will name a supported window.

## Response expectations

Kiban is built and maintained by a small team. There is no SLA. Best-effort targets, stated
honestly rather than aspirationally:

- **Acknowledgment**: we aim to acknowledge a report within a few business days, not hours.
- **Triage**: severity and validity assessed after acknowledgment; we'll tell you what we found,
  including if we conclude it isn't exploitable or is out of scope.
- **Fix and disclosure**: timeline depends entirely on severity and the fix's complexity — a
  straightforward fix might ship in days, a design-level issue could take longer. We'll keep the
  reporter updated rather than going silent, and we'll credit the reporter (if they want credit)
  once a fix ships.

If you haven't heard back in a reasonable time, following up is welcome — it does not mean the
report was ignored, but a small team can miss things.

## Scope

In scope: the foundation services (`cmd/`, `internal/`), the sample modules
(`modules/notification`, `modules/docs`, `modules/helpdesk`, `modules/timesheet`), the SDK and
shell (`web/sdk`, `web/shell`), infra/deployment manifests (`infra/`, `deploy/`), and the
authorization model itself (the thing this project exists to get right).

Out of scope: vulnerabilities requiring physical access, social engineering of maintainers, or
issues in third-party dependencies that should be reported upstream (though a pointer here to
help us track exposure is still welcome — see `THIRD-PARTY-LICENSES.md` for the
dependency inventory).
