# Licensing

## One licence

Everything first-party in this repository is licensed under the
[Apache License, Version 2.0](LICENSE): the foundation services, the sample modules, the module
kit, the SDK, the sample shell, the tools and the documentation. There is no other first-party
licence and no dual licensing.

This is the same licence Keycloak carries, so a deployment that combines Kiban with the Keycloak
it embeds sits under a single set of terms.

## Copyright

All first-party code and documentation is copyright 2026 Ross Chiu. The same holder appears in
every `LICENSE` file in this tree and in the root `NOTICE` file.

## Path to licence map

| Path | Licence | Class |
|---|---|---|
| `/` (default, everything not listed below) | [Apache-2.0](LICENSE) | Foundation |
| `modules/docs/`, `modules/notification/`, `modules/helpdesk/`, `modules/timesheet/` | Apache-2.0 (each has its own `LICENSE`) | Foundation, sample modules |
| `web/sdk/` | [Apache-2.0](web/sdk/LICENSE) | Ecosystem |
| `modulekit/` | [Apache-2.0](modulekit/LICENSE) | Ecosystem, module kit |
| `web/shell/` | [Apache-2.0](web/shell/LICENSE) | Ecosystem, sample shell |
| `internal/modvalidate/`, `cmd/modvalidate/` | Apache-2.0 | Ecosystem, module validator |
| `internal/authz/harness/` | Apache-2.0 | Trust artifact, differential authorization harness |
| `docs/` | Apache-2.0 | Documentation |

The classes describe who owns and maintains a path, not a difference in terms. Commercially
licensed modules are not part of this repository.

## Every module declares its class

Every `module.manifest.json` carries a `license` object (`class`, `spdx`, `entitlementRequired`)
declared when the module is created. `class` is `foundation` (Apache-2.0) or `open` (Apache-2.0
or MIT); `entitlementRequired` is reserved and must be `false`. The module's own `LICENSE` file
must match the canonical text for its declared `spdx`; `make license-check` enforces this. For an
`open`-class module, Apache-2.0 is recommended for patent-grant consistency with the rest of the
tree.

## Third-party code

No third-party source files are vendored in this repository. Third-party dependencies (Go
modules, npm packages) are inventoried by `make license-scan`, which fails on any GPL, AGPL or
SSPL-family or unclassified licence in a distributed component.

## Files without SPDX headers

The SPDX header sweep (`make license-check`) skips build output and third-party-owned files:
sqlc-generated Go, built bundles under `web/*/dist/` and `node_modules/`, and lockfiles. The
exact rules are in `tools/licensecheck`.
