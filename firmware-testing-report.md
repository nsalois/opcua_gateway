# Firmware testing and acceptance limits

The project aims to make one Büchi R-300 available as a dependable OPC UA server
through one Opta Lite. **Unattended production suitability has not been established.**
This source publication includes reproducible host checks; device results below
are historical development evidence for their particular firmware and simulator.

## Checks available in this repository

`bash tools/check.sh` runs formatting, Clippy, shared-crate unit/integration tests
in debug and optimized profiles, and the extracted production write-completion
regression. Tests cover parsing, stale data, configuration persistence and counter
rollover, bounded subscriptions, write validation and trust-loss outcomes, and
certificate validation with synthetic inputs. Diagnostic features receive host
tests but are not enabled in the product firmware build.

The write-completion regression executes the production request, response and
accounting code against scripted transport/time/locking collaborators. It proves
the named host behavior, not target scheduling, contention or real TLS exchange.
Certificate fixtures contain no real vendor trust material or signing keys.

The publication preparation executed **375 shared-crate tests per profile** and
**four production write-completion tests per profile**: 758 passing executions
across debug and optimized builds. These are 379 test cases exercised twice,
not 758 distinct cases. Seven explicitly ignored cases per profile are excluded
from passing counts. Formatting and all-feature Clippy checks also passed.

Some imported regression cases remain explicitly ignored because they document
unresolved findings, including PHY link-state caching and duplicate writes after
a lost client response. Ignored tests are not passes. Test output reports them
separately. The public suite excludes the private live-mock, external-client and
hardware campaign runners. Their test counts do not describe the exported suite.

Both canonical builders check firmware composition, source identity and resource
limits. M4 additionally checks its pinned interrupt table, vector table, permitted
instructions and dependency isolation. These checks prove properties of the
reported artifacts; they do not install firmware or qualify physical recovery.

## Historical development evidence

The following observations used controlled R-300 HTTPS simulators. They are not
results for the final public-source binary, and the underlying private logs are
not included in this repository.

| Product goal | Recorded observation | Limit |
| --- | --- | --- |
| Useful readings with honest quality | On 6 October 2026, one normal product 1.2.171 gateway completed 80 fields through five phases each: 400 phases, including omissions and recovery. Raw recount recorded 55,810 Reads and 2,359 Publishes. | One board, one exact image, simulator upstream; real-instrument acceptance remains open. |
| Validate and forward setpoints | A separate product screen completed 100 client/write cycles and failed-write/timeout recovery cases. | Two trust-loss accounting defects were corrected and host-tested; dedicated board confirmations remain open. |
| Unattended recovery | Bounded ordinary-product connection and silent-client release/reuse cases passed. Separate diagnostic stack observations exercised 100 writes. | Diagnostic and normal-product evidence are distinct. Power testing is deferred; unexplained timing/read-status symptoms and final recovery gates remain open. |
| Independent fleet identity | Earlier September simulator campaigns exercised two physical gateways and their separate identities and upstreams. | Historical firmware only; final-composition dual-device acceptance remains open. |
| USB provisioning and diagnostics | Earlier firmware demonstrated configuration, factory reset, reprovisioning and bounded USB interruption behavior. | Historical results do not validate all USB/recovery cases on this public artifact. |

These bounded observations do not establish months of reliability, real R-300
interoperability, OPC Foundation conformance, release acceptance or field
installation approval. Completing those gates is separate from publishing
buildable development source.
