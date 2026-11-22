# Contributing to pwnproxy

Thanks for taking the time to contribute. This document explains what you need to do before your
work can be merged: sign the Contributor License Agreement (CLA), follow the licensing rules, and
send a pull request that a maintainer can review without extra back-and-forth.

## Sign the CLA first

Every contributor must sign the CLA **once**, before their first pull request can be merged.

1. **Read the agreement:** [`CLA.md`](CLA.md) (English, the version that governs). A Spanish
   translation is available at [`CLA.es.md`](CLA.es.md); it is informative only, and the English
   text prevails in case of any discrepancy.
2. **Open your pull request.** The [CLA Assistant](https://cla-assistant.io) bot comments on it with
   a link to the agreement and instructions, and adds a `license/cla` status check.
3. **Sign through the link.** Click the signing link in that comment. It takes you to
   [cla-assistant.io](https://cla-assistant.io), where you authorize with your GitHub account
   (OAuth) — the signature is tied to your GitHub username — and accept the agreement on that page.
4. **That's it.** The app records your signature and updates the `license/cla` status check of the
   pull request to green, so the pull request becomes mergeable (subject to review and CI). You never
   have to sign again for this version of the text — it covers your current and future contributions
   until a new version of the agreement is published, at which point everyone is asked to sign again.

> There is no comment to paste and no form to email: the only valid signature is the one recorded by
> CLA Assistant after you accept through the link it posts. Signatures are stored per GitHub account,
> and the maintainer can export the list.

The check is enforced by the branch protection of `master`: a pull request from an account that has
not signed cannot be merged.

### What the CLA means, in plain language

- **You keep the copyright of your contribution.** The agreement is a license, not an assignment:
  nothing is transferred to the maintainer.
- **You give the maintainer permission to license your contribution**, including commercially. That
  is what lets the same code be part of the open-source project and, separately, part of a
  commercially licensed product.
- **Nothing already published changes.** Your contribution is published in this repository under
  the AGPLv3, and it stays available under the AGPLv3 to everyone who received it.
- **You can keep using your own work** however you like, including in your own projects, under any
  terms you choose.

The CLA covers contributions to this repository only. If you are contributing in the course of your
employment, read Section 7.1 of [`CLA.md`](CLA.md) and write to
[info@nextechsolutions.mx](mailto:info@nextechsolutions.mx) before signing.

### What the CLA is not

The CLA is **not legal advice**, and it is not a substitute for advice from a lawyer: it is a
document written by the project maintainer to state clearly what rights are granted. If the terms
matter to you or to your employer, have them reviewed by a legal professional.

### Who does not need to sign

| Who | Signs? | Why |
|---|---|---|
| External contributor (code, docs, tests, translations) | **Yes**, once | It is the case the CLA covers |
| The maintainer (`ericmtzmtz`) | No | He is the licensor; his account is on the app's allowed-users list (or he signs once) |
| `dependabot[bot]` | No | It only bumps lockfiles and manifests; bots cannot sign, so their names are imported as allowed |
| People opening issues, or commenting | No | There is no contribution to license |

### No retroactive signatures

There are no external contributions in this repository's history — only the maintainer and
`dependabot[bot]`. Nothing needs to be regularized, and nobody is being asked to sign for past
commits. The CLA applies from the moment it was published, to contributions made from then on.

## Licensing

- **The core is open source under the AGPLv3.** See [`LICENSE`](LICENSE). You are free to use,
  modify and distribute pwnproxy under those terms.
- **There is also a commercial offering, by the same copyright holder, over separate code.** The
  commercial product is new code with its own proprietary license; it is not a different license
  applied to this repository's code.
- **Published code is not relicensed.** Code already released under the AGPLv3 stays available under
  the AGPLv3. The CLA gives the maintainer the option to also license *your contribution* under
  other terms; it does not withdraw anything already published, and it does not change the license
  of the code you did not write.
- **Your contribution is distributed under the AGPLv3** once it is merged into this repository.

## Before you open a pull request

- **Open an issue first for anything non-trivial.** A short discussion avoids a large pull request
  that does not fit the architecture. Bug fixes and small documentation corrections can go straight
  to a pull request.
- **Branch from `master`** and keep the change focused on a single concern.
- **Add or update tests** for the behavior you touch, and make sure they fail without your change.
  Cite the scenario, issue or rule the test protects.
- **Run the test suite** before pushing (see below).
- **Do not include commits or branches from someone else**, and do not mix unrelated formatting or
  refactors into a functional change.
- **Document public interfaces** you add or change: a docstring and the relevant `docs/` page.

### Development setup

```bash
git clone https://github.com/ericmtzmtz/pwnproxy.git
cd pwnproxy

poetry install
poetry run pytest
```

For the web UI (`apps/web`):

```bash
npm install --prefix apps/web
npm run build --prefix apps/web
```

### What CI runs

The same commands run in CI (`.github/workflows/ci.yml`). Run them locally, in this order:

```bash
poetry run pytest -m "not live and not golden and not perf" -q
poetry run pytest -m "golden and not live" -q
poetry run pytest tests/perf -m "perf and not live" --perf-check -q
```

Tests marked `live` reach the network and are excluded by default.

### Review and merge

- A maintainer reviews every pull request; CI and the `license/cla` check must be green.
- Review comments are about the change, not about you. Expect questions about scope, tests and
  naming.
- If a pull request cannot be accepted (scope, licensing, or an unsigned CLA), the maintainer will
  say so explicitly instead of leaving it open silently.

## Reporting security issues

Do not open a public issue for a vulnerability. Contact
[info@nextechsolutions.mx](mailto:info@nextechsolutions.mx) instead, as described in the security
section of the [README](README.md).
