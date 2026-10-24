# Contributing

This is a fork of [obegron/rootlessRelay](https://github.com/obegron/rootlessRelay)
that adds a hosted, multi-tenant mode (accounts, organizations, tiers,
metering, an operator panel). It runs [relaynet](https://relaynet.network).

Everyone taking part follows the [code of conduct](CODE_OF_CONDUCT.md).

## Where changes go

- **Hosted mode** (`auth/`, `admin/`, `metering/`, `policy/`, `server/`,
  `hosted.js`, `config.js`): here.
- **The shared relay** (`relay.js` and the TCP/UDP code): here too, but a fix
  that applies to upstream as well is worth offering there; say so in the
  pull request.
- **Security problems:** don't open an issue; email
  security@relaynet.network.

## Pull requests

- One change per pull request, with the reason in the description.
- Add tests: `npm test` runs the unit tests, `npm run test:network` the ones
  that open real sockets. Both run in CI.
- Add a line to `CHANGELOG.md` under "Unreleased".
- A pull request that goes into a release bumps `version` in `package.json`
  (`X.Y.Z-hosted.N`); the release workflow refuses a tag that doesn't match.

## Sign your commits (DCO)

Every commit must be signed off under the
[Developer Certificate of Origin](https://developercertificate.org): a
statement that you wrote the change, or otherwise have the right to submit
it under this project's license (MIT, see `LICENSE`). Add a line with your
real name and the email of the commit's author:

```
Signed-off-by: Your Name <you@example.com>
```

`git commit -s` adds it. To sign off commits already on a branch:

```sh
git rebase --signoff main
git push --force-with-lease
```

The **dco** check fails a pull request with any commit that lacks a
matching sign-off. Bot commits (Dependabot) are exempt.
