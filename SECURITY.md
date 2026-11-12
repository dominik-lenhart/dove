# Security policy

Dove holds read and draft access to mailboxes, so security reports are welcome and taken seriously.

## Reporting a vulnerability

**Do not open a public issue, pull request or discussion for a security problem.**

Report privately through this channel:

> **OWNER ACTION REQUIRED, placeholder:** `<security-contact: replace with a monitored address or the repository's private vulnerability reporting link before the repository is made public>`

Until that placeholder is replaced, this repository has no working private reporting channel. Maintainers: set up
GitHub private vulnerability reporting (Security tab, "Report a vulnerability") or a dedicated mailbox, publish an
encryption key if you want encrypted reports, and edit this section. Do not publish the repository before then.

Please include: the affected version or commit, what you did, what you expected, what happened, and the impact you
see. Use example data; never send real mail content, tokens or Google credentials. If you accidentally obtained
a real token or mail, say so and delete it.

What to expect (targets for the maintainers once the channel exists, not a contract): acknowledgement within 3 working
days, an assessment within 10 working days, and coordinated disclosure after a fix is available. Reporters who act in
good faith and avoid harming other people's data will not face legal action from the maintainers.

## Supported versions

Dove is pre-release. There are no tagged releases yet; only the `main` branch receives security fixes. When releases
exist, this section will name the supported versions.

## Scope

In scope, for a default configuration of the code in this repository:

- bypassing a token's project or mailbox scope, or learning that another project's mailbox or object exists
  (the identical `not_found` rule)
- bypassing either send gate (`allow_send`, per-token send grant), sending a draft Dove does not own, or a double send
- authentication or authorization flaws on the MCP endpoint, the OAuth routes and the Google callback
- reaching the admin socket's operations without the operator OS identity
- disclosure of secrets or mail content in logs, audit records, error messages or backups, or weak handling of the
  KEK, pepper, index key, Google refresh tokens and client tokens
- header injection, HTML or Unicode handling that lets mail content break out of its envelope, SSRF or requests to
  anything outside the fixed Google origins
- flaws in the container image, systemd unit or proxy configurations under `deploy/` that weaken the documented
  isolation

Out of scope:

- a host or account that is already compromised (root, the service user, or the operator user), including reading
  process memory; this is documented in the README's threat model
- prompt injection as such. Dove mitigates it with scoping and delimiters but cannot prevent a steered agent from
  using permissions its token holds, including a send grant. Reports that show Dove granting more than the token
  allows are in scope; "an agent followed instructions in an email" is not
- weaknesses on Google's side, in Apple Mail, in an MCP host, or in a reverse proxy you configured differently from
  `deploy/`
- denial of service by clients holding a valid token within the configured rate limits, and volumetric network attacks
- missing hardening on hosts you operate, social engineering, and findings from automated scanners without a working
  exploit against Dove

Dependency advisories are tracked in CI with `cargo deny`. Two advisories (RUSTSEC-2023-0071 and RUSTSEC-2026-0387)
are ignored on purpose, with reasons recorded in `deny.toml`, because Dove only verifies RS256 signatures and holds
no private RSA or EC keys. If you believe that reasoning is wrong, report it.
