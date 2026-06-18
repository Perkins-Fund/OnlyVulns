# Security Policy

## Purpose

OnlyVulns is a nonprofit, public-interest project focused on vulnerability transparency, responsible disclosure, and defensive security.

This security policy explains how to report security issues affecting OnlyVulns systems, repositories, infrastructure, data, and project operations. It also explains how OnlyVulns handles vulnerability information submitted to or published through the project.

## Scope

This policy applies to security issues affecting:

* OnlyVulns GitHub repositories
* OnlyVulns websites, APIs, infrastructure, and services
* Project-maintained datasets, tools, documentation, and automation
* GitHub Actions, CI/CD workflows, secrets, deployment systems, and integrations
* Access controls for maintainers, contributors, and administrators
* Sensitive vulnerability reports submitted to OnlyVulns
* Security or abuse issues involving OnlyVulns project operations

This policy does not authorize testing against third-party systems, vendors, researchers, users, or organizations referenced by OnlyVulns unless you have separate permission from those parties.

## Supported Repositories and Versions

Security support is provided for active OnlyVulns repositories.

A repository is considered active if it is not archived and is still maintained by the project.

Archived, deprecated, or experimental repositories may receive best-effort review, but OnlyVulns does not guarantee fixes or response timelines for inactive projects.

Each repository may include additional security notes in its own `README.md` or repository-specific documentation.

## Reporting a Vulnerability

Please report suspected security vulnerabilities privately.

Do not create a public GitHub issue for security-sensitive reports.

Preferred reporting method:

* Use GitHub private vulnerability reporting if enabled for the affected repository.

Alternative reporting method:

* Email: `contact@perkinsfund.org`

If that address is not yet active, use the official contact address listed in the repository `README.md` or on the OnlyVulns website.

When submitting a report, please include as much of the following information as possible:

* A clear description of the issue
* The affected repository, service, URL, package, or component
* Steps to reproduce the issue
* Proof-of-concept details, if safe to share
* The potential security impact
* Whether the issue is actively exploitable
* Whether you believe the issue is being exploited in the wild
* Any relevant logs, screenshots, commits, package versions, or configuration details
* Your preferred contact information
* Whether you request credit or anonymity

Please do not include live secrets, private keys, passwords, access tokens, personal data, or exploit payloads that could cause unnecessary harm.

## Good-Faith Research

OnlyVulns welcomes good-faith security research.

Good-faith research means activity that is intended to improve security, avoids harm, respects privacy, and is reported responsibly.

Researchers must not:

* Access, modify, delete, or exfiltrate data that does not belong to them
* Disrupt project services or infrastructure
* Conduct denial-of-service testing
* Use social engineering, phishing, or physical attacks
* Attempt persistence, lateral movement, or privilege escalation beyond what is necessary to demonstrate impact
* Publicly disclose unresolved vulnerabilities without coordination
* Submit malware, weaponized exploit chains, or unsafe payloads unless specifically requested by the Security Response Team
* Test third-party systems without authorization

If you accidentally access sensitive data, stop testing immediately, preserve only the minimum information necessary to report the issue, and notify OnlyVulns privately.

## Safe Harbor

OnlyVulns will not pursue legal action against researchers who act in good faith, follow this policy, and make a reasonable effort to avoid harm.

This safe harbor applies only to security research involving OnlyVulns-controlled systems and repositories.

It does not apply to:

* Third-party systems
* Unauthorized access to systems not controlled by OnlyVulns
* Malicious activity
* Extortion or threats
* Public disclosure before coordinated review
* Privacy violations
* Destructive testing
* Activity prohibited by applicable law

OnlyVulns cannot bind third parties, vendors, service providers, law enforcement agencies, or other organizations.

## Handling of Vulnerability Information

OnlyVulns may receive, review, publish, reference, or discuss vulnerability-related information.

Because vulnerability information can create safety, legal, reputational, and operational risk, OnlyVulns may moderate or restrict content that is unsafe or outside project scope.

OnlyVulns may redact, delay, remove, or decline content that:

* Enables active exploitation without a legitimate defensive purpose
* Contains live credentials, secrets, tokens, private keys, or personal data
* Identifies vulnerable third-party systems before reasonable disclosure
* Doxxes researchers, maintainers, vendors, users, or affected individuals
* Encourages unauthorized access
* Contains malware, destructive payloads, or unsafe exploit automation
* Violates applicable law
* Creates unreasonable risk to users or affected organizations
* Is knowingly false, misleading, or unverifiable

The project may preserve private records of reports for security, legal, audit, or nonprofit governance purposes.

## Coordinated Disclosure

OnlyVulns supports coordinated vulnerability disclosure.

When a report involves a vulnerability in OnlyVulns-controlled systems, the Security Response Team will work to validate, remediate, and disclose the issue appropriately.

When a report involves a third-party product, vendor, or service, OnlyVulns may:

* Direct the reporter to the affected vendor’s disclosure process
* Help identify the appropriate contact when practical
* Delay publication to reduce harm
* Publish only defensive, contextual, or non-exploitative information
* Decline to publish information that creates unacceptable risk

OnlyVulns does not guarantee coordination on behalf of third-party vendors.

## Response Targets

OnlyVulns aims to follow these response targets for reports affecting OnlyVulns-controlled systems:

* Initial acknowledgment: within 5 business days
* Initial triage: within 10 business days
* Status update: at least every 15 business days while unresolved
* Remediation timeline: based on severity, complexity, and available nonprofit resources

These are targets, not guarantees.

Critical issues involving active exploitation, credential exposure, or major user risk may be prioritized immediately.

## Severity Assessment

OnlyVulns may classify reports using severity levels such as:

### Critical

A vulnerability that could allow major compromise, such as:

* Remote code execution
* Unauthorized administrative access
* Exposure of production secrets
* Widespread data exposure
* Active exploitation affecting users or project infrastructure

### High

A vulnerability with serious impact, such as:

* Authentication or authorization bypass
* Significant privilege escalation
* Exposure of sensitive nonpublic data
* Compromise of CI/CD, package publishing, or deployment systems

### Medium

A vulnerability with limited but meaningful impact, such as:

* Stored cross-site scripting in a restricted context
* Limited information disclosure
* Security misconfiguration with constrained exploitability
* Dependency vulnerabilities with plausible impact

### Low

A vulnerability or weakness with minor impact, such as:

* Security header issues
* Low-impact misconfiguration
* Dependency advisory with no practical exploit path
* Minor information leakage

Severity is determined by the OnlyVulns Security Response Team based on impact, exploitability, affected assets, and public-interest considerations.

## Security Response Team

The Security Response Team is responsible for:

* Receiving and triaging private reports
* Validating vulnerabilities
* Coordinating fixes
* Communicating with reporters
* Managing disclosure timelines
* Protecting sensitive information
* Escalating legal, ethical, or governance concerns
* Coordinating with the Project Steering Committee or nonprofit Board when needed

The Security Response Team may include maintainers, project leadership, designated security experts, and legal or nonprofit advisors.

## Public Disclosure

Public disclosure should occur only after reasonable review and mitigation.

A public advisory may include:

* A description of the issue
* Affected repositories, packages, services, or versions
* Severity assessment
* Remediation steps
* Fixed versions or commits
* Workarounds
* Credit to the reporter, if requested and appropriate
* Timeline of report, validation, fix, and disclosure

OnlyVulns may withhold technical details when disclosure would create unnecessary risk.

## Credit

OnlyVulns generally credits researchers who report valid security issues in good faith.

Credit may be withheld when:

* The reporter requests anonymity
* Credit would expose sensitive personal information
* The report involved unsafe, abusive, or unlawful conduct
* Public attribution would increase risk to affected parties
* The issue is already known or previously reported

## Confidentiality

OnlyVulns treats private security reports as sensitive.

Participants handling private reports must not disclose them outside authorized channels unless disclosure is approved by the Security Response Team or required by law.

Private report materials may be shared internally with:

* Maintainers responsible for remediation
* Security Response Team members
* Project Steering Committee members
* Nonprofit leadership
* Legal advisors
* Infrastructure or service providers when necessary to investigate or remediate the issue

Only the minimum necessary information should be shared.

## Secrets and Credentials

Do not submit live secrets, credentials, tokens, private keys, or passwords.

If you discover exposed secrets connected to OnlyVulns:

1. Stop testing.
2. Do not use the secret.
3. Do not share it publicly.
4. Report it privately immediately.
5. Include where the secret was found and what system it appears to affect.

OnlyVulns may rotate credentials, revoke access, invalidate tokens, audit logs, and notify affected parties as appropriate.

## Dependency Vulnerabilities

Dependency vulnerability reports should include:

* The affected dependency name
* The affected version
* The advisory or CVE identifier, if available
* The vulnerable path or usage within the project
* Whether the vulnerable code path is reachable
* Recommended fixed version
* Any known exploitability constraints

Reports based solely on automated scanner output may be closed if they do not demonstrate practical impact or relevance to the project.

## Abuse Reports

Reports involving spam, harassment, impersonation, doxxing, malicious content, or misuse of OnlyVulns infrastructure may be submitted through the same private security channels.

OnlyVulns may remove content, restrict accounts, lock discussions, revoke access, or escalate issues under the project’s governance and Code of Conduct procedures.

## Out-of-Scope Reports

The following are generally out of scope unless they demonstrate a concrete security impact:

* Missing security headers without exploitability
* Clickjacking on pages with no sensitive actions
* Version disclosure without demonstrated risk
* Rate-limit observations without impact
* Automated scanner output without validation
* Denial-of-service testing
* Social engineering
* Physical security issues
* Vulnerabilities in third-party systems not controlled by OnlyVulns
* Reports requiring access to private accounts or data without authorization
* Theoretical issues with no plausible attack path

OnlyVulns may still accept defensive recommendations, but they may not be treated as security vulnerabilities.

## Repository Security Practices

OnlyVulns maintainers should follow these baseline practices:

* Use least-privilege repository access
* Require multi-factor authentication for privileged accounts
* Protect default branches
* Review GitHub Actions and third-party integrations
* Avoid storing secrets in source code
* Use dependency review where practical
* Pin or verify sensitive build dependencies where appropriate
* Review permission scopes for tokens and workflows
* Remove access for inactive maintainers
* Archive inactive repositories that are no longer maintained
* Document supported versions and security contacts

## Changes to This Policy

This policy may be updated by the OnlyVulns maintainers, Security Response Team, Project Steering Committee, or nonprofit leadership.

Material changes should be documented in the repository history.

Emergency changes may be made immediately when needed to address legal, safety, security, or mission-related risk.

## Contact

Security reports: `contact@perkinsfund.org`

General project contact: see the repository `README.md`.

Please do not submit security-sensitive reports through public GitHub issues, public discussions, social media, or other public channels.
