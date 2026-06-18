# OnlyVulns Governance

## 1. Purpose

OnlyVulns is a nonprofit, public-interest project focused on improving vulnerability transparency, responsible disclosure, and access to security information.

This governance document defines how decisions are made, who has authority over the project, how maintainers are selected, and how conflicts or security-sensitive issues are handled.

The goal of this governance model is to keep OnlyVulns:

- Mission-aligned
- Transparent
- Secure
- Accountable
- Community-oriented
- Independent from improper commercial or political influence

## 2. Mission

OnlyVulns exists to support the responsible discovery, documentation, discussion, and remediation of software vulnerabilities.

The project prioritizes public benefit, user safety, researcher participation, and ethical security practices.

## 3. Scope

This governance document applies to:

- The OnlyVulns GitHub organization
- All repositories under the OnlyVulns project
- Maintainers, contributors, reviewers, moderators, and project administrators
- Technical, security, moderation, and policy decisions made within the project

This document does not replace the nonprofit organization’s bylaws, board policies, fiscal policies, employment policies, or legal obligations. Where this document conflicts with those governing documents, the nonprofit’s formal governing documents control.

## 4. Roles

### 4.1 Board of Directors

The nonprofit’s Board of Directors has ultimate oversight over the organization and its mission.

The Board is responsible for:

- Ensuring the project remains aligned with the nonprofit’s mission
- Approving major governance changes
- Overseeing legal, financial, and fiduciary matters
- Resolving escalated governance disputes
- Appointing or removing project leadership when necessary
- Protecting the independence and integrity of the project

The Board does not normally make day-to-day technical decisions unless those decisions create legal, financial, ethical, or mission-level risk.

### 4.2 Project Steering Committee

The Project Steering Committee provides operational oversight for OnlyVulns.

The Steering Committee is responsible for:

- Setting project priorities
- Approving major technical or policy changes
- Maintaining this governance document
- Appointing maintainers
- Reviewing appeals and escalated disputes
- Coordinating with the Board when needed
- Ensuring the project follows its nonprofit purpose

The Steering Committee should include a mix of technical, security, nonprofit, and community perspectives when possible.

### 4.3 Maintainers

Maintainers are trusted contributors with repository-level permissions.

Maintainers are responsible for:

- Reviewing and merging pull requests
- Managing issues and discussions
- Enforcing project standards
- Triaging security-sensitive reports
- Maintaining documentation
- Supporting contributors
- Escalating sensitive matters when appropriate

Maintainers must act in the best interests of the project and nonprofit mission.

### 4.4 Contributors

Contributors are individuals or organizations that submit issues, pull requests, documentation, vulnerability information, research, or other project input.

Contributors are expected to:

- Follow the Code of Conduct
- Respect responsible disclosure practices
- Provide accurate information to the best of their ability
- Avoid submitting exploitative, abusive, or unlawful content
- Respect maintainer decisions and review processes

### 4.5 Security Response Team

The Security Response Team handles sensitive vulnerability reports, abuse reports, coordinated disclosure issues, and content that may create safety or legal risk.

The Security Response Team may include maintainers, Steering Committee members, legal advisors, or designated security experts.

The Security Response Team is responsible for:

- Receiving and triaging sensitive reports
- Coordinating disclosure timelines
- Protecting reporters from unnecessary exposure
- Reducing risk to users and affected vendors
- Escalating legal or ethical concerns
- Maintaining private security communication channels

## 5. Decision-Making

OnlyVulns uses a consensus-seeking model for ordinary project decisions.

Consensus does not require unanimity. It means that relevant participants have had a reasonable opportunity to comment and that no unresolved objection presents a serious technical, ethical, legal, or mission-related concern.

### 5.1 Routine Decisions

Routine decisions may be made by maintainers, including:

- Bug fixes
- Documentation updates
- Minor feature changes
- Issue triage
- Repository maintenance
- Noncontroversial pull request merges

### 5.2 Major Decisions

Major decisions require Steering Committee review.

Major decisions include:

- Changes to governance
- Changes to project mission or scope
- Creation or archival of major repositories
- Changes to maintainer permissions
- Adoption of new licensing terms
- Major security policy changes
- Decisions involving substantial legal, ethical, reputational, or financial risk

### 5.3 Emergency Decisions

Emergency decisions may be made by the Security Response Team or designated maintainers when delay could create meaningful harm.

Emergency decisions may include:

- Temporarily removing dangerous content
- Restricting repository access
- Locking issues or discussions
- Privately triaging sensitive vulnerability information
- Coordinating urgent disclosure actions

Emergency actions must be documented and reviewed by the Steering Committee as soon as practical.

## 6. Maintainer Appointment and Removal

### 6.1 Appointment

Maintainers may be nominated by existing maintainers, Steering Committee members, or the Board.

Nominees should demonstrate:

- Sustained constructive contribution
- Technical competence
- Sound judgment
- Respect for responsible disclosure
- Alignment with the nonprofit mission
- Commitment to the Code of Conduct

Maintainer appointments require approval by the Steering Committee.

### 6.2 Removal

Maintainers may be removed for:

- Violation of the Code of Conduct
- Abuse of project access
- Mishandling sensitive security information
- Sustained inactivity
- Conflict of interest that cannot be managed
- Conduct inconsistent with the nonprofit mission
- Legal, ethical, or reputational risk to the project

Removal decisions should be documented. When appropriate, the affected maintainer should receive notice and an opportunity to respond.

In urgent cases, repository access may be suspended immediately pending review.

## 7. Repository Permissions

Repository permissions should follow the principle of least privilege.

Access levels should be granted only to the extent needed for a person’s role.

Administrative access should be limited to trusted individuals designated by the Steering Committee or Board.

The project should periodically review:

- Organization owners
- Repository administrators
- Maintainers
- GitHub Actions permissions
- Deployment secrets
- Third-party integrations
- Archived or inactive access

## 8. Security and Responsible Disclosure

OnlyVulns is a security-focused project. Security-sensitive information must be handled carefully.

Contributors must not knowingly submit content that:

- Enables active exploitation without legitimate defensive purpose
- Contains live credentials, private keys, or secrets
- Doxxes researchers, users, vendors, or affected individuals
- Encourages unauthorized access
- Violates applicable law
- Creates unreasonable risk to affected systems or users

Security reports should be submitted according to the project’s `SECURITY.md`.

The project may temporarily withhold, redact, or restrict information when necessary to protect users, affected vendors, reporters, or the public.

## 9. Conflicts of Interest

All project leaders, maintainers, and Steering Committee members must disclose conflicts of interest that could affect their judgment.

Conflicts may include:

- Employment or consulting relationships
- Vendor relationships
- Financial interests
- Competitive interests
- Personal relationships
- Prior involvement in a vulnerability report or dispute

A person with a material conflict may be asked to recuse themselves from a decision.

The Steering Committee is responsible for determining whether a conflict requires recusal or other mitigation.

## 10. Transparency

OnlyVulns should conduct its work openly whenever practical.

Public documentation should be used for:

- Governance changes
- Project roadmap decisions
- Major policy updates
- Maintainer appointments
- Repository lifecycle decisions

Private processes may be used for:

- Security-sensitive reports
- Legal matters
- Personnel matters
- Abuse reports
- Confidential reporter or vendor communications
- Matters involving user safety

When private decisions affect the public project, the project should provide an appropriate public summary when safe and lawful to do so.

## 11. Code of Conduct

All participants must follow the project’s `CODE_OF_CONDUCT.md`.

The project may moderate, restrict, suspend, or remove participants who violate the Code of Conduct.

Code of Conduct enforcement should be fair, documented, and proportionate to the conduct involved.

## 12. Licensing

OnlyVulns repositories should clearly identify their applicable licenses.

Code, documentation, data, and vulnerability information may require different licensing approaches.

License changes require Steering Committee approval and, where legally necessary, contributor consent.

The project should avoid accepting contributions that are incompatible with the project’s licenses or nonprofit mission.

## 13. Data and Content Integrity

OnlyVulns should prioritize accuracy, provenance, and responsible handling of vulnerability information.

Maintainers may request evidence, references, or clarification before accepting vulnerability-related submissions.

The project may label, qualify, redact, or remove content that is:

- Unverified
- Misleading
- Duplicative
- Unsafe
- Legally problematic
- Outside the project scope

Where practical, corrections should be made transparently.

## 14. Appeals

A contributor or maintainer may appeal a significant project decision, including:

- Rejection of a major contribution
- Removal of content
- Restriction from participation
- Maintainer removal
- Conflict of interest determination
- Code of Conduct enforcement action

Appeals should be submitted to the Steering Committee.

If the Steering Committee has a conflict or cannot fairly resolve the appeal, the matter may be escalated to the Board.

Board decisions are final unless the nonprofit’s bylaws or applicable law provide otherwise.

## 15. Amendments

This governance document may be amended by approval of the Steering Committee, subject to Board oversight.

Material changes should be proposed publicly when possible and allow a reasonable comment period.

Emergency amendments may be adopted immediately when necessary to address legal, security, or mission-related risk, but should be reviewed after adoption.

## 16. Relationship to Nonprofit Governance

OnlyVulns operates as a project of a nonprofit organization.

This document governs project-level decision-making. It does not override:

- Articles of incorporation
- Bylaws
- Board resolutions
- Fiscal sponsorship agreements
- Grant agreements
- Employment policies
- Applicable law
- Legal obligations of the nonprofit

The nonprofit’s Board retains ultimate authority over the organization and may intervene when necessary to protect the organization, its mission, or the public interest.

## 17. Contact

Questions about project governance may be directed to the Project Steering Committee.

Security-sensitive issues should be reported according to `SECURITY.md`.

Code of Conduct concerns should be reported according to `CODE_OF_CONDUCT.md`.