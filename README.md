# OnlyVulns

OnlyVulns is a nonprofit, open-source vulnerability disclosure platform built for security researchers.

The platform exists to give researchers a protected, researcher-controlled place to publish vulnerability research when corporations ignore them, threaten them, ban them, underpay them, or refuse to engage in good faith.

Researchers should not have to rely entirely on vendor-controlled disclosure programs, closed bug bounty platforms, or corporate-owned repositories to publish legitimate security research. OnlyVulns gives researchers a neutral place to document their work, preserve disclosure timelines, publish proof-of-concept research, and receive community support.

OnlyVulns is for researchers first. Vendors do not get profiles, dashboards, accounts, or control over the disclosure process. Vendor communication can be tracked as part of the disclosure record, but the platform itself is built around researcher ownership, researcher safety, and public-interest disclosure.

## Core Idea

OnlyVulns should function as a coordinated disclosure platform for proof-of-concept research, technical write-ups, and researcher-controlled publication workflows.

Researchers should be able to:

* Upload a proof of concept
* Upload a technical write-up
* Add affected products and versions
* Add severity details
* Calculate or manually enter a CVSS score
* Track vendor communications
* Add remediation or mitigation notes
* Set an embargo date
* Cancel, delay, delete, or modify a disclosure before publication
* Publish the disclosure publicly after the embargo and waiting period
* Receive tips or crowdfunded payouts for valuable research

OnlyVulns should be completely open-source, free to use, and operated under a nonprofit entity. The nonprofit structure should help protect the platform’s mission, reduce corporate influence, and provide a safer publishing environment for researchers.

The platform should also allow users to tip the platform itself to help cover hosting, legal, moderation, infrastructure, and operational costs.

## Disclosure Flow

A researcher creates a disclosure by uploading a PoC, write-up, supporting files, affected product information, severity metadata, and vendor communication details.

The researcher then sets an embargo date.

During the embargo period, the disclosure remains private and unpublished. The researcher can use this time to coordinate externally with the affected vendor, maintainers, or other relevant parties.

When the embargo expires, the disclosure enters a waiting period. During this waiting period, the researcher can still cancel, delay, modify, or delete the disclosure.

If the researcher does not cancel or delay the disclosure before the waiting period ends, OnlyVulns automatically publishes the disclosure publicly.

Once published, the disclosure becomes part of a permanent public archive of security research, unless removed under a clearly defined moderation, abuse, or legal process.

## Public Disclosure Pages

Each public disclosure page should provide clear, structured information about the vulnerability.

Public pages should include:

* Vulnerability title
* Researcher attribution
* Researcher profile link
* Disclosure summary
* Technical write-up
* Proof-of-concept details
* Affected products and versions
* CVSS score
* CVSS vector
* Severity rating
* CWE tags
* Remediation or mitigation notes
* Patch status
* Known exploitation status
* Vendor communication timeline
* Vendor response status, if entered by the researcher
* References and external links
* Community votes
* Researcher tipping option
* Machine-readable vulnerability metadata

The goal is to make each disclosure useful to researchers, defenders, nonprofits, journalists, incident responders, and the broader security community.

## Why OnlyVulns Exists

Vulnerability disclosure has become increasingly hostile to independent researchers.

Researchers often report serious vulnerabilities only to be ignored, threatened, banned, silenced, or offered little to no compensation for meaningful work. In some cases, corporations benefit from the research while the researcher absorbs the legal, financial, reputational, and operational risk.

OnlyVulns exists to change that balance.

The platform gives researchers a place to publish their findings when corporations refuse to engage in good faith. It gives them a way to preserve evidence, document timelines, disclose responsibly, and publish transparently without handing control of the process to the vendor.

OnlyVulns is not designed to protect corporate reputations. It is designed to protect researchers, preserve public-interest security research, and make vulnerability information available to the people who need it.

## Researcher Control

Researchers should remain in control of their disclosures.

They should be able to decide:

* What to upload
* When to publish
* How long the embargo should last
* Whether to cancel before publication
* Whether to delay publication
* Whether to delete an unpublished disclosure
* Whether to accept tips
* Whether to show public donation totals
* Whether to publish under a name, handle, organization, or approved pseudonym

OnlyVulns should support responsible disclosure workflows without forcing researchers into vendor-controlled systems.

## Vendor Role

Vendors do not get accounts, profiles, dashboards, or administrative influence over researcher disclosures.

Vendor information exists only as disclosure metadata entered by the researcher.

Researchers may track:

* Vendor name
* Vendor contact method
* Initial disclosure date
* Follow-up dates
* Vendor acknowledgement status
* Vendor response summary
* Vendor remediation status
* Vendor dispute or denial status
* Patch availability
* Relevant correspondence or evidence

Vendor communication history should help establish the timeline and context of the disclosure, but vendors should not control the publication workflow.

## Funding Model

OnlyVulns should be free forever for researchers.

The platform should support:

* Tips to researchers
* Crowdfunded payouts for specific disclosures
* Tips or donations to the platform
* Public or private donation options
* Nonprofit donation reporting
* Transparent platform funding where appropriate

The goal is to create a community-funded model that rewards useful vulnerability research without forcing researchers to depend entirely on corporate bug bounty programs.

## Threat Intelligence Feed

OnlyVulns should provide a free threat intelligence feed for publicly disclosed vulnerabilities.

This feed should be available to defenders, researchers, nonprofits, journalists, incident responders, and the general public.

The feed should support:

* RSS
* JSON
* Public API access
* Webhooks
* Search indexing
* Machine-readable vulnerability metadata
* Filtering by severity, product, researcher, CWE, CVSS score, publication date, and exploitation status

The feed should not be locked behind a paywall.


## Policies Needed Before Launch

OnlyVulns should not launch without clear policies for handling high-risk disclosures, disputed claims, legal threats, abuse, and researcher safety.

Required policies:

* Coordinated disclosure policy
* Researcher protection policy
* Moderation policy
* Takedown policy
* Legal request policy
* Malware and PoC handling policy
* Responsible use policy
* Privacy policy
* Terms of use
* Donation and payout policy
* Abuse reporting policy
* Appeal policy
* Security policy for OnlyVulns itself

## Long-Term Goal

OnlyVulns should become a permanent, public-interest archive for vulnerability research.

The long-term goal is to make it harder for corporations to bury valid vulnerability reports and easier for researchers to publish safely, transparently, and independently.

OnlyVulns should protect researchers, preserve their work, reward useful disclosures, and make vulnerability information freely available to the public.

## Vendor Reputation and Bug Bounty Transparency

OnlyVulns should include a public vendor reputation system based on disclosed vulnerabilities, researcher-submitted disclosure timelines, and community feedback about vendor behavior.

Vendors should not receive accounts, dashboards, moderation control, or direct control over disclosures. Vendor reputation should be generated from public disclosure records, researcher-entered communication timelines, and community-submitted feedback.

Vendor reputation should help researchers understand how companies behave when vulnerabilities are reported to them.

Vendor reputation pages should include:

* Vendor name
* Number of disclosed vulnerabilities
* Number of patched vulnerabilities
* Number of unpatched vulnerabilities
* Average time to acknowledge reports
* Average time to remediate reports
* Public disclosure count
* Ignored disclosure count
* Disputed disclosure count
* Researcher-reported payment issues
* Bug bounty program comments
* Researcher-submitted bug bounty experiences
* Community reputation score
* Transparency score
* Responsiveness score
* Remediation score
* Researcher treatment score

Researchers and community members should be able to leave comments on vendor bug bounty programs, including feedback about:

* Report handling
* Response quality
* Payment reliability
* Duplicate handling
* Scope issues
* Safe harbor quality
* Researcher treatment
* Retaliation or threats
* Account bans
* Disclosure restrictions
* Program fairness

To prevent abuse, vendor comments should support moderation, reporting, evidence attachment, reputation weighting, rate limits, and anti-brigading controls.

The goal is not to give vendors control over the platform. The goal is to create public accountability for how vendors treat researchers.

## Roadmap

## Backend

### Accounts and Identity

* [x] Researcher registration
* [x] Researcher login and authentication
* [x] Email verification
* [ ] Optional MFA for researchers
* [x] Researcher profiles
* [x] Researcher reputation system
* [ ] Researcher verification badges
* [ ] Researcher pseudonym support
* [ ] Role-based permissions for researchers, moderators, and admins
* [ ] Account recovery
* [ ] Account deletion
* [ ] Researcher notification preferences
* [ ] Researcher payout settings
* [ ] Researcher public/private profile controls

### Disclosure Management

* [x] Researcher report uploads
* [x] PoC file uploads
* [x] Technical write-up editor
* [ ] Markdown support for reports
* [x] Attachment support for logs, screenshots, patches, and references
* [ ] Draft disclosures
* [ ] Private disclosures
* [x] Public disclosures
* [x] Embargo management
* [x] Researcher-controlled release date
* [ ] Researcher-controlled deletion before publication
* [ ] Researcher-controlled cancellation before publication
* [ ] Disclosure delay requests
* [ ] Disclosure cancellation during waiting period
* [x] Automatic publication after waiting period
* [ ] Disclosure version history
* [ ] Disclosure edit history
* [ ] Disclosure timeline tracking
* [ ] Duplicate disclosure detection
* [ ] Related vulnerability linking
* [ ] Affected product and version tracking
* [ ] Remediation and mitigation fields
* [ ] Patch status tracking
* [ ] Vendor response status tracking, entered by the researcher
* [ ] Disclosure status workflow: draft, embargoed, waiting period, published, cancelled, removed
* [x] Public preview before publication
* [ ] Admin review queue for flagged disclosures
* [x] Public advisory ID generated by OnlyVulns

### Vendor Communication Tracking

* [x] Researcher-entered vendor name
* [ ] Researcher-entered vendor contact details
* [ ] Vendor communication log
* [ ] Communication date tracking
* [ ] Initial disclosure date tracking
* [ ] Vendor acknowledgement tracking
* [ ] Vendor remediation status tracking
* [ ] Vendor response summary
* [ ] Vendor dispute or denial status field
* [ ] Timeline generated from researcher-entered communication events
* [ ] Attachments for vendor correspondence
* [ ] Optional redaction of sensitive communication details before publication
* [ ] Evidence preservation for researcher-entered communications
* [ ] Public/private toggle for selected communication details

### Vulnerability Scoring and Metadata

* [x] Calculate CVSS score on backend
* [x] Support manual CVSS vector input
* [ ] Store CVSS vector string
* [x] Severity classification
* [ ] CWE tagging
* [ ] CPE/product tagging
* [ ] Exploitability indicators
* [ ] Patch availability status
* [ ] Known exploitation status
* [ ] References and external links
* [ ] Optional CVE ID field
* [x] Optional OnlyVulns advisory ID
* [ ] Integration-ready metadata for future CVE/CNA workflows
* [ ] Vulnerability category tagging
* [ ] Affected platform tagging
* [ ] Impact summary field
* [ ] Remediation confidence field

### Payments and Funding

* [ ] Researcher tipping
* [ ] Platform tips
* [ ] Crowdfunded payouts for researchers
* [ ] Donation receipts
* [ ] Payout account management
* [ ] Payment processor integration
* [ ] Platform fee configuration
* [ ] Refund handling
* [ ] Fraud and abuse checks for tips
* [ ] Public donation totals where enabled
* [ ] Private tipping option
* [ ] Nonprofit donation reporting support
* [ ] Researcher payout history
* [ ] Platform funding transparency tools
* [ ] Donation dispute handling
* [ ] Anti-money-laundering and payment compliance review

### Community and Reputation

* [x] Community votes up or down the disclosure
* [x] Community votes up or down the vulnerability quality
* [x] Researcher community-based reputation
* [x] Comment system
* [ ] Comment moderation
* [ ] Abuse reporting
* [ ] Research quality indicators
* [ ] Verified reproduction status
* [ ] Trusted reviewer feedback
* [ ] Reputation weighting for votes
* [ ] Anti-brigading protections
* [x] Limits on vote manipulation
* [ ] Researcher reputation decay or dispute handling
* [ ] Trending disclosures
* [x] Top researchers
* [x] Researcher contribution history
* [x] Comment rate limiting

### Threat Intelligence and Public Data

* [x] Free threat intel feed for disclosed vulnerabilities
* [x] RSS feed
* [x] JSON feed
* [x] Public API feed
* [ ] Webhook support
* [ ] Search indexing
* [x] Export disclosed vulnerability data
* [ ] Public archive pages
* [x] Machine-readable disclosure metadata
* [x] Rate limiting for public feeds
* [x] Abuse-resistant scraping policy
* [ ] Feed filtering by severity
* [ ] Feed filtering by affected product
* [ ] Feed filtering by CWE
* [ ] Feed filtering by CVSS score
* [ ] Feed filtering by publication date
* [ ] Feed filtering by known exploitation status

### Moderation, Safety, and Abuse Prevention

* [ ] Administrative moderation tools
* [ ] Report abuse flow
* [ ] Malware upload scanning
* [ ] Dangerous payload handling rules
* [x] File type restrictions
* [ ] Sandboxed PoC storage
* [ ] Automated secret scanning
* [ ] Automated doxxing/PII detection
* [x] Spam prevention
* [ ] Sybil resistance
* [ ] Account suspension tools
* [ ] Disclosure takedown workflow
* [ ] Legal escalation workflow
* [ ] Audit logs for admin actions
* [ ] Abuse-prevention controls
* [ ] Public redaction workflow
* [ ] Private admin notes on disclosures
* [ ] Researcher safety review process
* [ ] Sensitive target handling policy
* [ ] Moderation appeal process
* [ ] Immutable audit trail for critical actions

### API and Infrastructure

* [ ] API documentation
* [x] Public API
* [ ] Private internal API
* [x] Authentication tokens
* [x] Rate limiting
* [ ] Webhook system
* [ ] Background job queue
* [ ] Scheduled embargo release jobs
* [ ] Scheduled waiting-period publication jobs
* [x] Secure object storage for uploads
* [ ] Database migrations
* [ ] Full-text search backend
* [ ] Logging and monitoring
* [ ] Backup and recovery
* [ ] Admin dashboard
* [ ] Open-source deployment documentation
* [ ] Self-hosting support
* [ ] Security policy
* [ ] Contributor guidelines
* [ ] License selection
* [ ] Infrastructure-as-code support
* [ ] CI/CD pipeline
* [ ] Test suite
* [ ] Vulnerability reporting process for OnlyVulns itself

## Frontend

### Public Pages

* [x] Display disclosed vulnerabilities
* [x] Display pending disclosures where appropriate
* [x] Public disclosure detail pages
* [x] Researcher profile pages
* [x] Disclosure timeline view
* [x] CVSS severity display
* [ ] CVSS vector display
* [ ] Affected product/version display
* [ ] Vendor response status display, based on researcher-entered information
* [ ] Patch/remediation status display
* [ ] Known exploitation status display
* [ ] References section
* [ ] Downloadable advisory view
* [x] Shareable disclosure URLs
* [x] Public researcher attribution
* [ ] Public tipping interface for researchers
* [ ] Public tipping interface for the platform
* [ ] Public archive browsing
* [ ] Related disclosures
* [x] Researcher reputation display

### Search and Discovery

* [x] Search by researcher
* [x] Search by vulnerability title
* [ ] Search by affected product
* [ ] Search by vendor name
* [ ] Search by CVSS score
* [x] Search by severity
* [ ] Search by CWE
* [ ] Search by disclosure status
* [ ] Search by publication date
* [x] Search by advisory ID
* [x] Sort by highest votes
* [x] Sort by lowest votes
* [x] Sort by researcher reputation
* [x] Sort by newest disclosures
* [x] Sort by highest severity
* [ ] Sort by most tipped
* [ ] Sort by most discussed
* [ ] Filter by patched/unpatched status
* [ ] Filter by known exploited status
* [ ] Filter by affected product
* [ ] Filter by vulnerability category

### Researcher Dashboard

* [x] Create new disclosure
* [x] Upload PoC and write-up
* [ ] Save disclosure drafts
* [x] Set embargo date
* [x] View embargo countdown
* [x] View waiting-period countdown
* [ ] Cancel disclosure during waiting period
* [ ] Delete disclosure before publication
* [ ] Delay disclosure release
* [ ] Edit disclosure metadata
* [ ] Track vendor communications
* [x] Add vendor communication events
* [ ] Add vendor response summary
* [ ] Add remediation status
* [ ] Add patch status
* [ ] Preview public disclosure page
* [ ] View tips and payouts
* [ ] Manage researcher profile
* [x] View reputation score
* [ ] View disclosure analytics
* [ ] Manage notification settings
* [ ] Manage payout settings
* [ ] Manage public attribution settings
* [ ] View moderation status for flagged disclosures

### Community Features

* [x] Vote on disclosures
* [x] Vote on vulnerability quality
* [x] Comment on public disclosures
* [x] Report abuse
* [ ] Tip researchers
* [ ] Tip the platform
* [ ] Follow researchers
* [ ] Subscribe to vulnerability feeds
* [ ] Notification preferences
* [x] View top researchers
* [ ] View trending disclosures
* [ ] View most tipped disclosures
* [x] View recently published disclosures
* [x] View high-severity disclosures

### Platform and Trust

* [x] About page explaining nonprofit model
* [x] Open-source repository links
* [x] Public roadmap
* [ ] Donation transparency page
* [ ] Moderation policy page
* [ ] Coordinated disclosure policy page
* [x] Researcher protection policy page
* [x] Terms of use
* [ ] Privacy policy
* [x] Security policy
* [ ] Responsible use policy
* [ ] Takedown policy
* [ ] Legal request policy
* [ ] Contact page
* [ ] Accessibility support
* [x] Mobile-friendly layout
* [x] Dark mode
