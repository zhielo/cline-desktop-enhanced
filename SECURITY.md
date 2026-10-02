# Security Policy

## Supported Versions

We actively patch only the most recent minor release of Cline. Older versions receive fixes at our discretion.

## Reporting a Vulnerability

We appreciate your efforts to responsibly disclose your findings and will make every effort to acknowledge your contributions.

To report a security issue, please submit your report through our [Bugcrowd Vulnerability Disclosure Program](https://bugcrowd.com/engagements/clinebot-vdp-ess). Bugcrowd will manage communication and triage on our behalf.

When reporting, please include:

- A short summary of the issue
- Steps to reproduce or a proof of concept
- Any logs, stack traces, or screenshots that might help us understand the problem

Please keep the details private until a resolution has been reached.

## Escalation

If you are unable to submit through Bugcrowd, you may send an email to security@cline.bot.

Thank you for helping us keep Cline users safe.

## Enhanced desktop fork safeguards

Cline Enhanced provides host-enforced Read only, Workspace, Workspace + network,
and Full access profiles. Full access removes repetitive tool approvals but does
not bypass Windows UAC, filesystem ACLs, authentication, parser limits, or
licensing. Keep restricted profiles available for untrusted projects and review
the persistent Full Access indicator before starting a local session.

The packaged Tauri application uses an explicit content security policy. The
upstream auto-update endpoint remains disabled, so maintainers of this fork are
responsible for monitoring and applying upstream security fixes. Tagged Windows
releases must be Authenticode signed; private manual artifacts may remain
unsigned and can trigger Windows SmartScreen.
