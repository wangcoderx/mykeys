# Security Policy

MyKeys handles high-value API credentials. Do not include real API keys, vault files, passwords, screenshots containing secrets, or system-keychain exports in a vulnerability report.

## Reporting a vulnerability

Until a private reporting address is published, do not open a public issue containing exploit details. Contact the repository owner privately and include:

- the affected version and operating system;
- a minimal reproduction using synthetic credentials only;
- the expected impact and any suggested mitigation.

Compromised provider API keys must be revoked at the provider. Deleting a MyKeys vault does not revoke them.

## Supported versions

Only the latest signed release is intended to receive security fixes. Development builds and the HTML-only demo must never be used with real credentials.

