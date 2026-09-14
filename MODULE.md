# Privacy Audit

On-TV process, microphone-device and network metadata inspection with an optional bounded local event log.

## Prerequisites

Install only on a TV you own with existing owner-controlled unjailed root and Unknown Core supporting maintenance/dependency contracts. Keep independent recovery access. Review this ZIP's source and license before activation. No rooting method or LG login is included.

## Install and Use

Build with the workspace Build.cmd or npm run build. Install this ZIP using Core's Install screen, then enable it. Open this module's settings in Core or Home's Module Apps view. Existing legacy settings are adopted when present; a fresh installation does not silently enable protections or listeners. Maintenance runs about once per minute while Core's monitor is healthy.

## Disable, Restore and Limits

This is sampled metadata, not an audit of literally everything the TV does. A missing observation is not proof of inactivity. Network/app indicators are not evidence of actual proxy abuse. Recording is off by default on a fresh installation. Disabling stops sampling without removing retained logs.

Migration claims remain under /var/lib/unknown-home/core-owners after disabling or removing a module so a compatible legacy guardian cannot silently reactivate it. Configuration and recovery state are retained. A legacy guardian that does not recognize these claims must be migrated or stopped explicitly first.

## Audit and Responsibility

View current status and Check module health show this module's observations. Core Audit independently verifies packaged file hashes and records lifecycle failures. Neither a checksum nor a successful health check guarantees safety or universal model support. Unsupported states must remain visible. This is owner-installed software for privacy, transparency and local device control, not unauthorized access or surveillance. MIT warranty/liability limitations apply to the extent permitted by law.

Attribution: Unknown Digital and Unknown Suite contributors.
