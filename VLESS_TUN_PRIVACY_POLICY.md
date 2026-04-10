# vless-tun Privacy Policy

Last updated: April 10, 2026

This Privacy Policy applies to the `vless-tun` mobile application published by Relux Works LLC (`Relux Works`, `we`, `us`, or `our`).

## Summary

`vless-tun` is a client application that lets you import or enter a VLESS configuration, establish a VPN tunnel on your device, and inspect the apparent network egress of the app. We do not provide the upstream VPN service itself. Your chosen VPN or subscription provider operates the remote servers that carry your traffic.

## Information We Process

We designed `vless-tun` to work primarily on-device.

### Information you provide in the app

The app may process information that you enter or import, including:

- subscription URLs
- VLESS connection strings
- tunnel profile names
- server hostnames, ports, SNI/server names, UUIDs, transport settings, and related tunnel configuration fields

This information is stored locally on your device so the app can reconnect to your selected tunnel profile.

### Information processed during tunnel operation

When you connect a tunnel, the app processes network data necessary to establish and maintain the VPN session, including:

- the remote VPN server address you selected
- DNS settings and routing metadata needed for tunnel operation
- traffic routed through the Android VPN interface on your device

We do not operate the remote VPN endpoint. Traffic that passes through your chosen VPN provider is subject to that provider's own privacy practices and retention policies.

### Optional network diagnostic requests

The app includes an optional egress check feature. When you use that feature, the app sends a request to a third-party IP lookup endpoint to display the current public IP address and country seen from the app's network path.

As of April 10, 2026, the Android implementation uses `ip-api.com` for this check.

### Local technical logs

The app and its networking runtime may generate local diagnostic logs on your device to support tunnel setup, runtime status, and crash troubleshooting. We do not intentionally transmit those logs to Relux Works automatically.

### Backups and device transfer

Depending on your Android system settings, app data stored on your device may be included in device backup or transfer features managed by the operating system or your platform account provider.

## What We Do Not Do

Unless we explicitly add and disclose such behavior in a later update, `vless-tun` does not:

- require you to create a Relux Works account
- collect your contacts, photos, microphone input, camera input, or location
- use advertising SDKs
- sell your personal information
- send analytics events or marketing telemetry to Relux Works servers

## Why We Process Data

We process the limited information above only to:

- store your tunnel configuration on your device
- resolve a subscription URL or direct VLESS link that you provide
- establish and maintain the VPN connection
- show connection state and optional egress diagnostics
- troubleshoot local runtime failures

## Legal Bases

Where applicable, we process data because:

- it is necessary to provide the functionality you request inside the app
- you direct the app to connect to a server or run a diagnostic check
- we have a legitimate interest in maintaining a functioning and secure application

## Sharing

We do not share your tunnel configuration with Relux Works servers.

Data may be disclosed to third parties only as required for the app to function in the way you request, for example:

- your chosen VPN or subscription provider, when you connect using their service
- the third-party IP lookup service, if you use the optional egress check
- infrastructure providers or authorities where disclosure is legally required

## Data Retention

Tunnel profiles and related configuration remain on your device until you edit them, remove them, clear the app's data, or uninstall the app. Third-party services that you use through the app may retain data under their own policies.

## Security

We use a local-storage-first design, but no software or transmission method is perfectly secure. You are responsible for choosing trustworthy VPN providers and handling your subscription links and credentials carefully.

## Children's Privacy

`vless-tun` is not directed to children.

## International Use

If you use the app outside the country where you obtained it, your data may be processed in other jurisdictions through the VPN provider, DNS resolver, network operators, or diagnostic endpoint involved in your connection.

## Changes to This Policy

We may update this Privacy Policy from time to time. We will post the updated version at the policy URL and revise the `Last updated` date.

## Contact

If you have questions about this Privacy Policy, contact:

- Relux Works LLC
- Email: ivan@relux.works
- Website: https://relux.works/
