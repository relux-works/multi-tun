# VpnService Declaration Notes

Use this note when Play Console warns:

> Please fill up all the fields in the Declaration Form.
> If your app does not require VpnService, please remove the relevant service element from the app manifest.

For the current `vless-tun` Android app, `VpnService` is required and should not be removed from the published app bundle unless the product is intentionally changed to a non-VPN app.

## Why `VpnService` is required in this app

Current implementation evidence:

- The app depends on `:platform:vpnservice` in [android/app/build.gradle.kts](/Users/alexis/src/multi-tun/android/app/build.gradle.kts:131).
- The service is declared in [android/platform/vpnservice/src/main/AndroidManifest.xml](/Users/alexis/src/multi-tun/android/platform/vpnservice/src/main/AndroidManifest.xml:5).
- The service implementation extends `android.net.VpnService` in [android/platform/vpnservice/src/main/kotlin/works/relux/vless_tun_app/platform/vpnservice/TunnelVpnService.kt](/Users/alexis/src/multi-tun/android/platform/vpnservice/src/main/kotlin/works/relux/vless_tun_app/platform/vpnservice/TunnelVpnService.kt:47).
- The app starts the foreground VPN runtime from [TunnelServiceConnector.kt](/Users/alexis/src/multi-tun/android/platform/vpnservice/src/main/kotlin/works/relux/vless_tun_app/platform/vpnservice/TunnelServiceConnector.kt:115).
- The foreground service type is resolved as `systemExempted` for Android 14+ in [TunnelForegroundServiceType.kt](/Users/alexis/src/multi-tun/android/platform/vpnservice/src/main/kotlin/works/relux/vless_tun_app/platform/vpnservice/TunnelForegroundServiceType.kt:6) and passed to `ServiceCompat.startForeground(...)` in [TunnelVpnService.kt](/Users/alexis/src/multi-tun/android/platform/vpnservice/src/main/kotlin/works/relux/vless_tun_app/platform/vpnservice/TunnelVpnService.kt:399).

This is a real device-level tunnel client, not a leftover manifest entry.

## Suggested Play Console answers

Use language close to the following when filling the declaration:

- Does the app require `VpnService`?
  Yes.
- Is VPN the app's core functionality?
  Yes.
- Reviewer description:
  `vless-tun` is a user-initiated Android VPN client. It creates a device-level TUN tunnel with Android `VpnService`, connects to a user-configured remote VLESS endpoint, and routes device traffic through that tunnel until the user disconnects it.
- Why foreground service is needed:
  The tunnel must stay active while the user is connected, show a persistent notification, and remain user-stoppable at any time.
- What the user does:
  The user opens the app, provides either an `https://` subscription source or an inline `vless://` URI, taps Connect, accepts the Android VPN consent dialog, and can later disconnect from the app.

## Google Play listing text

The Play listing should explicitly mention the VPN behavior. Suggested sentence:

`vless-tun is a user-controlled VPN client that uses Android VpnService to create a secure device-level tunnel to a remote VLESS endpoint.`

Do not hide VPN usage behind generic wording like "network helper" or "connectivity tool".

## Review video checklist

If Play asks for a policy/demo video, record these steps on a real Android device:

1. Open the app.
2. Show the tunnel source field with a real `https://` subscription or inline `vless://` URI.
3. Tap Connect.
4. Show the Android VPN consent dialog.
5. Show the app in connected state and the ongoing VPN notification.
6. Tap Disconnect.

Keep the video short and focused on the user-triggered VPN flow.

## Foreground service declaration note

For Android 14+ the service is declared as `systemExempted` in the manifest. Android's foreground-service documentation explicitly allows this type for active VPN apps configured through the system VPN settings flow.

Play Console still requires the matching foreground-service declaration in `Policy > App content` for Android 14+ submissions.

## Secure transport note

Play-facing builds should stay on secure transports only:

- `https://` is required for subscription sources.
- `vless://` inputs without secure transport metadata are rejected.
- Manual endpoints default to `security=tls`.
- `security=reality` still requires a public key.
