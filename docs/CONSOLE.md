# GuardianMesh Parent Console

The Parent Console is the local human-friendly interface for GuardianMesh
Atlas v1.1.0. It turns the existing Trust, Vista, Aegis, Orion, Sentinel,
and Atlas subsystems into simple parent-facing screens without exposing
internal architecture.

## Architecture

```text
GuardianMesh backend (Python)
  ├── identity, pairing, trust, telemetry, alerts, audit
  ├── Vista screen authorization and session state
  ├── Aegis system-consent and Android companion boundary
  ├── Orion safe action and capability model
  └── Atlas diagnostics and release health
          │
          ▼
Local authenticated HTTP API (`127.0.0.1` only)
          │
          ▼
Parent Console static web UI (HTML/CSS/JavaScript, no build step)
```

The console uses only the Python standard library for HTTP service. There is
no cloud account, no external frontend framework, no remote server, and no
third-party analytics. UI preferences are stored locally in the GuardianMesh
data directory with `0600` permissions where supported.

## Installation

```bash
pip install -e ".[dev]"
guardian init --role parent
```

Termux users need Python, git, libffi, clang, and make as documented in
`docs/DEVELOPMENT.md`. The console does not require root, Android Studio,
Node.js, or a frontend build toolchain.

## Launching

```bash
guardian console --web
# or the explicit subcommand
guardian console web --no-open --port 8765 --host 127.0.0.1
```

Options:

- `--host`: bind host. Only `127.0.0.1`, `localhost`, or `::1` are accepted.
- `--port`: TCP port, default `8765`.
- `--no-open`: print the local URL without opening a browser.

The server prints a local URL and remains in the foreground. Press
`Ctrl+C` to stop it.

## Navigation

The UI provides persistent navigation for:

- Home
- Devices
- Screen
- Alerts
- Activity
- Settings
- About

Desktop uses a sidebar. Phone-sized windows use compact bottom navigation.

## Device management

The Devices page shows trusted devices, online/offline state, last seen,
battery/storage where available, and alert counts. Device detail pages group
information into Overview, Connection, Health, Permissions/Consent, Screen
Sharing, Recent Activity, and Advanced details.

Pairing and trust are not reimplemented by the UI. The console calls the
existing GuardianMesh pairing and trust APIs.

## Screen-sharing flow

The Screen page always shows the consent requirements before starting:

1. Parent authorization.
2. Trusted device.
3. Child approval in GuardianMesh.
4. Android `MediaProjection` system permission.

A session request can create the Vista PENDING authorization record through
the existing `ScreenController`, but the UI cannot fabricate child approval
or Android system consent. On Linux/Termux Python, the page clearly states
that the GuardianMesh Android companion is required for real capture. No
synthetic frames or fake live previews are shown.

The STOP control is visible for every active session. The backend remains the
authorization boundary.

## Consent model

The Parent Console preserves the existing model:

```text
Trust + Parent Authorization + System/Child Consent = Allowed Capability
```

For screen sharing, the existing Vista authorization and Aegis system-consent
gates remain authoritative. The frontend only displays requirements and
calls safe backend actions.

## Localization

All UI strings live in `guardianmesh/console/web/locales/`:

- English (`en`)
- Hindi (`hi`)
- Hinglish (`hinglish`)
- Portuguese (`pt`)
- French (`fr`)
- Chinese (`zh`)
- Korean (`ko`)
- Spanish (`es`)

Hinglish uses conversational phrasing rather than mechanical word-for-word
translation.

## Settings and diagnostics

Settings exposes only parent-safe preferences: language, appearance,
notifications, local retention, and session timeout information. Advanced
diagnostics call Atlas read-only checks and do not expose private keys,
database paths beyond what is necessary, secrets, or frame bytes.

## Security model

- Default bind address is loopback only.
- Requests are checked against the `Host` header.
- State-changing requests require a local session cookie and CSRF token.
- The API action surface is an allowlist. There is no shell, eval, command,
  remote-input, file, or arbitrary Orion action endpoint.
- Private keys, OTPs, passwords, tokens, and raw database files are never sent
  to the browser.
- Static responses use a restrictive Content Security Policy.
- Audit records continue to use the existing redaction system.

## Offline behavior

The console is local-first and does not depend on cloud connectivity. It
clearly displays offline state and never claims that a device is online when
recent telemetry or transport state does not support that claim.

## Troubleshooting

- **Database not initialized:** run `guardian init --role parent`.
- **Port already in use:** run `guardian console web --port 8766`.
- **Screen sharing unavailable:** install/run the GuardianMesh Android
  companion and complete the visible child/system consent flow.
- **Browser does not open:** use `--no-open` and copy the printed URL.
- **Unexpected local issue:** run `guardian doctor` and `guardian diagnostics`.

## Termux usage

```bash
pkg install python git libffi clang make
pip install -e ".[dev]"
guardian init --role parent
guardian console web --no-open --port 8765
```

Open the printed URL in the Android browser on the same parent device. The
Python/Termux process cannot perform Android screen capture by itself; that
requires the separate Aegis Android companion and system consent.
