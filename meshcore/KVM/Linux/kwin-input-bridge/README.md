# Agent-owned KWin input-method bridge

The Agent installs a standard Wayland relay without a KWin plugin, private C++
ABI or compositor package patch. It preserves an existing input-method choice;
when no method is selected, it supplies an owned headless input method.

## Installation and prerequisites

Use the normal Linux Agent installer. Assets are root-owned under
`/usr/local/lib/meshagent-kwin-wire`; shared service ownership is recorded under
`/var/lib/meshagent-kwin-wire`. Session profile changes run as the desktop user.
Owned autostart/systemd hooks activate later user and greeter sessions. No
target-side compiler, KWin SDK or extra on-screen-keyboard package is required.

Authorization requires Python 3.9 or newer with `os.pidfd_open` and a kernel
supporting pidfds. Missing support fails closed; UID-only authorization is not
a fallback. The Agent parent publishes protected worker registrations under
`/run/meshagent-kwin-workers/`; do not make this directory user-writable.

Keep the Agent and installed bridge/session assets on matching versions.
Replacing only the executable does not replace an already running relay.
Uninstall restores the prior input-method choice while preserving unrelated
settings and other services' ownership. Do not manually replace owned or vendor
files to force activation. A bounded activation timeout leaves the managed
selection pending rather than claiming readiness.

## Regenerating embedded assets

```sh
node meshcore/KVM/Linux/kwin-input-bridge/generate-assets.mjs
node addons/gnome-shell/generate-installer-modules.mjs
```

Both generators accept `--check` to verify generated data matches source.
