# GNOME attached-console companion

GNOME Shell loads this Agent-owned component for composed capture and native
input. Network transport and JPEG encoding remain in the Agent.

## Build and installation

The three Shell payload files are embedded in the Linux Agent. After editing
them, regenerate the payload and embedded installer modules:

```sh
node addons/gnome-shell/generate-assets.mjs
node addons/gnome-shell/generate-installer-modules.mjs
```

The ordinary Agent installer installs and activates owned companion files.
Do not overwrite package-owned or unmanaged extensions. The installer uses
root-owned system extension storage, hashes and per-service ownership records;
updates and uninstall preserve other services' leases and refuse modified files.
The installer also prepares future user sessions and the GDM greeter through
owned startup hooks rather than editing vendor Shell/GDM files.

An already running Shell may need a normal sign-out/sign-in to load changed
code. The interactive installer offers a session-refresh choice when required;
declining leaves activation pending. Automatic updates and remote connections
do not force logout. Successful file installation alone does not imply that
the current Shell has loaded the component.

Use the system's stock GNOME Shell/GJS and GLib APIs. No target-side compiler or
replacement GNOME/Mutter package is required. Keep the Agent and its generated
companion payload on matching versions. Do not enable the component inside a
nested or headless Shell as a substitute for the attached console.

Both generators accept `--check` to verify generated data matches source.
