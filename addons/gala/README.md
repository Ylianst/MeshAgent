# Gala text companion

The Linux build embeds the Agent-owned Gala addition for out-of-layout Unicode
in Pantheon Secure/Wayland. Classic/X11 retains the existing input path.

## Build and installation

The normal Linux make target builds the addition and its installer helper with
the selected target compiler. The included `glib-abi.h` avoids a desktop SDK
dependency in cross builds. Target systems use their installed Gala, Clutter,
GLib/GIO, Gtk 3 and systemd libraries; no target-side compiler is required.

The Agent installer manages `libmeshagent-console.so` in the existing Gala
plugin directory. Do not replace vendor packages or install it over unmanaged
files. Installation and updates validate file ownership and hashes and preserve
leases held by other Agent services. Uninstall removes only unchanged owned
files after the final service releases them.

If an existing Secure session needs to reload the addition, the interactive
installer offers Later or Sign Out. Sign Out requests normal logout and respects
application inhibitors. Automatic updates and remote connections do not request
logout. Classic sessions can activate the addition on their next Secure sign-in.

Verify the embedded installer modules with:

```sh
node addons/gnome-shell/generate-installer-modules.mjs --check
```

## License

`console.c` and `glib-abi.h` are GPL-3.0-or-later; see `COPYING`. Source must
accompany distribution of the embedded addition under that license. The Agent
transport, ownership store and installer helper remain Apache-2.0.
