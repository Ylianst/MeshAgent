# Linux desktop compatibility

The combinations below support remote desktop viewing, mouse and keyboard input.
**Automatic** means no extra desktop setup after installing the Agent on a normal
desktop installation. The installer manages any required companion components;
remote connections do not require a local approval prompt.

| Distribution | Desktop/session | Support and setup |
| --- | --- | --- |
| Arch Linux | GNOME 51 and KDE Plasma 6.8, Wayland | Supported; automatic. |
| Debian 13.7 | GNOME 48, KDE Plasma 6.3, Cinnamon 6.4 and labwc, Wayland | Supported; automatic. |
| Fedora 45 | GNOME (including Classic), KDE Plasma, Cinnamon, COSMIC, Sway, Budgie/labwc, Miracle WM and LXQt/Miriway, Wayland | Supported; automatic. |
| Ubuntu 26.04.1 | GNOME 50, KDE Plasma 6.6, Xfce/labwc and Budgie/labwc, Wayland | Supported; automatic. |
| Ubuntu 26.04.1 | Cinnamon, Wayland | Requires an OS fix: stock Xwayland 24.1.10 can crash the desktop even without the Agent. Works with Xwayland 24.1.11; the Agent does not install that update. Cinnamon X11 works without this change. |
| Linux Mint 22.3 | Cinnamon 6.6, Wayland; Cinnamon, MATE and Xfce, X11 | Supported; automatic. |
| LMDE 7 | Cinnamon 6.6, Wayland or X11 | Supported; automatic with current vendor packages. |
| elementary OS 8.1.1 | Pantheon Secure, Wayland | Supported; the installer may request one sign-out/sign-in to activate its companion. No separate download is required. |
| elementary OS 8.1.1 | Pantheon Classic, X11 | Supported; automatic. |
| Pop!_OS 24.04 | COSMIC, Wayland | Supported with current vendor updates. The original build-20 ISO's compositor cannot enter some Unicode characters correctly; update the OS first. |
| openSUSE Leap 16 | GNOME 48 and KDE Plasma 6.4, Wayland | Supported; automatic. |
| openSUSE Leap 16.1 | GNOME and KDE Plasma 6.6, Wayland; Xfce, X11 | Supported; automatic. |
| openSUSE Tumbleweed | GNOME 51, KDE Plasma 6.8, Sway and LXQt/labwc, Wayland; Xfce and LXQt, X11 | Supported; automatic on the listed desktop versions. |
| Zorin OS 18.1 | Core GNOME 46, Wayland or X11; Lite Xfce, X11 | Supported; automatic. |
| Rocky Linux 10.2 | GNOME 49, Wayland | Supported; automatic, including with SELinux enforcing. |
| Manjaro 26.1.3 | GNOME 50, KDE Plasma 6.7 and Xfce/labwc, Wayland; Xfce, X11 | Supported; automatic with current vendor packages. |
| Ubuntu Kylin 26.04.1 | UKUI, Wayland or X11 | X11: automatic. Wayland: systems without graphics acceleration may need software rendering enabled in the compositor; the Agent does not enable it. |
| Ubuntu 24.04.5 | MATE and Unity, X11 | Supported; automatic. |

## Things to know

- GNOME, KDE and Gala companions are installed and removed by the Agent. An
  already running desktop may need a normal sign-out/sign-in after installation
  or an update. Automatic updates do not force logout.
- KDE requires Python 3.9 or newer with `os.pidfd_open` and a kernel supporting
  pidfds. These are supplied by the normal installations listed above. Without
  them, the authenticated input bridge cannot run.
- On X11, supplementary Unicode characters such as many emoji cannot be entered
  through the keyboard-input path. Ordinary mapped keys and mouse input work.
- Native Wayland applications support out-of-layout Unicode on the listed
  sessions. Some XWayland applications remain limited to the installed keyboard
  layout; selecting the required layout may be necessary.
- Minimal/server images need the distribution's normal desktop, input and D-Bus
  packages. The Agent installer does not turn a minimal image into a desktop OS.
