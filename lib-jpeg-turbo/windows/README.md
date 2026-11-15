# Windows JPEG encoder dependency

Windows x64 and Win32 builds of `MeshAgent-2022.sln` use libjpeg-turbo 3.2.1,
statically linked through its libjpeg API. ARM64 and the legacy solution retain
GDI+. GDI+ also remains the runtime fallback and the PNG/TIFF encoder.

`windows-jpeg.props` builds the codec from the included, unmodified official source
archive using the selected Visual Studio compiler and matching /MT or /MTd CRT.
Generated files live under
`.build/windows-jpeg/<compiler>/<architecture>/<configuration>/`.
Visual Studio's C++ CMake tools, PowerShell 5.1+, and Windows tar are build prerequisites.
The first build downloads a private copy of NASM 3.02. Source and assembler archives
are SHA-256 checked before extraction. Build tools stay in the private cache.

Source: https://github.com/libjpeg-turbo/libjpeg-turbo/releases/tag/3.2.1

- `libjpeg-turbo-3.2.1.tar.gz`: `c27ad72a68da151177929aa969ae773a2da5ac2af9ce946079314fdac8cece7f`
- `nasm-3.02-win64.zip`: `161d0bfaff53c2f9e9f3e69fd0672323ebabafd1268976a5cec11be92a19aee7`

The source archive digest was checked against the upstream GitHub release asset's
digest. Public headers are copied unchanged from that release; `jconfig.h` is the
upstream-generated Windows configuration shared by the x86/x64 builds.
Retain `LICENSE.md` and `README.ijg` with redistributed binaries; the archive also
contains all upstream notices and sources. NASM is a build tool only.

Manual build:

```powershell
powershell -NoProfile -File lib-jpeg-turbo/windows/build.ps1 -Architecture x64 -Configuration Release
```

Repeat with `x86` and/or `Debug` as required. Cache paths separate compiler,
architecture and CRT configuration. Remove the relevant ignored cache directory
to request a clean rebuild.
