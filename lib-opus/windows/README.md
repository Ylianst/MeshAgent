# Windows Opus libraries

`libopus.lib` is **not** committed here. It is produced during the Windows build
by `.github/workflows/windows-build.yml`, which compiles Opus from source with
the same MSVC toolchain that builds the agent, for `x86`, `x64` and `arm64`.

A static library has to come from the toolchain that consumes it. A MinGW/GCC
archive cannot be linked by MSVC — doing so fails with unresolved
`___chkstk_ms`, `__mingw_vfprintf` and `__memcpy_chk`, because those are GCC
runtime helpers that the Microsoft CRT does not provide. Committing a prebuilt
`.lib` also silently pins an Opus version that can drift from the headers in
`../includes`.

The workflow caches the built library per architecture, so it is only compiled
when the Opus version or the cache key changes.

To build locally with Visual Studio, produce the library the same way:

```powershell
# from the repository root, once per architecture (Win32 / x64 / ARM64)
curl -L -o opus.tar.gz https://downloads.xiph.org/releases/opus/opus-1.5.2.tar.gz
tar -xzf opus.tar.gz
cmake -S opus-1.5.2 -B opus-build -A x64 `
  -DOPUS_BUILD_SHARED_LIBRARY=OFF -DOPUS_BUILD_TESTING=OFF `
  -DOPUS_BUILD_PROGRAMS=OFF -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded
cmake --build opus-build --config Release --parallel
copy opus-build\Release\opus.lib lib-opus\windows\x64\libopus.lib
```

The Linux/macOS libraries under `../linux` and `../macos` are still committed:
those are built with GCC/Clang, which is also what compiles the agent there.
