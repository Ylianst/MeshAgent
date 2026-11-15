# Static Windows OpenSSL

`MeshService-2022.vcxproj` builds x64 and Win32 with OpenSSL **3.5.9 LTS**, source
archive SHA-256 `603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a`.
ARM64 and other unmigrated build targets retain the existing Windows libraries.

The build downloads verified upstream source and private copies of Strawberry
Perl 5.42.3.1 and NASM 3.02. These tools stay in the private build cache.
Cache/output is under `.build/windows-openssl/<compiler>/<arch>/<configuration>`.
Libraries and headers use the same compiler, architecture and static CRT as the
Agent. Assembly routines select supported CPU features at runtime; neither
AVX2 nor AES-NI is imposed as a global compiler requirement.

Configuration enables assembly and uses `no-shared no-module no-dso no-engine`.
Providers needed by OpenSSL are built in. The existing Windows system-library dependencies
remain. TLS certificate validation and CPU-feature dispatch use the library's
standard behavior.

Build from the normal solution, or run:

```powershell
powershell.exe -NoProfile -File openssl/windows/build.ps1 -Architecture x64 -Configuration Release
```

Visual Studio C++ tools, Windows SDK, network access on the first build, and
enough local disk space for the dependency cache are required. The recipe hash
isolates changed build recipes and records completed installs. Do not commit
the cache or generated binaries.

See [the upstream release](https://www.openssl-library.org/source/) and
[Windows build notes](https://github.com/openssl/openssl/blob/openssl-3.5.9/NOTES-WINDOWS.md).
The upstream OpenSSL license is included beside this file.
