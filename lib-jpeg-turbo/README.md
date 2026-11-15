# How the libjpeg-turbo libraries in this directory were built

All libraries are libjpeg-turbo **3.2.1**, built from the official source tarball `libjpeg-turbo-3.2.1.tar.gz`
(SHA-256 `c27ad72a68da151177929aa969ae773a2da5ac2af9ce946079314fdac8cece7f`, signature checked against the project key
`0338C8D8D9FDA62CF9C421BD7EC2DBB6F4DBF434`).

The agent only uses the libjpeg API (`jpeg_create_compress()`, `jpeg_write_scanlines()` and so on), so every library is
the plain libjpeg library without the TurboJPEG API.

## Options common to every library

| Option | Value | Why |
|---|---|---|
| `ENABLE_SHARED` | `0` | The agent links statically. |
| `WITH_TURBOJPEG` | `0` | Leaves out the TurboJPEG API with its bundled zlib, libspng and image file loaders, which the agent never calls. |
| `WITH_ARITH_ENC`, `WITH_ARITH_DEC` | `0` | No browser decodes arithmetic-coded JPEG. See the note on `v80` below. |
| `REQUIRE_SIMD` | `1` | The build fails when the SIMD code cannot be built, instead of producing a slow library. |
| `NO_GETENV` (compile definition) | defined | The library does not read `JPEGMEM` or the `JSIMD_*` variables from the environment. |
| `-ffunction-sections -fdata-sections` (compile flags) | set | Every function and data item gets its own section, so the agent's link can drop the ones it does not use. |
| `CMAKE_BUILD_TYPE` | `Release` | `-O3 -DNDEBUG`. |

Not used: `WITH_JPEG7`, `WITH_SIMDE`, `WITH_PROFILE`, `WITH_FUZZ`, link-time optimization, and CPU-specific flags such as
`-march=native`. The library picks its SIMD code at run time.

## Linux and macOS

The makefile links `lib-jpeg-turbo/<os>/<arch>/libturbojpeg.a`, so each file below is the `libjpeg.a` of its build,
stored under that name.

Tools: CMake 3.31.6, gcc 14.2.0 (native, `aarch64-linux-gnu`, `arm-linux-gnueabihf`), NASM 2.16.03, clang 19.1.7 with
`llvm-ar` and `llvm-ranlib`, macOS SDK 26.5.

```bash
cmake -S libjpeg-turbo-3.2.1 -B build/<target> -DCMAKE_TOOLCHAIN_FILE=<target>.cmake -DCMAKE_BUILD_TYPE=Release \
  -DENABLE_SHARED=0 -DENABLE_STATIC=1 -DWITH_TURBOJPEG=0 -DWITH_ARITH_ENC=0 -DWITH_ARITH_DEC=0 -DREQUIRE_SIMD=1 \
  -DCMAKE_POSITION_INDEPENDENT_CODE=ON
cmake --build build/<target> -j
```

The Linux libraries are compiled against the glibc 2.24 headers of the Bootlin `2017.05-toolchains-1-1` toolchains, the
same sysroots the Linux CI build uses, so they add no libc symbol newer than glibc 2.24. Every Linux toolchain file sets:

```cmake
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR <processor>)
set(CMAKE_C_COMPILER <compiler>)
set(CMAKE_C_FLAGS_INIT "<target flags> --sysroot=<sysroot> -isystem <sysroot>/usr/include -D_FORTIFY_SOURCE=2 -fstack-protector-strong -DNO_GETENV -ffunction-sections -fdata-sections")
set(CMAKE_EXE_LINKER_FLAGS_INIT "<target flags> --sysroot=<sysroot> -B<sysroot>/usr/lib -L<sysroot>/lib -L<sysroot>/usr/lib")
set(CMAKE_ASM_NASM_COMPILER <path to nasm>)
```

| File | Processor | Compiler | Target flags | Bootlin sysroot | Extra option |
|---|---|---|---|---|---|
| `linux/x86/libturbojpeg.a` | `i386` | `gcc` | `-m32 -mtune=generic` | `x86-i686--glibc--stable` | |
| `linux/x86/v80/libturbojpeg.a` | `i386` | `gcc` | `-m32 -mtune=generic` | `x86-i686--glibc--stable` | `-DWITH_JPEG8=1` |
| `linux/x86-64/libturbojpeg.a` | `x86_64` | `gcc` | `-march=x86-64 -mtune=generic` | `x86-64-core-i7--glibc--stable` | |
| `linux/x86-64/v80/libturbojpeg.a` | `x86_64` | `gcc` | `-march=x86-64 -mtune=generic` | `x86-64-core-i7--glibc--stable` | `-DWITH_JPEG8=1` |
| `linux/arm64/libturbojpeg.a` and `linux/aarch64/libturbojpeg.a` (same file) | `aarch64` | `aarch64-linux-gnu-gcc` | none | `aarch64--glibc--stable` | |
| `linux/armhf/libturbojpeg.a` | `arm` | `arm-linux-gnueabihf-gcc` | `-marm -mcpu=arm1176jzf-s -mfpu=vfp -mfloat-abi=hard` | `armv6-eabihf--glibc--stable` | |

- `armhf` is ARMv6 code. The Neon routines are separate objects that the library only uses when the CPU reports Neon.
- libjpeg-turbo 3.2 needs GCC 12 or later, or Clang, for full-speed Neon code.
- The section flags only pay off because the makefile links the agent with `-Wl,--gc-sections`. On x86-64 this makes
  the agent 49 KB smaller than with a library built without them.
- The `v80` libraries emulate the libjpeg v8 API for build hosts whose `jpeglib.h` reports `JPEG_LIB_VERSION 80`.
  `WITH_JPEG8=1` turns arithmetic coding on again, CMake does not allow it off with that API.

The macOS toolchain files:

```cmake
set(CMAKE_SYSTEM_NAME Darwin)
set(CMAKE_SYSTEM_PROCESSOR <x86_64 or arm64>)
set(CMAKE_C_COMPILER clang)
set(CMAKE_C_COMPILER_TARGET <target>)
set(CMAKE_C_FLAGS_INIT "-DNO_GETENV -ffunction-sections -fdata-sections")
set(CMAKE_OSX_SYSROOT <path to MacOSX26.5.sdk>)
set(CMAKE_OSX_DEPLOYMENT_TARGET <version>)
set(CMAKE_OSX_ARCHITECTURES <x86_64 or arm64>)
set(CMAKE_AR llvm-ar)
set(CMAKE_RANLIB llvm-ranlib)
set(CMAKE_INSTALL_NAME_TOOL llvm-install-name-tool)
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
set(CMAKE_ASM_NASM_COMPILER <path to nasm>)
```

| File | Target | Deployment target |
|---|---|---|
| `macos/osx-x86-64/libturbojpeg.a` | `x86_64-apple-macos10.12` | `10.12` |
| `macos/osx-arm-64/libturbojpeg.a` | `arm64-apple-macos11` | `11.0` |

The macOS libraries were cross-built on Linux, with `cmake --build build/<target> --target jpeg-static`, because no
Mach-O linker was available for the test programs. The section flags change nothing in a Mach-O object: the libraries
are byte-identical with and without them, and the makefile's `-Wl,-dead_strip` works on symbols.

## Headers

`includes/jconfig.h` is the file CMake generated for the Linux and macOS builds without `WITH_JPEG8`, and
`includes/jpeglib.h`, `jmorecfg.h` and `jerror.h` come from the 3.2.1 source.

These four files are all an application needs. The library's private headers and `turbojpeg.h` are left out on purpose.

## Checks made on the libraries

- The upstream regression tests (`ctest`) pass for the six Linux builds: `x86` 191, `x86/v80` 208, `x86-64` 195,
  `x86-64/v80` 212, `arm64` 195 and `armhf` 187 tests. The two ARM builds ran under `qemu-user`.
- No library references `getenv`, and none has TurboJPEG symbols. Only the two `v80` libraries have the arithmetic coder.
- Programs linked against the Linux libraries need at most glibc 2.17.
- The macOS libraries have no test run of their own. An agent linked with them ran its KVM on an arm64 and on an
  x86-64 Mac.
