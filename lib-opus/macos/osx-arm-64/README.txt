libopus for macOS ARM64 (Apple Silicon) must be built on a Mac.

Build instructions:
  curl -O https://ftp.osuosl.org/pub/xiph/releases/opus/opus-1.6.1.tar.gz
  tar xzf opus-1.6.1.tar.gz
  cd opus-1.6.1
  ./configure --host=aarch64-apple-darwin \
              --enable-static --disable-shared \
              --disable-doc --disable-extra-programs \
              CFLAGS="-O2 -arch arm64"
  make -j$(nproc)
  cp .libs/libopus.a <MeshAgent-jugu>/lib-opus/macos/osx-arm-64/libopus.a

Note: mac_audio.c requires macOS 14.4+ at runtime.
