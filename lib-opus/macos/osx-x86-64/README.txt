libopus for macOS x86-64 must be built on a Mac.

Build instructions:
  curl -O https://ftp.osuosl.org/pub/xiph/releases/opus/opus-1.6.1.tar.gz
  tar xzf opus-1.6.1.tar.gz
  cd opus-1.6.1
  ./configure --host=x86_64-apple-darwin \
              --enable-static --disable-shared \
              --disable-doc --disable-extra-programs \
              CFLAGS="-O2 -arch x86_64"
  make -j$(nproc)
  cp .libs/libopus.a <MeshAgent-jugu>/lib-opus/macos/osx-x86-64/libopus.a

Note: mac_audio.c requires macOS 14.4+ at runtime.
