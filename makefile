# To built libturbojpeg.a
#
# Get the file "libjpeg-turbo-1.4.2.tar.gz", extract it. For Linux 64bit compile:
#   ./configure
# For Linux 32bit compile
#   ./configure --build=i686-pc-linux-gnu "CFLAGS=-m32" "CXXFLAGS=-m32" "LDFLAGS=-m32"
# Then do "make -j8" and get the resulting file /.libs/libturbojpeg.a
#
#
# To build MeshAgent2 on Linux you first got to download the dev libraries to compile the agent, we need x11, txt, ext and jpeg. To install, do this:
#	Using APT:
#		sudo apt-get install libx11-dev libxtst-dev libxext-dev libjpeg62-dev
#
#	Using YUM:
#		sudo yum install libX11-devel libXtst-devel libXext-devel libjpeg-devel
#
#	NOTE: If you install headers for jpeg8, you need to put the compiled .a in the v80 folder, and specify JPEGVER=v80 when building MeshAgent
#		eg: make linux ARCHID=6 JPEGVER=v80
#
#
# To build for 32 bit on 64 bit linux 
#  sudo apt-get install linux-libc-dev:i386 libc6-dev-i386 libjpeg62-dev:i386
#
# To install ARM Cross Compiler for Raspberry PI
#  sudo apt-get install libc6-armel-cross libc6-dev-armel-cross binutils-arm-linux-gnueabi libncurses5-dev gcc-arm-linux-gnueabihf
#
# Special builds:
#
#   make linux ARCHID=6 WEBLOG=1 KVM=0      # Linux x86 64 bit, with Web Logging, and KVM disabled
#   make linux ARCHID=6 DEBUG=1             # Linux x86 64 bit, with debug symbols and automated crash handling
#
# Compiling lib-turbojpeg from source, using libjpeg-turbo 1.4.2 on linux
#   64 bit JPEG8  -> ./configure --with-jpeg8 
#   64 bit JPEG62 -> ./configure
#   32 bit JPEG8  -> ./configure --with-jpeg8 --host i686-pc-linux-gnu CFLAGS='-O2 -m32' LDFLAGS=-m32
#   32 bit JPEG62 -> ./configure --host i686-pc-linux-gnu CFLAGS='-O2 -m32' LDFLAGS=-m32
#
# Cross compiling lib-turbojpeg from source, using libjpeg-turbo 1.4.2 on macOS
#   Intel Silicon macOS	->	./configure --host=x86_64-apple-darwin20.0.0 CFLAGS='-arch x86_64'
#   Apple Silicon macOS	->	./configure --host=aarch64-apple-darwin20.0.0 CFLAGS='-arch arm64'
#
#
#	NOTE: If you installed jpeg8 headers on your machine, you must specify --with-jpeg8 when building turbo jpeg, otherwise omit --with-jpeg8
#
#
#
#	Note: For ChromeOS, you need to disable rootfs verification, in order to install the meshagent service.
#		  After running the following commands, and rebooting, you should be able to install the meshagent service.
#
#			sudo su -
#			cd /usr/share/vboot/bin/
#			./make_dev_ssd.sh --remove_rootfs_verification
#		
#		The above line will return a warning, but it will tell you the boot partition number, which you 
#		will need when specifying the above command again, this time with the --partions options. Specify the number instead of (ID)
#
#			./make_dev_ssd.sh --remove_rootfs_verification --partitions ID
#			reboot
#
#		When you are ready to install the agent, you'll need to copy the binary to a path that is not marked noexec, like /usr/local,
#		so that you can execute the installer from there.
#
#
# Special Note about KVM Support on Linux: 
#    If you get an error stating that an Xauthority cannot be found, and asking if your DM is configured to use X, 
#    or if you get a black screen when connecting to the login screen, you may need to: 
#    1. Open /etc/gdm/custom.conf or /etc/gdm3/custom.conf
#    2. Uncomment: WaylandEnable=false.
#    3. Add the following line to the [daemon] section:
#       DefaultSession=gnome-xorg.desktop
#
#
# Special note about running on FreeBSD systems:
#	1. You'll need to mount procfs, which isn't mounted by default on FreeBSD. Add the following line to /etc/fstab
#		proc	/proc	procfs	rw	0	0
#	2. If you don't reboot, then you can manually mount with the command:
#		mount -t procfs proc /proc
#	3. In addition, it is recommended to install bash, which you can do with the following command:
#		pkg install bash
#	4. For KVM, my FreeBSD system was setup using X11 and KDE. KVM should work out of the box with that configuration.
#		4a. KVM is disabled by default. To build with KVM support, specify KVM=1 in when building (ie: gmake freebsd ARCHID=30 KVM=1)
#	5. Also note, that to build on FreeBSD, you must use gmake, not make.
#
#
# To build on Alpine Linux (MUSL), you'll need to install the following libraries
#	apk add build-base gcc abuild binutils linux-headers libexecinfo-dev bash binutils-doc gcc-doc
#
#
#
# Standard builds:
#
#   ARCHID=1                                # Windows Console x86 32 bit
#   ARCHID=2                                # Windows Console x86 64 bit
#   ARCHID=3                                # Windows Service x86 32 bit
#   ARCHID=4                                # Windows Service x86 64 bit
#   make macos ARCHID=16					# macOS x86 64 bit
#	make macos ARCHID=29					# macOS ARM 64 bit
#   make linux ARCHID=5						# Linux x86 32 bit
#   make linux ARCHID=6						# Linux x86 64 bit
#   make linux ARCHID=7						# Linux MIPSEL
#   make linux ARCHID=9						# Linux ARM 32 bit
#   make linux ARCHID=13					# Linux ARM 32 bit PogoPlug
#   make linux ARCHID=15					# Linux x86 32 bit POKY
#   make linux ARCHID=18					# Linux x86 64 bit POKY
#   make linux ARCHID=19					# Linux x86 32 bit NOKVM
#   make linux ARCHID=20					# Linux x86 64 bit NOKVM
#   make linux ARCHID=24 					# Linux ARM 32 bit HardFloat (Linaro)
#   make linux ARCHID=26 					# Linux ARM 64 bit
#   make linux ARCHID=32 					# Linux ARM 64 bit (glibc/2.24)
#   make linux ARCHID=27 					# Linux ARM 32 bit HardFloat NOKVM (Old Raspberry Pi on Raspian 7, 2015-02-02 build)
#   gmake freebsd ARCHID=30					# FreeBSD x86 64 bit
#   gmake freebsd ARCHID=31					# Reserved for FreeBSD x86 32 bit
#	gmake openbsd ARCHID=37					# OpenBSD x86 64 bit
#
#
# Alpine Linux (MUSL)
#	make linux ARCHID=33					# Alpine Linux x86 64 bit (MUSL)
#
# Raspberry Pi Builds:
#
#   make pi KVM=1 ARCHID=25					# Linux ARM 32 bit HardFloat, compiled on the Pi.
#	make linux ARCHID=25 CROSS=1			# Linux ARM 32 bit HardFloat, using cross compiler
#
# OpenWRT Builds:
#
#	make linux ARCHID=28					# Linux MIPS24KC/MUSL (OpenWRT)
#	make linux ARCHID=36					# Linux x86_64/MUSL (OpenWRT)
#	make linux ARCHID=40					# Linux MIPSEL24KC/MUSL (OpenWRT)
#	make linux ARCHID=41					# Linux ARMADA/CORTEX-A53/MUSL (OpenWRT)
#   make linux ARCHID=44					# Linux ARMVIRT32/MUSL (OpenWRT)
#
# RISC-V Builds:
#
#	make linux ARCHID=45					# Linux RISC-V 64 bit
#
# Synology Builds
#
#	make linux ARCHID=35					# Linux ARMADA 370 Hardfloat
#
# Windows Builds for ARCHID:
#   1 - 4 are Windows builds. please use Visual Studio to compile.
#   21 - 22 are Windows builds, please use Visual Studio to compile.
#   34 is Windows build, please use Visual Studio to compile.
#   42 - 43 are Windows builds, please use Visual Studio to compile.
# 
# Required build switches:
#	ARCHID									Architecture ID
# 
# 
# Optional build switches:
#	BIGCHAINLOCK							1 = No Compiler/Atomics support		=> Default is Compiler support present
#	DEBUG									0 = Release, 1 = DEBUG				=> Default is Release
#	FSWATCH_DISABLE							1 = Remove fswatchter support		=> Default is fswatcher supported
#	IPADDR_MONITOR_DISABLE					1 = No IPAddress Monitoring			=> Default is IPAddress Monitoring Enabled
#	IFADDR_DISABLE							1 = Don't use ifaddrs.h				=> Default is use IFADDR
#	KVM										1 = KVM Enabled, 0 = KVM Disabled   => Default depends on ARCHID
#	KVM_ALL_TILES							0 = Normal, 1 = All Tiles			=> Default is Normal Tiling Algorithm
#	LEGACY_LD								0 = Standard, 1 = Legacy			=> Default is Standard (CentOS 5.11 requires Legacy)
#	NET_SEND_FORCE_FRAGMENT					1 = net.send() fragments sends		=> Default is normal send operation
#	NOTLS									1 = TLS Support Compiled Out		=> Default is TLS Support Compiled In
#	NOTURBOJPEG								1 = Don't use Turbo JPEG			=> Default is USE TurboJPEG
#	SSL_EXPORTABLE_KEYS						1 = Export SSL Keys for debugging	=> Default is DO NOT export SSL keys
#	TLS_WRITE_TRACE							1 = Enable TLS Send Tracing			=> Default is tracing disabled
#	WatchDog								WatchDog timer interval.			=> Default is 6000000
#	WEBLOG									1 = Enable WebLogging Interface		=> Default is disabled
#	WEBRTCDEBUG								1 = Enable WebRTC Instrumentation	=> Default is disabled
#

# Microstack & Microscript
SOURCES = microstack/ILibAsyncServerSocket.c microstack/ILibAsyncSocket.c microstack/ILibAsyncUDPSocket.c microstack/ILibParsers.c microstack/ILibMulticastSocket.c
SOURCES += microstack/ILibRemoteLogging.c microstack/ILibWebClient.c microstack/ILibWebServer.c microstack/ILibCrypto.c
SOURCES += microstack/ILibSimpleDataStore.c microstack/ILibProcessPipe.c microstack/ILibIPAddressMonitor.c
SOURCES += microscript/duktape.c microscript/duk_module_duktape.c microscript/ILibDuktape_DuplexStream.c microscript/ILibDuktape_Helpers.c
SOURCES += microscript/ILibDuktape_net.c microscript/ILibDuktape_ReadableStream.c microscript/ILibDuktape_WritableStream.c
SOURCES += microscript/ILibDuktapeModSearch.c 
SOURCES += microscript/ILibDuktape_SimpleDataStore.c microscript/ILibDuktape_GenericMarshal.c
SOURCES += microscript/ILibDuktape_fs.c microscript/ILibDuktape_SHA256.c microscript/ILibduktape_EventEmitter.c
SOURCES += microscript/ILibDuktape_EncryptionStream.c microscript/ILibDuktape_Polyfills.c microscript/ILibDuktape_Dgram.c
SOURCES += microscript/ILibDuktape_ScriptContainer.c microscript/ILibDuktape_MemoryStream.c microscript/ILibDuktape_NetworkMonitor.c
SOURCES += microscript/ILibDuktape_ChildProcess.c microscript/ILibDuktape_HttpStream.c microscript/ILibDuktape_Debugger.c
SOURCES += microscript/ILibDuktape_CompressedStream.c meshcore/zlib/adler32.c meshcore/zlib/deflate.c meshcore/zlib/inffast.c meshcore/zlib/inflate.c meshcore/zlib/inftrees.c meshcore/zlib/trees.c meshcore/zlib/zutil.c

SOURCES += $(ADDITIONALSOURCES)

# Mesh Agent core
SOURCES += meshcore/agentcore.c meshconsole/main.c meshcore/meshinfo.c meshcore/version_info.c

# Mesh Agent settings
MESH_VER = 194
EXENAME ?= meshagent
BUILD_OUTPUT_DIR = build/output
BUNDLE_DISPLAY_NAME ?= MeshAgent
MODULESYNC_MODE ?= macos-only

# Cross-compiler paths
PATH_MIPS = ../ToolChains/ddwrt/3.4.6-uclibc-0.9.28/bin/
PATH_MIPS24KC = ../ToolChains/toolchain-mips_24kc_gcc-7.3.0_musl/
PATH_OPENWRT_ARMVIRT32 = ../ToolChains/staging_dir/toolchain-arm_cortex-a15+neon-vfpv4_gcc-8.4.0_musl_eabi/
PATH_MIPSEL24KC = ../ToolChains/toolchain-mipsel_24kc_gcc-7.3.0_musl/
PATH_ARM5 = ../ToolChains/LinuxArm/bin/
PATH_POGO = ../ToolChains/pogoplug-gcc/bin/
PATH_LINARO = ../ToolChains/linaro-arm/bin/
PATH_POKY = ../Galileo/arduino-1.5.3/hardware/tools/sysroots/x86_64-pokysdk-linux/usr/bin/i586-poky-linux-uclibc/
PATH_POKY64 = /opt/poky/1.6.1/sysroots/x86_64-pokysdk-linux/usr/bin/x86_64-poky-linux/
PATH_AARCH64 = ../ToolChains/aarch64--glibc--stable/
PATH_AARCH64_CORTEXA53 = ../ToolChains/toolchain-aarch64_cortex-a53_gcc-7.5.0_musl/
PATH_ARMADA370_HF = /home/dev/arm-unknown-linux-gnueabi/
PATH_RPI = ../ToolChains/arm-rpi-4.9.3-linux-gnueabihf/
PATH_OPENWRT_X86_64 = /home/dev/openwrt/staging_dir/toolchain-x86_64_gcc-7.3.0_musl/
PATH_RISCV64 = ../ToolChains/riscv64-linux-musl-x86_64/

OBJECTS = $(patsubst %.c,%.o, $(SOURCES))

# Compiler command name
CC = gcc
STRIP = strip

# Need to be separate for dependency generation	
INCDIRS = -I. -Iopenssl/include -Imicrostack -Imicroscript -Imeshcore -Imeshconsole

# Compiler and linker flags
CFLAGS ?= -std=gnu99 -g -Wall -D_POSIX -DMICROSTACK_PROXY $(CWEBLOG) $(CWATCHDOG) -fno-strict-aliasing $(INCDIRS) -DDUK_USE_DEBUGGER_SUPPORT -DDUK_USE_INTERRUPT_COUNTER -DDUK_USE_DEBUGGER_INSPECT -DDUK_USE_DEBUGGER_PAUSE_UNCAUGHT
# macOS (Darwin) doesn't have separate libutil - functions are in libSystem
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
LDFLAGS ?= -L. -lpthread -lm
else
LDFLAGS ?= -L. -lpthread -lutil -lm
endif
CEXTRA = -D_FORTIFY_SOURCE=2 -Wformat -Wformat-security -fstack-protector -fno-strict-aliasing
LDEXTRA = 

WatchDog = 6000000
KVMMaxTile = 0
SKIPFLAGS = 0
ifeq ($(AID), 7)
SKIPFLAGS = 1
endif
ifeq ($(AID), 28)
SKIPFLAGS = 1
endif
ifeq ($(AID), 9)
SKIPFLAGS = 1
endif
ifeq ($(AID), 13)
SKIPFLAGS = 1
endif
ifeq ($(AID), 25)
SKIPFLAGS = 1
endif

ifeq ($(FIPS),1)
DYNAMICTLS = 1
NOWEBRTC = 1
endif

ifeq ($(ARCHID),33)
ARCHNAME = alpine-x86-64
KVM=0
CRASH_HANDLER=0
endif

ifeq ($(ARCHID),32)
ARCHNAME = aarch64
export PATH := $(PATH_AARCH64)bin:$(PATH_AARCH64)libexec/gcc/aarch64-buildroot-linux-gnu/5.4.0:$(PATH_AARCH64)aarch64-buildroot-linux-gnu/bin:$(PATH)
export STAGING_DIR := $(PATH_AARCH64)
CC = $(PATH_AARCH64)bin/aarch64-linux-gcc 
STRIP = $(PATH_AARCH64)bin/aarch64-linux-strip
CEXTRA = -D_FORTIFY_SOURCE=2 -D_NOILIBSTACKDEBUG -D_NOFSWATCHER -Wformat -Wformat-security -fno-strict-aliasing
INCDIRS += -I$(PATH_AARCH64)include
KVM = 1
LMS = 0
endif

ifeq ($(ARCHID),41)
ARCHNAME = aarch64-cortex-a53
export PATH := $(PATH_AARCH64_CORTEXA53)bin:$(PATH_AARCH64_CORTEXA53)libexec/gcc/aarch64-openwrt-linux-musl/7.5.0:$(PATH_AARCH64_CORTEXA53)aarch64-openwrt-linux-musl/bin:$(PATH)
export STAGING_DIR := $(PATH_AARCH64_CORTEXA53)
CC = $(PATH_AARCH64_CORTEXA53)bin/aarch64-openwrt-linux-gcc
STRIP = $(PATH_AARCH64_CORTEXA53)bin/aarch64-openwrt-linux-strip
CEXTRA = -D_FORTIFY_SOURCE=2 -D_NOILIBSTACKDEBUG -D_NOFSWATCHER -Wformat -Wformat-security -fno-strict-aliasing
INCDIRS += -I$(PATH_AARCH64_CORTEXA53)include
KVM = 0
LMS = 0
endif


ifeq ($(ARCHID),35)
ARCHNAME = linux-armada370-hf
export PATH := $(PATH_ARMADA370_HF)bin:$(PATH_ARMADA370_HF)libexec/gcc/arm-unknown-linux-gnueabi/7.5.0:$(PATH_ARMADA370_HF)arm-unknown-linux-gnueabi/bin:$(PATH)
export STAGING_DIR := $(PATH_ARMADA370_HF)
CC = $(PATH_ARMADA370_HF)bin/arm-unknown-linux-gnueabi-gcc
STRIP = $(PATH_ARMADA370_HF)bin/arm-unknown-linux-gnueabi-strip
CEXTRA = -D_FORTIFY_SOURCE=2 -D_NOILIBSTACKDEBUG -D_NOFSWATCHER -Wformat -Wformat-security -fno-strict-aliasing
INCDIRS += -I$(PATH_AARCH64_CORTEXA53)include
KVM = 0
LMS = 0
endif



# Official Linux x86 32bit
ifeq ($(ARCHID),5)
ARCHNAME = x86
CC = gcc -m32
KVM = 1
LMS = 1
endif

# Official Linux x86 64bit
ifeq ($(ARCHID),6)
ARCHNAME = x86-64
KVM = 1
LMS = 1
endif

# Official macOS x86 64bit
ifeq ($(ARCHID),16)
ARCHNAME = osx-x86-64
LIBARCHNAME = macos-x86-64
KVM = 1
LMS = 0
MACOSARCH = -mmacosx-version-min=10.13
CC = gcc -arch x86_64
endif

# Official macOS ARM 64bit
ifeq ($(ARCHID),29)
ARCHNAME = osx-arm-64
LIBARCHNAME = macos-arm-64
KVM = 1
LMS = 0
MACOSARCH = -mmacosx-version-min=11.0
CC = gcc -arch arm64
endif

# Official macOS Universal 64bit (Intel + Apple Silicon)
ifeq ($(ARCHID),10005)
ARCHNAME = osx-universal-64
KVM = 1
LMS = 0
MACOSARCH = -mmacosx-version-min=11.0
# Universal binary uses lipo, no CC needed for this target
endif


# Official Linux MIPSEL
ifeq ($(ARCHID),7)
ARCHNAME = mips
CC = $(PATH_MIPS)mipsel-linux-gcc
STRIP = $(PATH_MIPS)mipsel-linux-strip
CEXTRA = -D_FORTIFY_SOURCE=2 -D_NOILIBSTACKDEBUG -D_NOFSWATCHER -Wformat -Wformat-security -fno-strict-aliasing -DILIBCHAIN_GLOBAL_LOCK
CFLAGS += -DBADMATH 
IPADDR_MONITOR_DISABLE = 1
IFADDR_DISABLE = 1
KVM = 0
LMS = 0
endif


# Official OpenWRT X86_64
ifeq ($(ARCHID),36)
ARCHNAME = openwrt_x86_64
export PATH := $(PATH_OPENWRT_X86_64)bin:$(PATH_OPENWRT_X86_64)libexec/gcc/x86_64-openwrt-linux-musl/7.3.0:$(PATH_OPENWRT_X86_64)x86_64-openwrt-linux-musl/bin:$(PATH)
export STAGING_DIR := $(PATH_OPENWRT_X86_64)
CC = $(PATH_OPENWRT_X86_64)bin/x86_64-openwrt-linux-musl-gcc --sysroot=$(PATH_OPENWRT_X86_64)
STRIP = $(PATH_OPENWRT_X86_64)bin/x86_64-openwrt-linux-musl-strip
CEXTRA = -D_FORTIFY_SOURCE=2 -D_NOILIBSTACKDEBUG -D_NOFSWATCHER -Wformat -Wformat-security -fno-strict-aliasing
CFLAGS += -DBADMATH 
INCDIRS += -I$(PATH_OPENWRT_X86_64)include
KVM = 0
LMS = 0
endif


# Official Linux MIPS24KC (OpenWRT)
ifeq ($(ARCHID),28)
ARCHNAME = mips24kc
export PATH := $(PATH_MIPS24KC)bin:$(PATH_MIPS24KC)libexec/gcc/mips-openwrt-linux-musl/7.3.0:$(PATH_MIPS24KC)mips-openwrt-linux-musl/bin:$(PATH)
export STAGING_DIR := $(PATH_MIPS24KC)
CC = $(PATH_MIPS24KC)bin/mips-openwrt-linux-musl-gcc --sysroot=$(PATH_MIPS24KC)
STRIP = $(PATH_MIPS24KC)bin/mips-openwrt-linux-musl-strip
CEXTRA = -D_FORTIFY_SOURCE=2 -D_NOILIBSTACKDEBUG -D_NOFSWATCHER -Wformat -Wformat-security -fno-strict-aliasing
CFLAGS += -DBADMATH 
INCDIRS += -I$(PATH_MIPS24KC)include

KVM = 0
LMS = 0
endif

# Official Linux MIPSEL24KC (OpenWRT)
ifeq ($(ARCHID),40)
ARCHNAME = mipsel24kc
export PATH := $(PATH_MIPSEL24KC)bin:$(PATH_MIPSEL24KC)libexec/gcc/mips-openwrt-linux-musl/7.3.0:$(PATH_MIPSEL24KC)mips-openwrt-linux-musl/bin:$(PATH)
export STAGING_DIR := $(PATH_MIPSEL24KC)
CC = $(PATH_MIPSEL24KC)bin/mipsel-openwrt-linux-musl-gcc --sysroot=$(PATH_MIPSEL24KC)
STRIP = $(PATH_MIPSEL24KC)bin/mipsel-openwrt-linux-musl-strip
CEXTRA = -D_FORTIFY_SOURCE=2 -D_NOILIBSTACKDEBUG -D_NOFSWATCHER -Wformat -Wformat-security -fno-strict-aliasing
CFLAGS += -DBADMATH 
INCDIRS += -I$(PATH_MIPSEL24KC)include

KVM = 0
LMS = 0
endif

# Official Linux ARMVIRT32 (OpenWRT)
ifeq ($(ARCHID),44)
ARCHNAME = armvirt32
export PATH := $(PATH_OPENWRT_ARMVIRT32)bin:$(PATH_OPENWRT_ARMVIRT32)libexec/gcc/arm-openwrt-linux-muslgnueabi/8.4.0:$(PATH_OPENWRT_ARMVIRT32)arm-openwrt-linux-muslgnueabi/bin:$(PATH)
export STAGING_DIR := $(PATH_OPENWRT_ARMVIRT32)
CC = $(PATH_OPENWRT_ARMVIRT32)bin/arm-openwrt-linux-gcc --sysroot=$(PATH_OPENWRT_ARMVIRT32)
STRIP = $(PATH_OPENWRT_ARMVIRT32)bin/arm-openwrt-linux-muslgnueabi-strip
CEXTRA = -D_FORTIFY_SOURCE=2 -D_NOILIBSTACKDEBUG -D_NOFSWATCHER -Wformat -Wformat-security -fno-strict-aliasing
CFLAGS += -DBADMATH 
INCDIRS += -I$(PATH_OPENWRT_ARMVIRT32)include

KVM = 0
LMS = 0
endif

# Official Linux RISC-V 64bit
ifeq ($(ARCHID),45)
ARCHNAME = riscv64
export PATH := $(PATH_RISCV64)bin:$(PATH_RISKV64)libexec/gcc/riscv64-unknown-linux-musl/10.2.0:$(PATH_RISCV64)riscv64-unknown-linux-musl/bin:$(PATH)
export STAGING_DIR := $(PATH_RISCV64)
CC = $(PATH_RISCV64)bin/riscv64-unknown-linux-musl-gcc
STRIP = $(PATH_RISCV64)bin/riscv64-unknown-linux-musl-strip
CEXTRA = -D_FORTIFY_SOURCE=2 -D_NOILIBSTACKDEBUG -D_NOFSWATCHER -Wformat -Wformat-security -fno-strict-aliasing -mcpu=c906fdv -march=rv64imafdcv0p7xthead -mcmodel=medany -mabi=lp64d
INCDIRS += -I$(PATH_RISCV64)include
KVM = 0
LMS = 0
endif

# Official Linux ARM
ifeq ($(ARCHID),9)
ARCHNAME = arm
CC = $(PATH_ARM5)arm-none-linux-gnueabi-gcc
STRIP = $(PATH_ARM5)arm-none-linux-gnueabi-strip
KVM = 0
LMS = 0
CFLAGS += -D_NOFSWATCHER 
CFLAGS += -DILIBCHAIN_GLOBAL_LOCK
CEXTRA = -fno-strict-aliasing
endif

# Official Linux PogoPlug
ifeq ($(ARCHID),13)
ARCHNAME = pogo
CC = $(PATH_POGO)arm-none-linux-gnueabi-gcc
STRIP = $(PATH_POGO)arm-none-linux-gnueabi-strip
KVM = 0
LMS = 0
CEXTRA = -D_FORTIFY_SOURCE=2 -D_NOILIBSTACKDEBUG -D_NOFSWATCHER -Wformat -Wformat-security -fno-strict-aliasing -DILIBCHAIN_GLOBAL_LOCK
endif

# Official Linux POKY
ifeq ($(ARCHID),15)
ARCHNAME = poky
CC = $(PATH_POKY)i586-poky-linux-uclibc-gcc --sysroot=../Galileo/arduino-1.5.3/hardware/tools/sysroots/i586-poky-linux-uclibc
STRIP = $(PATH_POKY)i586-poky-linux-uclibc-strip
KVM = 0
LMS = 0
CFLAGS += -D_NOFSWATCHER
CEXTRA = -D_FORTIFY_SOURCE=2 -Wformat -Wformat-security -fno-strict-aliasing
endif

# Official Linux POKY64
ifeq ($(ARCHID),18)
ARCHNAME = poky64
CC = $(PATH_POKY64)x86_64-poky-linux-gcc
STRIP = $(PATH_POKY64)x86_64-poky-linux-strip
KVM = 0
LMS = 0
CFLAGS += -D_NOFSWATCHER
#CEXTRA = -D_FORTIFY_SOURCE=2 -Wformat -Wformat-security -fno-strict-aliasing
endif

# Official Linux x86 32bit NOKVM
ifeq ($(ARCHID),19)
ARCHNAME = x86
CC = gcc -m32
KVM = 0
LMS = 1
EXENAME2=_nokvm
endif

# Official Linux x86 64bit NOKVM
ifeq ($(ARCHID),20)
ARCHNAME = x86-64
KVM = 0
LMS = 1
EXENAME2=_nokvm
endif

# Official Linux ARM 32bit HardFloat Linaro
ifeq ($(ARCHID),24)
ARCHNAME = arm-linaro
CC = $(PATH_LINARO)arm-linux-gnueabihf-gcc
STRIP = $(PATH_LINARO)arm-linux-gnueabihf-strip
KVM = 0
LMS = 0
CFLAGS += -D_NOFSWATCHER 
CEXTRA = -fno-strict-aliasing 
endif

# Official Linux ARM 32bit HardFloat
ifeq ($(ARCHID),25)
ARCHNAME = armhf
ifeq ($(CROSS),1)
	CC = $(PATH_RPI)bin/arm-linux-gnueabihf-gcc --sysroot=$(PATH_RPI)arm-linux-gnueabihf/sysroot
	STRIP = $(PATH_RPI)bin/arm-linux-gnueabihf-strip
endif
KVM = 1
LMS = 0
CEXTRA = -fno-strict-aliasing 
endif

# Official Linux ARM 64bit
ifeq ($(ARCHID),26)
ARCHNAME = arm64
#CC = arm-linux-gnueabihf-gcc
#STRIP = arm-linux-gnueabihf-strip
KVM = 1
LMS = 0
CEXTRA = -fno-strict-aliasing 
endif

# Official Linux ARM 32bit HardFloat on Raspian 7 2015-02-02
ifeq ($(ARCHID),27)
ARCHNAME = armhf2
#CC = arm-linux-gnueabihf-gcc
#STRIP = arm-linux-gnueabihf-strip
KVM = 0
LMS = 0
CFLAGS += -D_NOFSWATCHER 
CEXTRA = -fno-strict-aliasing 
endif

# Official FreeBSD x86-64
ifeq ($(ARCHID),30)
ARCHNAME = freebsd_x86-64
CC = clang
CFLAGS += -I/usr/local/include
KVM = 0
LMS = 0
endif

# Official OpenBSD x86-64
ifeq ($(ARCHID),37)
ARCHNAME = openbsd_x86-64
CC = clang
CFLAGS += -I/usr/local/include
KVM = 0
LMS = 0
endif


ifeq ($(WEBLOG),1)
CFLAGS += -D_REMOTELOGGINGSERVER -D_REMOTELOGGING
endif

# macOS utility sources (always compiled for macOS builds)
MACOSUTILSOURCES = meshcore/MacOS/mac_bundle_detection.c meshcore/MacOS/mac_tcc_detection.c meshcore/MacOS/mac_logging_utils.c meshcore/MacOS/mac_plist_utils.c meshcore/MacOS/mac_ui_helpers.m meshcore/MacOS/TCC_UI/mac_permissions_window.m meshcore/MacOS/Install_UI/mac_install_window.m meshcore/MacOS/Install_UI/mac_authorized_install.m

ifeq ($(KVM),1)
# Mesh Agent KVM, this is only included in builds that have KVM support
LINUXKVMSOURCES = meshcore/KVM/Linux/linux_kvm.c meshcore/KVM/Linux/linux_events.c meshcore/KVM/Linux/linux_tile.c meshcore/KVM/Linux/linux_compression.c
MACOSKVMSOURCES = meshcore/KVM/MacOS/mac_kvm.c meshcore/KVM/MacOS/mac_events.c meshcore/KVM/MacOS/mac_tile.c meshcore/KVM/MacOS/mac_kvm_auth.c meshcore/KVM/Linux/linux_compression.c
CFLAGS += -D_LINKVM
	ifneq ($(JPEGVER),)
		ifeq ($(LEGACY_LD),1)
			LINUXFLAGS = lib-jpeg-turbo/linux/$(ARCHNAME)/$(JPEGVER)/libturbojpeg.a
		else
			LINUXFLAGS = -l:lib-jpeg-turbo/linux/$(ARCHNAME)/$(JPEGVER)/libturbojpeg.a
		endif
		MACOSFLAGS = ./lib-jpeg-turbo/macos/$(LIBARCHNAME)/$(JPEGVER)/libturbojpeg.a
	else
		ifeq ($(NOTURBOJPEG),1)
			LINUXFLAGS = -ljpeg
		else
			ifeq ($(LEGACY_LD),1)
				LINUXFLAGS = lib-jpeg-turbo/linux/$(ARCHNAME)/libturbojpeg.a
			else
				LINUXFLAGS = -l:lib-jpeg-turbo/linux/$(ARCHNAME)/libturbojpeg.a
			endif
			MACOSFLAGS = ./lib-jpeg-turbo/macos/$(LIBARCHNAME)/libturbojpeg.a
		endif
	endif
	BSDFLAGS = /usr/local/lib/libjpeg.a
endif

ifeq ($(LMS),0)
CFLAGS += -D_NOHECI
endif

ifeq ($(WEBRTCDEBUG),1)
# Adds WebRTC Debug Interfaces
CFLAGS += -D_WEBRTCDEBUG
endif

ifneq ($(WatchDog),0)
CWATCHDOG := -DILibChain_WATCHDOG_TIMEOUT=$(WatchDog)
endif

ifeq ($(NOTLS),1)
SOURCES += microstack/nossl/sha384-512.c microstack/nossl/sha224-256.c microstack/nossl/md5.c microstack/nossl/sha1.c
CFLAGS += -DMICROSTACK_NOTLS
LINUXSSL =
MACSSL =
BSDSSL =
else
LINUXSSL = -Lopenssl/libstatic/linux/$(ARCHNAME)
MACSSL = -Lopenssl/libstatic/macos/$(LIBARCHNAME)
BSDSSL = -Lopenssl/libstatic/bsd/$(ARCHNAME)
CFLAGS += -DMICROSTACK_TLS_DETECT
LDEXTRA += -lssl -lcrypto
endif

ifeq ($(DYNAMICTLS),1)
LINUXSSL = 
MACSSL = 
BSDSSL = 
INCDIRS = -I. -I/usr/include/openssl -Imicrostack -Imicroscript -Imeshcore -Imeshconsole
endif

ifeq ($(DEBUG),1)
# Debug Build, include Symbols
CFLAGS += -g -D_DEBUG 
STRIP = $(NOECHO) $(NOOP)
SYMBOLCP = $(NOECHO) $(NOOP)
else
CFLAGS += -O2
STRIP += ./$(EXENAME)_$(ARCHNAME)$(EXENAME2)
SYMBOLCP = cp ./$(EXENAME)_$(ARCHNAME)$(EXENAME2) ./DEBUG_$(EXENAME)_$(ARCHNAME)$(EXENAME2)
endif

ifeq ($(SSL_TRACE),1)
CFLAGS += -DSSL_TRACE
endif

ifeq ($(IPADDR_MONITOR_DISABLE),1)
CFLAGS += -DNO_IPADDR_MONITOR
endif

ifeq ($(IFADDR_DISABLE),1)
CFLAGS += -DNO_IFADDR
endif

ifeq ($(FSWATCH_DISABLE),1)
CFLAGS += -D_NOFSWATCHER
endif

ifeq ($(CRASH_HANDLER),0)
CFLAGS += -D_NOILIBSTACKDEBUG
endif

ifeq ($(SSL_EXPORTABLE_KEYS),1)
CFLAGS += -D_SSL_KEYS_EXPORTABLE
endif

ifeq ($(TLS_WRITE_TRACE),1)
CFLAGS += -D_TLSLOG
endif

ifeq ($(NET_SEND_FORCE_FRAGMENT),1)
CFLAGS += -D_DEBUG_NET_FRAGMENT_SEND
endif

ifeq ($(KVM_ALL_TILES),1)
CFLAGS += -DKVM_ALL_TILES
endif

ifeq ($(BIGCHAINLOCK),1)
CFLAGS += -DILIBCHAIN_GLOBAL_LOCK
endif

ifeq ($(NOWEBRTC),1)
CFLAGS += -DNO_WEBRTC -DOLDSSL
SOURCES += microstack/ILibWebRTC.c
else
SOURCES += microstack/ILibWebRTC.c microstack/ILibWrapperWebRTC.c microscript/ILibDuktape_WebRTC.c
endif

ifeq ($(FIPS),1)
CFLAGS += -DFIPSMODE
endif

ifeq ($(MEMTRACK),1)
CFLAGS += -DILIBMEMTRACK
endif

# Skip -no-pie on macOS (Darwin) as clang warns it's unused during compilation
UNAME := $(shell uname -s)
ifneq ($(UNAME),Darwin)
GCCTEST := $(shell $(CC) meshcore/dummy.c -o /dev/null -no-pie > /dev/null 2>&1 ; echo $$? )
ifeq ($(GCCTEST),0)
LDFLAGS += -no-pie
endif
endif

GITTEST := $(shell git log -1 > /dev/null 2>&1 ; echo $$? )
ifeq ($(GITTEST),0)
$(shell echo "// This file is auto-generated, any edits may be overwritten" > microscript/ILibDuktape_Commit.h )
$(shell git log -1 | grep "Date: " | awk '{ aLen=split($$0, a, " "); printf "#define SOURCE_COMMIT_DATE \"%s-%s-%s %s%s\"\n", a[6], a[3], a[4], a[5], a[7]; }' >> microscript/ILibDuktape_Commit.h )
$(shell git log -1 --format=%H | awk '{ printf "#define SOURCE_COMMIT_HASH \"%s\"\n", $$0; }' >> microscript/ILibDuktape_Commit.h )
endif

.PHONY: all clean

all: $(EXENAME) $(LIBNAME)

$(EXENAME): $(OBJECTS)
ifeq ($(SKIPFLAGS), 1)
	$(V)$(CC) $^ $(LDFLAGS) -lrt -o $@
else
	$(V)$(CC) $^ $(LDFLAGS) $(ADDITIONALFLAGS) -o $@
endif
sign:
	strip ./$(EXENAME)
	./agent/signer/signer_linux $(EXENAME) $(shell ./$(EXENAME) -v)


clean:
	rm -f meshconsole/*.o
	rm -f microstack/*.o
	rm -f microstack/nossl/*.o
	rm -f microscript/*.o
	rm -f meshcore/*.o
	rm -f meshcore/zlib/*.o
	rm -f meshcore/KVM/Linux/*.o
	rm -f meshcore/KVM/MacOS/*.o
	rm -f meshcore/MacOS/*.o
	rm -f microlms/lms/*.o
	rm -f microlms/heci/*.o

cleanbin:
	rm -f $(EXENAME)_aarch64
	rm -f $(EXENAME)_aarch64-cortex-a53
	rm -f $(EXENAME)_alpine-x86-64
	rm -f $(EXENAME)_arm
	rm -f $(EXENAME)_armhf
	rm -f $(EXENAME)_arm-linaro
	rm -f $(EXENAME)_freebsd_x86-64
	rm -f $(EXENAME)_openbsd_x86-64
	rm -f $(EXENAME)_openwrt_x86_64
	rm -f $(EXENAME)_linux-armada370-hf
	rm -f $(EXENAME)_mips
	rm -f $(EXENAME)_mips24kc
	rm -f $(EXENAME)_mipsel24kc
	rm -f $(EXENAME)_armvirt32
	rm -f $(EXENAME)_osx-arm-64
	rm -f $(EXENAME)_osx-x86-64
	rm -f $(EXENAME)_osx-universal-64
	rm -f $(EXENAME)_pi
	rm -f $(EXENAME)_pi2
	rm -f $(EXENAME)_pogo
	rm -f $(EXENAME)_poky
	rm -f $(EXENAME)_poky64
	rm -f $(EXENAME)_x86
	rm -f $(EXENAME)_x86_nokvm
	rm -f $(EXENAME)_x86-64
	rm -f $(EXENAME)_x86-64_nokvm
	rm -f DEBUG_$(EXENAME)_aarch64
	rm -f DEBUG_$(EXENAME)_aarch64-cortex-a53
	rm -f DEBUG_$(EXENAME)_alpine-x86-64
	rm -f DEBUG_$(EXENAME)_arm
	rm -f DEBUG_$(EXENAME)_armhf
	rm -f DEBUG_$(EXENAME)_arm-linaro
	rm -f DEBUG_$(EXENAME)_freebsd_x86-64
	rm -f DEBUG_$(EXENAME)_openbsd_x86-64
	rm -f DEBUG_$(EXENAME)_openwrt_x86_64
	rm -f DEBUG_$(EXENAME)_linux-armada370-hf
	rm -f DEBUG_$(EXENAME)_mips
	rm -f DEBUG_$(EXENAME)_mips24kc
	rm -f DEBUG_$(EXENAME)_mipsel24kc
	rm -f DEBUG_$(EXENAME)_armvirt32
	rm -f DEBUG_$(EXENAME)_osx-arm-64
	rm -f DEBUG_$(EXENAME)_osx-x86-64
	rm -f DEBUG_$(EXENAME)_osx-universal-64
	rm -f DEBUG_$(EXENAME)_pi
	rm -f DEBUG_$(EXENAME)_pi2
	rm -f DEBUG_$(EXENAME)_pogo
	rm -f DEBUG_$(EXENAME)_poky
	rm -f DEBUG_$(EXENAME)_poky64
	rm -f DEBUG_$(EXENAME)_x86
	rm -f DEBUG_$(EXENAME)_x86_nokvm
	rm -f DEBUG_$(EXENAME)_x86-64
	rm -f DEBUG_$(EXENAME)_x86-64_nokvm
	rm -rf $(BUILD_OUTPUT_DIR)


depend: $(SOURCES)
	$(CC) -M $(CFLAGS) $(SOURCES) $(HEADERS) > depend

run:all
	strip ./$(EXENAME)
	./agent/signer/signer_linux $(EXENAME) $(shell ./$(EXENAME) -v)
	rm -f mtrax
	set MALLOC_TRACE=mtrax
	export MALLOC_TRACE;
	./$(EXENAME)
	mtrace ./$(EXENAME) mtrax

vrun:all
#	strip ./$(EXENAME)
#	./agent/signer/signer_linux $(EXENAME) $(shell ./$(EXENAME) -v)
	valgrind --tool=memcheck --leak-check=yes --show-reachable=yes --num-callers=20 --track-fds=yes --track-origins=yes ./mesh_linux

trace:
	mtrace ./$(EXENAME) mtrax

$(LIBNAME): $(OBJECTS) $(SOURCES)
	$(CC) $(OBJECTS) -shared -o $(LIBNAME)

# Compile on Raspberry Pi 2/3 with KVM
pi:
	@mkdir -p $(BUILD_OUTPUT_DIR)
	$(MAKE) EXENAME="meshagent_pi" CFLAGS="-std=gnu99 -g -Wall -D_POSIX -DMICROSTACK_PROXY -DMICROSTACK_TLS_DETECT -D_LINKVM $(CWEBLOG) $(CWATCHDOG) -fno-strict-aliasing $(INCDIRS) -DMESH_AGENTID=25 -D_NOFSWATCHER -D_NOHECI" ADDITIONALSOURCES="$(LINUXKVMSOURCES)" LDFLAGS="-Lopenssl/libstatic/linux/pi -lrt $(LINUXSSL) $(LINUXFLAGS) $(LDFLAGS) $(LDEXTRA) -ldl"
	strip meshagent_pi
	@mv meshagent_pi $(BUILD_OUTPUT_DIR)/meshagent_pi
	@echo "Build complete: $(BUILD_OUTPUT_DIR)/meshagent_pi"

linux:
	@mkdir -p $(BUILD_OUTPUT_DIR)/DEBUG
	$(MAKE) EXENAME="$(BUILD_OUTPUT_DIR)/DEBUG/$(EXENAME)_$(ARCHNAME)$(EXENAME2)" AID="$(ARCHID)" ADDITIONALSOURCES="$(LINUXKVMSOURCES)" ADDITIONALFLAGS="-lrt -z noexecstack -z relro -z now" CFLAGS="-DJPEGMAXBUF=$(KVMMaxTile) -DMESH_AGENTID=$(ARCHID) $(CFLAGS) $(CEXTRA)" LDFLAGS="$(LINUXSSL) $(LINUXFLAGS) $(LDFLAGS) $(LDEXTRA) -ldl"
	@if [ "$(DEBUG)" != "1" ]; then \
		cp $(BUILD_OUTPUT_DIR)/DEBUG/$(EXENAME)_$(ARCHNAME)$(EXENAME2) $(BUILD_OUTPUT_DIR)/$(EXENAME)_$(ARCHNAME)$(EXENAME2); \
		strip $(BUILD_OUTPUT_DIR)/$(EXENAME)_$(ARCHNAME)$(EXENAME2); \
		echo "Build complete: $(BUILD_OUTPUT_DIR)/$(EXENAME)_$(ARCHNAME)$(EXENAME2)"; \
	else \
		echo "Debug build complete: $(BUILD_OUTPUT_DIR)/DEBUG/$(EXENAME)_$(ARCHNAME)$(EXENAME2)"; \
	fi

# macOS build target
# Note: -sectcreate __CGPreLoginApp __cgpreloginapp /dev/null enables keyboard/mouse
# input at loginwindow (pre-login screen). This is required for remote desktop functionality
# before user login and is used by Chrome Remote Desktop, TeamViewer, etc.
# Reference: https://stackoverflow.com/questions/41429524/how-to-simulate-keyboard-and-mouse-events-using-cgeventpost-in-login-window-mac
#
# Info.plist embedding: The binary includes an embedded Info.plist with CFBundleIdentifier,
# CFBundleName, and CFBundleShortVersionString (build timestamp). For universal builds,
# the same timestamp is used for both architectures to ensure consistency.
#
# App Bundle: After building the binary, automatically creates a .app bundle in
# $(BUILD_OUTPUT_DIR)/<arch>-app/$(BUNDLE_DISPLAY_NAME).app for easy distribution and testing.
macos:
	@if [ -z "$(BUILD_TIMESTAMP)" ]; then \
		if echo "$(EXENAME)" | grep -q "code-utils"; then \
			echo "Skipping module sync for code-utils build (using minimal module set from polyfills regeneration)"; \
		else \
			./build/tools/sync-modules.sh --mode $(MODULESYNC_MODE) --verbose; \
		fi; \
		echo "Regenerating polyfills from modules_macos..."; \
		./build/tools/code-utils/macos/meshagent_code-utils -import --expandedPath="./modules_macos" --filePath="./microscript/ILibDuktape_Polyfills.c"; \
	fi
	@mkdir -p $(BUILD_OUTPUT_DIR)/DEBUG
	@if [ "$(ARCHID)" = "10005" ]; then \
		eval $$(./build/tools/generate-build-timestamp.sh); \
		echo "Building macOS Universal (Intel + Apple Silicon)..."; \
		echo "Build timestamp: $$BUILD_TIME (date: $$BUILD_DATE, time: $$BUILD_TIME_ONLY)"; \
		echo "Generating shared binary Info.plist with date: $$BUILD_DATE, time: $$BUILD_TIME_ONLY and exe name: $(EXENAME)"; \
		./build/tools/generate-info-plist.sh --output build/output/tmp_binary_Info.plist --exe-name $(EXENAME) --display-name "$(BUNDLE_DISPLAY_NAME)" --build-date $$BUILD_DATE --build-time $$BUILD_TIME_ONLY --mode binary; \
		echo "Building x86-64..."; \
		$(MAKE) clean; \
		$(MAKE) macos ARCHID=16 BUILD_TIMESTAMP=$$BUILD_TIMESTAMP BUILD_DATE=$$BUILD_DATE BUILD_TIME_ONLY=$$BUILD_TIME_ONLY EXENAME=$(EXENAME) BUNDLE_DISPLAY_NAME="$(BUNDLE_DISPLAY_NAME)" SKIP_PLIST_GEN=1; \
		echo "Building ARM64..."; \
		$(MAKE) clean; \
		$(MAKE) macos ARCHID=29 BUILD_TIMESTAMP=$$BUILD_TIMESTAMP BUILD_DATE=$$BUILD_DATE BUILD_TIME_ONLY=$$BUILD_TIME_ONLY EXENAME=$(EXENAME) BUNDLE_DISPLAY_NAME="$(BUNDLE_DISPLAY_NAME)" SKIP_PLIST_GEN=1; \
		echo "Creating universal binary..."; \
		lipo -create \
			$(BUILD_OUTPUT_DIR)/DEBUG/$(EXENAME)_osx-x86-64 \
			$(BUILD_OUTPUT_DIR)/DEBUG/$(EXENAME)_osx-arm-64 \
			-output $(BUILD_OUTPUT_DIR)/DEBUG/$(EXENAME)_osx-universal-64; \
		if [ "$(DEBUG)" != "1" ]; then \
			lipo -create \
				$(BUILD_OUTPUT_DIR)/$(EXENAME)_osx-x86-64 \
				$(BUILD_OUTPUT_DIR)/$(EXENAME)_osx-arm-64 \
				-output $(BUILD_OUTPUT_DIR)/$(EXENAME)_osx-universal-64; \
			./build/tools/macos_build/create-app-bundle.sh \
				$(BUILD_OUTPUT_DIR)/$(EXENAME)_osx-universal-64 \
				"$(BUILD_OUTPUT_DIR)/osx-universal-64-app/$(BUNDLE_DISPLAY_NAME).app" \
				$(EXENAME) \
				$$BUILD_DATE \
				$$BUILD_TIME_ONLY \
				$(EXENAME) \
				"$(BUNDLE_DISPLAY_NAME)"; \
			codesign -s - --deep $(BUILD_OUTPUT_DIR)/$(EXENAME)_osx-universal-64; \
			lipo $(BUILD_OUTPUT_DIR)/$(EXENAME)_osx-universal-64 -extract arm64 -output $(BUILD_OUTPUT_DIR)/$(EXENAME)_osx-arm-64; \
			lipo $(BUILD_OUTPUT_DIR)/$(EXENAME)_osx-universal-64 -extract x86_64 -output $(BUILD_OUTPUT_DIR)/$(EXENAME)_osx-x86-64; \
			codesign -s - --deep "$(BUILD_OUTPUT_DIR)/osx-universal-64-app/$(BUNDLE_DISPLAY_NAME).app"; \
			echo "Creating app bundle zip archive..."; \
			(cd $(BUILD_OUTPUT_DIR)/osx-universal-64-app && ditto -c -k --keepParent "$(BUNDLE_DISPLAY_NAME).app" ../$(EXENAME)_osx-universal-64-app.zip); \
			echo "  Created: $(BUILD_OUTPUT_DIR)/$(EXENAME)_osx-universal-64-app.zip"; \
			echo ""; \
			echo "---"; \
			EXPECTED_VERSION="$$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' build/output/tmp_binary_Info.plist) $$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' build/output/tmp_binary_Info.plist)"; \
			STANDALONE_VERSION=$$($(BUILD_OUTPUT_DIR)/$(EXENAME)_osx-universal-64 -fullversion 2>/dev/null || echo "ERROR"); \
			BUNDLE_VERSION=$$("$(BUILD_OUTPUT_DIR)/osx-universal-64-app/$(BUNDLE_DISPLAY_NAME).app/Contents/MacOS/$(EXENAME)" -fullversion 2>/dev/null || echo "ERROR"); \
			if [ "$$STANDALONE_VERSION" = "$$EXPECTED_VERSION" ] && [ "$$BUNDLE_VERSION" = "$$EXPECTED_VERSION" ]; then \
				echo ""; \
				echo "Regenerating FULL polyfills (all modules) for non-macOS builds..."; \
				./build/tools/code-utils/macos/meshagent_code-utils -import --expandedPath="./modules" --filePath="./microscript/ILibDuktape_Polyfills.c"; \
				echo "Full polyfills regenerated (commit ILibDuktape_Polyfills.c for Linux/BSD builds)"; \
				echo ""; \
				echo "---"; \
				echo "$$(date '+%Y-%m-%d %H:%M:%S') INFO: Successfully built version $$EXPECTED_VERSION"; \
				echo ""; \
				echo "$$(pwd)/$(BUILD_OUTPUT_DIR)/$(EXENAME)_osx-universal-64"; \
				echo "$$(pwd)/$(BUILD_OUTPUT_DIR)/osx-universal-64-app/$(BUNDLE_DISPLAY_NAME).app"; \
				echo ""; \
				echo "Cleaning up build artifact: modules_macos/"; \
				rm -rf ./modules_macos; \
			else \
				echo "$$(date '+%Y-%m-%d %H:%M:%S') ERROR: Build failed - version verification mismatch"; \
				echo "Expected version: $$EXPECTED_VERSION"; \
				echo "Standalone binary version: $$STANDALONE_VERSION"; \
				echo "Bundle binary version: $$BUNDLE_VERSION"; \
				exit 1; \
			fi; \
		else \
			echo "Debug build complete: $(BUILD_OUTPUT_DIR)/DEBUG/$(EXENAME)_osx-universal-64"; \
		fi; \
	else \
		if [ -z "$(BUILD_TIMESTAMP)" ]; then \
			eval $$(./build/tools/generate-build-timestamp.sh); \
		else \
			BUILD_TIME=$(BUILD_TIMESTAMP); \
			if [ -z "$(BUILD_DATE)" ]; then \
				BUILD_DATE=$$(echo $$BUILD_TIME | cut -d. -f1-3); \
			else \
				BUILD_DATE=$(BUILD_DATE); \
			fi; \
			if [ -z "$(BUILD_TIME_ONLY)" ]; then \
				BUILD_TIME_ONLY=$$(echo $$BUILD_TIME | cut -d. -f4-6); \
			else \
				BUILD_TIME_ONLY=$(BUILD_TIME_ONLY); \
			fi; \
		fi; \
		if [ "$(SKIP_PLIST_GEN)" != "1" ]; then \
			echo "Generating binary Info.plist with date: $$BUILD_DATE, time: $$BUILD_TIME_ONLY and exe name: $(EXENAME)"; \
			./build/tools/generate-info-plist.sh --output build/output/tmp_binary_Info.plist --exe-name $(EXENAME) --display-name "$(BUNDLE_DISPLAY_NAME)" --build-date $$BUILD_DATE --build-time $$BUILD_TIME_ONLY --mode binary; \
		fi; \
		$(MAKE) $(MAKEFILE) EXENAME="$(BUILD_OUTPUT_DIR)/DEBUG/$(EXENAME)_$(ARCHNAME)" ADDITIONALSOURCES="$(MACOSKVMSOURCES) $(MACOSUTILSOURCES)" CFLAGS="$(MACOSARCH) -std=gnu99 -Wall -DJPEGMAXBUF=$(KVMMaxTile) -DMESH_AGENTID=$(ARCHID) -D_POSIX -D_NOILIBSTACKDEBUG -D_NOHECI -DMICROSTACK_PROXY -D__APPLE__ $(CWEBLOG) -fno-strict-aliasing -fobjc-arc $(INCDIRS) $(CFLAGS) $(CEXTRA)" LDFLAGS="$(MACOSARCH) -Wl,-w $(MACSSL) $(MACOSFLAGS) -lz -lsqlite3 -sectcreate __CGPreLoginApp __cgpreloginapp /dev/null -sectcreate __TEXT __info_plist build/output/tmp_binary_Info.plist -framework IOKit -framework ApplicationServices -framework SystemConfiguration -framework CoreServices -framework CoreGraphics -framework CoreFoundation -framework Security -framework Cocoa -fconstant-cfstrings $(LDFLAGS) $(LDEXTRA)"; \
		if [ "$(DEBUG)" != "1" ]; then \
			cp $(BUILD_OUTPUT_DIR)/DEBUG/$(EXENAME)_$(ARCHNAME) $(BUILD_OUTPUT_DIR)/$(EXENAME)_$(ARCHNAME); \
			strip $(BUILD_OUTPUT_DIR)/$(EXENAME)_$(ARCHNAME); \
			./build/tools/macos_build/create-app-bundle.sh \
				$(BUILD_OUTPUT_DIR)/$(EXENAME)_$(ARCHNAME) \
				"$(BUILD_OUTPUT_DIR)/$(ARCHNAME)-app/$(BUNDLE_DISPLAY_NAME).app" \
				$(EXENAME) \
				$$BUILD_DATE \
				$$BUILD_TIME_ONLY \
				$(EXENAME) \
				"$(BUNDLE_DISPLAY_NAME)"; \
			codesign -s - --deep "$(BUILD_OUTPUT_DIR)/$(ARCHNAME)-app/$(BUNDLE_DISPLAY_NAME).app"; \
			echo "Creating app bundle zip archive..."; \
			(cd $(BUILD_OUTPUT_DIR)/$(ARCHNAME)-app && ditto -c -k --keepParent "$(BUNDLE_DISPLAY_NAME).app" ../$(EXENAME)_$(ARCHNAME)-app.zip); \
			echo "  Created: $(BUILD_OUTPUT_DIR)/$(EXENAME)_$(ARCHNAME)-app.zip"; \
			echo ""; \
			echo "---"; \
			EXPECTED_VERSION="$$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' build/output/tmp_binary_Info.plist) $$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' build/output/tmp_binary_Info.plist)"; \
			STANDALONE_VERSION=$$($(BUILD_OUTPUT_DIR)/$(EXENAME)_$(ARCHNAME) -fullversion 2>/dev/null || echo "ERROR"); \
			BUNDLE_VERSION=$$("$(BUILD_OUTPUT_DIR)/$(ARCHNAME)-app/$(BUNDLE_DISPLAY_NAME).app/Contents/MacOS/$(EXENAME)" -fullversion 2>/dev/null || echo "ERROR"); \
			if [ "$$STANDALONE_VERSION" = "$$EXPECTED_VERSION" ] && [ "$$BUNDLE_VERSION" = "$$EXPECTED_VERSION" ]; then \
				echo ""; \
				echo "Regenerating FULL polyfills (all modules) for non-macOS builds..."; \
				./build/tools/code-utils/macos/meshagent_code-utils -import --expandedPath="./modules" --filePath="./microscript/ILibDuktape_Polyfills.c"; \
				echo "Full polyfills regenerated (commit ILibDuktape_Polyfills.c for Linux/BSD builds)"; \
				echo ""; \
				echo "$$(date '+%Y-%m-%d %H:%M:%S') INFO: Successfully built version $$EXPECTED_VERSION"; \
				echo ""; \
				echo "$$(pwd)/$(BUILD_OUTPUT_DIR)/$(EXENAME)_$(ARCHNAME)"; \
				echo "$$(pwd)/$(BUILD_OUTPUT_DIR)/$(ARCHNAME)-app/$(BUNDLE_DISPLAY_NAME).app"; \
				echo ""; \
				echo "Cleaning up build artifact: modules_macos/"; \
				rm -rf ./modules_macos; \
			else \
				echo "$$(date '+%Y-%m-%d %H:%M:%S') ERROR: Build failed - version verification mismatch"; \
				echo "Expected version: $$EXPECTED_VERSION"; \
				echo "Standalone binary version: $$STANDALONE_VERSION"; \
				echo "Bundle binary version: $$BUNDLE_VERSION"; \
				exit 1; \
			fi; \
		else \
			echo "Debug build complete: $(BUILD_OUTPUT_DIR)/DEBUG/$(EXENAME)_$(ARCHNAME)"; \
		fi; \
	fi

# Sign macOS application bundle (works with any .app in output directory)
# Usage: make macos-sign-bundle BUNDLE_PATH=build/output/osx-arm-64-app/MeshAgent.app
macos-sign-bundle:
	@if [ -z "$(MACOS_SIGN_CERT)" ]; then \
		echo "Error: MACOS_SIGN_CERT environment variable not set"; \
		echo "Please set it to your Developer ID Application certificate"; \
		echo "Example: export MACOS_SIGN_CERT=\"Developer ID Application: Name (TEAMID)\""; \
		exit 1; \
	fi
	@if [ -z "$(BUNDLE_PATH)" ]; then \
		echo "Error: BUNDLE_PATH not specified"; \
		echo "Usage: make macos-sign-bundle BUNDLE_PATH=build/output/osx-arm-64-app/MeshAgent.app"; \
		exit 1; \
	fi
	@if [ ! -d "$(BUNDLE_PATH)" ]; then \
		echo "Error: Bundle not found: $(BUNDLE_PATH)"; \
		exit 1; \
	fi
	@echo "Signing bundle: $(BUNDLE_PATH)"
	@./build/tools/macos_build/sign-app-bundle.sh $(BUNDLE_PATH)

# Notarize macOS application bundle (requires signed bundle)
# Usage: make macos-notarize-bundle BUNDLE_PATH=build/output/osx-arm-64-app/MeshAgent.app
macos-notarize-bundle:
	@if [ -z "$(BUNDLE_PATH)" ]; then \
		echo "Error: BUNDLE_PATH not specified"; \
		echo "Usage: make macos-notarize-bundle BUNDLE_PATH=build/output/osx-arm-64-app/MeshAgent.app"; \
		exit 1; \
	fi
	@if [ ! -d "$(BUNDLE_PATH)" ]; then \
		echo "Error: Bundle not found: $(BUNDLE_PATH)"; \
		exit 1; \
	fi
	@echo "Notarizing bundle: $(BUNDLE_PATH)"
	@./build/tools/macos_build/notarize-app-bundle.sh $(BUNDLE_PATH)

freebsd:
	@mkdir -p $(BUILD_OUTPUT_DIR)/DEBUG
	$(MAKE) EXENAME="$(BUILD_OUTPUT_DIR)/DEBUG/$(EXENAME)_$(ARCHNAME)$(EXENAME2)" ADDITIONALSOURCES="$(LINUXKVMSOURCES)"  AID="$(ARCHID)" CFLAGS="-std=gnu99 -Wall -DJPEGMAXBUF=$(KVMMaxTile) -DMESH_AGENTID=$(ARCHID) -D_POSIX -D_FREEBSD -D_NOHECI -D_NOILIBSTACKDEBUG -DMICROSTACK_PROXY -fno-strict-aliasing $(INCDIRS) $(CFLAGS) $(CEXTRA)" LDFLAGS="$(BSDSSL) $(BSDFLAGS) -L. -lpthread -ldl -lz -lutil $(LDFLAGS) $(LDEXTRA)"
	@if [ "$(DEBUG)" != "1" ]; then \
		cp $(BUILD_OUTPUT_DIR)/DEBUG/$(EXENAME)_$(ARCHNAME)$(EXENAME2) $(BUILD_OUTPUT_DIR)/$(EXENAME)_$(ARCHNAME)$(EXENAME2); \
		strip $(BUILD_OUTPUT_DIR)/$(EXENAME)_$(ARCHNAME)$(EXENAME2); \
		echo "Build complete: $(BUILD_OUTPUT_DIR)/$(EXENAME)_$(ARCHNAME)$(EXENAME2)"; \
	else \
		echo "Debug build complete: $(BUILD_OUTPUT_DIR)/DEBUG/$(EXENAME)_$(ARCHNAME)$(EXENAME2)"; \
	fi

openbsd:
	@mkdir -p $(BUILD_OUTPUT_DIR)/DEBUG
	$(MAKE) EXENAME="$(BUILD_OUTPUT_DIR)/DEBUG/$(EXENAME)_$(ARCHNAME)$(EXENAME2)" ADDITIONALSOURCES="$(LINUXKVMSOURCES)"  AID="$(ARCHID)" CFLAGS="-std=gnu99 -Wall -DJPEGMAXBUF=$(KVMMaxTile) -DMESH_AGENTID=$(ARCHID) -D_POSIX -D_FREEBSD -D_OPENBSD -DILIB_NO_TIMEDJOIN -D_NOHECI -D_NOILIBSTACKDEBUG -DMICROSTACK_PROXY -fno-strict-aliasing $(INCDIRS) $(CFLAGS) $(CEXTRA)" LDFLAGS="$(BSDSSL) $(BSDFLAGS) -L. -lpthread -lz -lutil $(LDFLAGS) $(LDEXTRA)"
	@if [ "$(DEBUG)" != "1" ]; then \
		cp $(BUILD_OUTPUT_DIR)/DEBUG/$(EXENAME)_$(ARCHNAME)$(EXENAME2) $(BUILD_OUTPUT_DIR)/$(EXENAME)_$(ARCHNAME)$(EXENAME2); \
		strip $(BUILD_OUTPUT_DIR)/$(EXENAME)_$(ARCHNAME)$(EXENAME2); \
		echo "Build complete: $(BUILD_OUTPUT_DIR)/$(EXENAME)_$(ARCHNAME)$(EXENAME2)"; \
	else \
		echo "Debug build complete: $(BUILD_OUTPUT_DIR)/DEBUG/$(EXENAME)_$(ARCHNAME)$(EXENAME2)"; \
	fi

# Organize modules into platform-specific directories
organize-modules:
	@echo "Organizing MeshAgent modules into platform-specific directories..."
	@bash ./bin/organize_modules.sh

# Build TCC UI test window (macOS only)
tcc_ui_test:
	@echo "Building TCC Permissions UI Test..."
	clang -o meshcore/MacOS/TCC_UI/tcc_ui_test \
		meshcore/MacOS/TCC_UI/test_window.c \
		meshcore/MacOS/TCC_UI/mac_permissions_window.m \
		meshcore/MacOS/mac_tcc_detection.c \
		-framework Cocoa \
		-framework CoreFoundation \
		-framework ApplicationServices \
		-framework CoreGraphics \
		-lsqlite3 \
		-fobjc-arc
	@echo "Build complete. Run with: ./meshcore/MacOS/TCC_UI/tcc_ui_test"

