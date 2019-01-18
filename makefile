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
#		sudo apt-get install libx11-dev libxtst-dev libxext-dev libjpeg-dev
#
#	Using YUM:
#		sudo yum install libX11-devel libXtst-devel libXext-devel libjpeg-devel
#
#	NOTE: If you install headers for jpeg8, you need to put the headers in the v80 folder, and specify JPEGVER=v80 when building MeshAgent
#		eg: make linux ARCHID=6 JPEGVER=v80
#
#
# To build for 32 bit on 64 bit linux
#  sudo apt-get install linux-libc-dev:i386
#
# To install ARM Cross Compiler for Raspberry PI
#  sudo apt-get install libc6-armel-cross libc6-dev-armel-cross binutils-arm-linux-gnueabi libncurses5-dev gcc-arm-linux-gnueabihf
#
# Special builds:
#
#   make linux ARCHID=6 WEBLOG=1 KVM=0      # Linux x86 64 bit, with Web Logging, and KVM disabled
#   make linux ARCHID=6 DEBUG=1             # Linux x86 64 bit, with debug symbols and automated crash handling
#
# Compiling lib-turbojpeg from source, using libjpeg-turbo 1.4.2
#  64 bit-> ./configure --with-jpeg8 
#  32 bit-> ./configure --with-jpeg8 --host i686-pc-linux-gnu CFLAGS='-O3 -m32' LDFLAGS=-m32
#	NOTE: If you installed jpeg8 headers on your machine, you must specify --with-jpeg8 when building turbo jpeg, otherwise omit --with-jpeg8
#
# Standard builds
#
#   ARCHID=1                                # Windows Console x86 32 bit
#   ARCHID=2                                # Windows Console x86 64 bit
#   ARCHID=3                                # Windows Service x86 32 bit
#   ARCHID=4                                # Windows Service x86 64 bit
#	make macos ARCHID=16					# Mac OS x86 64 bit
#   make linux ARCHID=5						# Linux x86 32 bit
#   make linux ARCHID=6						# Linux x86 64 bit
#   make linux ARCHID=7						# Linux MIPS
#   make linux ARCHID=9						# Linux ARM 32 bit
#   make linux ARCHID=13					# Linux ARM 32 bit PogoPlug
#   make linux ARCHID=15					# Linux x86 32 bit POKY
#   make linux ARCHID=18					# Linux x86 64 bit POKY
#   make linux ARCHID=19					# Linux x86 32 bit NOKVM
#   make linux ARCHID=20					# Linux x86 64 bit NOKVM
#   make linux ARCHID=24 					# Linux ARM 32 bit HardFloat (Linaro)
#   make linux ARCHID=25 					# Linux ARM 32 bit HardFloat (Raspberry Pi, etc)
#   make pi KVM=1 ARCHID=25					# Linux ARM 32 bit HardFloat, compiled on the Pi.
#

# Microstack & Microscript
SOURCES = microstack/ILibAsyncServerSocket.c microstack/ILibAsyncSocket.c microstack/ILibAsyncUDPSocket.c microstack/ILibParsers.c microstack/ILibMulticastSocket.c
SOURCES += microstack/ILibRemoteLogging.c microstack/ILibWebClient.c microstack/ILibWebRTC.c microstack/ILibWebServer.c microstack/ILibCrypto.c
SOURCES += microstack/ILibWrapperWebRTC.c microstack/ILibSimpleDataStore.c microstack/ILibProcessPipe.c microstack/ILibIPAddressMonitor.c
SOURCES += microscript/duktape.c microscript/duk_module_duktape.c microscript/ILibDuktape_DuplexStream.c microscript/ILibDuktape_Helpers.c
SOURCES += microscript/ILibDuktape_http.c microscript/ILibDuktape_net.c microscript/ILibDuktape_ReadableStream.c microscript/ILibDuktape_WritableStream.c
SOURCES += microscript/ILibDuktapeModSearch.c microscript/ILibParsers_Duktape.c microscript/ILibDuktape_WebRTC.c
SOURCES += microscript/ILibWebServer_Duktape.c microscript/ILibDuktape_SimpleDataStore.c microscript/ILibDuktape_GenericMarshal.c
SOURCES += microscript/ILibDuktape_fs.c microscript/ILibDuktape_SHA256.c microscript/ILibduktape_EventEmitter.c
SOURCES += microscript/ILibDuktape_EncryptionStream.c microscript/ILibDuktape_Polyfills.c microscript/ILibDuktape_Dgram.c
SOURCES += microscript/ILibDuktape_ScriptContainer.c microscript/ILibDuktape_MemoryStream.c microscript/ILibDuktape_NetworkMonitor.c
SOURCES += microscript/ILibDuktape_ChildProcess.c microscript/ILibDuktape_HECI.c microscript/ILibDuktape_HttpStream.c microscript/ILibDuktape_Debugger.c
SOURCES += $(ADDITIONALSOURCES)

# Mesh Agent core
SOURCES += meshcore/agentcore.c meshconsole/main.c meshcore/meshinfo.c

# Mesh Agent settings
MESH_VER = 194
EXENAME = meshagent

# Cross-compiler paths
PATH_MIPS = ../ToolChains/ddwrt/3.4.6-uclibc-0.9.28/bin/
PATH_ARM5 = ../ToolChains/LinuxArm/bin/
PATH_POGO = ../ToolChains/pogoplug-gcc/bin/
PATH_LINARO = ../ToolChains/linaro-arm/bin/
PATH_POKY = ../Galileo/arduino-1.5.3/hardware/tools/sysroots/x86_64-pokysdk-linux/usr/bin/i586-poky-linux-uclibc/
PATH_POKY64 = /opt/poky/1.6.1/sysroots/x86_64-pokysdk-linux/usr/bin/x86_64-poky-linux/

OBJECTS = $(patsubst %.c,%.o, $(SOURCES))

# Compiler command name
CC = gcc
STRIP = strip

# Need to be separate for dependency generation	
INCDIRS = -I. -Iopenssl/include -Imicrostack -Imicroscript -Imeshcore -Imeshconsole

# Compiler and linker flags
CFLAGS ?= -std=gnu99 -g -Wall -D_POSIX -DMICROSTACK_PROXY $(CWEBLOG) $(CWATCHDOG) -fno-strict-aliasing $(INCDIRS) -DDUK_USE_DEBUGGER_SUPPORT -DDUK_USE_INTERRUPT_COUNTER -DDUK_USE_DEBUGGER_INSPECT -DDUK_USE_DEBUGGER_PAUSE_UNCAUGHT
LDFLAGS ?= -L. -lpthread -ldl -lutil -lm
CEXTRA = -D_FORTIFY_SOURCE=2 -Wformat -Wformat-security -fstack-protector -fno-strict-aliasing
LDEXTRA = 


SKIPFLAGS = 0
ifeq ($(AID), 7)
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

# Official MacOS x86 64bit
ifeq ($(ARCHID),16)
ARCHNAME = osx-x86-64
KVM = 1
LMS = 0
endif

# Official Linux MIPS
ifeq ($(ARCHID),7)
ARCHNAME = mips
CC = $(PATH_MIPS)mipsel-linux-gcc
STRIP = $(PATH_MIPS)mipsel-linux-strip
CEXTRA = -D_FORTIFY_SOURCE=2 -D_NOILIBSTACKDEBUG -D_NOFSWATCHER -Wformat -Wformat-security -fno-strict-aliasing
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
CEXTRA = -fno-strict-aliasing
endif

# Official Linux PogoPlug
ifeq ($(ARCHID),13)
ARCHNAME = pogo
CC = $(PATH_POGO)arm-none-linux-gnueabi-gcc
STRIP = $(PATH_POGO)arm-none-linux-gnueabi-strip
KVM = 0
LMS = 0
CEXTRA = -D_FORTIFY_SOURCE=2 -D_NOILIBSTACKDEBUG -D_NOFSWATCHER -Wformat -Wformat-security -fno-strict-aliasing
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
CC = arm-linux-gnueabihf-gcc
STRIP = arm-linux-gnueabihf-strip
KVM = 1
LMS = 0
CFLAGS += -D_NOFSWATCHER 
CEXTRA = -fno-strict-aliasing 
endif

ifeq ($(WEBLOG),1)
CFLAGS += -D_REMOTELOGGINGSERVER -D_REMOTELOGGING
endif

ifeq ($(KVM),1)
# Mesh Agent KVM, this is only included in builds that have KVM support
LINUXKVMSOURCES = meshcore/KVM/Linux/linux_kvm.c meshcore/KVM/Linux/linux_events.c meshcore/KVM/Linux/linux_tile.c meshcore/KVM/Linux/linux_compression.c
MACOSKVMSOURCES = meshcore/KVM/MacOS/mac_kvm.c meshcore/KVM/MacOS/mac_events.c meshcore/KVM/MacOS/mac_tile.c meshcore/KVM/Linux/linux_compression.c
CFLAGS += -D_LINKVM
	ifneq ($(JPEGVER),)
		LINUXFLAGS = -l:lib-jpeg-turbo/linux/$(ARCHNAME)/$(JPEGVER)/libturbojpeg.a
		MACOSFLAGS = ./lib-jpeg-turbo/macos/$(ARCHNAME)/$(JPEGVER)/libturbojpeg.a
	else
		LINUXFLAGS = -l:lib-jpeg-turbo/linux/$(ARCHNAME)/libturbojpeg.a
		MACOSFLAGS = ./lib-jpeg-turbo/macos/$(ARCHNAME)/libturbojpeg.a
	endif
endif

ifeq ($(LMS),0)
CFLAGS += -D_NOHECI
endif

ifeq ($(WEBRTCDEBUG),1)
# Adds WebRTC Debug Interfaces
CFLAGS += -D_WEBRTCDEBUG
endif

ifneq ($(WatchDog),)
CWATCHDOG := -DILibChain_WATCHDOG_TIMEOUT=$(WatchDog)
endif

ifeq ($(NOTLS),1)
SOURCES += microstack/nossl/sha384-512.c microstack/nossl/sha224-256.c microstack/nossl/md5.c microstack/nossl/sha1.c
CFLAGS += -DMICROSTACK_NOTLS
LINUXSSL = 
MACSSL =
else
LINUXSSL = -Lopenssl/libstatic/linux/$(ARCHNAME)
MACSSL = -Lopenssl/libstatic/macos/$(ARCHNAME)
CFLAGS += -DMICROSTACK_TLS_DETECT
LDEXTRA += -lssl -lcrypto
endif

ifeq ($(DEBUG),1)
# Debug Build, include Symbols
CFLAGS += -g -D_DEBUG 
STRIP = $(NOECHO) $(NOOP)
else
CFLAGS += -Os
STRIP += ./$(EXENAME)_$(ARCHNAME)$(EXENAME2)
endif

ifeq ($(SSL_TRACE),1)
CFLAGS += -DSSL_TRACE
endif

GCCTEST := $(shell $(CC) meshcore/dummy.c -o /dev/null -no-pie > /dev/null 2>&1 ; echo $$? )
ifeq ($(GCCTEST),0)
LDFLAGS += -no-pie
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
	rm -f meshcore/KVM/Linux/*.o
	rm -f microlms/lms/*.o
	rm -f microlms/heci/*.o

cleanbin:
	rm -f $(EXENAME)_x86
	rm -f $(EXENAME)_x86_nokvm
	rm -f $(EXENAME)_x86-64
	rm -f $(EXENAME)_x86-64_nokvm
	rm -f $(EXENAME)_arm
	rm -f $(EXENAME)_armhf
	rm -f $(EXENAME)_mips
	rm -f $(EXENAME)_osx-x86-64
	rm -f $(EXENAME)_pi
	rm -f $(EXENAME)_pi2
	rm -f $(EXENAME)_pogo
	rm -f $(EXENAME)_poky
	rm -f $(EXENAME)_poky64


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
	$(MAKE) EXENAME="meshagent_pi" CFLAGS="-std=gnu99 -g -Wall -D_POSIX -DMICROSTACK_PROXY -DMICROSTACK_TLS_DETECT -D_LINKVM $(CWEBLOG) $(CWATCHDOG) -fno-strict-aliasing $(INCDIRS) -DMESH_AGENTID=25 -D_NOFSWATCHER -D_NOHECI" ADDITIONALSOURCES="$(LINUXKVMSOURCES)" LDFLAGS="-Lopenssl/libstatic/linux/pi -lrt $(LINUXSSL) $(LINUXFLAGS) $(LDFLAGS) $(LDEXTRA)"
	strip meshagent_pi

linux:
	$(MAKE) EXENAME="$(EXENAME)_$(ARCHNAME)$(EXENAME2)" AID="$(ARCHID)" ADDITIONALSOURCES="$(LINUXKVMSOURCES)" ADDITIONALFLAGS="-lrt -z noexecstack -z relro -z now" CFLAGS="-DMESH_AGENTID=$(ARCHID) $(CFLAGS) $(CEXTRA)" LDFLAGS="$(LINUXSSL) $(LINUXFLAGS) $(LDFLAGS) $(LDEXTRA)"
	$(STRIP)

macos:
	$(MAKE) $(MAKEFILE) EXENAME="$(EXENAME)_$(ARCHNAME)" ADDITIONALSOURCES="$(MACOSKVMSOURCES)" CFLAGS="-arch x86_64 -mmacosx-version-min=10.5 -std=gnu99 -Os -Wall -DMESH_AGENTID=$(ARCHID) -D_POSIX -D_NOILIBSTACKDEBUG -D_NOHECI -DMICROSTACK_PROXY -D__APPLE__ $(CWEBLOG) -fno-strict-aliasing $(INCDIRS) $(CFLAGS) $(CEXTRA)" LDFLAGS="$(MACSSL) $(MACOSFLAGS) -L. -lpthread -ldl -lz -lutil -framework IOKit -framework ApplicationServices -framework SystemConfiguration -framework CoreFoundation -fconstant-cfstrings $(LDFLAGS) $(LDEXTRA)"
	$(STRIP)


