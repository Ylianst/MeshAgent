SOURCES = ./WebRTC_MicroStackSample.c ./SimpleRendezvousServer.c ../../microstack/ILibCrypto.c 
SOURCES += ../../microstack/ILibAsyncServerSocket.c ../../microstack/ILibAsyncUDPSocket.c ../../microstack/ILibWebClient.c ../../microstack/ILibAsyncSocket.c ../../microstack/ILibParsers.c ../../microstack/ILibWebServer.c ../../microstack/ILibWebRTC.c ../../microstack/ILibWrapperWebRTC.c ../../microstack/ILibRemoteLogging.c ../../microstack/ILibProcessPipe.c
SOURCES += $(ADDITIONALSOURCES)

PATH_ARM5 = /home/default/Public/ToolChains/LinuxArm/bin/

OBJECTS = $(patsubst %.c,%.o, $(SOURCES))

EXENAME = webrtc_sample_linux

# Compiler command name
CC = gcc

# need to be separate for dependency generation	
INCDIRS = -I. -I../../openssl/include -I../../openssl -I../../microstack

CFLAGS  ?= -Wall -D_POSIX -DMICROSTACK_PROXY -fno-strict-aliasing $(INCDIRS)
LDEXTRAS = -L. -lpthread -ldl -lssl -lz -lutil -lcrypto -lrt

ifeq ($(DEBUG),1)
CFLAGS += -g -D_DEBUG -rdynamic
STRIP = @:
else
CFLAGS += -Os 
endif

ifeq ($(WEBLOG),1)
CFLAGS += -D_REMOTELOGGINGSERVER -D_REMOTELOGGING
endif


.PHONY: all clean

all: $(EXENAME)

$(EXENAME): $(OBJECTS)
	$(V)$(CC) $^ $(LDFLAGS) -o $@

clean:
	rm -f *.o
	rm -f ../../microstack/*.o

cleanbin:
	-rm -f webrtc_sample_linux_arm*
	-rm -f webrtc_sample_linux_x64*
	-rm -f webrtc_sample_linux_x86*

depend: $(SOURCES)
	$(CC) -M $(CFLAGS) $(SOURCES) $(HEADERS) > depend
	
linux-32:
	$(MAKE) $(MAKEFILE) EXENAME="webrtc_sample_linux_x86" CFLAGS="-m32 $(CFLAGS) $(INCDIRS)" LDFLAGS="-m32 -L../../openssl/libstatic/linux/x86 $(LDEXTRAS)"
	$(STRIP) strip ./webrtc_sample_linux_x86

linux-64:
	$(MAKE) $(MAKEFILE) EXENAME="webrtc_sample_linux_x64" CFLAGS="$(CFLAGS) $(INCDIRS)" LDFLAGS="-L../../openssl/libstatic/linux/x86-64 $(LDEXTRAS)" 
	$(STRIP) strip ./webrtc_sample_linux_x64

linux-arm:
	$(MAKE) $(MAKEFILE) EXENAME="webrtc_sample_linux_arm" CC=$(PATH_ARM5)"arm-none-linux-gnueabi-gcc" INCDIRS="-I. -Iopenssl/include -Imicrostack -Icore" CFLAGS="-O2 -Wall -D_POSIX -D_DEBUG -D_DAEMON -DMICROSTACK_PROXY -fno-strict-aliasing $(INCDIRS)" LDFLAGS="-Lopenssl-static/arm -L. -lpthread -Wl,--no-as-needed -ldl -lssl -lutil -lcrypto -lrt"
	$(STRIP) $(PATH_ARM5)arm-none-linux-gnueabi-strip ./webrtc_sample_linux_arm


